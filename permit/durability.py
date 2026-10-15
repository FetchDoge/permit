"""
Durable persistence for Permit — Charter Gate 1.

File-backed, atomic, offline. Survives SIGKILL at any kill point.

Wraps Ledger, PermitStore, MockPayPalClient, ReleaseVerifier, SpendPipeline
with durable_dir persistence. When durable_dir is None, behaves exactly as
in-memory (no files, no behavior change) — existing tests and demos
use this path.

Atomic write: write to *.tmp + fsync + os.rename + fsync dir.

Integrity (REA R2):
  - Exclusive writer flock for the process lifetime; a second opener fails closed.
  - ledger.head binding records committed length/hash; truncation fails closed.
  - permits.json is bound to the ledger head (hash + HMAC); rewind fails closed.
  - On load, permit counters are rebuilt by folding the ledger (source of truth),
    so a crash after ALLOWED but before permits.json persist retains the reservation.
  - Directory fsync errors are logged and raised (fail closed).
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import logging
import os
import threading
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

from .ledger import GENESIS_HASH, Ledger, Receipt, _canonical
from .permit import PermitStore
from .sqlite_ledger import fold_receipts
from settlement.paypal_client import MockPayPalClient
from settlement.verifier import Escrow, PredicateType, ReleaseVerifier

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _durable_dir(durable_dir) -> Optional[Path]:
    if durable_dir is not None:
        return Path(durable_dir).expanduser()
    env = os.environ.get("PERMIT_DURABLE_DIR")
    if env:
        return Path(env).expanduser()
    return None


def _ensure_dir(d: Path) -> None:
    d.mkdir(parents=True, exist_ok=True)


def _fsync_dir(d: Path) -> None:
    try:
        fd = os.open(str(d), os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        logger.exception("fsync of durable directory %s failed", d)
        raise


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    _ensure_dir(path.parent)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.rename(tmp, path)
    _fsync_dir(path.parent)


def _atomic_write_json(path: Path, obj) -> None:
    data = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    _atomic_write_bytes(path, data)


def _atomic_append_jsonl(path: Path, obj: dict) -> None:
    _ensure_dir(path.parent)
    line = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str) + "\n"
    with path.open("a", encoding="utf-8") as f:
        f.write(line)
        f.flush()
        os.fsync(f.fileno())
    _fsync_dir(path.parent)


def _ledger_tip(receipts: list[Receipt]) -> dict:
    if not receipts:
        return {"len": 0, "seq": None, "hash": GENESIS_HASH}
    tip = receipts[-1]
    return {"len": len(receipts), "seq": tip.seq, "hash": tip.hash}


def _permits_mac(permits_body: dict, ledger_head: dict) -> str:
    """HMAC binding permits payload to the ledger head hash."""
    key = (ledger_head.get("hash") or GENESIS_HASH).encode("utf-8")
    body = _canonical({"permits": permits_body, "ledger_head": ledger_head})
    return hmac.new(key, body, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# DurableLedger
# ---------------------------------------------------------------------------

class DurableLedger(Ledger):
    def __init__(self, durable_dir=None):
        super().__init__()
        self._durable_dir = _durable_dir(durable_dir)
        self._lock_fd: int | None = None
        # Serializes the WHOLE durable append (in-memory receipt, ledger
        # line + fsync, ledger.head rewrite). Ledger._lock alone only covers
        # the in-memory step, so two threads could interleave their file
        # writes out of seq order and collide on ledger.head.tmp. Separate
        # from Ledger._lock so readers (receipts(), verify_chain()) are not
        # blocked behind fsync.
        self._append_lock = threading.Lock()
        self._ledger_fd: int | None = None
        self._ledger_ino: int | None = None
        self._ledger_dev: int | None = None
        self._ledger_path: Path | None = None
        self._head_path: Path | None = None
        if self._durable_dir is not None:
            self._ledger_path = self._durable_dir / "ledger.jsonl"
            self._head_path = self._durable_dir / "ledger.head"
            self._acquire_writer_lock()
            self._load()
            self._open_ledger_fd()

    def _acquire_writer_lock(self) -> None:
        assert self._durable_dir is not None
        _ensure_dir(self._durable_dir)
        lock_path = self._durable_dir / "writer.lock"
        fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(fd)
            raise RuntimeError(
                f"durable writer lock held by another process: {lock_path}"
            ) from exc
        # Record holder for operators; not relied on for correctness.
        os.ftruncate(fd, 0)
        os.write(fd, f"{os.getpid()}\n".encode("utf-8"))
        os.fsync(fd)
        self._lock_fd = fd

    def _open_ledger_fd(self) -> None:
        """Keep an O_APPEND fd open so rename/unlink of the path cannot divert writes."""
        assert self._ledger_path is not None
        _ensure_dir(self._ledger_path.parent)
        fd = os.open(
            str(self._ledger_path),
            os.O_CREAT | os.O_APPEND | os.O_WRONLY,
            0o644,
        )
        st = os.fstat(fd)
        self._ledger_fd = fd
        self._ledger_ino = st.st_ino
        self._ledger_dev = st.st_dev

    def _assert_ledger_inode(self) -> None:
        """Fail closed if ledger.jsonl was replaced under our feet."""
        assert self._ledger_path is not None
        try:
            st = os.stat(self._ledger_path)
        except FileNotFoundError as exc:
            raise RuntimeError(
                f"ledger path disappeared under writer: {self._ledger_path}"
            ) from exc
        if st.st_ino != self._ledger_ino or st.st_dev != self._ledger_dev:
            raise RuntimeError(
                f"ledger inode diverged under writer: path={self._ledger_path} "
                f"expected dev/ino={self._ledger_dev}/{self._ledger_ino} "
                f"got {st.st_dev}/{st.st_ino}"
            )

    def close(self) -> None:
        if self._ledger_fd is not None:
            try:
                os.close(self._ledger_fd)
            finally:
                self._ledger_fd = None
        if self._lock_fd is not None:
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(self._lock_fd)
                self._lock_fd = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def _read_committed_head(self) -> dict | None:
        if self._head_path is None or not self._head_path.exists():
            return None
        try:
            return json.loads(self._head_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            raise ValueError(f"corrupt ledger.head: {exc}") from exc

    def _write_committed_head(self, tip: dict) -> None:
        assert self._head_path is not None
        _atomic_write_json(self._head_path, tip)

    def _load(self) -> None:
        assert self._ledger_path is not None
        receipts: list[Receipt] = []
        if self._ledger_path.exists():
            raw_text = self._ledger_path.read_text(encoding="utf-8")
            # Torn final line (no trailing newline / incomplete JSON) fails closed
            # unless the file is empty.
            if raw_text and not raw_text.endswith("\n"):
                # Allow a completely empty file; otherwise a torn tail is corrupt.
                last_nl = raw_text.rfind("\n")
                if last_nl == -1:
                    # Single incomplete line
                    raise json.JSONDecodeError(
                        "torn ledger tail", raw_text, len(raw_text)
                    )
            for raw in raw_text.splitlines():
                if not raw.strip():
                    continue
                d = json.loads(raw)
                r = Receipt(
                    seq=d["seq"],
                    prev_hash=d["prev_hash"],
                    event_type=d["event_type"],
                    payload=d["payload"],
                    timestamp=d["timestamp"],
                )
                if d.get("hash") and d["hash"] != r.hash:
                    raise ValueError(f"ledger hash mismatch at seq {d['seq']}")
                receipts.append(r)

        tip = _ledger_tip(receipts)
        committed = self._read_committed_head()
        if committed is not None:
            c_len = int(committed.get("len", -1))
            if c_len > tip["len"]:
                raise ValueError(
                    f"ledger truncated: committed len={c_len} "
                    f"but file has {tip['len']} entries"
                )
            if c_len == tip["len"] and committed.get("hash") != tip["hash"]:
                raise ValueError(
                    "ledger.head hash mismatch at committed length "
                    f"{c_len}: committed={committed.get('hash')} "
                    f"actual={tip['hash']}"
                )
            # committed len < tip len: crash window after append before head
            # update — accept and advance the head below.

        with self._lock:
            self._receipts = receipts

        ok, reason = self.verify_chain()
        if not ok:
            raise ValueError(f"ledger chain broken on load: {reason}")

        # Advance or create the committed head to match the loaded tip.
        if committed is None or int(committed.get("len", -1)) < tip["len"]:
            self._write_committed_head(tip)

    def tip(self) -> dict:
        return _ledger_tip(self.receipts())

    def append(self, event_type: str, payload: dict) -> Receipt:
        with self._append_lock:
            return self._append_locked(event_type, payload)

    def _append_locked(self, event_type: str, payload: dict) -> Receipt:
        receipt = super().append(event_type, payload)
        if self._durable_dir is not None:
            assert self._ledger_fd is not None
            self._assert_ledger_inode()
            line = (
                json.dumps(
                    {
                        "seq": receipt.seq,
                        "prev_hash": receipt.prev_hash,
                        "event_type": receipt.event_type,
                        "payload": receipt.payload,
                        "timestamp": receipt.timestamp,
                        "hash": receipt.hash,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                    default=str,
                )
                + "\n"
            )
            os.write(self._ledger_fd, line.encode("utf-8"))
            os.fsync(self._ledger_fd)
            _fsync_dir(self._durable_dir)
            # Commit length/hash after the line is durable so a later truncate
            # of ledger.jsonl is detectable on reload.
            # Under _append_lock this receipt is the tip; derive it directly
            # instead of copying the whole chain (tip() is O(n)).
            self._write_committed_head(
                {"len": receipt.seq + 1, "seq": receipt.seq, "hash": receipt.hash})
        return receipt


# ---------------------------------------------------------------------------
# DurablePermitStore
# ---------------------------------------------------------------------------

class DurablePermitStore(PermitStore):
    def __init__(self, ledger: Optional[Ledger] = None, durable_dir=None):
        super().__init__(ledger=ledger)
        self._durable_dir = _durable_dir(durable_dir)
        if self._durable_dir is not None:
            self._permits_path = self._durable_dir / "permits.json"
            self._load()

    def _binding_from_file(self, data: dict) -> dict | None:
        head = data.get("ledger_head")
        if isinstance(head, dict) and "len" in head and "hash" in head:
            return head
        return None

    def _verify_permits_binding(self, data: dict, tip: dict) -> None:
        binding = self._binding_from_file(data)
        if binding is None:
            # Legacy unsigned snapshot with no binding: only acceptable when
            # the ledger is empty (nothing to bind). Otherwise fail closed —
            # an attacker could drop the binding key to skip the check.
            if tip["len"] > 0:
                raise ValueError(
                    "permits.json missing ledger_head binding while ledger "
                    f"has {tip['len']} entries"
                )
            return

        b_len = int(binding["len"])
        if b_len > tip["len"]:
            raise ValueError(
                f"ledger truncated relative to permits.json binding: "
                f"binding len={b_len} ledger len={tip['len']}"
            )
        if b_len == tip["len"] and binding.get("hash") != tip["hash"]:
            raise ValueError(
                "permits.json ledger_head hash mismatch: "
                f"binding={binding.get('hash')} ledger={tip['hash']}"
            )

        permits_body = data.get("permits")
        if permits_body is None:
            # Legacy flat map of permit_id -> fields (no envelope).
            permits_body = {
                k: v for k, v in data.items()
                if k not in ("ledger_head", "mac", "permits")
            }
        expected_mac = data.get("mac")
        if expected_mac is not None:
            actual = _permits_mac(permits_body, binding)
            if not hmac.compare_digest(actual, expected_mac):
                raise ValueError(
                    "permits.json HMAC mismatch (rewound or forged snapshot)"
                )

    def _rebuild_from_ledger(self) -> None:
        """Ledger is source of truth for reservations / in_flight / captures."""
        if self.ledger is None:
            return
        receipts = self.ledger.receipts()
        if not receipts:
            return
        folded = fold_receipts(receipts)
        with self._store_lock:
            self._permits = folded._permits
            self._children = getattr(folded, "_children", {})

    def _load(self) -> None:
        tip = (
            self.ledger.tip()
            if isinstance(self.ledger, DurableLedger)
            else _ledger_tip(self.ledger.receipts())
        )

        if self._permits_path.exists():
            data = json.loads(self._permits_path.read_text(encoding="utf-8"))
            self._verify_permits_binding(data, tip)

        # Always rebuild counters from the ledger so a crash between
        # ALLOWED append and permits.json persist cannot drop a reservation.
        self._rebuild_from_ledger()

        # If the ledger is ahead of a stale permits snapshot, rewrite the
        # bound snapshot now that fold has restored state.
        if tip["len"] > 0:
            self._persist()

    def _persist(self) -> None:
        if self._durable_dir is None:
            return
        tip = (
            self.ledger.tip()
            if isinstance(self.ledger, DurableLedger)
            else _ledger_tip(self.ledger.receipts())
        )
        permits_body = {}
        with self._store_lock:
            for pid, p in self._permits.items():
                permits_body[pid] = {
                    "permit_id": p.permit_id,
                    "agent_id": p.agent_id,
                    "cap_cents": p.cap_cents,
                    "allowlist": list(p.allowlist),
                    "expiry": p.expiry.isoformat(),
                    "revoked": p.revoked,
                    "reserved_cents": p.reserved_cents,
                    "captured_cents": p.captured_cents,
                    "in_flight": dict(p.in_flight),
                    "parent_id": p.parent_id,
                    "depth": p.depth,
                    "tighten_cap_cents": p.tighten_cap_cents,
                    "tighten_allowlist": (
                        list(p.tighten_allowlist)
                        if p.tighten_allowlist is not None
                        else None
                    ),
                    "tighten_expiry": (
                        p.tighten_expiry.isoformat()
                        if p.tighten_expiry is not None
                        else None
                    ),
                    "approval_threshold_cents": p.approval_threshold_cents,
                    "tighten_approval_threshold_cents": (
                        p.tighten_approval_threshold_cents
                    ),
                    "calibration_tau": p.calibration_tau,
                }
        envelope = {
            "permits": permits_body,
            "ledger_head": tip,
            "mac": _permits_mac(permits_body, tip),
        }
        _atomic_write_json(self._permits_path, envelope)

    def grant(
        self,
        agent_id: str,
        cap_cents: int,
        allowlist: list[str],
        expiry: datetime,
        approval_threshold_cents: int | None = None,
        calibration_tau: float | None = None,
    ):
        kwargs = {}
        if approval_threshold_cents is not None:
            kwargs["approval_threshold_cents"] = approval_threshold_cents
        if calibration_tau is not None:
            kwargs["calibration_tau"] = calibration_tau
        permit, receipt = super().grant(
            agent_id, cap_cents, allowlist, expiry, **kwargs
        )
        self._persist()
        return permit, receipt

    def check(self, permit_id: str, amount_cents: int, merchant_id: str, now: datetime | None = None):
        result = super().check(permit_id, amount_cents, merchant_id, now=now)
        # Persist on ALLOWED (reservation) — ledger line is already durable.
        if result.allowed:
            self._persist()
        return result

    def settle_capture(self, permit_id: str, auth_id: str):
        receipt = super().settle_capture(permit_id, auth_id)
        self._persist()
        return receipt

    def settle_void(self, permit_id: str, auth_id: str):
        receipt = super().settle_void(permit_id, auth_id)
        self._persist()
        return receipt

    def estop(self, permit_id: str):
        receipt, in_flight = super().estop(permit_id)
        self._persist()
        return receipt, in_flight

    def estop_cascade(self, permit_id: str):
        result = super().estop_cascade(permit_id)
        self._persist()
        return result


# ---------------------------------------------------------------------------
# DurableMockPayPalClient
# ---------------------------------------------------------------------------

class DurableMockPayPalClient(MockPayPalClient):
    def __init__(self, durable_dir=None, merchant_account_id: str | None = None):
        super().__init__(merchant_account_id=merchant_account_id)
        self._durable_dir = _durable_dir(durable_dir)
        if self._durable_dir is not None:
            self._paypal_path = self._durable_dir / "mock_paypal.json"
            self._load()

    def _load(self) -> None:
        if not self._paypal_path.exists():
            return
        try:
            data = json.loads(self._paypal_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return
        from settlement.paypal_client import Authorization, Capture, Void

        for auth_id, d in data.get("authorizations", {}).items():
            self.authorizations[auth_id] = Authorization(
                auth_id=d["auth_id"],
                amount_cents=d["amount_cents"],
                merchant_id=d["merchant_id"],
                status=d["status"],
                created_at=d["created_at"],
            )
        for key, d in data.get("captures", {}).items():
            self.captures[key] = Capture(
                capture_id=d["capture_id"],
                auth_id=d["auth_id"],
                amount_cents=d["amount_cents"],
                status=d["status"],
                idempotency_key=d["idempotency_key"],
            )
        for auth_id, d in data.get("voids", {}).items():
            self.voids[auth_id] = Void(auth_id=d["auth_id"], status=d["status"])
        self.capture_calls = list(data.get("capture_calls", []))
        self.authorize_calls = list(data.get("authorize_calls", []))
        self.inject_capture_timeout = data.get("inject_capture_timeout")
        self.inject_void_timeout = data.get("inject_void_timeout", False)
        self.capture_status = data.get("capture_status", "COMPLETED")

    def _persist(self) -> None:
        if self._durable_dir is None:
            return
        data = {
            "authorizations": {k: asdict(v) for k, v in self.authorizations.items()},
            "captures": {k: asdict(v) for k, v in self.captures.items()},
            "voids": {k: asdict(v) for k, v in self.voids.items()},
            "capture_calls": list(self.capture_calls),
            "authorize_calls": list(self.authorize_calls),
            "inject_capture_timeout": self.inject_capture_timeout,
            "inject_void_timeout": self.inject_void_timeout,
            "capture_status": self.capture_status,
        }
        _atomic_write_json(self._paypal_path, data)

    def authorize(self, amount_cents: int, merchant_id: str, idempotency_key: str | None = None):
        result = super().authorize(amount_cents, merchant_id, idempotency_key=idempotency_key)
        self._persist()
        return result

    def capture(self, auth_id: str, amount_cents: int, idempotency_key: str):
        try:
            result = super().capture(auth_id, amount_cents, idempotency_key)
            self._persist()
            return result
        except Exception:
            self._persist()
            raise

    def void(self, auth_id: str):
        result = super().void(auth_id)
        self._persist()
        return result

    def get_authorization(self, auth_id: str):
        return super().get_authorization(auth_id)


# ---------------------------------------------------------------------------
# DurableReleaseVerifier
# ---------------------------------------------------------------------------

class DurableReleaseVerifier(ReleaseVerifier):
    def __init__(self, paypal, permits: DurablePermitStore, ledger: Optional[Ledger] = None, durable_dir=None, **key_kwargs):
        super().__init__(paypal, permits, ledger=ledger, **key_kwargs)
        self._durable_dir = _durable_dir(durable_dir)
        if self._durable_dir is not None:
            self._escrows_path = self._durable_dir / "escrows.json"
            self._load()

    def _load(self) -> None:
        if not self._escrows_path.exists():
            return
        try:
            data = json.loads(self._escrows_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return
        for eid, d in data.items():
            pt = PredicateType(d["predicate_type"]) if isinstance(d["predicate_type"], str) else d["predicate_type"]
            if isinstance(pt, str):
                pt = PredicateType(pt)
            if isinstance(d["predicate_type"], str):
                try:
                    pt = PredicateType(d["predicate_type"])
                except ValueError:
                    pt = PredicateType.D
            escrow = Escrow(
                escrow_id=d["escrow_id"],
                permit_id=d["permit_id"],
                auth_id=d["auth_id"],
                paypal_auth_id=d["paypal_auth_id"],
                amount_cents=d["amount_cents"],
                merchant_id=d["merchant_id"],
                predicate_type=pt,
                artifact_hash=d["artifact_hash"],
                state=d.get("state", "AUTHORIZED"),
            )
            self._escrows[eid] = escrow

    def _persist(self) -> None:
        if self._durable_dir is None:
            return
        data = {}
        with self._lock:
            for eid, e in self._escrows.items():
                pt_val = e.predicate_type.value if isinstance(e.predicate_type, PredicateType) else str(e.predicate_type)
                data[eid] = {
                    "escrow_id": e.escrow_id,
                    "permit_id": e.permit_id,
                    "auth_id": e.auth_id,
                    "paypal_auth_id": e.paypal_auth_id,
                    "amount_cents": e.amount_cents,
                    "merchant_id": e.merchant_id,
                    "predicate_type": pt_val,
                    "artifact_hash": e.artifact_hash,
                    "state": e.state,
                }
        _atomic_write_json(self._escrows_path, data)

    def register(self, escrow: Escrow):
        receipt = super().register(escrow)
        self._persist()
        return receipt

    def verify_and_capture(self, escrow_id: str, evidence):
        result = super().verify_and_capture(escrow_id, evidence)
        self._persist()
        return result

    def reconcile(self, escrow_id: str):
        result = super().reconcile(escrow_id)
        self._persist()
        return result

    def retry_cleanup(self, escrow_id: str):
        result = super().retry_cleanup(escrow_id)
        self._persist()
        return result

    def void(self, escrow_id: str):
        result = super().void(escrow_id)
        self._persist()
        return result


# ---------------------------------------------------------------------------
# DurableSpendPipeline
# ---------------------------------------------------------------------------

from permit.flow import SpendPipeline


class DurableSpendPipeline(SpendPipeline):
    def __init__(self, permits: DurablePermitStore, paypal, verifier: DurableReleaseVerifier, ledger: Optional[Ledger] = None, durable_dir=None):
        super().__init__(permits, paypal, verifier, ledger=ledger)
        self._durable_dir = _durable_dir(durable_dir)
        if self._durable_dir is not None:
            self._outstanding_path = self._durable_dir / "outstanding.json"
            self._auth_to_escrow_path = self._durable_dir / "auth_to_escrow.json"
            self._cleanup_confirmed_path = self._durable_dir / "cleanup_confirmed.json"
            self._cleanup_committing_path = self._durable_dir / "cleanup_committing.json"
            self._load()

    def _load(self) -> None:
        if self._outstanding_path.exists():
            try:
                data = json.loads(self._outstanding_path.read_text(encoding="utf-8"))
                with self._outstanding_lock:
                    self._outstanding = dict(data)
            except (json.JSONDecodeError, OSError):
                pass
        if self._auth_to_escrow_path.exists():
            try:
                data = json.loads(self._auth_to_escrow_path.read_text(encoding="utf-8"))
                self._auth_to_escrow = dict(data)
            except (json.JSONDecodeError, OSError):
                pass
        if self._cleanup_confirmed_path.exists():
            try:
                data = json.loads(self._cleanup_confirmed_path.read_text(encoding="utf-8"))
                self._cleanup_confirmed = set(data)
            except (json.JSONDecodeError, OSError):
                pass
        if self._cleanup_committing_path.exists():
            try:
                data = json.loads(self._cleanup_committing_path.read_text(encoding="utf-8"))
                self._cleanup_committing = set(data)
            except (json.JSONDecodeError, OSError):
                pass

    def _persist(self) -> None:
        if self._durable_dir is None:
            return
        with self._outstanding_lock:
            outstanding_copy = dict(self._outstanding)
        _atomic_write_json(self._outstanding_path, outstanding_copy)
        _atomic_write_json(self._auth_to_escrow_path, dict(self._auth_to_escrow))
        _atomic_write_json(self._cleanup_confirmed_path, list(self._cleanup_confirmed))
        _atomic_write_json(self._cleanup_committing_path, list(self._cleanup_committing))

    def _track_outstanding(self, auth_id: str, permit_id: str) -> None:
        super()._track_outstanding(auth_id, permit_id)
        self._persist()

    def _set_outstanding_paypal_auth(self, auth_id: str, paypal_auth_id: str) -> None:
        super()._set_outstanding_paypal_auth(auth_id, paypal_auth_id)
        self._persist()

    def _drop_outstanding(self, auth_id: str) -> None:
        super()._drop_outstanding(auth_id)
        self._persist()

    def _hold_for_cleanup(self, auth_id: str, permit_id: str, paypal_auth_id: str | None) -> None:
        super()._hold_for_cleanup(auth_id, permit_id, paypal_auth_id)
        self._persist()

    def spend(self, permit_id: str, amount_cents: int, merchant_id: str, predicate_type, artifact_hash: str, approval_id: str | None = None):
        return super().spend(
            permit_id, amount_cents, merchant_id, predicate_type, artifact_hash,
            approval_id=approval_id,
        )

    def register_escrow(self, permit_id: str, auth_id: str, paypal_auth_id: str, amount_cents: int, merchant_id: str, predicate_type, artifact_hash: str):
        result = super().register_escrow(permit_id, auth_id, paypal_auth_id, amount_cents, merchant_id, predicate_type, artifact_hash)
        self._persist()
        return result
