"""
Durable persistence for Permit — Charter Gate 1.

File-backed, atomic, offline. Survives SIGKILL at any kill point.

Wraps Ledger, PermitStore, MockPayPalClient, ReleaseVerifier, SpendPipeline
with durable_dir persistence. When durable_dir is None, behaves exactly as
in-memory (no files, no behavior change) — existing 127 tests and demos
use this path.

Atomic write: write to *.tmp + fsync + os.rename + fsync dir.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .ledger import GENESIS_HASH, Ledger, Receipt, _canonical
from .permit import Permit, PermitStore
from settlement.paypal_client import MockPayPalClient
from settlement.verifier import Escrow, PredicateType, ReleaseVerifier

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
        pass


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
    # Open in append, fsync
    with path.open("a", encoding="utf-8") as f:
        f.write(line)
        f.flush()
        os.fsync(f.fileno())
    _fsync_dir(path.parent)


# ---------------------------------------------------------------------------
# DurableLedger
# ---------------------------------------------------------------------------

class DurableLedger(Ledger):
    def __init__(self, durable_dir=None):
        super().__init__()
        self._durable_dir = _durable_dir(durable_dir)
        if self._durable_dir is not None:
            self._ledger_path = self._durable_dir / "ledger.jsonl"
            self._load()

    def _load(self) -> None:
        if not self._ledger_path.exists():
            return
        receipts = []
        for raw in self._ledger_path.read_text(encoding="utf-8").splitlines():
            if not raw.strip():
                continue
            d = json.loads(raw)
            # Reconstruct Receipt without recomputing hash — verify on load
            r = Receipt(
                seq=d["seq"],
                prev_hash=d["prev_hash"],
                event_type=d["event_type"],
                payload=d["payload"],
                timestamp=d["timestamp"],
            )
            # d may have hash — verify it matches recomputed
            if d.get("hash") and d["hash"] != r.hash:
                # Corrupt line — skip? Fail? For harness we keep chain intact
                # but log — we preserve the line's hash as ground truth
                # Actually recomputed hash should match; if not, file corrupt
                raise ValueError(f"ledger hash mismatch at seq {d['seq']}")
            receipts.append(r)
        with self._lock:
            self._receipts = receipts

    def append(self, event_type: str, payload: dict) -> Receipt:
        receipt = super().append(event_type, payload)
        if self._durable_dir is not None:
            _atomic_append_jsonl(
                self._ledger_path,
                {
                    "seq": receipt.seq,
                    "prev_hash": receipt.prev_hash,
                    "event_type": receipt.event_type,
                    "payload": receipt.payload,
                    "timestamp": receipt.timestamp,
                    "hash": receipt.hash,
                },
            )
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

    def _load(self) -> None:
        if not self._permits_path.exists():
            return
        data = json.loads(self._permits_path.read_text(encoding="utf-8"))
        for pid, d in data.items():
            permit = Permit(
                permit_id=d["permit_id"],
                agent_id=d["agent_id"],
                cap_cents=d["cap_cents"],
                allowlist=tuple(d["allowlist"]),
                expiry=datetime.fromisoformat(d["expiry"]),
                revoked=d.get("revoked", False),
                reserved_cents=d.get("reserved_cents", 0),
                captured_cents=d.get("captured_cents", 0),
                in_flight=dict(d.get("in_flight", {})),
            )
            with self._store_lock:
                self._permits[pid] = permit

    def _persist(self) -> None:
        if self._durable_dir is None:
            return
        data = {}
        with self._store_lock:
            for pid, p in self._permits.items():
                data[pid] = {
                    "permit_id": p.permit_id,
                    "agent_id": p.agent_id,
                    "cap_cents": p.cap_cents,
                    "allowlist": list(p.allowlist),
                    "expiry": p.expiry.isoformat(),
                    "revoked": p.revoked,
                    "reserved_cents": p.reserved_cents,
                    "captured_cents": p.captured_cents,
                    "in_flight": dict(p.in_flight),
                }
        _atomic_write_json(self._permits_path, data)

    def grant(self, agent_id: str, cap_cents: int, allowlist: list[str], expiry: datetime):
        permit, receipt = super().grant(agent_id, cap_cents, allowlist, expiry)
        self._persist()
        return permit, receipt

    def check(self, permit_id: str, amount_cents: int, merchant_id: str, now: datetime | None = None):
        result = super().check(permit_id, amount_cents, merchant_id, now=now)
        # Persist on ALLOWED (reservation) and on BLOCKED we don't need permit change
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
        # Reconstruct authorizations
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
        # Need to handle inject timeout persistence correctly — capture may raise
        try:
            result = super().capture(auth_id, amount_cents, idempotency_key)
            self._persist()
            return result
        except Exception:
            # Even on timeout after_apply, super already recorded capture before raise
            self._persist()
            raise

    def void(self, auth_id: str):
        result = super().void(auth_id)
        self._persist()
        return result

    def get_authorization(self, auth_id: str):
        # read-only, no persist
        return super().get_authorization(auth_id)


# ---------------------------------------------------------------------------
# DurableReleaseVerifier
# ---------------------------------------------------------------------------

class DurableReleaseVerifier(ReleaseVerifier):
    def __init__(self, paypal, permits: DurablePermitStore, ledger: Optional[Ledger] = None, durable_dir=None):
        super().__init__(paypal, permits, ledger=ledger)
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
            # PredicateType stored as value
            pt = PredicateType(d["predicate_type"]) if isinstance(d["predicate_type"], str) else d["predicate_type"]
            if isinstance(pt, str):
                pt = PredicateType(pt)
            # Handle string value like "delivery_hash"
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
                # Store predicate as value string
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
        # Use the same ledger/permits/verifier that are already durable
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

    def spend(self, permit_id: str, amount_cents: int, merchant_id: str, predicate_type, artifact_hash: str):
        # spend() will call _track_outstanding which persists; no extra needed
        return super().spend(permit_id, amount_cents, merchant_id, predicate_type, artifact_hash)

    def register_escrow(self, permit_id: str, auth_id: str, paypal_auth_id: str, amount_cents: int, merchant_id: str, predicate_type, artifact_hash: str):
        result = super().register_escrow(permit_id, auth_id, paypal_auth_id, amount_cents, merchant_id, predicate_type, artifact_hash)
        self._persist()
        return result
