"""
Permit ledger: SQLite-backed durable variant of the hash-chained receipt log.

Same interface and semantics as permit/ledger.py's in-memory Ledger —
append-only, hash-chained, fail-closed — but every receipt is committed
to SQLite (WAL, synchronous=FULL) so the chain survives process restarts.
On open, the database is integrity-checked and the chain is re-verified
before the instance serves anything; any failure raises instead of
serving a broken chain.

Design: docs/sqlite-durability-design.md. Stdlib only (sqlite3).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading

from .ledger import GENESIS_HASH, Receipt, _canonical, _utcnow_iso


_DDL_TABLE = """
CREATE TABLE IF NOT EXISTS receipts (
  seq        INTEGER PRIMARY KEY,
  prev_hash  TEXT    NOT NULL,
  event_type TEXT    NOT NULL,
  payload    TEXT    NOT NULL,
  timestamp  TEXT    NOT NULL,
  hash       TEXT    NOT NULL UNIQUE
)
"""

_DDL_NO_UPDATE = """
CREATE TRIGGER IF NOT EXISTS receipts_no_update
BEFORE UPDATE ON receipts
BEGIN
    SELECT RAISE(ABORT, 'receipts append-only');
END
"""

_DDL_NO_DELETE = """
CREATE TRIGGER IF NOT EXISTS receipts_no_delete
BEFORE DELETE ON receipts
BEGIN
    SELECT RAISE(ABORT, 'receipts append-only');
END
"""

_DDL_LINK = """
CREATE TRIGGER IF NOT EXISTS receipts_link
BEFORE INSERT ON receipts
WHEN NEW.seq <> 0
BEGIN
    SELECT RAISE(ABORT, 'seq gap or prev_hash mismatch')
    WHERE NOT EXISTS (SELECT 1 FROM receipts WHERE seq = NEW.seq - 1 AND hash = NEW.prev_hash);
END
"""

_DDL_IDEMPOTENCY = """
CREATE UNIQUE INDEX IF NOT EXISTS receipts_idempotency_key
ON receipts (json_extract(payload, '$.idempotency_key'))
WHERE json_extract(payload, '$.idempotency_key') IS NOT NULL
"""

_DDL = (
    _DDL_TABLE,
    _DDL_NO_UPDATE,
    _DDL_NO_DELETE,
    _DDL_LINK,
    _DDL_IDEMPOTENCY,
)


class SqliteLedger:
    """Durable, thread-safe, append-only receipt log with chain verification."""

    def __init__(self, path: str) -> None:
        if not isinstance(path, str) or not path:
            raise ValueError("path is required")
        self._lock = threading.Lock()
        self._path = path
        # check_same_thread=False: the lock (not the connection) is the
        # cross-thread guard; without this the shared connection is a trap.
        self._conn = sqlite3.connect(
            path, isolation_level=None, check_same_thread=False
        )
        try:
            mode = self._conn.execute("PRAGMA journal_mode=WAL").fetchone()
            if mode is None or str(mode[0]).lower() != "wal":
                # ':memory:' databases cannot use WAL; they are
                # transactionally safe without it (no torn pages).
                if path != ":memory:":
                    raise RuntimeError(
                        "journal_mode WAL not engaged: %r" % (mode,)
                    )
            self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            for stmt in _DDL:
                self._conn.execute(stmt)
            integrity = self._conn.execute("PRAGMA integrity_check").fetchall()
            if integrity != [("ok",)]:
                raise RuntimeError("integrity_check failed: %r" % (integrity,))
            rows = self._conn.execute(
                "SELECT seq, prev_hash, event_type, payload, timestamp, hash"
                " FROM receipts ORDER BY seq"
            ).fetchall()
            receipts: list[Receipt] = []
            allowed: dict[str, Receipt] = {}
            for seq, prev_hash, event_type, payload_text, timestamp, stored_hash in rows:
                payload = json.loads(payload_text)
                receipt = Receipt(
                    seq=seq,
                    prev_hash=prev_hash,
                    event_type=event_type,
                    payload=payload,
                    timestamp=timestamp,
                )
                if receipt.hash != stored_hash:
                    raise RuntimeError(
                        "stored hash mismatch at seq %s (payload tampered)"
                        % (seq,)
                    )
                receipts.append(receipt)
                if event_type == "ALLOWED":
                    auth_id = payload.get("auth_id")
                    if not isinstance(auth_id, str):
                        raise RuntimeError(
                            "ALLOWED seq %s missing auth_id" % (seq,)
                        )
                    allowed[auth_id] = receipt
            self._receipts = receipts
            self._allowed_by_auth = allowed
            ok, detail = self._verify_receipts(receipts)
            if not ok:
                raise RuntimeError(
                    "restored chain failed verification: %s" % (detail,)
                )
        except Exception:
            self._conn.close()
            raise

    @staticmethod
    def _verify_receipts(receipts: list[Receipt]) -> tuple[bool, str]:
        """Same semantics as Ledger.verify_chain: never raises on a broken chain."""
        expected_prev = GENESIS_HASH
        for expected_seq, r in enumerate(receipts):
            if r.seq != expected_seq:
                return False, f"sequence gap at seq {r.seq}"
            if r.prev_hash != expected_prev:
                return False, f"prev_hash mismatch at seq {r.seq}"
            body = {
                "seq": r.seq,
                "prev_hash": r.prev_hash,
                "event_type": r.event_type,
                "payload": r.payload,
                "timestamp": r.timestamp,
            }
            if hashlib.sha256(_canonical(body)).hexdigest() != r.hash:
                return False, f"hash mismatch at seq {r.seq} (payload tampered)"
            expected_prev = r.hash
        return True, "ok"

    def append(self, event_type: str, payload: dict) -> Receipt:
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                tip = self._conn.execute(
                    "SELECT seq, hash FROM receipts ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                if tip is None:
                    seq, prev_hash = 0, GENESIS_HASH
                else:
                    seq, prev_hash = tip[0] + 1, tip[1]
                receipt = Receipt(
                    seq=seq,
                    prev_hash=prev_hash,
                    event_type=event_type,
                    payload=payload,
                    timestamp=_utcnow_iso(),
                )
                try:
                    self._conn.execute(
                        "INSERT INTO receipts"
                        " (seq, prev_hash, event_type, payload, timestamp, hash)"
                        " VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            receipt.seq,
                            receipt.prev_hash,
                            receipt.event_type,
                            json.dumps(
                                receipt.payload,
                                sort_keys=True,
                                separators=(",", ":"),
                            ),
                            receipt.timestamp,
                            receipt.hash,
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    # Either the link trigger fired (fail closed) or the
                    # idempotency index caught a re-append: return the
                    # existing row instead of writing a duplicate.
                    if payload.get("idempotency_key") is not None and (
                        "UNIQUE constraint failed" in str(exc)
                    ):
                        self._conn.execute("ROLLBACK")
                        row = self._conn.execute(
                            "SELECT seq FROM receipts WHERE"
                            " json_extract(payload, '$.idempotency_key') = ?",
                            (payload["idempotency_key"],),
                        ).fetchone()
                        if row is None:
                            raise RuntimeError(
                                "idempotency conflict with no existing row"
                            ) from exc
                        existing = self._receipts[row[0]]
                        if existing.hash != self._conn.execute(
                            "SELECT hash FROM receipts WHERE seq = ?",
                            (row[0],),
                        ).fetchone()[0]:
                            raise RuntimeError(
                                "idempotency row hash mismatch"
                            ) from exc
                        return existing
                    self._conn.execute("ROLLBACK")
                    raise RuntimeError(
                        "receipt insert rejected: %s" % (exc,)
                    ) from exc
                self._conn.execute("COMMIT")
            except Exception:
                try:
                    self._conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise
            # Cache and index update only after commit.
            self._receipts.append(receipt)
            if event_type == "ALLOWED":
                auth_id = payload.get("auth_id")
                if isinstance(auth_id, str):
                    self._allowed_by_auth[auth_id] = receipt
            return receipt

    def allowed_receipt(self, auth_id: str) -> Receipt | None:
        """The ALLOWED receipt for an auth_id, if any. O(1)."""
        with self._lock:
            return self._allowed_by_auth.get(auth_id)

    def __len__(self) -> int:
        with self._lock:
            return len(self._receipts)

    def receipts(self) -> list[Receipt]:
        with self._lock:
            return list(self._receipts)

    def verify_chain(self) -> tuple[bool, str]:
        """
        Returns (True, "ok") if the chain is intact, else (False, reason).
        Same contract as Ledger.verify_chain.
        """
        with self._lock:
            receipts = list(self._receipts)
        return self._verify_receipts(receipts)

    def close(self) -> None:
        """Close the database connection. The instance must not be used after."""
        with self._lock:
            self._conn.close()


def fold_receipts(receipts: list[Receipt]) -> "PermitStore":
    """
    Rebuild a PermitStore by folding a verified receipt chain.

    Pure: no clock, no network, no receipts written, no PayPal. Each
    event type applies its state transition; unknown event types are
    skipped (forward-compatible). A receipt referencing a permit id the
    fold has not seen raises RuntimeError — a chain with dangling
    references is corrupt, and fail-closed beats guessing.

    The incremental apply and the full replay are the same code path:
    every mutation below mirrors the corresponding store method's
    bookkeeping (grant/delegate/check/settle_*/tighten/estop/
    revoke_subtree/release_carve).
    """
    from datetime import datetime

    from .ledger import Ledger
    from .permit import Permit, PermitStore

    store = PermitStore(ledger=Ledger())

    def _permit(pid: str, seq: int) -> Permit:
        p = store._permits.get(pid)
        if p is None:
            raise RuntimeError(
                f"fold: seq {seq} references unknown permit {pid}"
            )
        return p

    for r in receipts:
        pl = r.payload
        et = r.event_type
        if et == "GRANTED":
            p = Permit(
                permit_id=pl["permit_id"],
                agent_id=pl["agent_id"],
                cap_cents=pl["cap_cents"],
                allowlist=tuple(pl["allowlist"]),
                expiry=datetime.fromisoformat(pl["expiry"]),
                approval_threshold_cents=pl.get("approval_threshold_cents"),
            )
            store._permits[p.permit_id] = p
        elif et == "ALLOWED":
            p = _permit(pl["permit_id"], r.seq)
            amount = pl["amount_cents"]
            p.reserved_cents += amount
            p.in_flight[pl["auth_id"]] = amount
        elif et == "DELEGATED":
            parent = _permit(pl["parent_permit_id"], r.seq)
            child = Permit(
                permit_id=pl["child_permit_id"],
                agent_id=pl["agent_id"],
                cap_cents=pl["cap_cents"],
                allowlist=tuple(pl["allowlist"]),
                expiry=datetime.fromisoformat(pl["expiry"]),
                parent_id=parent.permit_id,
                depth=pl.get("depth", parent.depth + 1),
            )
            parent.reserved_cents += pl["cap_cents"]
            store._permits[child.permit_id] = child
            store._children.setdefault(parent.permit_id, []).append(
                child.permit_id
            )
        elif et == "TIGHTEN":
            p = _permit(pl["permit_id"], r.seq)
            changes = pl.get("changes", {})
            if "cap_cents" in changes:
                p.tighten_cap_cents = changes["cap_cents"]["to"]
            if "allowlist" in changes:
                p.tighten_allowlist = tuple(changes["allowlist"]["to"])
            if "expiry" in changes:
                p.tighten_expiry = datetime.fromisoformat(
                    changes["expiry"]["to"]
                )
            if "approval_threshold_cents" in changes:
                p.tighten_approval_threshold_cents = changes[
                    "approval_threshold_cents"
                ]["to"]
        elif et in ("E-STOP", "REVOKED_CASCADE"):
            _permit(pl["permit_id"], r.seq).revoked = True
        elif et == "CAPTURED":
            p = _permit(pl["permit_id"], r.seq)
            auth_id = pl["auth_id"]
            amount = p.in_flight.pop(auth_id, None)
            if amount is None:
                # Reconciled captures may reference an auth already
                # settled; fall back to the receipted amount.
                amount = pl["amount_cents"]
            p.reserved_cents -= amount
            p.captured_cents += amount
            pid = p.parent_id
            while pid is not None:
                parent = store._permits.get(pid)
                if parent is None:
                    break
                parent.reserved_cents -= amount
                parent.captured_cents += amount
                pid = parent.parent_id
        elif et == "VOIDED":
            # Escrow-level VOIDEDs carry escrow_id, not auth_id, and no
            # permit bookkeeping — the permit-level VOIDED (with auth_id)
            # is the state transition.
            if "auth_id" not in pl:
                continue
            p = _permit(pl["permit_id"], r.seq)
            amount = p.in_flight.pop(pl["auth_id"], None)
            if amount is None:
                amount = pl["amount_cents"]
            p.reserved_cents -= amount
        elif et == "CARVE_RELEASED":
            parent = _permit(pl["parent_permit_id"], r.seq)
            child = store._permits.get(pl["child_permit_id"])
            parent.reserved_cents -= pl["released_cents"]
            if child is not None:
                child.parent_id = None
            kids = store._children.get(pl["parent_permit_id"], [])
            if pl["child_permit_id"] in kids:
                kids.remove(pl["child_permit_id"])
        # BLOCKED, REFUSED, FAILED, UNKNOWN, CLEANUP_PENDING,
        # APPROVAL_*, AUTHORIZED, OPERATION_EXPIRED: no permit-state
        # transition (their bookkeeping rode on ALLOWED/VOIDED receipts).
    return store
