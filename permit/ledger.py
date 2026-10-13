"""
Permit ledger: local append-only hash-chained log of receipted events.

Events (the ones the camera shows):
    GRANTED, ALLOWED, BLOCKED, AUTHORIZED, REFUSED, CAPTURED, VOIDED,
    E-STOP, REVOKED

Each receipt commits to the previous receipt's hash. A deleted receipt,
a reordered sequence, or a tampered payload breaks the chain, and the
settlement verifier refuses to proceed on a broken chain.

No external format dependency (Interlock cut 2026-10-02, Grok review).
Demo keys are hardcoded and labeled as such — no key-management scope.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone


GENESIS_HASH = "0" * 64


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class Receipt:
    seq: int
    prev_hash: str
    event_type: str
    payload: dict
    timestamp: str
    hash: str = field(init=False)

    def __post_init__(self):
        body = {
            "seq": self.seq,
            "prev_hash": self.prev_hash,
            "event_type": self.event_type,
            "payload": self.payload,
            "timestamp": self.timestamp,
        }
        h = hashlib.sha256(_canonical(body)).hexdigest()
        object.__setattr__(self, "hash", h)


class Ledger:
    """Thread-safe append-only receipt log with chain verification."""

    def __init__(self):
        self._lock = threading.Lock()
        self._receipts: list[Receipt] = []
        # Index: auth_id -> ALLOWED receipt. Maintained on append; the
        # ledger is append-only (entries are never removed), so the index
        # cannot go stale. Replaces the old O(n) scan per lookup.
        self._allowed_by_auth: dict[str, Receipt] = {}

    def append(self, event_type: str, payload: dict) -> Receipt:
        with self._lock:
            prev_hash = self._receipts[-1].hash if self._receipts else GENESIS_HASH
            receipt = Receipt(
                seq=len(self._receipts),
                prev_hash=prev_hash,
                event_type=event_type,
                payload=payload,
                timestamp=_utcnow_iso(),
            )
            self._receipts.append(receipt)
            # auth_ids are unique per check() (uuid4), so no overwrite risk.
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
        return len(self._receipts)

    def receipts(self) -> list[Receipt]:
        with self._lock:
            return list(self._receipts)

    def verify_chain(self) -> tuple[bool, str]:
        """
        Returns (True, "ok") if the chain is intact, else (False, reason).
        The settlement verifier calls this before every capture.
        """
        with self._lock:
            receipts = list(self._receipts)
        expected_prev = GENESIS_HASH
        # enumerate, not receipts.index(r): index() is O(n) per receipt,
        # which made verification O(n^2) — and this runs before every
        # capture. Position in the list IS the expected seq.
        for expected_seq, r in enumerate(receipts):
            if r.seq != expected_seq:
                return False, f"sequence gap at seq {r.seq}"
            if r.prev_hash != expected_prev:
                return False, f"prev_hash mismatch at seq {r.seq}"
            # Recompute the hash to catch payload tampering.
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
