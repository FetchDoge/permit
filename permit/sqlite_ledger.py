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
import uuid

from .ledger import (
    GENESIS_HASH,
    Receipt,
    _canonical,
    _rate_tally_key,
    _utcnow_iso,
)
from .retry_rate_store import (
    RetryRateIntegrityError,
    _DDL_ONE_OPEN,
    _DDL_RETRY_RATE,
    SqliteRetryRateStore,
    _ensure_rate_mac_column,
    rate_limited_mac,
    verify_rate_limited_mac,
)


_DDL_TABLE = """
CREATE TABLE IF NOT EXISTS receipts (
  seq          INTEGER PRIMARY KEY,
  prev_hash    TEXT    NOT NULL,
  event_type   TEXT    NOT NULL,
  payload      TEXT    NOT NULL,
  timestamp    TEXT    NOT NULL,
  hash         TEXT    NOT NULL UNIQUE,
  escrow_id    TEXT,
  window_id    TEXT,
  refusal_kind TEXT
)
"""

# Indexed denial lookup: O(log n) COUNT for (escrow_id, window_id).
_DDL_ALREADY_DENIAL_IDX = """
CREATE INDEX IF NOT EXISTS receipts_already_denial_idx
ON receipts (escrow_id, window_id)
WHERE event_type = 'REFUSED' AND refusal_kind = 'already'
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

# F7: at most one rate_limited tally receipt per (escrow_id, window_id).
_DDL_RATE_TALLY_UNIQUE = """
CREATE UNIQUE INDEX IF NOT EXISTS receipts_rate_limited_window
ON receipts (
  json_extract(payload, '$.escrow_id'),
  json_extract(payload, '$.window_id')
)
WHERE event_type = 'REFUSED'
  AND json_extract(payload, '$.reason') = 'rate_limited'
"""

_DDL = (
    _DDL_TABLE,
    _DDL_NO_UPDATE,
    _DDL_NO_DELETE,
    _DDL_LINK,
    _DDL_IDEMPOTENCY,
    _DDL_RATE_TALLY_UNIQUE,
    _DDL_ALREADY_DENIAL_IDX,
    _DDL_RETRY_RATE,
    _DDL_ONE_OPEN,
)


def _refusal_kind(event_type: str, payload: dict) -> str | None:
    if event_type != "REFUSED":
        return None
    reason = payload.get("reason")
    if not isinstance(reason, str):
        return None
    if reason.startswith("already_"):
        return "already"
    if reason == "rate_limited":
        return "rate_tally"
    return None


def _payload_escrow_window(payload: dict) -> tuple[str | None, str | None]:
    eid = payload.get("escrow_id")
    wid = payload.get("window_id")
    return (
        eid if isinstance(eid, str) else None,
        wid if isinstance(wid, str) else None,
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
            self._migrate_receipt_index_columns()
            _ensure_rate_mac_column(self._conn)
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
            rate_tallies: dict[tuple[str, str], Receipt] = {}
            for receipt in receipts:
                if receipt.event_type != "REFUSED":
                    continue
                key = _rate_tally_key(receipt.payload)
                if key is not None:
                    rate_tallies[key] = receipt
            self._rate_tally_by_window = rate_tallies
            ok, detail = self._verify_receipts(receipts)
            if not ok:
                raise RuntimeError(
                    "restored chain failed verification: %s" % (detail,)
                )
            # F7 side store: outside the hash chain, SAME connection as
            # receipts so denial+increment can share one BEGIN IMMEDIATE.
            # Cross-process writers each open their own SqliteLedger on the
            # file; SQLite serializes the transactions. One OPEN window per
            # escrow is enforced by retry_rate_one_open_window.
            self.retry_rate_store = SqliteRetryRateStore(
                self._conn, lock=self._lock
            )
        except Exception:
            self._conn.close()
            raise

    def _migrate_receipt_index_columns(self) -> None:
        """Add escrow_id/window_id/refusal_kind and backfill from payload."""
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(receipts)")}
        added = False
        for col, decl in (
            ("escrow_id", "TEXT"),
            ("window_id", "TEXT"),
            ("refusal_kind", "TEXT"),
        ):
            if col not in cols:
                self._conn.execute(
                    f"ALTER TABLE receipts ADD COLUMN {col} {decl}"
                )
                added = True
        # One-time backfill only when columns were just added, OR when a
        # REFUSED row still lacks its indexed escrow_id (payload has one).
        # Do NOT treat "any NULL escrow_id" as dirty — GRANTED/ALLOWED/etc.
        # legitimately leave the column NULL, and re-running UPDATE on every
        # open races the append-only trigger across processes.
        need = self._conn.execute(
            "SELECT 1 FROM receipts"
            " WHERE event_type = 'REFUSED'"
            " AND escrow_id IS NULL"
            " AND json_extract(payload, '$.escrow_id') IS NOT NULL"
            " LIMIT 1"
        ).fetchone()
        if added or need is not None:
            self._conn.execute("DROP TRIGGER IF EXISTS receipts_no_update")
            try:
                self._conn.execute(
                    "UPDATE receipts SET"
                    " escrow_id = json_extract(payload, '$.escrow_id'),"
                    " window_id = json_extract(payload, '$.window_id'),"
                    " refusal_kind = CASE"
                    "  WHEN event_type = 'REFUSED'"
                    "   AND json_extract(payload, '$.reason') LIKE 'already_%'"
                    "  THEN 'already'"
                    "  WHEN event_type = 'REFUSED'"
                    "   AND json_extract(payload, '$.reason') = 'rate_limited'"
                    "  THEN 'rate_tally'"
                    "  ELSE NULL END"
                    " WHERE escrow_id IS NULL"
                    " AND json_extract(payload, '$.escrow_id') IS NOT NULL"
                )
            finally:
                self._conn.execute(_DDL_NO_UPDATE)
        self._conn.execute(_DDL_ALREADY_DENIAL_IDX)

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

    def find_rate_limited_tally(
        self, escrow_id: str, window_id: str
    ) -> Receipt | None:
        """Existing rate_limited tally for (escrow_id, window_id), if any."""
        with self._lock:
            return self._rate_tally_by_window.get((escrow_id, window_id))

    def count_individual_denials(self) -> dict[tuple[str, str], int]:
        """
        Count already_* denial receipts per (escrow_id, window_id) from SQL.
        Uses indexed columns (O(log n) per group).
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT escrow_id, window_id, COUNT(*)"
                " FROM receipts"
                " WHERE event_type = 'REFUSED' AND refusal_kind = 'already'"
                " AND escrow_id IS NOT NULL AND window_id IS NOT NULL"
                " GROUP BY escrow_id, window_id"
            ).fetchall()
        return {
            (str(eid), str(wid)): int(n) for eid, wid, n in rows if eid and wid
        }

    def _count_already_denials_unlocked(
        self, escrow_id: str, window_id: str
    ) -> int:
        """Indexed COUNT inside an open transaction."""
        row = self._conn.execute(
            "SELECT COUNT(*) FROM receipts"
            " WHERE event_type = 'REFUSED' AND refusal_kind = 'already'"
            " AND escrow_id = ? AND window_id = ?",
            (escrow_id, window_id),
        ).fetchone()
        return int(row[0]) if row else 0

    def check_retry_rate_integrity(
        self, *, original_refusal_id_for=None, limit_n: int = 100
    ) -> None:
        """
        Startup / snapshot integrity: one read transaction (WAL snapshot).
        Raises RetryRateIntegrityError on disagreement. Never mutates.
        """
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                self._check_retry_rate_integrity_unlocked(
                    original_refusal_id_for=original_refusal_id_for,
                    limit_n=limit_n,
                )
                self._conn.execute("COMMIT")
            except Exception:
                try:
                    self._conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise

    def _original_refusal_hash_unlocked(self, escrow_id: str) -> str | None:
        """
        Chain-derived MAC key: hash of the first terminal REFUSED (non-already,
        non-rate_limited) for escrow_id, else the first VOIDED. Same rule as
        ReleaseVerifier._rebuild_original_refusals_from_ledger.
        """
        row = self._conn.execute(
            "SELECT hash FROM receipts"
            " WHERE json_extract(payload, '$.escrow_id') = ?"
            " AND ("
            "   (event_type = 'REFUSED'"
            "    AND COALESCE(refusal_kind, '') NOT IN ('already', 'rate_tally')"
            "    AND COALESCE(json_extract(payload, '$.reason'), '')"
            "        NOT LIKE 'already_%'"
            "    AND COALESCE(json_extract(payload, '$.reason'), '')"
            "        <> 'rate_limited')"
            "   OR event_type = 'VOIDED'"
            " )"
            " ORDER BY seq LIMIT 1",
            (escrow_id,),
        ).fetchone()
        return str(row[0]) if row else None

    def _check_retry_rate_integrity_unlocked(
        self, *, original_refusal_id_for=None, limit_n: int = 100
    ) -> None:
        """Caller holds lock; runs inside an open transaction."""
        side_rows = self._conn.execute(
            "SELECT escrow_id, window_id, window_start, individual,"
            " rate_limited, covered_reason, tally_flushed, rate_mac"
            " FROM retry_rate_windows"
        ).fetchall()
        side_by_key = {
            (r[0], r[1]): r for r in side_rows
        }
        chain_denials = self._conn.execute(
            "SELECT escrow_id, window_id, COUNT(*)"
            " FROM receipts"
            " WHERE event_type = 'REFUSED' AND refusal_kind = 'already'"
            " AND escrow_id IS NOT NULL AND window_id IS NOT NULL"
            " GROUP BY escrow_id, window_id"
        ).fetchall()
        tallies = {
            (r[0], r[1])
            for r in self._conn.execute(
                "SELECT escrow_id, window_id FROM receipts"
                " WHERE event_type = 'REFUSED' AND refusal_kind = 'rate_tally'"
                " AND escrow_id IS NOT NULL AND window_id IS NOT NULL"
            ).fetchall()
        }
        for eid, wid, n in chain_denials:
            key = (eid, wid)
            if key in tallies:
                continue
            side = side_by_key.get(key)
            if side is None:
                raise RetryRateIntegrityError(
                    "retry rate side table missing open row derived from chain "
                    f"denials escrow_id={eid!r} window_id={wid!r} "
                    f"(chain_individual={int(n)}); refuse"
                )
            if int(side[6]):  # tally_flushed
                raise RetryRateIntegrityError(
                    "retry rate side table marked flushed but chain has no tally "
                    f"for escrow_id={eid!r} window_id={wid!r}; refuse"
                )
            if int(side[3]) != int(n):
                raise RetryRateIntegrityError(
                    "retry rate side table individual mismatch for "
                    f"escrow_id={eid!r} window_id={wid!r}: "
                    f"side={int(side[3])} chain={int(n)}; refuse"
                )
            if original_refusal_id_for is not None:
                orig = original_refusal_id_for(eid)
            else:
                orig = self._original_refusal_hash_unlocked(eid)
            verify_rate_limited_mac(
                orig, eid, wid, int(side[4]), side[7] or ""
            )
            if int(side[4]) > 0 and int(side[3]) < limit_n:
                raise RetryRateIntegrityError(
                    "retry rate side table rate_limited set before exhausting N "
                    f"for escrow_id={eid!r} window_id={wid!r}; refuse"
                )
        for key in tallies:
            if key not in side_by_key:
                raise RetryRateIntegrityError(
                    "retry rate side table missing row for chain tally "
                    f"escrow_id={key[0]!r} window_id={key[1]!r}; refuse"
                )

    def sync_receipts_from_db(self) -> None:
        """Reload in-memory receipt cache from SQLite (after foreign writers)."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT seq, prev_hash, event_type, payload, timestamp, hash"
                " FROM receipts ORDER BY seq"
            ).fetchall()
            receipts: list[Receipt] = []
            allowed: dict[str, Receipt] = {}
            rate_tallies: dict[tuple[str, str], Receipt] = {}
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
                        "stored hash mismatch at seq %s" % (seq,)
                    )
                receipts.append(receipt)
                if event_type == "ALLOWED":
                    auth_id = payload.get("auth_id")
                    if isinstance(auth_id, str):
                        allowed[auth_id] = receipt
                if event_type == "REFUSED":
                    key = _rate_tally_key(payload)
                    if key is not None:
                        rate_tallies[key] = receipt
            self._receipts = receipts
            self._allowed_by_auth = allowed
            self._rate_tally_by_window = rate_tallies

    def _insert_receipt_unlocked(
        self, event_type: str, payload: dict
    ) -> Receipt:
        """Insert a receipt. Caller holds _lock and an open BEGIN IMMEDIATE."""
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
        eid, wid = _payload_escrow_window(payload)
        kind = _refusal_kind(event_type, payload)
        self._conn.execute(
            "INSERT INTO receipts"
            " (seq, prev_hash, event_type, payload, timestamp, hash,"
            "  escrow_id, window_id, refusal_kind)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                receipt.seq,
                receipt.prev_hash,
                receipt.event_type,
                json.dumps(
                    receipt.payload, sort_keys=True, separators=(",", ":")
                ),
                receipt.timestamp,
                receipt.hash,
                eid,
                wid,
                kind,
            ),
        )
        return receipt

    def _cache_receipt_unlocked(self, receipt: Receipt) -> None:
        self._receipts.append(receipt)
        if receipt.event_type == "ALLOWED":
            auth_id = receipt.payload.get("auth_id")
            if isinstance(auth_id, str):
                self._allowed_by_auth[auth_id] = receipt
        if receipt.event_type == "REFUSED":
            key = _rate_tally_key(receipt.payload)
            if key is not None:
                self._rate_tally_by_window[key] = receipt

    def _load_open_window_unlocked(self, escrow_id: str):
        return self._conn.execute(
            "SELECT window_id, window_start, individual, rate_limited,"
            " covered_reason, rate_mac FROM retry_rate_windows"
            " WHERE escrow_id = ? AND tally_flushed = 0",
            (escrow_id,),
        ).fetchone()

    def _orphan_open_windows_from_chain_unlocked(
        self, escrow_id: str
    ) -> list[tuple[str, int]]:
        """(window_id, chain_individual) with denials but no tally and no side row."""
        rows = self._conn.execute(
            "SELECT r.window_id, COUNT(*)"
            " FROM receipts r"
            " WHERE r.event_type = 'REFUSED' AND r.refusal_kind = 'already'"
            " AND r.escrow_id = ?"
            " AND NOT EXISTS ("
            "   SELECT 1 FROM receipts t"
            "   WHERE t.event_type = 'REFUSED' AND t.refusal_kind = 'rate_tally'"
            "   AND t.escrow_id = r.escrow_id AND t.window_id = r.window_id"
            " )"
            " AND NOT EXISTS ("
            "   SELECT 1 FROM retry_rate_windows s"
            "   WHERE s.escrow_id = r.escrow_id AND s.window_id = r.window_id"
            " )"
            " GROUP BY r.window_id",
            (escrow_id,),
        ).fetchall()
        return [(str(wid), int(n)) for wid, n in rows]

    def _close_open_window_unlocked(
        self,
        escrow_id: str,
        window_id: str,
        window_start: float,
        rate_limited: int,
        covered_reason: str,
        original_refusal_id: str | None,
        rate_mac: str = "",
    ) -> Receipt | None:
        """Append tally if needed and mark flushed. Inside an open transaction."""
        # Protect rate_limited via chain-keyed MAC before trusting the count.
        verify_rate_limited_mac(
            original_refusal_id, escrow_id, window_id, rate_limited, rate_mac
        )
        chain_indiv = self._count_already_denials_unlocked(escrow_id, window_id)
        side_indiv = self._conn.execute(
            "SELECT individual FROM retry_rate_windows"
            " WHERE escrow_id = ? AND window_id = ?",
            (escrow_id, window_id),
        ).fetchone()
        if side_indiv is not None and int(side_indiv[0]) != chain_indiv:
            raise RetryRateIntegrityError(
                "retry rate side table individual mismatch on close for "
                f"escrow_id={escrow_id!r} window_id={window_id!r}: "
                f"side={int(side_indiv[0])} chain={chain_indiv}; refuse"
            )
        tally: Receipt | None = None
        existing_key = (escrow_id, window_id)
        if existing_key in self._rate_tally_by_window:
            tally = self._rate_tally_by_window[existing_key]
        elif rate_limited > 0:
            row = self._conn.execute(
                "SELECT seq, prev_hash, event_type, payload, timestamp, hash"
                " FROM receipts WHERE event_type = 'REFUSED'"
                " AND json_extract(payload, '$.reason') = 'rate_limited'"
                " AND json_extract(payload, '$.escrow_id') = ?"
                " AND json_extract(payload, '$.window_id') = ?",
                (escrow_id, window_id),
            ).fetchone()
            if row is not None:
                seq, prev_hash, et, payload_text, ts, stored_hash = row
                if seq < len(self._receipts):
                    tally = self._receipts[seq]
                else:
                    tally = Receipt(
                        seq=seq,
                        prev_hash=prev_hash,
                        event_type=et,
                        payload=json.loads(payload_text),
                        timestamp=ts,
                    )
                    if tally.hash != stored_hash:
                        raise RuntimeError("tally hash mismatch on close")
            else:
                try:
                    tally = self._insert_receipt_unlocked(
                        "REFUSED",
                        {
                            "escrow_id": escrow_id,
                            "reason": "rate_limited",
                            "count": rate_limited,
                            "window_id": window_id,
                            "window_start": window_start,
                            "covered_reason": covered_reason,
                            "receipt_id": f"rl_{uuid.uuid4().hex}",
                            "original_refusal_id": original_refusal_id,
                        },
                    )
                except sqlite3.IntegrityError:
                    # Lost the race to another writer; load the winner.
                    row = self._conn.execute(
                        "SELECT seq, prev_hash, event_type, payload,"
                        " timestamp, hash FROM receipts"
                        " WHERE event_type = 'REFUSED'"
                        " AND json_extract(payload, '$.reason') = 'rate_limited'"
                        " AND json_extract(payload, '$.escrow_id') = ?"
                        " AND json_extract(payload, '$.window_id') = ?",
                        (escrow_id, window_id),
                    ).fetchone()
                    if row is None:
                        raise
                    seq, prev_hash, et, payload_text, ts, stored_hash = row
                    tally = Receipt(
                        seq=seq,
                        prev_hash=prev_hash,
                        event_type=et,
                        payload=json.loads(payload_text),
                        timestamp=ts,
                    )
                    if tally.hash != stored_hash:
                        raise RuntimeError("tally hash mismatch on close race")
        self._conn.execute(
            "UPDATE retry_rate_windows SET tally_flushed = 1,"
            " rate_limited = ?"
            " WHERE escrow_id = ? AND window_id = ?",
            (
                int(tally.payload["count"]) if tally is not None else int(rate_limited),
                escrow_id,
                window_id,
            ),
        )
        return tally

    def record_terminal_retry(
        self,
        escrow_id: str,
        already_reason: str,
        *,
        limit_n: int,
        window_w: float,
        now: float,
        original_refusal_id: str | None,
    ) -> tuple[str, Receipt | None]:
        """
        Cross-process rate limit. Inside one BEGIN IMMEDIATE:

          - Detect a deleted mid-window side row (chain denials, no tally)
          - Derive ``individual`` from an indexed COUNT of chain denials —
            never trust the side row for the allow/limit decision
          - If the side row disagrees with the chain → RetryRateIntegrityError
          - ``rate_limited`` is protected by a chain-keyed HMAC (rate_mac)
          - if chain_individual < N: INSERT denial + sync side.individual
          - else: rate_limited+1 with updated MAC

        Returns (result_reason, denial_receipt_or_None).
        """
        with self._lock:
            cached: list[Receipt] = []
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                wid, wstart_f, chain_indiv, rlim = (
                    self._ensure_open_window_unlocked(
                        escrow_id,
                        already_reason=already_reason,
                        window_w=window_w,
                        now=now,
                        original_refusal_id=original_refusal_id,
                        cached=cached,
                    )
                )

                if chain_indiv < limit_n:
                    denial = self._insert_receipt_unlocked(
                        "REFUSED",
                        {
                            "escrow_id": escrow_id,
                            "reason": already_reason,
                            "window_id": wid,
                            "window_start": wstart_f,
                            "receipt_id": f"den_{uuid.uuid4().hex}",
                            "original_refusal_id": original_refusal_id,
                        },
                    )
                    new_indiv = chain_indiv + 1
                    cur = self._conn.execute(
                        "UPDATE retry_rate_windows"
                        " SET individual = ?,"
                        " covered_reason = ?"
                        " WHERE escrow_id = ? AND window_id = ?"
                        " AND tally_flushed = 0"
                        " RETURNING individual",
                        (new_indiv, already_reason, escrow_id, wid),
                    ).fetchone()
                    if cur is None:
                        raise RuntimeError(
                            "individual sync missed open window "
                            f"escrow_id={escrow_id!r} window_id={wid!r}"
                        )
                    self._conn.execute("COMMIT")
                    for r in cached:
                        self._cache_receipt_unlocked(r)
                    self._cache_receipt_unlocked(denial)
                    return already_reason, denial

                new_rl = int(rlim) + 1
                new_mac = rate_limited_mac(
                    original_refusal_id, escrow_id, wid, new_rl
                )
                cur = self._conn.execute(
                    "UPDATE retry_rate_windows"
                    " SET rate_limited = ?,"
                    " rate_mac = ?,"
                    " covered_reason = ?"
                    " WHERE escrow_id = ? AND window_id = ?"
                    " AND tally_flushed = 0"
                    " RETURNING rate_limited",
                    (new_rl, new_mac, already_reason, escrow_id, wid),
                ).fetchone()
                if cur is None:
                    raise RuntimeError(
                        "rate_limited increment missed open window "
                        f"escrow_id={escrow_id!r} window_id={wid!r}"
                    )
                self._conn.execute("COMMIT")
                for r in cached:
                    self._cache_receipt_unlocked(r)
                return "rate_limited", None
            except Exception:
                try:
                    self._conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise

    def _ensure_open_window_unlocked(
        self,
        escrow_id: str,
        *,
        already_reason: str,
        window_w: float,
        now: float,
        original_refusal_id: str | None,
        cached: list[Receipt],
    ) -> tuple[str, float, int, int]:
        """
        Return (window_id, window_start, chain_individual, rate_limited).
        ``chain_individual`` comes from an indexed COUNT — not the side row.
        Closes an expired open window first. Caller holds lock + transaction.
        """
        open_row = self._load_open_window_unlocked(escrow_id)
        if open_row is None:
            orphans = self._orphan_open_windows_from_chain_unlocked(escrow_id)
            if orphans:
                wid, n = orphans[0]
                raise RetryRateIntegrityError(
                    "retry rate side table missing open row mid-window for "
                    f"escrow_id={escrow_id!r} window_id={wid!r} "
                    f"(chain_individual={n}); refuse"
                )
        else:
            wid, wstart, side_indiv, rlim, covered, rate_mac = open_row
            wstart_f = float(wstart)
            verify_rate_limited_mac(
                original_refusal_id,
                escrow_id,
                str(wid),
                int(rlim),
                rate_mac or "",
            )
            if (now - wstart_f) >= window_w:
                tally = self._close_open_window_unlocked(
                    escrow_id,
                    str(wid),
                    wstart_f,
                    int(rlim),
                    covered or "",
                    original_refusal_id,
                    rate_mac=rate_mac or "",
                )
                if tally is not None:
                    cached.append(tally)
                open_row = None
            else:
                chain_indiv = self._count_already_denials_unlocked(
                    escrow_id, str(wid)
                )
                if int(side_indiv) != chain_indiv:
                    raise RetryRateIntegrityError(
                        "retry rate side table individual mismatch for "
                        f"escrow_id={escrow_id!r} window_id={str(wid)!r}: "
                        f"side={int(side_indiv)} chain={chain_indiv}; refuse"
                    )
                return str(wid), wstart_f, chain_indiv, int(rlim)

        # No open window: insert one (or adopt a concurrent writer's).
        for _ in range(3):
            wid = f"rw_{uuid.uuid4().hex}"
            zero_mac = rate_limited_mac(original_refusal_id, escrow_id, wid, 0)
            try:
                self._conn.execute(
                    "INSERT INTO retry_rate_windows"
                    " (escrow_id, window_id, window_start, individual,"
                    "  rate_limited, covered_reason, tally_flushed, rate_mac)"
                    " VALUES (?, ?, ?, 0, 0, ?, 0, ?)",
                    (escrow_id, wid, now, already_reason, zero_mac),
                )
                return wid, now, 0, 0
            except sqlite3.IntegrityError:
                open_row = self._load_open_window_unlocked(escrow_id)
                if open_row is None:
                    continue
                wid, wstart, side_indiv, rlim, covered, rate_mac = open_row
                wstart_f = float(wstart)
                verify_rate_limited_mac(
                    original_refusal_id,
                    escrow_id,
                    str(wid),
                    int(rlim),
                    rate_mac or "",
                )
                if (now - wstart_f) >= window_w:
                    tally = self._close_open_window_unlocked(
                        escrow_id,
                        str(wid),
                        wstart_f,
                        int(rlim),
                        covered or "",
                        original_refusal_id,
                        rate_mac=rate_mac or "",
                    )
                    if tally is not None:
                        cached.append(tally)
                    continue
                chain_indiv = self._count_already_denials_unlocked(
                    escrow_id, str(wid)
                )
                if int(side_indiv) != chain_indiv:
                    raise RetryRateIntegrityError(
                        "retry rate side table individual mismatch for "
                        f"escrow_id={escrow_id!r} window_id={str(wid)!r}: "
                        f"side={int(side_indiv)} chain={chain_indiv}; refuse"
                    )
                return str(wid), wstart_f, chain_indiv, int(rlim)
        raise RuntimeError(
            f"unable to open retry-rate window for escrow_id={escrow_id!r}"
        )

    def flush_open_retry_windows(
        self,
        *,
        original_refusal_id_for,
        escrow_id: str | None = None,
    ) -> None:
        """
        Close open window(s): append tally if rate_limited>0, mark flushed.
        original_refusal_id_for(escrow_id) -> str|None.
        """
        with self._lock:
            cached: list[Receipt] = []
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                if escrow_id is None:
                    rows = self._conn.execute(
                        "SELECT escrow_id, window_id, window_start,"
                        " individual, rate_limited, covered_reason, rate_mac"
                        " FROM retry_rate_windows WHERE tally_flushed = 0"
                    ).fetchall()
                else:
                    rows = self._conn.execute(
                        "SELECT escrow_id, window_id, window_start,"
                        " individual, rate_limited, covered_reason, rate_mac"
                        " FROM retry_rate_windows"
                        " WHERE tally_flushed = 0 AND escrow_id = ?",
                        (escrow_id,),
                    ).fetchall()
                for eid, wid, wstart, _indiv, rlim, covered, rate_mac in rows:
                    # Flush closes even if W has not elapsed (clean shutdown).
                    tally = self._close_open_window_unlocked(
                        eid,
                        wid,
                        float(wstart),
                        int(rlim),
                        covered or "",
                        original_refusal_id_for(eid),
                        rate_mac=rate_mac or "",
                    )
                    if tally is not None:
                        cached.append(tally)
                self._conn.execute("COMMIT")
            except Exception:
                try:
                    self._conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise
            for r in cached:
                self._cache_receipt_unlocked(r)

    def append(self, event_type: str, payload: dict) -> Receipt:
        with self._lock:
            tally_key = (
                _rate_tally_key(payload) if event_type == "REFUSED" else None
            )
            if tally_key is not None and tally_key in self._rate_tally_by_window:
                return self._rate_tally_by_window[tally_key]
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
                    eid, wid = _payload_escrow_window(payload)
                    kind = _refusal_kind(event_type, payload)
                    self._conn.execute(
                        "INSERT INTO receipts"
                        " (seq, prev_hash, event_type, payload, timestamp, hash,"
                        "  escrow_id, window_id, refusal_kind)"
                        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                            eid,
                            wid,
                            kind,
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    err = str(exc)
                    # Idempotent re-append of a rate_limited tally window
                    # (crash replay or a second writer on the same DB file).
                    if tally_key is not None and "UNIQUE constraint failed" in err:
                        self._conn.execute("ROLLBACK")
                        existing = self._rate_tally_by_window.get(tally_key)
                        if existing is not None:
                            return existing
                        row = self._conn.execute(
                            "SELECT seq, prev_hash, event_type, payload,"
                            " timestamp, hash FROM receipts"
                            " WHERE event_type = 'REFUSED'"
                            " AND json_extract(payload, '$.reason') = 'rate_limited'"
                            " AND json_extract(payload, '$.escrow_id') = ?"
                            " AND json_extract(payload, '$.window_id') = ?",
                            tally_key,
                        ).fetchone()
                        if row is None:
                            raise RuntimeError(
                                "rate_limited window conflict with no existing row"
                            ) from exc
                        seq, prev_hash, et, payload_text, ts, stored_hash = row
                        if seq < len(self._receipts):
                            existing = self._receipts[seq]
                            self._rate_tally_by_window[tally_key] = existing
                            return existing
                        receipt = Receipt(
                            seq=seq,
                            prev_hash=prev_hash,
                            event_type=et,
                            payload=json.loads(payload_text),
                            timestamp=ts,
                        )
                        if receipt.hash != stored_hash:
                            raise RuntimeError(
                                "rate_limited conflict row hash mismatch"
                            ) from exc
                        self._rate_tally_by_window[tally_key] = receipt
                        return receipt
                    # Either the link trigger fired (fail closed) or the
                    # idempotency index caught a re-append: return the
                    # existing row instead of writing a duplicate.
                    if payload.get("idempotency_key") is not None and (
                        "UNIQUE constraint failed" in err
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
                # Same transaction: mark side-table row flushed for this tally.
                if tally_key is not None:
                    self._conn.execute(
                        "UPDATE retry_rate_windows SET tally_flushed = 1,"
                        " rate_limited = ?"
                        " WHERE escrow_id = ? AND window_id = ?",
                        (int(payload.get("count", 0)), tally_key[0], tally_key[1]),
                    )
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
            if tally_key is not None:
                self._rate_tally_by_window[tally_key] = receipt
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
