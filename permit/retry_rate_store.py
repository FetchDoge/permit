"""
REA F7: durable per-escrow retry rate-limit side table, outside the hash chain.

Decisions do NOT trust this table's counters as authority: `individual` is
derived from an indexed COUNT of chain denial receipts inside the same
BEGIN IMMEDIATE as the allow/limit choice. This table holds window_id,
window_start, and a MAC-protected rate_limited counter so mid-window
tampering is detectable before the tally.

At most one OPEN window (tally_flushed=0) per escrow — UNIQUE partial index.
"""

from __future__ import annotations

import hashlib
import hmac
import sqlite3
import threading
from dataclasses import dataclass


class RetryRateIntegrityError(RuntimeError):
    """Side store disagrees with the hash chain — refuse the operation."""


@dataclass
class RetryRateRow:
    escrow_id: str
    window_id: str
    window_start: float
    individual: int
    rate_limited: int
    covered_reason: str
    tally_flushed: bool
    rate_mac: str = ""


def rate_limited_mac(
    original_refusal_id: str | None,
    escrow_id: str,
    window_id: str,
    rate_limited: int,
) -> str:
    """
    Running integrity tag for rate_limited, keyed from a chain value
    (original refusal receipt hash). Bound: any undetected tamper of
    rate_limited requires forging this HMAC (SHA-256) without the key.
    """
    key = (original_refusal_id or ("0" * 64)).encode("utf-8")
    msg = f"{escrow_id}|{window_id}|{int(rate_limited)}".encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def verify_rate_limited_mac(
    original_refusal_id: str | None,
    escrow_id: str,
    window_id: str,
    rate_limited: int,
    rate_mac: str,
) -> None:
    expected = rate_limited_mac(
        original_refusal_id, escrow_id, window_id, rate_limited
    )
    if not hmac.compare_digest(expected, rate_mac or ""):
        raise RetryRateIntegrityError(
            "retry rate side table rate_mac mismatch for "
            f"escrow_id={escrow_id!r} window_id={window_id!r} "
            f"rate_limited={rate_limited}; refuse (chain-keyed MAC)"
        )


_DDL_RETRY_RATE = """
CREATE TABLE IF NOT EXISTS retry_rate_windows (
  escrow_id      TEXT    NOT NULL,
  window_id      TEXT    NOT NULL,
  window_start   REAL    NOT NULL,
  individual     INTEGER NOT NULL DEFAULT 0,
  rate_limited   INTEGER NOT NULL DEFAULT 0,
  covered_reason TEXT    NOT NULL DEFAULT '',
  tally_flushed  INTEGER NOT NULL DEFAULT 0,
  rate_mac       TEXT    NOT NULL DEFAULT '',
  PRIMARY KEY (escrow_id, window_id)
)
"""

_DDL_ONE_OPEN = """
CREATE UNIQUE INDEX IF NOT EXISTS retry_rate_one_open_window
ON retry_rate_windows (escrow_id)
WHERE tally_flushed = 0
"""


def _ensure_rate_mac_column(conn: sqlite3.Connection) -> None:
    cols = {r[1] for r in conn.execute("PRAGMA table_info(retry_rate_windows)")}
    if "rate_mac" not in cols:
        conn.execute(
            "ALTER TABLE retry_rate_windows"
            " ADD COLUMN rate_mac TEXT NOT NULL DEFAULT ''"
        )


class InMemoryRetryRateStore:
    """Process-local side store; still enforces one open window per escrow."""

    def __init__(self) -> None:
        self._rows: dict[tuple[str, str], RetryRateRow] = {}
        self._escrow_locks: dict[str, threading.Lock] = {}
        self._guard = threading.Lock()

    def _lock_for(self, escrow_id: str) -> threading.Lock:
        with self._guard:
            lock = self._escrow_locks.get(escrow_id)
            if lock is None:
                lock = threading.Lock()
                self._escrow_locks[escrow_id] = lock
            return lock

    def upsert(self, row: RetryRateRow) -> None:
        with self._lock_for(row.escrow_id):
            if not row.tally_flushed:
                for (eid, wid), existing in list(self._rows.items()):
                    if (
                        eid == row.escrow_id
                        and not existing.tally_flushed
                        and wid != row.window_id
                    ):
                        raise RuntimeError(
                            "in-memory retry rate: second open window for "
                            f"escrow_id={row.escrow_id!r}"
                        )
            self._rows[(row.escrow_id, row.window_id)] = RetryRateRow(
                escrow_id=row.escrow_id,
                window_id=row.window_id,
                window_start=row.window_start,
                individual=row.individual,
                rate_limited=row.rate_limited,
                covered_reason=row.covered_reason,
                tally_flushed=row.tally_flushed,
                rate_mac=row.rate_mac,
            )

    def get_open(self, escrow_id: str) -> RetryRateRow | None:
        with self._lock_for(escrow_id):
            for (eid, _wid), row in self._rows.items():
                if eid == escrow_id and not row.tally_flushed:
                    return RetryRateRow(
                        escrow_id=row.escrow_id,
                        window_id=row.window_id,
                        window_start=row.window_start,
                        individual=row.individual,
                        rate_limited=row.rate_limited,
                        covered_reason=row.covered_reason,
                        tally_flushed=row.tally_flushed,
                        rate_mac=row.rate_mac,
                    )
            return None

    def load_all(self) -> list[RetryRateRow]:
        with self._guard:
            items = list(self._rows.values())
        return [
            RetryRateRow(
                escrow_id=r.escrow_id,
                window_id=r.window_id,
                window_start=r.window_start,
                individual=r.individual,
                rate_limited=r.rate_limited,
                covered_reason=r.covered_reason,
                tally_flushed=r.tally_flushed,
                rate_mac=r.rate_mac,
            )
            for r in items
        ]

    def delete(self, escrow_id: str, window_id: str) -> None:
        with self._lock_for(escrow_id):
            self._rows.pop((escrow_id, window_id), None)


class SqliteRetryRateStore:
    """SQLite side table on the receipt-log connection (shared transactions)."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        *,
        lock: threading.Lock | None = None,
    ) -> None:
        self._conn = conn
        self._lock = lock if lock is not None else threading.Lock()
        with self._lock:
            self._conn.execute(_DDL_RETRY_RATE)
            _ensure_rate_mac_column(self._conn)
            self._conn.execute(_DDL_ONE_OPEN)

    def upsert(self, row: RetryRateRow) -> None:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute(
                    "INSERT INTO retry_rate_windows"
                    " (escrow_id, window_id, window_start, individual,"
                    "  rate_limited, covered_reason, tally_flushed, rate_mac)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
                    " ON CONFLICT(escrow_id, window_id) DO UPDATE SET"
                    " window_start=excluded.window_start,"
                    " individual=excluded.individual,"
                    " rate_limited=excluded.rate_limited,"
                    " covered_reason=excluded.covered_reason,"
                    " tally_flushed=excluded.tally_flushed,"
                    " rate_mac=excluded.rate_mac",
                    (
                        row.escrow_id,
                        row.window_id,
                        row.window_start,
                        row.individual,
                        row.rate_limited,
                        row.covered_reason,
                        1 if row.tally_flushed else 0,
                        row.rate_mac or "",
                    ),
                )
                self._conn.execute("COMMIT")
            except Exception:
                try:
                    self._conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise

    def get_open(self, escrow_id: str) -> RetryRateRow | None:
        with self._lock:
            r = self._conn.execute(
                "SELECT escrow_id, window_id, window_start, individual,"
                " rate_limited, covered_reason, tally_flushed, rate_mac"
                " FROM retry_rate_windows"
                " WHERE escrow_id = ? AND tally_flushed = 0",
                (escrow_id,),
            ).fetchone()
        if r is None:
            return None
        return RetryRateRow(
            escrow_id=r[0],
            window_id=r[1],
            window_start=float(r[2]),
            individual=int(r[3]),
            rate_limited=int(r[4]),
            covered_reason=r[5] or "",
            tally_flushed=bool(r[6]),
            rate_mac=r[7] or "",
        )

    def load_all(self) -> list[RetryRateRow]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT escrow_id, window_id, window_start, individual,"
                " rate_limited, covered_reason, tally_flushed, rate_mac"
                " FROM retry_rate_windows"
            ).fetchall()
        return [
            RetryRateRow(
                escrow_id=r[0],
                window_id=r[1],
                window_start=float(r[2]),
                individual=int(r[3]),
                rate_limited=int(r[4]),
                covered_reason=r[5] or "",
                tally_flushed=bool(r[6]),
                rate_mac=r[7] or "",
            )
            for r in rows
        ]

    def delete(self, escrow_id: str, window_id: str) -> None:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute(
                    "DELETE FROM retry_rate_windows"
                    " WHERE escrow_id = ? AND window_id = ?",
                    (escrow_id, window_id),
                )
                self._conn.execute("COMMIT")
            except Exception:
                try:
                    self._conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise
