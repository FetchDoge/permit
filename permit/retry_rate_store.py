"""
REA F7: durable per-escrow retry rate-limit side table, outside the hash chain.

Decisions do NOT trust this table's counters as authority: `individual` is
derived from an indexed COUNT of chain denial receipts inside the same
BEGIN IMMEDIATE as the allow/limit choice. This table holds window_id,
window_start, and an HMAC-protected ``rate_mac`` over rate_limited so
mid-window tampering is detectable before the tally (loss bound = 0 —
no checkpoint/K sampling).

The HMAC key is held OUTSIDE the database (env var or 0600 key file) —
never in the repo or the DB. Threat model: an attacker with DB write but
no key cannot forge a valid tag; an attacker who has both the DB and the
key is out of scope.

At most one OPEN window (tally_flushed=0) per escrow — UNIQUE partial index.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
import threading
import warnings
from dataclasses import dataclass

# Env: raw key material. File: path to a 0600 key file (contents = key bytes).
_ENV_KEY = "PERMIT_RETRY_RATE_MAC_KEY"
_ENV_KEY_FILE = "PERMIT_RETRY_RATE_MAC_KEY_FILE"

# Tests / local demos only — never ship as a production secret.
_DEMO_MAC_KEY = b"demo-retry-rate-mac-key-NOT-FOR-PRODUCTION"

_mac_key_cache: bytes | None = None
_mac_key_warned = False


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


def load_retry_rate_mac_key(*, refresh: bool = False) -> bytes:
    """
    Load the HMAC key from outside the DB.

    Precedence: PERMIT_RETRY_RATE_MAC_KEY, else PERMIT_RETRY_RATE_MAC_KEY_FILE
    (must be mode 0600 when the filesystem reports permissions), else a
    demo key with a RuntimeWarning (tests / local only).
    """
    global _mac_key_cache, _mac_key_warned
    if _mac_key_cache is not None and not refresh:
        return _mac_key_cache

    env = os.environ.get(_ENV_KEY, "")
    if env:
        _mac_key_cache = env.encode("utf-8")
        return _mac_key_cache

    path = os.environ.get(_ENV_KEY_FILE, "")
    if path:
        st = os.stat(path)
        mode = st.st_mode & 0o777
        if mode & 0o077:
            raise RetryRateIntegrityError(
                f"{_ENV_KEY_FILE}={path!r} must be mode 0600 "
                f"(got {oct(mode)}); refuse"
            )
        with open(path, "rb") as f:
            key = f.read()
        if not key:
            raise RetryRateIntegrityError(
                f"{_ENV_KEY_FILE}={path!r} is empty; refuse"
            )
        _mac_key_cache = key
        return _mac_key_cache

    if not _mac_key_warned:
        warnings.warn(
            f"{_ENV_KEY} / {_ENV_KEY_FILE} unset: running on the demo "
            "retry-rate MAC key. Set a secret outside the DB in any real "
            "deployment.",
            RuntimeWarning,
            stacklevel=2,
        )
        _mac_key_warned = True
    _mac_key_cache = _DEMO_MAC_KEY
    return _mac_key_cache


def clear_retry_rate_mac_key_cache() -> None:
    """Test helper: drop the cached key so the next load re-reads env/file."""
    global _mac_key_cache
    _mac_key_cache = None


def rate_limited_mac(
    denial_chain_hash: str | None,
    escrow_id: str,
    window_id: str,
    rate_limited: int,
    *,
    key: bytes | None = None,
) -> str:
    """
    HMAC-SHA256 over (latest window denial chain hash || escrow || window ||
    rate_limited count), keyed by a secret held outside the database.

    Updated atomically with every increment; verified on every increment
    and at tally. Loss bound = 0 (no checkpoint/K).
    """
    if not denial_chain_hash:
        return ""
    material = key if key is not None else load_retry_rate_mac_key()
    msg = (
        f"{denial_chain_hash}|{escrow_id}|{window_id}|{int(rate_limited)}"
    ).encode("utf-8")
    return hmac.new(material, msg, hashlib.sha256).hexdigest()


def unkeyed_rate_limited_digest(
    denial_chain_hash: str,
    escrow_id: str,
    window_id: str,
    rate_limited: int,
) -> str:
    """
    Plain SHA-256 of the same message (no secret). What a DB-only attacker
    can recompute — must NOT verify as a valid rate_mac.
    """
    msg = (
        f"{denial_chain_hash}|{escrow_id}|{window_id}|{int(rate_limited)}"
    ).encode("utf-8")
    return hashlib.sha256(msg).hexdigest()


def verify_rate_limited_mac(
    denial_chain_hash: str | None,
    escrow_id: str,
    window_id: str,
    rate_limited: int,
    rate_mac: str,
    *,
    key: bytes | None = None,
) -> None:
    if int(rate_limited) == 0 and not (rate_mac or "") and not denial_chain_hash:
        return
    expected = rate_limited_mac(
        denial_chain_hash,
        escrow_id,
        window_id,
        rate_limited,
        key=key,
    )
    if not hmac.compare_digest(expected, rate_mac or ""):
        raise RetryRateIntegrityError(
            "retry rate side table rate_mac mismatch for "
            f"escrow_id={escrow_id!r} window_id={window_id!r} "
            f"rate_limited={rate_limited}; refuse (HMAC, key outside DB)"
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
