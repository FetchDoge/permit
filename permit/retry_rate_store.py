"""
REA F7: durable per-escrow retry rate-limit side table, outside the hash chain.

Decisions do NOT trust this table's counters as authority: `individual` is
derived from an indexed COUNT of chain denial receipts inside the same
BEGIN IMMEDIATE as the allow/limit choice. This table holds window_id,
window_start, and an HMAC-protected ``rate_mac`` over rate_limited so
mid-window tampering is detectable before the tally (loss bound = 0 —
no checkpoint/K sampling).

The HMAC key and a monotonic high-water sidecar live OUTSIDE the database
(env var / 0600 key file + 0600 ``.hw`` sidecar next to the key) — never
in the repo or the DB. Each ``rate_mac`` binds the previous MAC, the latest
denial hash, escrow, window, count, and the sidecar high-water.

Crash ordering: the SQL count is committed first, then the sidecar
high-water is raised (locked + fsynced) to match under the same file
lock as the increment. A crash can leave exactly one step of skew
either way (DB one ahead after COMMIT-before-sidecar, or sidecar one
ahead); both are allowed and reconciled on the next honest step. A gap
larger than one → ``RetryRateIntegrityError`` (sidecar/chain wins —
rollback of an old saved pair).

Threat model: an attacker with DB write but not the key+sidecar cannot
forge a valid tag or roll the counter back. An attacker who has the DB,
the sidecar, and the key is out of scope.

At most one OPEN window (tally_flushed=0) per escrow — UNIQUE partial index.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
from dataclasses import dataclass

try:
    import fcntl
except ImportError:  # pragma: no cover - non-Unix
    fcntl = None  # type: ignore[assignment]

# Env: raw key material. File: path to a 0600 key file (contents = key bytes).
_ENV_KEY = "PERMIT_RETRY_RATE_MAC_KEY"
_ENV_KEY_FILE = "PERMIT_RETRY_RATE_MAC_KEY_FILE"
# Optional explicit high-water sidecar path (else ``{KEY_FILE}.hw``).
_ENV_HW_FILE = "PERMIT_RETRY_RATE_MAC_HW_FILE"
# demo.py only: allow the built-in demo key when neither env source is set.
_ENV_ALLOW_DEMO = "PERMIT_RETRY_RATE_ALLOW_DEMO_MAC_KEY"
_DEMO_FLAG_VALUES = frozenset({"1", "true", "yes", "on"})

_MIN_KEY_LEN = 32
_DEMO_MAC_KEY = b"demo-retry-rate-mac-key-NOT-FOR-PRODUCTION!!"  # 42 bytes

_mac_key_cache: bytes | None = None
_hw_path_cache: str | None = None


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
    prev_rate_mac: str = ""


def _demo_allowed() -> bool:
    return os.environ.get(_ENV_ALLOW_DEMO, "").strip().lower() in _DEMO_FLAG_VALUES


def _validate_key_material(key: bytes, *, source: str) -> bytes:
    if not key:
        raise RetryRateIntegrityError(
            f"retry-rate MAC key from {source} is empty; refuse "
            f"(minimum {_MIN_KEY_LEN} bytes)"
        )
    if len(key) < _MIN_KEY_LEN:
        raise RetryRateIntegrityError(
            f"retry-rate MAC key from {source} is too short "
            f"({len(key)} bytes; minimum {_MIN_KEY_LEN}); refuse"
        )
    return key


def load_retry_rate_mac_key(*, refresh: bool = False) -> bytes:
    """
    Load the HMAC key from outside the DB.

    Precedence: PERMIT_RETRY_RATE_MAC_KEY, else PERMIT_RETRY_RATE_MAC_KEY_FILE
    (must be mode 0600 when the filesystem reports permissions). Missing,
    empty, or short (<32 bytes) keys raise ``RetryRateIntegrityError``.

    The built-in demo key is used only when
    ``PERMIT_RETRY_RATE_ALLOW_DEMO_MAC_KEY`` is set (demo.py ``--allow-demo-mac-key``).
    Library code never falls back silently.
    """
    global _mac_key_cache
    if _mac_key_cache is not None and not refresh:
        return _mac_key_cache

    if _ENV_KEY in os.environ:
        _mac_key_cache = _validate_key_material(
            os.environ.get(_ENV_KEY, "").encode("utf-8"), source=_ENV_KEY
        )
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
        _mac_key_cache = _validate_key_material(
            key, source=f"{_ENV_KEY_FILE}={path!r}"
        )
        return _mac_key_cache

    if _demo_allowed():
        _mac_key_cache = _DEMO_MAC_KEY
        return _mac_key_cache

    raise RetryRateIntegrityError(
        f"{_ENV_KEY} / {_ENV_KEY_FILE} unset and demo MAC key not allowed "
        f"(set {_ENV_ALLOW_DEMO}=1 only for local demo.py); refuse"
    )


def clear_retry_rate_mac_key_cache() -> None:
    """Test helper: drop the cached key/path so the next load re-reads env/file."""
    global _mac_key_cache, _hw_path_cache
    _mac_key_cache = None
    _hw_path_cache = None


def retry_rate_hw_path(*, refresh: bool = False) -> str:
    """
    Path to the 0600 high-water sidecar.

    Precedence: PERMIT_RETRY_RATE_MAC_HW_FILE, else ``{KEY_FILE}.hw``.
    When only the env key (or demo key) is used, HW_FILE must be set.
    """
    global _hw_path_cache
    if _hw_path_cache is not None and not refresh:
        return _hw_path_cache

    override = os.environ.get(_ENV_HW_FILE, "").strip()
    if override:
        _hw_path_cache = override
        return _hw_path_cache

    key_file = os.environ.get(_ENV_KEY_FILE, "").strip()
    if key_file:
        _hw_path_cache = key_file + ".hw"
        return _hw_path_cache

    raise RetryRateIntegrityError(
        f"{_ENV_HW_FILE} unset and no {_ENV_KEY_FILE} to place the "
        "high-water sidecar next to; refuse"
    )


def _hw_map_key(escrow_id: str, window_id: str) -> str:
    return f"{escrow_id}|{window_id}"


def _hw_entry_path(escrow_id: str, window_id: str) -> str:
    """
    Per-(escrow, window) sidecar file under the HW path directory.

    ``PERMIT_RETRY_RATE_MAC_HW_FILE`` / ``{KEY_FILE}.hw`` names a directory
    (or a base path whose ``.d`` sibling directory holds entries). Using one
    file per window avoids JSON whole-map rewrite races under multiprocess.
    """
    base = retry_rate_hw_path()
    # Prefer a directory: if base exists as a file (legacy JSON map), use
    # ``base + ".d"``; if base has no extension-as-dir yet, create ``base`` as dir.
    if os.path.isdir(base):
        root = base
    else:
        root = base + ".d"
        os.makedirs(root, mode=0o700, exist_ok=True)
        try:
            os.chmod(root, 0o700)
        except OSError:
            pass
    digest = hashlib.sha256(_hw_map_key(escrow_id, window_id).encode()).hexdigest()[
        :32
    ]
    return os.path.join(root, digest + ".hw")


def _ensure_hw_entry(path: str) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, mode=0o700, exist_ok=True)
        try:
            os.chmod(parent, 0o700)
        except OSError:
            pass
    if os.path.exists(path):
        st = os.stat(path)
        mode = st.st_mode & 0o777
        if mode & 0o077:
            raise RetryRateIntegrityError(
                f"high-water sidecar {path!r} must be mode 0600 "
                f"(got {oct(mode)}); refuse"
            )
        return
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        # Lost the create race to another process; re-check mode.
        st = os.stat(path)
        mode = st.st_mode & 0o777
        if mode & 0o077:
            raise RetryRateIntegrityError(
                f"high-water sidecar {path!r} must be mode 0600 "
                f"(got {oct(mode)}); refuse"
            )
        return
    try:
        os.write(fd, b"0")
        os.fsync(fd)
    finally:
        os.close(fd)


def _read_hw_int_unlocked(fh) -> int:
    fh.seek(0)
    raw = fh.read().strip()
    if not raw:
        return 0
    return int(raw.decode("utf-8"))


def _write_hw_int_unlocked(fh, value: int) -> None:
    payload = str(int(value)).encode("utf-8")
    fh.seek(0)
    fh.truncate(0)
    fh.write(payload)
    fh.flush()
    os.fsync(fh.fileno())


def get_high_water(escrow_id: str, window_id: str) -> int:
    """Read the sidecar high-water for (escrow, window). Missing → 0."""
    path = _hw_entry_path(escrow_id, window_id)
    if not os.path.exists(path):
        return 0
    _ensure_hw_entry(path)
    with open(path, "r+b") as fh:
        if fcntl is not None:
            fcntl.flock(fh.fileno(), fcntl.LOCK_SH)
        try:
            return _read_hw_int_unlocked(fh)
        finally:
            if fcntl is not None:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


def set_high_water(escrow_id: str, window_id: str, value: int) -> int:
    """
    Raise the sidecar high-water to at least ``value`` (monotonic).
    Locked + fsynced. Returns the stored value after update.
    """
    path = _hw_entry_path(escrow_id, window_id)
    _ensure_hw_entry(path)
    want = int(value)
    with open(path, "r+b") as fh:
        if fcntl is not None:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        try:
            cur = _read_hw_int_unlocked(fh)
            if want > cur:
                _write_hw_int_unlocked(fh, want)
                cur = want
            mode = os.stat(path).st_mode & 0o777
            if mode & 0o077:
                os.chmod(path, 0o600)
        finally:
            if fcntl is not None:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    return cur


def check_high_water(
    escrow_id: str, window_id: str, db_count: int
) -> int:
    """
    Sidecar vs DB count (SQL-then-sidecar ordering).

    - db_count < hw → ``RetryRateIntegrityError`` (rollback of an old pair).
    - db_count == hw + 1 → crash: SQL committed, sidecar not yet raised;
      allowed — caller should ``reconcile_high_water``.
    - db_count > hw + 1 → refuse / lost sidecar → refuse.
    - otherwise OK.

    Returns the sidecar high-water.
    """
    hw = get_high_water(escrow_id, window_id)
    count = int(db_count)
    if count < hw:
        if hw == count + 1:
            return hw  # one-step crash skew; reconcile on increment
        raise RetryRateIntegrityError(
            "retry rate high-water sidecar ahead of DB count for "
            f"escrow_id={escrow_id!r} window_id={window_id!r}: "
            f"db_count={count} sidecar_hw={hw}; refuse "
            "(sidecar/chain wins; possible rollback)"
        )
    if count > hw + 1:
        raise RetryRateIntegrityError(
            "retry rate DB count ahead of high-water sidecar by more than "
            f"one for escrow_id={escrow_id!r} window_id={window_id!r}: "
            f"db_count={count} sidecar_hw={hw}; refuse"
        )
    return hw


def reconcile_high_water(
    escrow_id: str, window_id: str, db_count: int
) -> int:
    """
    After a successful SQL commit (or when DB is one ahead of the sidecar),
    raise the sidecar to ``db_count``. Crash between COMMIT and this call
    leaves the sidecar exactly one behind — the next honest step reconciles.
    """
    return set_high_water(escrow_id, window_id, int(db_count))


def mac_high_water_for_verify(
    escrow_id: str, window_id: str, db_count: int
) -> int:
    """
    High-water value bound into the stored MAC at mint time equals ``db_count``.
    Sidecar may be one behind after a crash; MAC verify still uses ``db_count``.
    Does not mutate the sidecar — reconcile only after a successful SQL commit.
    """
    check_high_water(escrow_id, window_id, db_count)
    return int(db_count)


def rate_limited_mac(
    denial_chain_hash: str | None,
    escrow_id: str,
    window_id: str,
    rate_limited: int,
    *,
    prev_mac: str = "",
    high_water: int = 0,
    key: bytes | None = None,
) -> str:
    """
    HMAC-SHA256 over
    ``prev_mac || denial || escrow || window || count || high_water``,
    keyed by a secret held outside the database.

    Updated atomically with every increment (sidecar HW raised in the same
    step); verified on every increment and at tally. Loss bound = 0.
    """
    if not denial_chain_hash:
        return ""
    material = key if key is not None else load_retry_rate_mac_key()
    msg = (
        f"{prev_mac or ''}|"
        f"{denial_chain_hash}|{escrow_id}|{window_id}|"
        f"{int(rate_limited)}|{int(high_water)}"
    ).encode("utf-8")
    return hmac.new(material, msg, hashlib.sha256).hexdigest()


def unkeyed_rate_limited_digest(
    denial_chain_hash: str,
    escrow_id: str,
    window_id: str,
    rate_limited: int,
    *,
    prev_mac: str = "",
    high_water: int = 0,
) -> str:
    """
    Plain SHA-256 of the same message (no secret). What a DB-only attacker
    can recompute — must NOT verify as a valid rate_mac.
    """
    msg = (
        f"{prev_mac or ''}|"
        f"{denial_chain_hash}|{escrow_id}|{window_id}|"
        f"{int(rate_limited)}|{int(high_water)}"
    ).encode("utf-8")
    return hashlib.sha256(msg).hexdigest()


def verify_rate_limited_mac(
    denial_chain_hash: str | None,
    escrow_id: str,
    window_id: str,
    rate_limited: int,
    rate_mac: str,
    *,
    prev_mac: str = "",
    high_water: int | None = None,
    key: bytes | None = None,
    check_sidecar: bool = True,
) -> None:
    count = int(rate_limited)
    if count == 0 and not (rate_mac or "") and not denial_chain_hash:
        if check_sidecar:
            check_high_water(escrow_id, window_id, count)
        return
    if high_water is None:
        if check_sidecar:
            hw = mac_high_water_for_verify(escrow_id, window_id, count)
        else:
            hw = count
    else:
        hw = int(high_water)
        if check_sidecar:
            check_high_water(escrow_id, window_id, count)
    expected = rate_limited_mac(
        denial_chain_hash,
        escrow_id,
        window_id,
        count,
        prev_mac=prev_mac or "",
        high_water=hw,
        key=key,
    )
    if not hmac.compare_digest(expected, rate_mac or ""):
        raise RetryRateIntegrityError(
            "retry rate side table rate_mac mismatch for "
            f"escrow_id={escrow_id!r} window_id={window_id!r} "
            f"rate_limited={count}; refuse (HMAC, key outside DB)"
        )


def bump_high_water_for_increment(
    escrow_id: str, window_id: str, new_count: int
) -> int:
    """
    Raise HW to ``new_count`` under lock+fsync (call after SQL COMMIT).
    Crash before this leaves HW one behind the durable DB count.
    """
    return set_high_water(escrow_id, window_id, int(new_count))


class high_water_lock:
    """Exclusive flock on the per-window sidecar entry for an increment."""

    def __init__(self, escrow_id: str, window_id: str) -> None:
        self.escrow_id = escrow_id
        self.window_id = window_id
        self._path = ""
        self._fh = None

    def __enter__(self):
        self._path = _hw_entry_path(self.escrow_id, self.window_id)
        _ensure_hw_entry(self._path)
        self._fh = open(self._path, "r+b")
        if fcntl is not None:
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._fh is not None:
            try:
                if fcntl is not None:
                    fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
            finally:
                self._fh.close()
                self._fh = None

    def get(self) -> int:
        assert self._fh is not None
        return _read_hw_int_unlocked(self._fh)

    def set(self, value: int) -> int:
        assert self._fh is not None
        want = int(value)
        cur = _read_hw_int_unlocked(self._fh)
        if want > cur:
            _write_hw_int_unlocked(self._fh, want)
            cur = want
        mode = os.stat(self._path).st_mode & 0o777
        if mode & 0o077:
            os.chmod(self._path, 0o600)
        return cur

    def check(self, db_count: int) -> int:
        """
        Compare DB count to sidecar. Does **not** mutate the sidecar —
        callers raise HW only after a successful SQL COMMIT.
        Allows exactly one step of skew either way (crash window).
        """
        hw = self.get()
        count = int(db_count)
        if count < hw:
            if hw == count + 1:
                return hw  # sidecar one ahead; reconcile after next commit
            raise RetryRateIntegrityError(
                "retry rate high-water sidecar ahead of DB count for "
                f"escrow_id={self.escrow_id!r} window_id={self.window_id!r}: "
                f"db_count={count} sidecar_hw={hw}; refuse "
                "(sidecar/chain wins; possible rollback)"
            )
        if count > hw + 1:
            raise RetryRateIntegrityError(
                "retry rate DB count ahead of high-water sidecar by more than "
                f"one for escrow_id={self.escrow_id!r} "
                f"window_id={self.window_id!r}: "
                f"db_count={count} sidecar_hw={hw}; refuse"
            )
        return hw


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
  prev_rate_mac  TEXT    NOT NULL DEFAULT '',
  PRIMARY KEY (escrow_id, window_id)
)
"""

_DDL_ONE_OPEN = """
CREATE UNIQUE INDEX IF NOT EXISTS retry_rate_one_open_window
ON retry_rate_windows (escrow_id)
WHERE tally_flushed = 0
"""

# Defense in depth: rate_limited is monotonic for an open window. A stale
# upsert / raw UPDATE that tries to lower it aborts (rollback detection
# for DB-only attackers still works via the sidecar high-water).
_DDL_RATE_LIMITED_MONOTONIC = """
CREATE TRIGGER IF NOT EXISTS retry_rate_rate_limited_monotonic
BEFORE UPDATE OF rate_limited ON retry_rate_windows
WHEN NEW.rate_limited < OLD.rate_limited
BEGIN
    SELECT RAISE(ABORT, 'rate_limited is monotonic');
END
"""


def _ensure_rate_mac_column(conn: sqlite3.Connection) -> None:
    cols = {r[1] for r in conn.execute("PRAGMA table_info(retry_rate_windows)")}
    if "rate_mac" not in cols:
        conn.execute(
            "ALTER TABLE retry_rate_windows"
            " ADD COLUMN rate_mac TEXT NOT NULL DEFAULT ''"
        )
    if "prev_rate_mac" not in cols:
        conn.execute(
            "ALTER TABLE retry_rate_windows"
            " ADD COLUMN prev_rate_mac TEXT NOT NULL DEFAULT ''"
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
                prev_rate_mac=row.prev_rate_mac,
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
                        prev_rate_mac=row.prev_rate_mac,
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
                prev_rate_mac=r.prev_rate_mac,
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
            self._conn.execute(_DDL_RATE_LIMITED_MONOTONIC)

    def upsert(self, row: RetryRateRow) -> None:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute(
                    "INSERT INTO retry_rate_windows"
                    " (escrow_id, window_id, window_start, individual,"
                    "  rate_limited, covered_reason, tally_flushed,"
                    "  rate_mac, prev_rate_mac)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
                    # Never lower rate_limited via upsert (monotonic): a
                    # stale rebuild snapshot must not clobber a live flood.
                    " ON CONFLICT(escrow_id, window_id) DO UPDATE SET"
                    " window_start=excluded.window_start,"
                    " individual=excluded.individual,"
                    " rate_limited=excluded.rate_limited,"
                    " covered_reason=excluded.covered_reason,"
                    " tally_flushed=excluded.tally_flushed,"
                    " rate_mac=excluded.rate_mac,"
                    " prev_rate_mac=excluded.prev_rate_mac"
                    " WHERE excluded.rate_limited >= "
                    "retry_rate_windows.rate_limited"
                    " OR excluded.tally_flushed = 1",
                    (
                        row.escrow_id,
                        row.window_id,
                        row.window_start,
                        row.individual,
                        row.rate_limited,
                        row.covered_reason,
                        1 if row.tally_flushed else 0,
                        row.rate_mac or "",
                        row.prev_rate_mac or "",
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
                " rate_limited, covered_reason, tally_flushed,"
                " rate_mac, prev_rate_mac"
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
            prev_rate_mac=r[8] or "",
        )

    def load_all(self) -> list[RetryRateRow]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT escrow_id, window_id, window_start, individual,"
                " rate_limited, covered_reason, tally_flushed,"
                " rate_mac, prev_rate_mac"
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
                prev_rate_mac=r[8] or "",
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
