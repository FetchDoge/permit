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

Crash ordering: write an intent record (target count) into the
HMAC-tied counter file under exclusive flock (random temp,
O_CREAT|O_EXCL|O_NOFOLLOW, fsync, atomic rename, directory fsync)
*before* the SQL commit, then confirm the intent after commit.
Startup reconciles only through that intent record — never through
count skew tolerance. After reconcile, DB count must equal the file's
confirmed count exactly.

Fail-closed sidecar: deleted, truncated, unreadable, corrupt, symlinked,
or MAC-invalid counter files raise ``RetryRateIntegrityError`` and never
restart from 0. Only creating a brand-new rate window (or a fresh DB
with no rate rows) may create a new file. Startup cross-checks every
DB rate row against its counter file and every counter file against the
DB. Operator recovery: stop writers, restore each missing
``{HW}.d/<digest>.hw`` from backup (or rewrite with the row's
``rate_limited`` under mode 0600 owned by the service uid, with a valid
file HMAC), then restart.

An in-process high-water per (escrow, window) catches live joint
rollback of DB+file on the next decision. An optional external anchor
hook (callable or URL) receives the latest ``rate_mac``; rolling back
all on-disk state between restarts is detected only when an anchor is
configured.

Threat model: an attacker with DB write but not the key+sidecar cannot
forge a valid tag or roll the counter back. An attacker who has the DB,
the sidecar, and the key is out of scope without an external anchor.

At most one OPEN window (tally_flushed=0) per escrow — UNIQUE partial index.
"""

from __future__ import annotations

import hashlib
import secrets
import hmac
import json
import os
import sqlite3
import stat
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator

try:
    import fcntl
except ImportError:  # pragma: no cover - non-Unix
    fcntl = None  # type: ignore[assignment]

# Env: raw key material. File: path to a 0600 key file (contents = key bytes).
_ENV_KEY = "PERMIT_RETRY_RATE_MAC_KEY"
_ENV_KEY_FILE = "PERMIT_RETRY_RATE_MAC_KEY_FILE"
# Optional explicit high-water sidecar path (else ``{KEY_FILE}.hw``).
_ENV_HW_FILE = "PERMIT_RETRY_RATE_MAC_HW_FILE"

_MIN_KEY_LEN = 32

_mac_key_cache: bytes | None = None
_hw_path_cache: str | None = None
# Process-local high-water (confirmed count) per (escrow|window) for the
# life of the process. Catches live joint rollback of DB+file on the next
# decision even when on-disk state was rewritten together.
_hw_mem: dict[str, int] = {}
_hw_mem_guard = threading.Lock()

# Optional external anchor: callable receives latest rate_mac hex after each
# confirmed increment; url is recorded for operators (library never fetches).
# Rolling back all on-disk state between restarts is detected only when an
# anchor is configured and consulted at startup.
_anchor_hook: object | None = None
_anchor_url: str | None = None


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


@dataclass
class HighWaterRecord:
    """On-disk counter file payload (HMAC-tied to the MAC key)."""

    escrow_id: str
    window_id: str
    confirmed: int
    intent: int | None  # target count written before SQL; None when idle
    mac: str = ""
    # Writer liveness for pending intent: pid + /proc starttime token.
    # Set whenever intent is non-None; cleared when intent is cleared.
    writer_pid: int | None = None
    writer_start: int | None = None


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


def require_retry_rate_mac_key() -> bytes:
    """
    Validate that a usable MAC key is configured (present, non-empty, ≥32).
    Call from SqliteLedger / ReleaseVerifier constructors so a bad key
    fails before the first decision.
    """
    return load_retry_rate_mac_key(refresh=True)


def load_retry_rate_mac_key(*, refresh: bool = False) -> bytes:
    """
    Load the HMAC key from outside the DB.

    Precedence: PERMIT_RETRY_RATE_MAC_KEY, else PERMIT_RETRY_RATE_MAC_KEY_FILE
    (must be mode 0600 when the filesystem reports permissions). Missing,
    empty, or short (<32 bytes) keys raise ``RetryRateIntegrityError``.
    There is no built-in demo key — demo.py generates a per-run key itself.
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
        _refuse_if_symlink(path, what="MAC key file")
        st = os.lstat(path)
        mode = st.st_mode & 0o777
        if mode & 0o077:
            raise RetryRateIntegrityError(
                f"{_ENV_KEY_FILE}={path!r} must be mode 0600 "
                f"(got {oct(mode)}); refuse"
            )
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags)
        try:
            key = os.read(fd, 1 << 20)
        finally:
            os.close(fd)
        _mac_key_cache = _validate_key_material(
            key, source=f"{_ENV_KEY_FILE}={path!r}"
        )
        return _mac_key_cache

    raise RetryRateIntegrityError(
        f"{_ENV_KEY} / {_ENV_KEY_FILE} unset; refuse "
        "(no built-in demo key; demo.py must set a per-run key itself)"
    )


def clear_retry_rate_mac_key_cache() -> None:
    """Test helper: drop the cached key/path so the next load re-reads env/file."""
    global _mac_key_cache, _hw_path_cache
    _mac_key_cache = None
    _hw_path_cache = None
    with _hw_mem_guard:
        _hw_mem.clear()


def set_rate_mac_anchor(
    hook: object | None = None,
    *,
    url: str | None = None,
) -> None:
    """
    Optional external anchor for the latest ``rate_mac``.

    ``hook`` is a callable invoked as ``hook(rate_mac_hex)`` after each
    confirmed increment. If ``hook`` exposes ``check_startup(macs)``,
    startup calls it with the set of current DB ``rate_mac`` values.

    ``url`` is recorded for operators only — this library never fetches it.
    Rolling back DB + counter files between restarts is detected **only**
    when an anchor is configured (and its startup check is consulted).
    """
    global _anchor_hook, _anchor_url
    _anchor_hook = hook
    _anchor_url = url


def clear_rate_mac_anchor() -> None:
    set_rate_mac_anchor(None, url=None)


def publish_rate_mac_to_anchor(rate_mac: str) -> None:
    if not rate_mac:
        return
    hook = _anchor_hook
    if hook is None:
        return
    if callable(hook):
        hook(rate_mac)


def consult_anchor_at_startup(rate_macs: set[str]) -> None:
    """Refuse if the configured anchor says on-disk MACs were rolled back."""
    hook = _anchor_hook
    if hook is None:
        return
    check = getattr(hook, "check_startup", None)
    if check is None:
        return
    check(set(rate_macs))


def get_rate_mac_anchor_url() -> str | None:
    return _anchor_url


def retry_rate_hw_path(*, refresh: bool = False) -> str:
    """
    Path to the 0600 high-water sidecar.

    Precedence: PERMIT_RETRY_RATE_MAC_HW_FILE, else ``{KEY_FILE}.hw``.
    When only the env key is used, HW_FILE must be set.
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


def _refuse_if_symlink(path: str, *, what: str) -> None:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise RetryRateIntegrityError(
            f"{what} at {path!r} unreadable: {exc}; refuse"
        ) from exc
    if stat.S_ISLNK(st.st_mode):
        raise RetryRateIntegrityError(
            f"{what} at {path!r} is a symlink; refuse"
        )


def _hw_root_dir() -> str:
    """Directory that holds per-window ``.hw`` counter files."""
    base = retry_rate_hw_path()
    # Refuse a symlinked base path (dir or file) before creating siblings.
    _refuse_if_symlink(base, what="high-water parent directory")
    if os.path.isdir(base):
        return base
    root = base + ".d"
    _refuse_if_symlink(root, what="high-water parent directory")
    os.makedirs(root, mode=0o700, exist_ok=True)
    try:
        os.chmod(root, 0o700)
    except OSError:
        pass
    _refuse_if_symlink(root, what="high-water parent directory")
    return root


def _hw_entry_path(escrow_id: str, window_id: str) -> str:
    digest = hashlib.sha256(_hw_map_key(escrow_id, window_id).encode()).hexdigest()[
        :32
    ]
    return os.path.join(_hw_root_dir(), digest + ".hw")


def _hw_lock_path(data_path: str) -> str:
    return data_path + ".lock"


def _hw_root_lock_path() -> str:
    return os.path.join(_hw_root_dir(), ".root.lock")


@contextmanager
def high_water_root_lock() -> Iterator[None]:
    """
    Exclusive flock over the HW root.

    Held across create_high_water + the matching DB INSERT, and across the
    startup orphan cross-check, so a live writer cannot plant a counter file
    that a concurrent opener lists as an orphan (or the reverse).
    """
    root = _hw_root_dir()
    _refuse_if_symlink(root, what="high-water parent directory")
    lock_path = _hw_root_lock_path()
    _refuse_if_symlink(lock_path, what="high-water root lock file")
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(lock_path, flags, 0o600)
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        if fcntl is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
        os.close(fd)


def remove_high_water(escrow_id: str, window_id: str) -> None:
    """
    Delete a counter file + lock after a lost INSERT race (file created,
    UNIQUE open-window INSERT failed). Not for operator recovery of
    missing-sidecar cases.
    """
    path = _hw_entry_path(escrow_id, window_id)
    lock_path = _hw_lock_path(path)
    for p in (path, lock_path):
        try:
            if os.path.exists(p) and not os.path.islink(p):
                os.remove(p)
        except OSError:
            pass


def _assert_hw_file_meta(path: str) -> None:
    """Require regular file, mode 0600, owner == euid; refuse symlinks."""
    _refuse_if_symlink(path, what="high-water sidecar")
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise RetryRateIntegrityError(
            f"high-water sidecar unreadable at {path!r}: {exc}; refuse"
        ) from exc
    if not stat.S_ISREG(st.st_mode):
        raise RetryRateIntegrityError(
            f"high-water sidecar {path!r} is not a regular file; refuse"
        )
    mode = st.st_mode & 0o777
    if mode != 0o600:
        raise RetryRateIntegrityError(
            f"high-water sidecar {path!r} must be mode 0600 "
            f"(got {oct(mode)}); refuse"
        )
    euid = os.geteuid()
    if st.st_uid != euid:
        raise RetryRateIntegrityError(
            f"high-water sidecar {path!r} owner uid={st.st_uid} "
            f"!= current euid={euid}; refuse"
        )


# intent=-1 marks a counter file created before the matching DB INSERT commits.
_HW_CREATING_INTENT = -1

# Test instrumentation: directory of per-pid markers while a write holds
# the counter lock; overlap counter file incremented by startup checks.
_ENV_WRITE_ACTIVE_DIR = "PERMIT_RETRY_RATE_WRITE_ACTIVE_DIR"
_ENV_STARTUP_OVERLAP_FILE = "PERMIT_RETRY_RATE_STARTUP_OVERLAP_FILE"


def _process_start_token(pid: int) -> int | None:
    """Linux `/proc/<pid>/stat` starttime (field 22); None if unavailable."""
    try:
        with open(f"/proc/{int(pid)}/stat", "r", encoding="utf-8") as fh:
            buf = fh.read()
    except (OSError, ValueError):
        return None
    # comm may contain spaces/parens — starttime is field 22 of the
    # space-separated tail after the closing paren of comm.
    try:
        rparen = buf.rfind(")")
        if rparen < 0:
            return None
        fields = buf[rparen + 2 :].split()
        return int(fields[19])  # starttime is index 19 in the tail (field 22)
    except (IndexError, ValueError):
        return None


def _current_writer_identity() -> tuple[int, int]:
    pid = os.getpid()
    start = _process_start_token(pid)
    if start is None:
        # Non-Linux / restricted proc: fall back to a per-process token.
        start = int(getattr(_current_writer_identity, "_fallback", 0)) or (
            int(os.times().elapsed * 1000) ^ (pid << 16)
        )
        _current_writer_identity._fallback = start  # type: ignore[attr-defined]
    return pid, int(start)


def _writer_still_alive(pid: int | None, start: int | None) -> bool:
    if pid is None or start is None:
        return False
    if int(pid) <= 0:
        return False
    try:
        os.kill(int(pid), 0)
    except OSError:
        return False
    cur = _process_start_token(int(pid))
    if cur is None:
        return False
    return int(cur) == int(start)


def _hw_record_mac(
    escrow_id: str,
    window_id: str,
    confirmed: int,
    intent: int | None,
    *,
    writer_pid: int | None = None,
    writer_start: int | None = None,
    key: bytes | None = None,
) -> str:
    material = key if key is not None else load_retry_rate_mac_key()
    intent_s = "" if intent is None else str(int(intent))
    pid_s = "" if writer_pid is None else str(int(writer_pid))
    start_s = "" if writer_start is None else str(int(writer_start))
    msg = (
        f"hw2|{escrow_id}|{window_id}|{int(confirmed)}|{intent_s}|"
        f"{pid_s}|{start_s}"
    ).encode("utf-8")
    return hmac.new(material, msg, hashlib.sha256).hexdigest()


def _record_to_payload(rec: HighWaterRecord) -> bytes:
    obj = {
        "v": 2,
        "escrow_id": rec.escrow_id,
        "window_id": rec.window_id,
        "confirmed": int(rec.confirmed),
        "intent": None if rec.intent is None else int(rec.intent),
        "writer_pid": None if rec.writer_pid is None else int(rec.writer_pid),
        "writer_start": (
            None if rec.writer_start is None else int(rec.writer_start)
        ),
        "mac": rec.mac,
    }
    return (json.dumps(obj, separators=(",", ":"), sort_keys=True) + "\n").encode(
        "utf-8"
    )


def _parse_hw_record(raw: bytes, *, path: str) -> HighWaterRecord:
    if not raw or not raw.strip():
        raise RetryRateIntegrityError(
            f"high-water sidecar truncated/empty at {path!r}; refuse "
            "(never restart from 0)"
        )
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RetryRateIntegrityError(
            f"high-water sidecar corrupt at {path!r}; refuse "
            "(never restart from 0)"
        ) from exc
    try:
        escrow_id = str(obj["escrow_id"])
        window_id = str(obj["window_id"])
        confirmed = int(obj["confirmed"])
        intent_raw = obj.get("intent", None)
        intent = None if intent_raw is None else int(intent_raw)
        mac = str(obj.get("mac") or "")
        pid_raw = obj.get("writer_pid", None)
        start_raw = obj.get("writer_start", None)
        writer_pid = None if pid_raw is None else int(pid_raw)
        writer_start = None if start_raw is None else int(start_raw)
    except (KeyError, TypeError, ValueError) as exc:
        raise RetryRateIntegrityError(
            f"high-water sidecar corrupt at {path!r}; refuse"
        ) from exc
    if confirmed < 0:
        raise RetryRateIntegrityError(
            f"high-water sidecar corrupt at {path!r} (negative); refuse"
        )
    # intent=-1 is the creating sentinel (file exists before DB INSERT).
    if intent is not None and intent < 0 and intent != _HW_CREATING_INTENT:
        raise RetryRateIntegrityError(
            f"high-water sidecar corrupt at {path!r} (negative intent); refuse"
        )
    if intent is None:
        writer_pid = None
        writer_start = None
    elif writer_pid is None or writer_start is None:
        raise RetryRateIntegrityError(
            f"high-water sidecar pending without writer identity at {path!r}; "
            "refuse"
        )
    expected = _hw_record_mac(
        escrow_id,
        window_id,
        confirmed,
        intent,
        writer_pid=writer_pid,
        writer_start=writer_start,
    )
    if not mac or not hmac.compare_digest(expected, mac):
        raise RetryRateIntegrityError(
            f"high-water sidecar MAC mismatch at {path!r}; refuse "
            "(file values are tied to the HMAC key)"
        )
    return HighWaterRecord(
        escrow_id=escrow_id,
        window_id=window_id,
        confirmed=confirmed,
        intent=intent,
        mac=mac,
        writer_pid=writer_pid,
        writer_start=writer_start,
    )


def _read_hw_record(path: str) -> HighWaterRecord:
    if not os.path.exists(path):
        raise RetryRateIntegrityError(
            f"high-water sidecar missing at {path!r}; refuse "
            "(never restart from 0; restore from backup or rewrite "
            "from DB rate_limited under mode 0600, then restart)"
        )
    _assert_hw_file_meta(path)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
        try:
            raw = os.read(fd, 1 << 20)
        finally:
            os.close(fd)
    except OSError as exc:
        raise RetryRateIntegrityError(
            f"high-water sidecar unreadable at {path!r}: {exc}; refuse"
        ) from exc
    return _parse_hw_record(raw, path=path)


def _read_hw_file(path: str) -> int:
    """Return confirmed count (fail-closed)."""
    return _read_hw_record(path).confirmed


def _atomic_write_hw_record(path: str, rec: HighWaterRecord) -> None:
    """
    Write temp (random name, O_CREAT|O_EXCL|O_NOFOLLOW, 0600) → fsync →
    atomic rename → fsync dir. Caller must hold the exclusive ``.lock`` flock.
    """
    parent = os.path.dirname(path) or "."
    _refuse_if_symlink(parent, what="high-water parent directory")
    os.makedirs(parent, mode=0o700, exist_ok=True)
    try:
        os.chmod(parent, 0o700)
    except OSError:
        pass
    _refuse_if_symlink(parent, what="high-water parent directory")
    if os.path.exists(path):
        _refuse_if_symlink(path, what="high-water sidecar")
    if rec.intent is None:
        rec.writer_pid = None
        rec.writer_start = None
    rec.mac = _hw_record_mac(
        rec.escrow_id,
        rec.window_id,
        rec.confirmed,
        rec.intent,
        writer_pid=rec.writer_pid,
        writer_start=rec.writer_start,
    )
    payload = _record_to_payload(rec)
    tmp = os.path.join(
        parent, f".hwtmp.{secrets.token_hex(16)}.{os.getpid()}"
    )
    _refuse_if_symlink(tmp, what="high-water temp file")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(tmp, flags, 0o600)
    except OSError as exc:
        # O_NOFOLLOW → ELOOP when a symlink was planted at the temp path.
        raise RetryRateIntegrityError(
            f"high-water temp file at {tmp!r} refused: {exc}; refuse"
        ) from exc
    try:
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)
    dir_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        pass
    if hasattr(os, "O_NOFOLLOW"):
        dir_flags |= os.O_NOFOLLOW
    dir_fd = os.open(parent, dir_flags)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    _assert_hw_file_meta(path)


def _mark_write_active() -> str | None:
    """Test hook: drop a pid marker while a writer holds the counter lock."""
    root = os.environ.get(_ENV_WRITE_ACTIVE_DIR) or ""
    if not root:
        return None
    try:
        os.makedirs(root, mode=0o700, exist_ok=True)
        path = os.path.join(root, f"{os.getpid()}.writing")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("1")
        return path
    except OSError:
        return None


def _clear_write_active(marker: str | None) -> None:
    if not marker:
        return
    try:
        os.remove(marker)
    except OSError:
        pass


def _note_startup_overlap_if_writers_active() -> None:
    """Test hook: count startups that overlap a concurrent writer marker."""
    active_dir = os.environ.get(_ENV_WRITE_ACTIVE_DIR) or ""
    overlap_path = os.environ.get(_ENV_STARTUP_OVERLAP_FILE) or ""
    if not active_dir or not overlap_path:
        return
    try:
        names = os.listdir(active_dir)
    except OSError:
        return
    if not any(n.endswith(".writing") for n in names):
        return
    try:
        flags = os.O_CREAT | os.O_WRONLY | os.O_APPEND
        fd = os.open(overlap_path, flags, 0o600)
        try:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_EX)
            os.write(fd, b"1\n")
        finally:
            if fcntl is not None:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    pass
            os.close(fd)
    except OSError:
        pass


def create_high_water(
    escrow_id: str, window_id: str, *, initial: int = 0
) -> int:
    """
    Create a new per-window counter file at ``initial`` (default 0).

    Only for a brand-new rate window (caller inserting the DB row) or a
    fresh DB with no rate rows. If the file already exists, verify and
    return its confirmed value (never reset to 0).

    Convenience helper clears the creating intent before returning (idle
    file). Production window creation must use ``high_water_create`` so the
    flock stays held through the matching DB INSERT.
    """
    with high_water_create(escrow_id, window_id, initial=initial) as hwlock:
        val = int(hwlock.read().confirmed)
        hwlock.clear_creating_intent()
        return val


@contextmanager
def high_water_create(
    escrow_id: str, window_id: str, *, initial: int = 0
) -> Iterator["high_water_lock"]:
    """
    Create (or adopt) a counter file and hold its exclusive flock until
    the context exits. Pending creating intent is only valid while this
    writer is alive and holds the lock.
    """
    path = _hw_entry_path(escrow_id, window_id)
    lock_path = _hw_lock_path(path)
    parent = os.path.dirname(path) or "."
    _refuse_if_symlink(parent, what="high-water parent directory")
    os.makedirs(parent, mode=0o700, exist_ok=True)
    try:
        os.chmod(parent, 0o700)
    except OSError:
        pass
    _refuse_if_symlink(lock_path, what="high-water lock file")
    lock_flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        lock_flags |= os.O_NOFOLLOW
    lock_fd = os.open(lock_path, lock_flags, 0o600)
    marker = None
    holder = high_water_lock(escrow_id, window_id)
    holder._path = path
    holder._lock_path = lock_path
    holder._fd = lock_fd
    try:
        if fcntl is not None:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
        marker = _mark_write_active()
        if os.path.exists(path):
            rec = _read_hw_record(path)
            if rec.escrow_id != escrow_id or rec.window_id != window_id:
                raise RetryRateIntegrityError(
                    f"high-water sidecar identity mismatch at {path!r}; refuse"
                )
            val = rec.confirmed
        else:
            pid, start = _current_writer_identity()
            rec = HighWaterRecord(
                escrow_id=escrow_id,
                window_id=window_id,
                confirmed=int(initial),
                intent=_HW_CREATING_INTENT,
                writer_pid=pid,
                writer_start=start,
            )
            _atomic_write_hw_record(path, rec)
            val = int(initial)
        with _hw_mem_guard:
            _hw_mem[_hw_map_key(escrow_id, window_id)] = val
        yield holder
    finally:
        _clear_write_active(marker)
        if fcntl is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            except OSError:
                pass
        try:
            os.close(lock_fd)
        except OSError:
            pass
        holder._fd = -1


def clear_high_water_creating_intent(escrow_id: str, window_id: str) -> None:
    """After a successful DB INSERT, clear the creating intent (-1)."""
    with high_water_lock(escrow_id, window_id) as hwlock:
        hwlock.clear_creating_intent()


def get_high_water(escrow_id: str, window_id: str) -> int:
    """Read confirmed sidecar count; missing/corrupt → refuse."""
    mk = _hw_map_key(escrow_id, window_id)
    path = _hw_entry_path(escrow_id, window_id)
    if not os.path.exists(path):
        raise RetryRateIntegrityError(
            f"high-water sidecar missing for escrow_id={escrow_id!r} "
            f"window_id={window_id!r} path={path!r}; refuse "
            "(never restart from 0)"
        )
    lock_path = _hw_lock_path(path)
    _refuse_if_symlink(lock_path, what="high-water lock file")
    lock_flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        lock_flags |= os.O_NOFOLLOW
    lock_fd = os.open(lock_path, lock_flags, 0o600)
    try:
        if fcntl is not None:
            fcntl.flock(lock_fd, fcntl.LOCK_SH)
        rec = _read_hw_record(path)
    finally:
        if fcntl is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            except OSError:
                pass
        os.close(lock_fd)
    val = rec.confirmed
    with _hw_mem_guard:
        prev = _hw_mem.get(mk, 0)
        if val < prev:
            raise RetryRateIntegrityError(
                "process high-water ahead of counter file for "
                f"escrow_id={escrow_id!r} window_id={window_id!r}: "
                f"file={val} process_hw={prev}; refuse (live rollback)"
            )
        if val > prev:
            _hw_mem[mk] = val
    return val


def set_high_water(escrow_id: str, window_id: str, value: int) -> int:
    """Confirm the sidecar to ``value`` (monotonic confirmed count)."""
    path = _hw_entry_path(escrow_id, window_id)
    if not os.path.exists(path):
        raise RetryRateIntegrityError(
            f"high-water sidecar missing at {path!r}; refuse to set "
            "(never create from set_high_water / never restart from 0)"
        )
    with high_water_lock(escrow_id, window_id) as hwlock:
        return hwlock.confirm(int(value))


def check_high_water(
    escrow_id: str, window_id: str, db_count: int
) -> int:
    """
    Sidecar confirmed count must equal ``db_count`` exactly.
    No skew tolerance — crash recovery goes through the intent record.
    Also enforces the in-process high-water (live joint-rollback bar).
    """
    count = int(db_count)
    mk = _hw_map_key(escrow_id, window_id)
    with _hw_mem_guard:
        proc = _hw_mem.get(mk, 0)
        if count < proc:
            raise RetryRateIntegrityError(
                "process high-water ahead of DB count for "
                f"escrow_id={escrow_id!r} window_id={window_id!r}: "
                f"db_count={count} process_hw={proc}; refuse "
                "(live joint rollback)"
            )
    with high_water_lock(escrow_id, window_id) as hwlock:
        rec = hwlock.read()
        if rec.intent == _HW_CREATING_INTENT and rec.confirmed == count:
            # Creating sentinel left after INSERT; clear before exact check.
            hwlock.reconcile(count)
            rec = hwlock.read()
        if rec.intent is not None:
            raise RetryRateIntegrityError(
                "high-water sidecar has pending intent for "
                f"escrow_id={escrow_id!r} window_id={window_id!r}: "
                f"confirmed={rec.confirmed} intent={rec.intent} "
                f"db_count={count}; refuse (reconcile intent first)"
            )
        if count != rec.confirmed:
            raise RetryRateIntegrityError(
                "retry rate high-water sidecar != DB count for "
                f"escrow_id={escrow_id!r} window_id={window_id!r}: "
                f"db_count={count} sidecar_confirmed={rec.confirmed}; refuse "
                "(exact match required; possible rollback)"
            )
        with _hw_mem_guard:
            if rec.confirmed > _hw_mem.get(mk, 0):
                _hw_mem[mk] = rec.confirmed
        return rec.confirmed


def reconcile_intent_with_db(
    escrow_id: str, window_id: str, db_count: int
) -> int:
    """Startup / pre-decision: resolve a pending intent against ``db_count``."""
    with high_water_lock(escrow_id, window_id) as hwlock:
        return hwlock.reconcile(int(db_count))


def reconcile_high_water(
    escrow_id: str, window_id: str, db_count: int
) -> int:
    """Confirm sidecar to ``db_count`` after SQL commit (intent protocol)."""
    return set_high_water(escrow_id, window_id, int(db_count))


def list_hw_entry_digests() -> dict[str, str]:
    """Map digest filename stem → full path for every ``.hw`` under the root."""
    root = _hw_root_dir()
    out: dict[str, str] = {}
    try:
        names = os.listdir(root)
    except FileNotFoundError:
        return out
    for name in names:
        if not name.endswith(".hw"):
            continue
        out[name[: -len(".hw")]] = os.path.join(root, name)
    return out


def assert_high_water_files_for_rows(
    rows: list[tuple[str, str, int]],
    *,
    fresh_count: object | None = None,
    refresh_rows: object | None = None,
    row_exists: object | None = None,
) -> None:
    """
    Startup bidirectional cross-check:
    - every DB rate row has a valid HMAC-tied sidecar; reconcile intent;
      confirmed must equal DB ``rate_limited``.
    - every counter file under the HW root maps to a DB row (no orphans).

    Runs under ``high_water_root_lock``. Pending intent is allowed only when
    the recorded writer is still alive (and held the lock while writing);
    under this exclusive lock a live concurrent writer cannot also hold it,
    so unmatched pending files are resolved against the committed row or
    refused (stale dead writer / planted pending with deleted row).
    """
    _note_startup_overlap_if_writers_active()
    # No root lock here: writers use per-window flock → SQL. Holding a
    # root lock across per-window flocks deadlocks with that order.
    if refresh_rows is not None:
        rows = list(refresh_rows())

    known: set[str] = set()
    for escrow_id, window_id, db_count in rows:
        digest = hashlib.sha256(
            _hw_map_key(escrow_id, window_id).encode()
        ).hexdigest()[:32]
        known.add(digest)
        path = _hw_entry_path(escrow_id, window_id)
        if not os.path.exists(path):
            # Row may have disappeared under a concurrent lost-create
            # cleanup, or the sidecar is truly missing for a live row.
            if fresh_count is not None and fresh_count(escrow_id, window_id) is None:
                continue
            raise RetryRateIntegrityError(
                "high-water sidecar missing at startup for "
                f"escrow_id={escrow_id!r} window_id={window_id!r} "
                f"path={path!r}; refuse to start (DB has rate rows; "
                "never recreate from 0 — restore sidecar from backup or "
                "rewrite with the row's rate_limited under mode 0600 "
                "owned by the service uid, then restart)"
            )
        try:
            with high_water_lock(escrow_id, window_id) as hwlock:
                count = int(db_count)
                if fresh_count is not None:
                    refreshed = fresh_count(escrow_id, window_id)
                    if refreshed is None:
                        # Row disappeared under flock (flushed/deleted); skip.
                        continue
                    count = int(refreshed)
                rec = hwlock.read()
                if (
                    rec.intent is not None
                    and _writer_still_alive(rec.writer_pid, rec.writer_start)
                    and int(rec.writer_pid or -1) != os.getpid()
                ):
                    # Live foreign writer still pending — do not reconcile yet.
                    continue
                hwlock.reconcile(count)
                hwlock.check(count)
        except RetryRateIntegrityError:
            if fresh_count is not None and fresh_count(escrow_id, window_id) is None:
                continue
            if not os.path.exists(path):
                # Sidecar raced with lost-create cleanup and row is gone too.
                continue
            raise

    for digest, fpath in list_hw_entry_digests().items():
        if digest in known:
            continue
        # Unmatched digest: acquire per-window flock and resolve/refuse.
        try:
            rec0 = _read_hw_record(fpath)
        except RetryRateIntegrityError:
            # Lost-create cleanup may unlink between readdir and read.
            if not os.path.exists(fpath):
                continue
            raise RetryRateIntegrityError(
                f"orphan high-water sidecar at {fpath!r} "
                f"(digest={digest}); refuse to start "
                "(DB↔file cross-check)"
            ) from None
        try:
            with high_water_lock(rec0.escrow_id, rec0.window_id) as hwlock:
                rec = hwlock.read()
                exists = False
                db_count_for = None
                if fresh_count is not None:
                    refreshed = fresh_count(rec.escrow_id, rec.window_id)
                    if refreshed is not None:
                        exists = True
                        db_count_for = int(refreshed)
                elif row_exists is not None:
                    exists = bool(row_exists(rec.escrow_id, rec.window_id))
                elif refresh_rows is not None:
                    for escrow_id, window_id, c in refresh_rows():
                        if (
                            escrow_id == rec.escrow_id
                            and window_id == rec.window_id
                        ):
                            exists = True
                            db_count_for = int(c)
                            break
                if rec.intent is not None:
                    if _writer_still_alive(rec.writer_pid, rec.writer_start):
                        # Live writer mid-flight — pending allowed.
                        continue
                    if not exists:
                        raise RetryRateIntegrityError(
                            f"orphan high-water sidecar at {fpath!r} "
                            f"(digest={digest}, pending intent from dead "
                            f"writer pid={rec.writer_pid}); refuse to start"
                        )
                    hwlock.reconcile(int(db_count_for))
                    hwlock.check(int(db_count_for))
                    known.add(digest)
                    continue
                if exists:
                    if db_count_for is None:
                        raise RetryRateIntegrityError(
                            f"orphan high-water sidecar at {fpath!r} "
                            f"(digest={digest}); refuse to start "
                            "(DB↔file cross-check)"
                        )
                    hwlock.reconcile(int(db_count_for))
                    hwlock.check(int(db_count_for))
                    known.add(digest)
                    continue
        except RetryRateIntegrityError:
            if not os.path.exists(fpath):
                # Lost-create cleanup raced with our lock acquire.
                continue
            raise
        raise RetryRateIntegrityError(
            f"orphan high-water sidecar at {fpath!r} "
            f"(digest={digest}); refuse to start "
            "(DB↔file cross-check)"
        )


def mac_high_water_for_verify(
    escrow_id: str, window_id: str, db_count: int
) -> int:
    """High-water bound into the stored MAC equals ``db_count`` (exact)."""
    check_high_water(escrow_id, window_id, db_count)
    return int(db_count)


# Test-only crash hooks (None = disabled).
_crash_hook: str | None = None


def set_hw_test_hooks(
    *,
    crash_after: str | None = None,
    hw_first: bool = False,
) -> None:
    """Test helper: inject crash points (``after_intent``, ``after_sql_before_confirm``)."""
    global _crash_hook
    del hw_first  # intent protocol replaces HW-first ordering
    _crash_hook = crash_after


def clear_hw_test_hooks() -> None:
    set_hw_test_hooks(crash_after=None)


def _maybe_crash(point: str) -> None:
    if _crash_hook == point:
        raise RetryRateIntegrityError(
            f"injected crash at {point} (test hook)"
        )


def hw_increment_hw_first() -> bool:
    """Deprecated no-op; intent protocol supersedes HW-first ordering."""
    return False


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
    return set_high_water(escrow_id, window_id, int(new_count))


def note_process_high_water(escrow_id: str, window_id: str, value: int) -> None:
    mk = _hw_map_key(escrow_id, window_id)
    with _hw_mem_guard:
        prev = _hw_mem.get(mk, 0)
        if int(value) > prev:
            _hw_mem[mk] = int(value)


def process_high_water(escrow_id: str, window_id: str) -> int:
    with _hw_mem_guard:
        return int(_hw_mem.get(_hw_map_key(escrow_id, window_id), 0))


class high_water_lock:
    """
    Exclusive flock on a sibling ``.lock`` file (not the data inode).

    Data file must already exist (``create_high_water`` / ``high_water_create``).
    Writes go through ``_atomic_write_hw_record`` (random temp, O_CREAT|O_EXCL|
    O_NOFOLLOW, fsync, rename, dir fsync). Pending intent is valid only while
    the recorded writer is alive; checkers that acquire this lock resolve or
    refuse stale/planted pending records.
    """

    def __init__(self, escrow_id: str, window_id: str) -> None:
        self.escrow_id = escrow_id
        self.window_id = window_id
        self._path = ""
        self._lock_path = ""
        self._fd = -1
        self._write_marker: str | None = None

    def __enter__(self):
        self._path = _hw_entry_path(self.escrow_id, self.window_id)
        if not os.path.exists(self._path):
            raise RetryRateIntegrityError(
                f"high-water sidecar missing at {self._path!r}; refuse "
                "(never create under lock / never restart from 0)"
            )
        _refuse_if_symlink(self._path, what="high-water sidecar")
        parent = os.path.dirname(self._path) or "."
        _refuse_if_symlink(parent, what="high-water parent directory")
        os.makedirs(parent, mode=0o700, exist_ok=True)
        self._lock_path = _hw_lock_path(self._path)
        _refuse_if_symlink(self._lock_path, what="high-water lock file")
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        self._fd = os.open(self._lock_path, flags, 0o600)
        if fcntl is not None:
            fcntl.flock(self._fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        _clear_write_active(self._write_marker)
        self._write_marker = None
        if self._fd >= 0:
            try:
                if fcntl is not None:
                    fcntl.flock(self._fd, fcntl.LOCK_UN)
            finally:
                os.close(self._fd)
                self._fd = -1

    def read(self) -> HighWaterRecord:
        return _read_hw_record(self._path)

    def get(self) -> int:
        return self.read().confirmed

    def clear_creating_intent(self) -> None:
        """Clear creating sentinel under the held lock (after DB INSERT)."""
        rec = self.read()
        if rec.intent == _HW_CREATING_INTENT:
            rec.intent = None
            rec.writer_pid = None
            rec.writer_start = None
            _atomic_write_hw_record(self._path, rec)

    def write_intent(self, target: int) -> HighWaterRecord:
        """Write intent=target before SQL commit (confirmed unchanged)."""
        rec = self.read()
        if rec.intent == _HW_CREATING_INTENT:
            # Creating sentinel left until after DB INSERT was visible;
            # clear it so a real increment intent can be recorded.
            rec.intent = None
            rec.writer_pid = None
            rec.writer_start = None
            _atomic_write_hw_record(self._path, rec)
            rec = self.read()
        if rec.intent is not None:
            raise RetryRateIntegrityError(
                "high-water intent already pending for "
                f"escrow_id={self.escrow_id!r} window_id={self.window_id!r}"
            )
        want = int(target)
        if want != rec.confirmed + 1:
            raise RetryRateIntegrityError(
                "high-water intent must be confirmed+1 for "
                f"escrow_id={self.escrow_id!r} window_id={self.window_id!r}: "
                f"confirmed={rec.confirmed} intent={want}"
            )
        pid, start = _current_writer_identity()
        rec.intent = want
        rec.writer_pid = pid
        rec.writer_start = start
        if self._write_marker is None:
            self._write_marker = _mark_write_active()
        _atomic_write_hw_record(self._path, rec)
        return rec

    def confirm(self, value: int) -> int:
        """After SQL commit: set confirmed=value and clear intent.

        Confirmed may advance only when ``intent == value``. A no-op
        confirm when already ``confirmed == value`` and intent is clear
        is allowed (idempotent recovery). Confirmed must never jump
        ahead of the DB without a matching intent record.
        """
        rec = self.read()
        want = int(value)
        if want < rec.confirmed:
            raise RetryRateIntegrityError(
                "high-water confirmed is monotonic; refuse lower value for "
                f"escrow_id={self.escrow_id!r} window_id={self.window_id!r}"
            )
        if rec.intent is None:
            if want != rec.confirmed:
                raise RetryRateIntegrityError(
                    "high-water confirm without pending intent for "
                    f"escrow_id={self.escrow_id!r} window_id={self.window_id!r}: "
                    f"confirmed={rec.confirmed} confirm={want}; refuse"
                )
            note_process_high_water(self.escrow_id, self.window_id, rec.confirmed)
            return rec.confirmed
        if rec.intent != want:
            raise RetryRateIntegrityError(
                "high-water confirm != pending intent for "
                f"escrow_id={self.escrow_id!r} window_id={self.window_id!r}: "
                f"intent={rec.intent} confirm={want}"
            )
        rec.confirmed = want
        rec.intent = None
        rec.writer_pid = None
        rec.writer_start = None
        _atomic_write_hw_record(self._path, rec)
        note_process_high_water(self.escrow_id, self.window_id, rec.confirmed)
        return rec.confirmed

    def set(self, value: int) -> int:
        return self.confirm(value)

    def reconcile(self, db_count: int) -> int:
        """Resolve pending intent against DB; then require exact equality.

        Live pending (writer alive with matching start token) is refused
        here — callers must not reconcile while another writer still owns
        the intent. Stale pending (dead/mismatched writer) is resolved
        against the committed row when unambiguous; otherwise refused.
        """
        rec = self.read()
        count = int(db_count)
        if rec.intent is None:
            if rec.confirmed != count:
                raise RetryRateIntegrityError(
                    "high-water confirmed != DB count at reconcile for "
                    f"escrow_id={self.escrow_id!r} window_id={self.window_id!r}: "
                    f"db_count={count} confirmed={rec.confirmed}; refuse"
                )
        elif _writer_still_alive(rec.writer_pid, rec.writer_start):
            # Exclusive flock held here. A concurrent live writer cannot also
            # hold it — so either this is our own uncommitted intent (same
            # process rollback) or a planted record claiming a live pid.
            same_writer = (
                int(rec.writer_pid or -1) == os.getpid()
                and int(rec.writer_start or -1)
                == int(_process_start_token(os.getpid()) or -2)
            )
            if same_writer and rec.intent == count and rec.confirmed == count - 1:
                # Our own post-SQL pre-confirm crash: advance confirmed.
                rec.confirmed = count
                rec.intent = None
                rec.writer_pid = None
                rec.writer_start = None
                _atomic_write_hw_record(self._path, rec)
            elif same_writer and (
                (
                    rec.intent == rec.confirmed + 1
                    and rec.confirmed == count
                )
                or (
                    rec.intent == _HW_CREATING_INTENT
                    and rec.confirmed == count
                )
            ):
                # Our own uncommitted intent — clear.
                rec.intent = None
                rec.writer_pid = None
                rec.writer_start = None
                _atomic_write_hw_record(self._path, rec)
            else:
                raise RetryRateIntegrityError(
                    "high-water pending intent claims live writer under "
                    "exclusive lock for "
                    f"escrow_id={self.escrow_id!r} "
                    f"window_id={self.window_id!r} pid={rec.writer_pid}; "
                    "refuse (stale/planted pending)"
                )
        elif rec.intent == _HW_CREATING_INTENT and rec.confirmed == count:
            # Dead writer; INSERT landed — clear creating sentinel.
            rec.intent = None
            rec.writer_pid = None
            rec.writer_start = None
            _atomic_write_hw_record(self._path, rec)
        elif rec.intent == count and rec.confirmed == count - 1:
            rec.confirmed = count
            rec.intent = None
            rec.writer_pid = None
            rec.writer_start = None
            _atomic_write_hw_record(self._path, rec)
        elif rec.intent == rec.confirmed + 1 and rec.confirmed == count:
            rec.intent = None
            rec.writer_pid = None
            rec.writer_start = None
            _atomic_write_hw_record(self._path, rec)
        else:
            raise RetryRateIntegrityError(
                "high-water intent/DB disagree at reconcile for "
                f"escrow_id={self.escrow_id!r} window_id={self.window_id!r}: "
                f"db_count={count} confirmed={rec.confirmed} "
                f"intent={rec.intent}; refuse "
                "(stale pending from dead writer)"
            )
        note_process_high_water(self.escrow_id, self.window_id, rec.confirmed)
        if rec.confirmed != count:
            raise RetryRateIntegrityError(
                "high-water != DB after intent reconcile for "
                f"escrow_id={self.escrow_id!r} window_id={self.window_id!r}: "
                f"db_count={count} confirmed={rec.confirmed}; refuse"
            )
        return rec.confirmed

    def check(self, db_count: int) -> int:
        """Exact equality of confirmed and DB; no skew tolerance."""
        rec = self.read()
        count = int(db_count)
        if rec.intent is not None:
            raise RetryRateIntegrityError(
                "high-water pending intent under check for "
                f"escrow_id={self.escrow_id!r} window_id={self.window_id!r}; "
                "reconcile first"
            )
        mk = _hw_map_key(self.escrow_id, self.window_id)
        with _hw_mem_guard:
            proc = _hw_mem.get(mk, 0)
            if count < proc:
                raise RetryRateIntegrityError(
                    "process high-water ahead of DB count for "
                    f"escrow_id={self.escrow_id!r} window_id={self.window_id!r}: "
                    f"db_count={count} process_hw={proc}; refuse "
                    "(live joint rollback)"
                )
            if rec.confirmed > proc:
                _hw_mem[mk] = rec.confirmed
            elif rec.confirmed < proc:
                raise RetryRateIntegrityError(
                    "process high-water ahead of counter file for "
                    f"escrow_id={self.escrow_id!r} window_id={self.window_id!r}: "
                    f"file={rec.confirmed} process_hw={proc}; refuse"
                )
        if count != rec.confirmed:
            raise RetryRateIntegrityError(
                "retry rate high-water sidecar != DB count for "
                f"escrow_id={self.escrow_id!r} window_id={self.window_id!r}: "
                f"db_count={count} sidecar_confirmed={rec.confirmed}; refuse "
                "(exact match required; possible rollback)"
            )
        return rec.confirmed


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
