"""
Release-verifier: the ONLY module that may call PayPal capture.

For an authorized escrow, the verifier evaluates the release predicate
against submitted evidence. Predicate passes → single-flight idempotent
capture. Predicate fails → REFUSED receipt, and capture is NEVER called.

Predicate types:
    Type D (delivery): sha256(delivered_bytes) == precommitted artifact_hash.
    Type A (acceptance): a SEPARATE acceptance key signs
        (escrow_id, artifact_hash, amount_cents).
        A worker's signature alone releases nothing. The signature is
        bound to the escrow id (replay on another escrow fails).

Fail-closed rules (adversary-required):
    - Ledger chain broken → refuse (no capture); the hold IS voided
      (P1-4b fix: a broken ledger must not leave money encumbered).
    - Escrow not in AUTHORIZED state → refuse.
    - Permit missing / revoked / expired at release time → refuse;
      the hold IS voided (admission recheck, P1 fix).
    - Predicate fails → REFUSED receipt, no capture call. The hold is
      voided; if the void times out the escrow goes CLEANUP_PENDING
      with the reservation still held (P1-4 fix).
    - AI dispute arbitration is advisory only: a model saying "looks good"
      is not evidence and cannot authorize capture.
    - Any PayPalTimeout → escrow goes UNKNOWN. A timed-out call has
      unknown provider state, so the verifier NEVER optimistically marks
      captured/failed — reconcile() queries provider truth first.

Idempotency: capture is keyed by
    idempotency_key = f"{escrow.permit_id}:{escrow.auth_id}:capture",
derived from the permit/claim ids so it is stable across retries.
Retries return the same capture; the money moves at most once.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from permit.ledger import Ledger, Receipt
from permit.permit import PermitStore

from .paypal_client import PayPalClient, PayPalTimeout, Capture


class PredicateType(str, Enum):
    D = "delivery_hash"
    A = "acceptance_signature"


@dataclass
class Escrow:
    escrow_id: str
    permit_id: str
    auth_id: str  # permit-level reservation id
    paypal_auth_id: str  # PayPal authorization id
    amount_cents: int
    merchant_id: str
    predicate_type: PredicateType
    artifact_hash: str  # precommitted at escrow creation
    state: str = "AUTHORIZED"  # AUTHORIZED -> CAPTURED | VOIDED | REFUSED
    # Indeterminate states (P1 fixes):
    #   UNKNOWN          - provider state unknown after a timeout or a
    #                      PENDING capture; reconcile() resolves it.
    #   CLEANUP_PENDING  - capture forbidden, void not yet confirmed;
    #                      retry_cleanup() resolves it.
    # Transitional states (lock rework): provider I/O in flight with the
    # verifier lock released; the owning call commits the outcome.
    #   CAPTURING, REFUSING, VOIDING.


@dataclass(frozen=True)
class Evidence:
    """What the worker submits to request release."""

    delivered_bytes: bytes | None = None  # Type D
    acceptance_signature: str | None = None  # Type A (hex HMAC)


@dataclass(frozen=True)
class VerifyResult:
    released: bool
    reason: str
    capture: Capture | None = None


@dataclass(frozen=True)
class ReconcileResult:
    """Outcome of reconcile(): resolving an UNKNOWN escrow."""

    resolved: bool
    outcome: str  # captured | voided | still_unknown | already_resolved
    capture: Capture | None = None
    receipt: Receipt | None = None


# Acceptance key (issues #35, #53): there is NO fallback key in library
# code. A known fallback key lets anyone forge Type A acceptances in a
# default deployment, so construction fails closed: the key must come
# from the caller or from PERMIT_ACCEPTANCE_KEY, be exactly 32 bytes,
# and must not be whitespace-only. Demo entry points opt in explicitly
# with --allow-demo-key / allow_demo_key=True (off by default). When that
# flag is set and no key is configured, a fresh random key is generated;
# if a durable demo_key_path is also given (server --db), the key is
# persisted as a regular file owned by the server euid with mode exactly
# 0600 (O_NOFOLLOW; create uses O_CREAT|O_EXCL|O_NOFOLLOW + fsync). A key
# that IS set (env or argument) but invalid always raises — the demo flag
# never papered over a bad configured key. If the durable ledger already
# has entries and the key file is missing, startup refuses rather than
# silently regenerating. Durable ledgers also bind an HMAC commitment of
# the key (SqliteLedger and DurableLedger); rotation refuses startup.
import errno as _errno
import os as _os
import secrets as _secrets
import stat as _stat
from pathlib import Path as _Path

MIN_ACCEPTANCE_KEY_BYTES = 32
ACCEPTANCE_KEY_COMMITMENT_MSG = b"permit-acceptance-key-v1"


def acceptance_key_commitment(key: bytes) -> str:
    """HMAC(key, 'permit-acceptance-key-v1') as hex — durable binding (REA N-b)."""
    return hmac.new(key, ACCEPTANCE_KEY_COMMITMENT_MSG, hashlib.sha256).hexdigest()


_SILENT_REBIND_MSG = (
    "acceptance key commitment missing on nonempty durable ledger: "
    "refusing silent rebind (use rebind_acceptance_key_commitment "
    "with the old key to migrate)"
)
_ROTATION_REFUSE_MSG = (
    "acceptance key commitment mismatch with durable ledger: "
    "rotating the acceptance key on an existing database refuses "
    "startup (use rebind_acceptance_key_commitment with the old key)"
)


def ensure_acceptance_key_commitment(db_ledger, key: bytes) -> None:
    """Bind ``key`` to a durable ledger on first use; refuse silent rebind.

    Only an *empty* store may bind a key for the first time. A nonempty store
    without a commitment refuses startup (no silent rebind). Concurrent
    first-boot uses ``try_bind_meta`` (INSERT OR IGNORE + re-read/compare)
    when available. Rotating the key without ``rebind_acceptance_key_commitment``
    refuses startup (REA seq 1854 / 1888 / round 5).
    """
    # Imported here to keep settlement.verifier free of a hard sqlite import
    # cycle at module load for callers that never touch durable mode.
    from permit.sqlite_ledger import ACCEPTANCE_KEY_COMMITMENT_META

    digest = acceptance_key_commitment(key)
    stored = db_ledger.get_meta(ACCEPTANCE_KEY_COMMITMENT_META)
    if stored is None:
        if len(db_ledger) > 0:
            raise ValueError(_SILENT_REBIND_MSG)
        try_bind = getattr(db_ledger, "try_bind_meta", None)
        if callable(try_bind):
            bound = try_bind(ACCEPTANCE_KEY_COMMITMENT_META, digest)
        else:
            db_ledger.set_meta(ACCEPTANCE_KEY_COMMITMENT_META, digest)
            bound = db_ledger.get_meta(ACCEPTANCE_KEY_COMMITMENT_META)
        if bound is None or not hmac.compare_digest(str(bound), digest):
            raise ValueError(_ROTATION_REFUSE_MSG)
        return
    if not hmac.compare_digest(stored, digest):
        raise ValueError(_ROTATION_REFUSE_MSG)


def rebind_acceptance_key_commitment(
    db_ledger,
    old_key: bytes | str,
    new_key: bytes | str,
) -> None:
    """One-time migration: verify ``old_key``, then bind exact-32 ``new_key``.

    Pre-exact-32 databases (e.g. bound at 19b62ce with ``token_hex(32)`` /
    64 UTF-8 bytes) are locked out after the exact-32 upgrade. Operators pass
    the OLD key (any non-empty length) plus a new exact-32-byte key. The OLD
    key is checked against the stored commitment; on match the commitment is
    replaced atomically via ``set_meta``.
    """
    from permit.sqlite_ledger import ACCEPTANCE_KEY_COMMITMENT_META

    old = _coerce_key(old_key)
    if old is None or old.strip() == b"":
        raise ValueError("old acceptance key is empty or whitespace-only")
    new = _coerce_key(new_key)
    if new is None:
        raise ValueError("new acceptance key is empty")
    new = _require_valid_key(new, what="new acceptance key")

    stored = db_ledger.get_meta(ACCEPTANCE_KEY_COMMITMENT_META)
    if stored is None:
        raise ValueError(
            "no acceptance key commitment to rebind on this durable ledger"
        )
    if not hmac.compare_digest(stored, acceptance_key_commitment(old)):
        raise ValueError(
            "old acceptance key does not match stored commitment; "
            "refusing rebind"
        )
    new_digest = acceptance_key_commitment(new)
    db_ledger.set_meta(ACCEPTANCE_KEY_COMMITMENT_META, new_digest)
    bound = db_ledger.get_meta(ACCEPTANCE_KEY_COMMITMENT_META)
    if bound is None or not hmac.compare_digest(str(bound), new_digest):
        raise RuntimeError("acceptance key rebind failed to persist")


def _bind_ledger_acceptance_key_commitment(ledger, key: bytes) -> None:
    """Enforce commitment unless the ledger is explicitly ephemeral (round 5).

    Fail-closed default: commitment is *required*. Only ledgers marked
    ``ephemeral_acceptance_key_commitment`` (in-memory ``Ledger``,
    ``:memory:`` SqliteLedger, DurableLedger without ``durable_dir``) skip.
    File-backed SqliteLedger cannot opt out (property with no setter).
    """
    ephemeral_prop = getattr(
        type(ledger), "ephemeral_acceptance_key_commitment", None
    )
    if isinstance(ephemeral_prop, property) and ephemeral_prop.fget is not None:
        ephemeral = bool(ephemeral_prop.fget(ledger))
    else:
        ephemeral = bool(
            getattr(ledger, "ephemeral_acceptance_key_commitment", False)
        )
    if ephemeral:
        return
    has_meta = hasattr(ledger, "get_meta") and hasattr(ledger, "set_meta")
    if not has_meta:
        raise ValueError(
            "durable ledger cannot store acceptance key commitment "
            "(get_meta/set_meta required; refusing silent skip)"
        )
    ensure_acceptance_key_commitment(ledger, key)


def _coerce_key(key: bytes | str | None) -> bytes | None:
    if key is None:
        return None
    return key.encode() if isinstance(key, str) else bytes(key)


def _require_valid_key(resolved: bytes, *, what: str = "acceptance key") -> bytes:
    """Reject empty, whitespace-only, and wrong-length keys (exactly 32 bytes)."""
    if resolved.strip() == b"":
        if len(resolved) == 0:
            raise ValueError(f"{what} is empty")
        raise ValueError(f"{what} is whitespace-only")
    if len(resolved) != MIN_ACCEPTANCE_KEY_BYTES:
        raise ValueError(
            f"{what} must be exactly {MIN_ACCEPTANCE_KEY_BYTES} bytes "
            f"(got {len(resolved)})"
        )
    return resolved


def _key_oserror(key_path: _Path, exc: OSError) -> ValueError:
    """Map any open/read OSError to a clean ValueError (no raw traceback)."""
    err = _errno.errorcode.get(exc.errno, str(exc.errno))
    if exc.errno in (
        getattr(_errno, "ELOOP", -1),
        getattr(_errno, "EMLINK", -1),
    ):
        return ValueError(
            f"demo acceptance key at {key_path} must not be a symlink"
        )
    if exc.errno == _errno.EPERM and "symlink" in (exc.strerror or "").lower():
        return ValueError(
            f"demo acceptance key at {key_path} must not be a symlink"
        )
    return ValueError(
        f"demo acceptance key at {key_path} cannot be opened "
        f"({err}: {exc.strerror})"
    )


def _clear_nonblock(fd: int) -> None:
    """Clear O_NONBLOCK so the subsequent read blocks normally on a regular file."""
    try:
        import fcntl as _fcntl
    except ImportError:  # pragma: no cover - non-POSIX
        return
    flags = _fcntl.fcntl(fd, _fcntl.F_GETFL)
    _fcntl.fcntl(fd, _fcntl.F_SETFL, flags & ~getattr(_os, "O_NONBLOCK", 0))


def _reject_foreign_demo_key_owner(key_path: _Path) -> None:
    """Refuse foreign-owned key paths before open.

    A 0600 file owned by another uid yields EACCES on open for a non-root
    euid, which would mask the ownership failure. Check ``lstat`` first so
    a real ``chown`` foreign-owner case reaches the owner check. Symlinks are
    rejected here too; ``O_NOFOLLOW`` remains on the subsequent open.
    """
    try:
        st = _os.lstat(key_path)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise _key_oserror(key_path, exc) from None
    if _stat.S_ISLNK(st.st_mode):
        raise ValueError(
            f"demo acceptance key at {key_path} must not be a symlink"
        )
    euid = _os.geteuid()
    if st.st_uid != euid:
        raise ValueError(
            f"demo acceptance key at {key_path} must be owned by euid "
            f"{euid} (got uid {st.st_uid})"
        )


def _open_demo_key_readonly(key_path: _Path) -> int:
    """Open ``key_path`` with O_NOFOLLOW|O_NONBLOCK; map OSError → ValueError.

    O_NONBLOCK keeps a FIFO (or other blocking special file) from hanging
    startup forever; the regular-file check then rejects non-files.
    Ownership is checked via ``lstat`` before open so foreign-owned 0600
    files fail the owner check instead of masking as EACCES.
    """
    _reject_foreign_demo_key_owner(key_path)
    flags = (
        _os.O_RDONLY
        | getattr(_os, "O_NOFOLLOW", 0)
        | getattr(_os, "O_NONBLOCK", 0)
    )
    try:
        return _os.open(key_path, flags)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise _key_oserror(key_path, exc) from None


def _require_demo_key_fstat(fd: int, key_path: _Path) -> int:
    """Require a regular file owned by euid with mode exactly 0600.

    Returns the verified mode (always 0o600 on success).
    """
    try:
        st = _os.fstat(fd)
    except OSError as exc:
        raise _key_oserror(key_path, exc) from None
    if not _stat.S_ISREG(st.st_mode):
        raise ValueError(
            f"demo acceptance key at {key_path} must be a regular file"
        )
    mode = _stat.S_IMODE(st.st_mode)
    if mode != 0o600:
        raise ValueError(
            f"demo acceptance key at {key_path} must have mode 0600 "
            f"(got {mode:04o})"
        )
    euid = _os.geteuid()
    if st.st_uid != euid:
        raise ValueError(
            f"demo acceptance key at {key_path} must be owned by euid "
            f"{euid} (got uid {st.st_uid})"
        )
    return mode


def _read_exact_demo_key(fd: int, key_path: _Path) -> bytes:
    """Read exactly MIN_ACCEPTANCE_KEY_BYTES and require EOF (no trailing)."""
    try:
        data = _os.read(fd, MIN_ACCEPTANCE_KEY_BYTES + 1)
    except OSError as exc:
        raise _key_oserror(key_path, exc) from None
    if len(data) < MIN_ACCEPTANCE_KEY_BYTES:
        raise ValueError(
            f"demo acceptance key at {key_path} is truncated "
            f"({len(data)} bytes, need {MIN_ACCEPTANCE_KEY_BYTES})"
        )
    if len(data) > MIN_ACCEPTANCE_KEY_BYTES:
        raise ValueError(
            f"demo acceptance key at {key_path} has trailing bytes after "
            f"{MIN_ACCEPTANCE_KEY_BYTES}-byte key"
        )
    return _require_valid_key(data, what=f"demo acceptance key at {key_path}")


def _fsync_dir(dir_path: _Path) -> None:
    try:
        dir_fd = _os.open(
            dir_path, _os.O_RDONLY | getattr(_os, "O_DIRECTORY", 0)
        )
    except OSError as exc:
        raise _key_oserror(dir_path, exc) from None
    try:
        _os.fsync(dir_fd)
    finally:
        _os.close(dir_fd)


def load_or_create_demo_key(
    path: str | _os.PathLike[str],
    *,
    db_nonempty: bool = False,
) -> tuple[bytes, int]:
    """Load or create a durable demo acceptance key file.

    Security posture (REA #54 / seq 1690 + seq 1801):
    - Open existing files with ``O_NOFOLLOW|O_NONBLOCK``; refuse symlinks and
      non-regular files (FIFOs must not hang startup).
    - Map every open/read ``OSError`` (including EACCES) to ``ValueError``.
    - Require a regular file owned by the process euid with mode exactly 0600.
    - Clear O_NONBLOCK, then read exactly 32 bytes and require EOF.
    - Create with ``O_CREAT|O_EXCL|O_NOFOLLOW`` at 0600, then ``fsync`` the
      file and its directory.
    - If ``db_nonempty`` and the key file is missing, refuse to regenerate.

    Returns ``(key_bytes, verified_mode)`` so callers can log the mode only
    after it has been checked — and without opening the file a second time.
    """
    key_path = _Path(path)
    try:
        fd = _open_demo_key_readonly(key_path)
    except FileNotFoundError:
        if db_nonempty:
            raise ValueError(
                f"demo acceptance key missing at {key_path} but the durable "
                "ledger has entries; refusing to regenerate (issue #53)"
            )
        return _create_demo_key_file(key_path)

    try:
        # Reject FIFO/device/etc. before clearing NONBLOCK / reading.
        mode = _require_demo_key_fstat(fd, key_path)
        _clear_nonblock(fd)
        key = _read_exact_demo_key(fd, key_path)
        return key, mode
    finally:
        _os.close(fd)


def _create_demo_key_file(key_path: _Path) -> tuple[bytes, int]:
    key = _secrets.token_bytes(MIN_ACCEPTANCE_KEY_BYTES)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    flags = (
        _os.O_WRONLY
        | _os.O_CREAT
        | _os.O_EXCL
        | getattr(_os, "O_NOFOLLOW", 0)
    )
    try:
        fd = _os.open(key_path, flags, 0o600)
    except OSError as exc:
        raise _key_oserror(key_path, exc) from None
    try:
        try:
            _os.write(fd, key)
            # umask may have cleared bits from the create mode; force 0600.
            _os.fchmod(fd, 0o600)
            _os.fsync(fd)
        except OSError as exc:
            raise _key_oserror(key_path, exc) from None
        mode = _require_demo_key_fstat(fd, key_path)
    finally:
        _os.close(fd)
    _fsync_dir(key_path.parent)
    return key, mode


def resolve_acceptance_key(
    key: bytes | str | None = None,
    *,
    allow_demo_key: bool = False,
    demo_key_path: str | _os.PathLike[str] | None = None,
    demo_key_db_nonempty: bool = False,
) -> bytes:
    """Resolve and validate the acceptance key, failing closed.

    Order: explicit ``key`` argument, then PERMIT_ACCEPTANCE_KEY.
    A key that is set (argument or env) but empty, whitespace-only, or
    short (under 32 bytes) always raises ValueError — even when
    ``allow_demo_key`` is set (#53).

    When no key is configured at all and ``allow_demo_key`` is set:
    if ``demo_key_path`` is given, load or create a 0600 key file there
    (see ``load_or_create_demo_key``); otherwise generate a fresh per-call
    random key (ephemeral demos).
    """
    if key is not None:
        resolved = _coerce_key(key)
        if resolved is None:
            raise ValueError("acceptance key is empty")
        return _require_valid_key(resolved)

    if "PERMIT_ACCEPTANCE_KEY" in _os.environ:
        resolved = _coerce_key(_os.environ.get("PERMIT_ACCEPTANCE_KEY"))
        return _require_valid_key(resolved if resolved is not None else b"")

    if allow_demo_key:
        if demo_key_path is not None:
            key_bytes, _mode = load_or_create_demo_key(
                demo_key_path, db_nonempty=demo_key_db_nonempty
            )
            return key_bytes
        return _secrets.token_bytes(MIN_ACCEPTANCE_KEY_BYTES)

    raise ValueError(
        "acceptance key missing, empty, whitespace-only, or not exactly "
        f"{MIN_ACCEPTANCE_KEY_BYTES} bytes: pass acceptance_key or set "
        "PERMIT_ACCEPTANCE_KEY (fail closed, issues #35/#53)"
    )


def sign_acceptance(
    escrow_id: str, artifact_hash: str, amount_cents: int, key: bytes | str
) -> str:
    """What the counterparty (acceptance key holder) does off-camera.

    The key is required: there is no module-level key to fall back to.
    Empty, whitespace-only, and wrong-length keys are rejected (#53 / seq 1888).
    """
    resolved = _coerce_key(key)
    if resolved is None:
        raise ValueError(
            "sign_acceptance requires a key of exactly 32 bytes"
        )
    resolved = _require_valid_key(resolved, what="sign_acceptance key")
    msg = f"{escrow_id}|{artifact_hash}|{amount_cents}".encode()
    return hmac.new(resolved, msg, hashlib.sha256).hexdigest()


class ReleaseVerifier:
    def __init__(
        self,
        paypal: PayPalClient,
        permits: PermitStore,
        ledger: Ledger | None = None,
        *,
        acceptance_key: bytes | str | None = None,
        allow_demo_key: bool = False,
        demo_key_path: str | _os.PathLike[str] | None = None,
        demo_key_db_nonempty: bool = False,
    ):
        # Fail closed at construction (issues #35/#53): no usable
        # acceptance key, no verifier. Demo callers pass
        # allow_demo_key=True only when no key is configured.
        self._acceptance_key = resolve_acceptance_key(
            acceptance_key,
            allow_demo_key=allow_demo_key,
            demo_key_path=demo_key_path,
            demo_key_db_nonempty=demo_key_db_nonempty,
        )
        self._demo_key_path = (
            str(demo_key_path) if demo_key_path is not None else None
        )
        self.paypal = paypal
        self.permits = permits
        # NOTE: explicit None check — an empty Ledger is falsy via __len__.
        self.ledger = ledger if ledger is not None else Ledger()
        # Durable ledgers (SqliteLedger --db, DurableLedger / harness) must
        # bind/refuse the acceptance-key commitment; never skip silently.
        _bind_ledger_acceptance_key_commitment(
            self.ledger, self._acceptance_key
        )
        self._escrows: dict[str, Escrow] = {}
        self._lock = threading.Lock()

    def sign_acceptance(
        self, escrow_id: str, artifact_hash: str, amount_cents: int
    ) -> str:
        """Sign with this verifier's acceptance key.

        Demo/test convenience standing in for the off-camera counterparty
        who holds the key in a real deployment.
        """
        return sign_acceptance(
            escrow_id, artifact_hash, amount_cents, self._acceptance_key
        )

    def register(self, escrow: Escrow) -> Receipt:
        """Register an escrow hold. Returns the AUTHORIZED receipt."""
        with self._lock:
            self._escrows[escrow.escrow_id] = escrow
        return self.ledger.append(
            "AUTHORIZED",
            {
                "escrow_id": escrow.escrow_id,
                "permit_id": escrow.permit_id,
                "paypal_auth_id": escrow.paypal_auth_id,
                "amount_cents": escrow.amount_cents,
                "predicate": escrow.predicate_type.value,
                "artifact_hash": escrow.artifact_hash,
            },
        )

    def get_escrow(self, escrow_id: str) -> Escrow | None:
        """Read-only lookup of one escrow by id."""
        with self._lock:
            return self._escrows.get(escrow_id)

    def escrows_snapshot(self) -> list[dict]:
        """
        Read-only projection of all escrows for dashboards and operators.
        Plain dicts, no live references — safe to serialize.
        """
        with self._lock:
            escrows = list(self._escrows.values())
        return [{
            "escrow_id": e.escrow_id,
            "permit_id": e.permit_id,
            "amount_cents": e.amount_cents,
            "merchant_id": e.merchant_id,
            "predicate": e.predicate_type.value,
            "state": e.state,
            "paypal_auth_id": e.paypal_auth_id,
        } for e in escrows]

    @staticmethod
    def _capture_key(escrow: Escrow) -> str:
        """
        Idempotency key derived from the permit/claim ids — stable across
        retries and process restarts, unlike the old escrow-id key.
        """
        return f"{escrow.permit_id}:{escrow.auth_id}:capture"

    def _original_refusal_id(self, escrow_id: str) -> str | None:
        """Hash of the first terminal denial for this escrow (original REFUSED,
        else escrow-level VOIDED). Retry denials reference this id."""
        original_refused: str | None = None
        original_voided: str | None = None
        for r in self.ledger.receipts():
            if r.payload.get("escrow_id") != escrow_id:
                continue
            if r.event_type == "REFUSED":
                reason = r.payload.get("reason", "")
                if isinstance(reason, str) and reason.startswith("already_"):
                    continue
                if original_refused is None:
                    original_refused = r.hash
            elif r.event_type == "VOIDED" and original_voided is None:
                original_voided = r.hash
        return original_refused or original_voided

    def _append_retry_denial(self, escrow_id: str, reason: str) -> Receipt:
        """Review F6: unique denial receipt for a refused retry; never captures."""
        original = self._original_refusal_id(escrow_id)
        return self.ledger.append(
            "REFUSED",
            {
                "escrow_id": escrow_id,
                "reason": reason,
                "receipt_id": f"den_{uuid.uuid4().hex}",
                "original_refusal_id": original,
            },
        )

    def _predicate_passes(self, escrow: Escrow, evidence: Evidence) -> tuple[bool, str]:
        if escrow.predicate_type is PredicateType.D:
            if evidence.delivered_bytes is None:
                return False, "missing_delivered_bytes"
            digest = hashlib.sha256(evidence.delivered_bytes).hexdigest()
            if not hmac.compare_digest(digest, escrow.artifact_hash):
                return False, "hash_mismatch"
            return True, "hash_match"

        if escrow.predicate_type is PredicateType.A:
            if evidence.acceptance_signature is None:
                return False, "missing_acceptance_signature"
            expected = sign_acceptance(
                escrow.escrow_id,
                escrow.artifact_hash,
                escrow.amount_cents,
                self._acceptance_key,
            )
            if not hmac.compare_digest(evidence.acceptance_signature, expected):
                return False, "invalid_acceptance_signature"
            return True, "acceptance_valid"

        return False, "unknown_predicate"

    # Transitional escrow states for the lock-free I/O window. These are
    # never persisted and never returned to callers as terminal outcomes:
    #   CAPTURING — Phase 1 admitted the release; provider capture in flight.
    #   REFUSING  — Phase 1 refused the release; hold void in flight.
    # While transitional, the escrow is single-flight: concurrent
    # verify_and_capture calls short-circuit instead of double-driving.

    def _void_hold_outside_lock(self, paypal_auth_id: str) -> bool:
        """
        Best-effort hold void with NO verifier lock held. Returns True if
        the void was accepted, False on PayPalTimeout (outcome unknown —
        the commit phase marks CLEANUP_PENDING, fail closed).
        """
        try:
            self.paypal.void(paypal_auth_id)
            return True
        except PayPalTimeout:
            return False

    def verify_and_capture(self, escrow_id: str, evidence: Evidence) -> VerifyResult:
        """
        Single-flight, fail-closed release (see _verify_and_capture).

        Once the late admission recheck takes settlement_gate, the gate stays
        held until the outcome is committed (CAPTURED receipt, permit
        settlement). An E-STOP is therefore receipted either before the
        recheck (capture refused) or after CAPTURED, never in between (#22).
        The gate is an RLock; gate_hold re-enters it and releases it when this
        call returns or raises.
        """
        with contextlib.ExitStack() as gate_hold:
            return self._verify_and_capture(escrow_id, evidence, gate_hold)

    def _verify_and_capture(
        self, escrow_id: str, evidence: Evidence, gate_hold: contextlib.ExitStack
    ) -> VerifyResult:
        """
        Single-flight, fail-closed release. The ONLY path to capture.

        Three phases:
          1. Decide under the verifier lock (no provider I/O): lookups,
             terminal-state short-circuits, admission recheck, chain
             verify, predicate check → CAPTURING or REFUSING.
          2. Provider I/O with the lock RELEASED: capture or void. The
             settlement gate still serializes the late admission recheck
             against e-stop/revocation, preserving the e-stop atomicity
             guarantee ("E-STOP is either before the recheck or after
             CAPTURED").
          3. Commit under the lock (no provider I/O): state transition,
             receipts, permit settlement.

        One slow PayPal call no longer stalls every escrow operation:
        void(), reconcile(), register(), and other captures proceed
        while the I/O is in flight.
        """
        # ---- Phase 1: decide. Verifier lock held, no provider I/O. ----
        with self._lock:
            escrow = self._escrows.get(escrow_id)
            if escrow is None:
                self.ledger.append(
                    "REFUSED", {"escrow_id": escrow_id, "reason": "unknown_escrow"}
                )
                return VerifyResult(False, "unknown_escrow")

            # Already resolved → return the recorded outcome, never re-capture.
            if escrow.state == "CAPTURED":
                return VerifyResult(True, "already_captured")
            if escrow.state in ("VOIDED", "REFUSED"):
                # Review F6: every refused retry writes a unique denial receipt
                # referencing the original refusal; money is never captured.
                reason = f"already_{escrow.state.lower()}"
                self._append_retry_denial(escrow_id, reason)
                return VerifyResult(False, reason)
            # Indeterminate states need an explicit operator step first:
            # reconcile() for UNKNOWN, retry_cleanup() for CLEANUP_PENDING.
            if escrow.state == "UNKNOWN":
                return VerifyResult(False, "unknown_reconcile_first")
            if escrow.state == "CLEANUP_PENDING":
                return VerifyResult(False, "cleanup_pending")
            # Transitional: another thread is already driving provider I/O
            # for this escrow. Single-flight — do not double-drive.
            if escrow.state in ("CAPTURING", "REFUSING", "VOIDING"):
                return VerifyResult(False, "release_in_flight")

            # Admission recheck, chain verify, predicate — all local.
            admit_reason = self.permits.release_block_reason(escrow.permit_id)
            refuse_reason: str | None = None
            result_reason: str | None = None
            refused_state = "VOIDED"  # admission/chain refusals unwind to VOIDED
            if admit_reason is not None:
                refuse_reason = admit_reason
                result_reason = admit_reason
            else:
                ok, chain_reason = self.ledger.verify_chain()
                if not ok:
                    refuse_reason = f"broken_chain:{chain_reason}"
                    result_reason = "broken_chain"
                else:
                    passes, pred_reason = self._predicate_passes(escrow, evidence)
                    if not passes:
                        refuse_reason = f"predicate:{pred_reason}"
                        result_reason = f"predicate:{pred_reason}"
                        refused_state = "REFUSED"  # predicate refusals mark REFUSED

            if refuse_reason is not None:
                self.ledger.append(
                    "REFUSED", {"escrow_id": escrow_id, "reason": refuse_reason}
                )
                escrow.state = "REFUSING"
            else:
                escrow.state = "CAPTURING"
            # Snapshot for the lock-free phases; the escrow row is not
            # touched again until the commit phase.
            paypal_auth_id = escrow.paypal_auth_id
            permit_id = escrow.permit_id
            auth_id = escrow.auth_id
            amount_cents = escrow.amount_cents
            capture_key = self._capture_key(escrow)

        # ---- Phase 2: provider I/O. Verifier lock RELEASED. ----
        # outcome is one of:
        #   ("refused", void_ok)
        #   ("late_refused", late_reason, void_ok)
        #   ("captured", capture)
        #   ("unknown", receipt_reason, result_reason, capture_or_None)
        #   ("failed", capture, void_ok)
        if refuse_reason is not None:
            outcome = ("refused", self._void_hold_outside_lock(paypal_auth_id))
        else:
            with self.permits.settlement_gate:
                # Keep the gate through Phase 3 so the commit cannot be
                # overtaken by an E-STOP receipt (lock order: gate -> verifier
                # -> permit, same as estop_cascade's gate -> permit).
                gate_hold.enter_context(self.permits.settlement_gate)
                late_reason = self.permits.release_block_reason(permit_id)
                if late_reason is not None:
                    # Refuse: void the hold (I/O, no verifier lock).
                    self.ledger.append(
                        "REFUSED", {"escrow_id": escrow_id, "reason": late_reason}
                    )
                    outcome = (
                        "late_refused",
                        late_reason,
                        self._void_hold_outside_lock(paypal_auth_id),
                    )
                else:
                    try:
                        capture = self.paypal.capture(
                            paypal_auth_id,
                            amount_cents,
                            idempotency_key=capture_key,
                        )
                    except PayPalTimeout:
                        # Response lost: the capture may or may not have
                        # applied. NEVER guess — UNKNOWN; reconcile()
                        # queries provider truth before anything else happens.
                        outcome = (
                            "unknown",
                            "capture_timeout",
                            "unknown_after_timeout",
                            None,
                        )
                    else:
                        if capture.status == "PENDING":
                            # Provider accepted but not completed: obligation
                            # retained (reservation held) until reconcile()
                            # sees completed provider truth.
                            outcome = (
                                "unknown",
                                "capture_pending",
                                "capture_pending",
                                capture,
                            )
                        elif capture.status != "COMPLETED":
                            # Provider refused the capture: unwind fail-closed.
                            self.ledger.append(
                                "FAILED",
                                {
                                    "escrow_id": escrow_id,
                                    "paypal_capture_id": capture.capture_id,
                                    "status": capture.status,
                                },
                            )
                            outcome = (
                                "failed",
                                capture,
                                self._void_hold_outside_lock(paypal_auth_id),
                            )
                        else:
                            outcome = ("captured", capture)

        # ---- Phase 3: commit. Verifier lock held, no provider I/O. Still
        # under settlement_gate when the release was admitted (Phase 2). ----
        with self._lock:
            escrow = self._escrows.get(escrow_id)
            # The escrow cannot vanish mid-flight (only this method drives
            # transitional states); a broken invariant fails closed.
            if escrow is None or escrow.state not in ("CAPTURING", "REFUSING"):
                return VerifyResult(False, "release_in_flight")

            kind = outcome[0]
            if kind in ("refused", "late_refused"):
                if kind == "refused":
                    _, void_ok = outcome
                    reason = result_reason
                    final_state = refused_state
                else:
                    _, reason, void_ok = outcome
                    final_state = "VOIDED"
                if void_ok:
                    escrow.state = final_state
                    if self.permits.get(permit_id) is not None:
                        # settle_void appends the VOIDED receipt (shared ledger).
                        self.permits.settle_void(permit_id, auth_id)
                else:
                    # The void may or may not have applied: cleanup is
                    # pending, retry_cleanup() finishes it.
                    escrow.state = "CLEANUP_PENDING"
                    self.ledger.append(
                        "CLEANUP_PENDING",
                        {
                            "escrow_id": escrow_id,
                            "reason": reason,
                            "detail": "void_timeout",
                        },
                    )
                return VerifyResult(False, reason)

            if kind == "captured":
                _, capture = outcome
                escrow.state = "CAPTURED"
                self.permits.settle_capture(permit_id, auth_id)
                self.ledger.append(
                    "CAPTURED",
                    {
                        "escrow_id": escrow_id,
                        "paypal_capture_id": capture.capture_id,
                        "amount_cents": amount_cents,
                    },
                )
                return VerifyResult(True, "released", capture)

            if kind == "unknown":
                _, receipt_reason, result_reason, capture = outcome
                escrow.state = "UNKNOWN"
                self.ledger.append(
                    "UNKNOWN",
                    {
                        "escrow_id": escrow_id,
                        "reason": receipt_reason,
                        **(
                            {"paypal_capture_id": capture.capture_id}
                            if capture is not None
                            else {}
                        ),
                        "idempotency_key": capture_key,
                    },
                )
                return VerifyResult(False, result_reason)

            # kind == "failed"
            _, capture, void_ok = outcome
            if void_ok:
                escrow.state = "VOIDED"
                self.permits.settle_void(permit_id, auth_id)
            else:
                escrow.state = "CLEANUP_PENDING"
                self.ledger.append(
                    "CLEANUP_PENDING",
                    {
                        "escrow_id": escrow_id,
                        "reason": "capture_failed",
                        "detail": "void_timeout",
                    },
                )

    def reconcile(self, escrow_id: str) -> ReconcileResult:
        """
        Resolve an UNKNOWN escrow against provider truth. The operator
        calls this after a capture timeout or a PENDING capture; the demo
        calls it on the timeout beat.

        Only UNKNOWN escrows are eligible — anything else returns
        already_resolved with NO side effects (idempotent).

        Rules:
          - get_authorization raises PayPalTimeout → stay UNKNOWN
            ("still_unknown", retryable).
          - Truth CAPTURED, or a capture recorded under the escrow's
            idempotency key → record the capture even if the permit is
            revoked/expired (a completed capture can't be voided).
          - Otherwise (AUTHORIZED/no capture, VOIDED, DENIED, FAILED) →
            fail closed: attempt void; void success → VOIDED; void
            timeout → stay UNKNOWN ("still_unknown").
        """
        with self._lock:
            escrow = self._escrows.get(escrow_id)
            if escrow is None or escrow.state != "UNKNOWN":
                return ReconcileResult(False, "already_resolved")

            try:
                truth = self.paypal.get_authorization(escrow.paypal_auth_id)
            except PayPalTimeout:
                return ReconcileResult(False, "still_unknown")

            key = self._capture_key(escrow)
            # Mock-only provider-side record: the sandbox client has no
            # .captures attribute; getattr keeps the interface uniform.
            recorded = getattr(self.paypal, "captures", {}) or {}

            if truth.status == "CAPTURED" or key in recorded:
                # The money moved. Record truth — even against a dead
                # permit, a completed capture cannot be voided.
                escrow.state = "CAPTURED"
                self.permits.settle_capture(escrow.permit_id, escrow.auth_id)
                capture = recorded.get(key)
                receipt = self.ledger.append(
                    "CAPTURED",
                    {
                        "escrow_id": escrow_id,
                        "paypal_capture_id": (
                            capture.capture_id if capture else truth.auth_id
                        ),
                        "amount_cents": escrow.amount_cents,
                        "reconciled": True,
                    },
                )
                return ReconcileResult(True, "captured", capture, receipt)

            # Fail closed: nothing captured, so unwind whatever may be live.
            try:
                self.paypal.void(escrow.paypal_auth_id)
            except PayPalTimeout:
                return ReconcileResult(False, "still_unknown")
            escrow.state = "VOIDED"
            receipt = self.permits.settle_void(escrow.permit_id, escrow.auth_id)
            return ReconcileResult(True, "voided", receipt=receipt)

    def retry_cleanup(self, escrow_id: str) -> bool:
        """
        Retry the void for a CLEANUP_PENDING escrow. True on success
        (escrow VOIDED, reservation released); False on PayPalTimeout
        (stays pending, retryable). No-ops on any other state.
        """
        with self._lock:
            escrow = self._escrows.get(escrow_id)
            if escrow is None or escrow.state != "CLEANUP_PENDING":
                return False
            try:
                self.paypal.void(escrow.paypal_auth_id)
            except PayPalTimeout:
                return False
            escrow.state = "VOIDED"
            self.permits.settle_void(escrow.permit_id, escrow.auth_id)
            return True

    def void(self, escrow_id: str) -> bool:
        """
        Void an in-flight authorization (e-stop path). The provider void
        runs with the verifier lock released; the escrow is marked
        VOIDING (transitional) for the flight so concurrent releases
        short-circuit instead of double-driving.
        """
        with self._lock:
            escrow = self._escrows.get(escrow_id)
            if escrow is None or escrow.state != "AUTHORIZED":
                return False
            escrow.state = "VOIDING"
            paypal_auth_id = escrow.paypal_auth_id
            permit_id = escrow.permit_id
            auth_id = escrow.auth_id
        try:
            self.paypal.void(paypal_auth_id)
        except PayPalTimeout:
            # Outcome unknown; revert to AUTHORIZED so the void can be
            # retried (matches the pre-rework contract: the timeout
            # propagates and the escrow stays voidable).
            with self._lock:
                escrow = self._escrows.get(escrow_id)
                if escrow is not None and escrow.state == "VOIDING":
                    escrow.state = "AUTHORIZED"
            raise
        with self._lock:
            escrow = self._escrows.get(escrow_id)
            if escrow is None or escrow.state != "VOIDING":
                return False
            escrow.state = "VOIDED"
            self.permits.settle_void(permit_id, auth_id)
            self.ledger.append("VOIDED", {"escrow_id": escrow_id})
            return True
