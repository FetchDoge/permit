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

import hashlib
import hmac
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable

from permit.ledger import Ledger, Receipt
from permit.permit import PermitStore
from permit.retry_rate_store import (
    InMemoryRetryRateStore,
    RetryRateIntegrityError,
    RetryRateRow,
    create_high_water,
    high_water_lock,
    publish_rate_mac_to_anchor,
    rate_limited_mac,
    require_retry_rate_mac_key,
    verify_rate_limited_mac,
)

from .paypal_client import PayPalClient, PayPalTimeout, Capture

# REA F7: per-escrow retry denial rate limit.
#   N = max individual F6 denial receipts per escrow per window
#   W = window length (seconds; wall / injectable non-rewinding clock)
# Decisions do NOT trust the side row for allow/limit: inside the same
# BEGIN IMMEDIATE, ``individual`` is an indexed COUNT of chain already_*
# denial receipts for (escrow, window_id). The side table holds window_id,
# window_start, and an HMAC rate_mac over rate_limited
# (HMAC-SHA256(key, prev_mac || denial || escrow || window || count || hw)),
# key + monotonic high-water sidecar outside the DB — loss bound 0, no
# checkpoint/K. Threat model: DB write without the key+sidecar is in
# scope; attacker with DB + sidecar + key is out of scope. At most one
# OPEN window per escrow (UNIQUE partial index). Process memory is never
# the authority. window_start comes from the row and is NOT reset on
# restart; a window closes when any writer sees now >= start + W.
# Tallies are idempotent on (escrow_id, window_id). Disagreement →
# RetryRateIntegrityError (chain wins; no anomaly receipt). Log growth
# ≤ N+1 per window.
DEFAULT_RETRY_RATE_LIMIT_N = 100
DEFAULT_RETRY_RATE_LIMIT_W = 60.0  # seconds


# Re-exported from permit.retry_rate_store for call-site / test compat.
# Policy: on disagreement, raise RetryRateIntegrityError (chain wins;
# no anomaly receipt).


class PredicateType(str, Enum):
    D = "delivery_hash"
    A = "acceptance_signature"


@dataclass
class _RetryRateWindow:
    """Snapshot of a side-store window (not an authoritative cache)."""

    window_id: str
    window_start: float  # clock seconds from the side row
    individual: int = 0
    rate_limited: int = 0
    last_already_reason: str = ""
    tally_flushed: bool = False


def _non_rewinding_clock(underlying: Callable[[], float]) -> Callable[[], float]:
    """Wrap a clock so observed time never steps backwards (clamp)."""
    last: list[float | None] = [None]

    def _clock() -> float:
        t = float(underlying())
        prev = last[0]
        if prev is not None and t < prev:
            return prev
        last[0] = t
        return t

    return _clock


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


# Acceptance key: the counterparty's key in production. Defaults to the
# hardcoded demo key ONLY when PERMIT_ACCEPTANCE_KEY is unset, and says
# so loudly — a payment authority layer must never silently run on a
# demo key. (Audit item 12: env-provided keys now; KMS/HSM story next.)
import os as _os

DEMO_ACCEPTANCE_KEY = b"demo-acceptance-key-NOT-FOR-PRODUCTION"
ACCEPTANCE_KEY = _os.environ.get("PERMIT_ACCEPTANCE_KEY", "").encode() or DEMO_ACCEPTANCE_KEY
if ACCEPTANCE_KEY is DEMO_ACCEPTANCE_KEY:
    import warnings as _warnings
    _warnings.warn(
        "PERMIT_ACCEPTANCE_KEY unset: running on the demo acceptance key. "
        "Set PERMIT_ACCEPTANCE_KEY in any real deployment.",
        RuntimeWarning,
        stacklevel=2,
    )


def sign_acceptance(escrow_id: str, artifact_hash: str, amount_cents: int) -> str:
    """What the counterparty (acceptance key holder) does off-camera."""
    msg = f"{escrow_id}|{artifact_hash}|{amount_cents}".encode()
    return hmac.new(ACCEPTANCE_KEY, msg, hashlib.sha256).hexdigest()


class ReleaseVerifier:
    def __init__(
        self,
        paypal: PayPalClient,
        permits: PermitStore,
        ledger: Ledger | None = None,
        *,
        retry_rate_limit_n: int = DEFAULT_RETRY_RATE_LIMIT_N,
        retry_rate_limit_w: float = DEFAULT_RETRY_RATE_LIMIT_W,
        clock: Callable[[], float] | None = None,
        # Deprecated alias kept for call-site compat; prefer `clock`.
        monotonic: Callable[[], float] | None = None,
        retry_rate_store=None,
    ):
        self.paypal = paypal
        self.permits = permits
        # NOTE: explicit None check — an empty Ledger is falsy via __len__.
        self.ledger = ledger if ledger is not None else Ledger()
        # Fail before any decision if the MAC key is missing/empty/short.
        # SqliteLedger also validates in its constructor; this covers the
        # in-memory ledger path and double-checks the sqlite path.
        require_retry_rate_mac_key()
        self._escrows: dict[str, Escrow] = {}
        self._lock = threading.Lock()
        if retry_rate_limit_n < 0:
            raise ValueError("retry_rate_limit_n must be >= 0")
        if retry_rate_limit_w <= 0:
            raise ValueError("retry_rate_limit_w must be > 0")
        self.retry_rate_limit_n = retry_rate_limit_n
        self.retry_rate_limit_w = retry_rate_limit_w
        # Default: wall clock so window_start survives restart and is
        # comparable across processes. Wrapped so a step backwards cannot
        # reopen a window within one process.
        raw_clock = clock or monotonic or time.time
        self._clock = _non_rewinding_clock(raw_clock)
        self._original_refusal_by_escrow: dict[str, str] = {}
        # Soft mirror of open windows for tests / flush targets only —
        # never the authority for counts (chain COUNT + MAC-protected side).
        self._retry_rate_windows: dict[str, _RetryRateWindow] = {}
        # (escrow_id, window_id) -> latest already_* denial hash (HMAC input).
        self._latest_denial_by_window: dict[tuple[str, str], str] = {}
        # Process-local chain denial counts (in-memory ledger); rebuilt on
        # startup, incremented on each denial — avoids O(n) log scans (bar 3).
        self._denial_count_by_window: dict[tuple[str, str], int] = {}
        self._rate_locks: dict[str, threading.Lock] = {}
        self._rate_locks_guard = threading.Lock()
        # Terminal escrow_id -> already_refused/already_voided. Written when
        # an escrow first becomes REFUSED/VOIDED; read lock-free so a flood
        # of retries on one escrow never contends on self._lock.
        self._terminal_reasons: dict[str, str] = {}
        # Side store outside the hash chain (Sqlite table when available).
        if retry_rate_store is not None:
            self._rate_store = retry_rate_store
        else:
            store = getattr(self.ledger, "retry_rate_store", None)
            self._rate_store = (
                store if store is not None else InMemoryRetryRateStore()
            )
        self._rebuild_retry_state()

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

    def _remember_original_refusal(self, escrow_id: str, receipt_hash: str) -> None:
        """Index the first terminal denial for escrow_id (O(1) retry lookup)."""
        if escrow_id not in self._original_refusal_by_escrow:
            self._original_refusal_by_escrow[escrow_id] = receipt_hash

    def _rate_lock_for(self, escrow_id: str) -> threading.Lock:
        with self._rate_locks_guard:
            lock = self._rate_locks.get(escrow_id)
            if lock is None:
                lock = threading.Lock()
                self._rate_locks[escrow_id] = lock
            return lock

    def _latest_denial_hash(self, escrow_id: str, window_id: str) -> str | None:
        """Hash of the window's latest already_* denial (HMAC message input)."""
        key = (escrow_id, window_id)
        cached = self._latest_denial_by_window.get(key)
        if cached is not None:
            return cached
        finder = getattr(self.ledger, "latest_denial_hash", None)
        if finder is None:
            finder = getattr(self.ledger, "first_denial_hash", None)
        if finder is not None:
            found = finder(escrow_id, window_id)
            if isinstance(found, str) and found:
                self._latest_denial_by_window[key] = found
                return found
            return None
        latest: str | None = None
        for r in self.ledger.receipts():
            if r.event_type != "REFUSED":
                continue
            reason = r.payload.get("reason", "")
            if not isinstance(reason, str) or not reason.startswith("already_"):
                continue
            if (
                r.payload.get("escrow_id") == escrow_id
                and r.payload.get("window_id") == window_id
            ):
                latest = r.hash
        if latest is not None:
            self._latest_denial_by_window[key] = latest
        return latest

    def _remember_latest_denial(
        self, escrow_id: str, window_id: str, receipt_hash: str
    ) -> None:
        self._latest_denial_by_window[(escrow_id, window_id)] = receipt_hash

    def _persist_rate_window(
        self,
        escrow_id: str,
        state: _RetryRateWindow,
        *,
        rate_mac: str | None = None,
        prev_rate_mac: str | None = None,
    ) -> None:
        """Write window counters to the side store (durable on Sqlite)."""
        side = self._rate_store.get_open(escrow_id)
        if (
            prev_rate_mac is None
            and side is not None
            and side.window_id == state.window_id
        ):
            prev_rate_mac = side.prev_rate_mac
        if prev_rate_mac is None:
            prev_rate_mac = ""
        if rate_mac is None:
            anchor = self._latest_denial_hash(escrow_id, state.window_id)
            # Preserve existing mac when only non-count fields change and
            # there is already a tag; otherwise mint with current HW=count.
            if (
                side is not None
                and side.window_id == state.window_id
                and side.rate_limited == state.rate_limited
                and side.rate_mac
            ):
                rate_mac = side.rate_mac
                prev_rate_mac = side.prev_rate_mac
            else:
                rate_mac = rate_limited_mac(
                    anchor,
                    escrow_id,
                    state.window_id,
                    state.rate_limited,
                    prev_mac=prev_rate_mac,
                    high_water=int(state.rate_limited),
                )
        self._rate_store.upsert(
            RetryRateRow(
                escrow_id=escrow_id,
                window_id=state.window_id,
                window_start=state.window_start,
                individual=state.individual,
                rate_limited=state.rate_limited,
                covered_reason=state.last_already_reason,
                tally_flushed=state.tally_flushed,
                rate_mac=rate_mac,
                prev_rate_mac=prev_rate_mac or "",
            )
        )

    def _rebuild_original_refusals_from_ledger(self) -> None:
        originals: dict[str, str] = {}
        for r in self.ledger.receipts():
            eid = r.payload.get("escrow_id")
            if not isinstance(eid, str) or eid in originals:
                continue
            if r.event_type == "REFUSED":
                reason = r.payload.get("reason", "")
                if reason == "rate_limited":
                    continue
                if isinstance(reason, str) and reason.startswith("already_"):
                    continue
                originals[eid] = r.hash
            elif r.event_type == "VOIDED":
                originals[eid] = r.hash
        self._original_refusal_by_escrow = originals

    def _chain_rate_tallies(self) -> dict[tuple[str, str], Receipt]:
        """Index rate_limited tally receipts by (escrow_id, window_id)."""
        out: dict[tuple[str, str], Receipt] = {}
        for r in self.ledger.receipts():
            if r.event_type != "REFUSED":
                continue
            if r.payload.get("reason") != "rate_limited":
                continue
            eid = r.payload.get("escrow_id")
            wid = r.payload.get("window_id")
            if isinstance(eid, str) and isinstance(wid, str):
                out[(eid, wid)] = r
        return out

    def _rebuild_denial_count_cache(self) -> None:
        """One-shot scan into the process-local denial count cache."""
        counts: dict[tuple[str, str], int] = {}
        latest: dict[tuple[str, str], str] = {}
        for r in self.ledger.receipts():
            if r.event_type != "REFUSED":
                continue
            reason = r.payload.get("reason", "")
            if not isinstance(reason, str) or not reason.startswith("already_"):
                continue
            eid = r.payload.get("escrow_id")
            wid = r.payload.get("window_id")
            if isinstance(eid, str) and isinstance(wid, str):
                key = (eid, wid)
                counts[key] = counts.get(key, 0) + 1
                latest[key] = r.hash
        self._denial_count_by_window = counts
        self._latest_denial_by_window = latest

    def _chain_individual_denials(self) -> dict[tuple[str, str], int]:
        """Count already_* denial receipts per (escrow_id, window_id)."""
        counter = getattr(self.ledger, "count_individual_denials", None)
        if counter is not None:
            return counter()
        if not self._denial_count_by_window:
            self._rebuild_denial_count_cache()
        return dict(self._denial_count_by_window)

    def _assert_side_matches_chain_individuals(
        self,
        escrow_id: str,
        window_id: str,
        side_individual: int,
        chain_counts: dict[tuple[str, str], int],
    ) -> None:
        """Raise if side.individual disagrees with chain denial count."""
        expected = chain_counts.get((escrow_id, window_id), 0)
        if side_individual != expected:
            raise RetryRateIntegrityError(
                "retry rate side table individual mismatch for "
                f"escrow_id={escrow_id!r} window_id={window_id!r}: "
                f"side={side_individual} chain={expected}; refuse "
                "(chain wins)"
            )

    def _reconcile_open_window_integrity(
        self,
        row: RetryRateRow,
        chain_tallies: dict[tuple[str, str], Receipt],
        chain_denials: dict[tuple[str, str], int],
        *,
        closing: bool = False,
    ) -> None:
        """
        Tamper checks for an open (or about-to-close) side row.
        Chain individual denials are the expected `individual`.
        rate_limited is checked via HMAC rate_mac (latest-denial + external key).
        rate_limited>0 while individual < N is also refused.
        """
        key = (row.escrow_id, row.window_id)
        if key in chain_tallies:
            return
        self._assert_side_matches_chain_individuals(
            row.escrow_id, row.window_id, row.individual, chain_denials
        )
        verify_rate_limited_mac(
            self._latest_denial_hash(row.escrow_id, row.window_id),
            row.escrow_id,
            row.window_id,
            row.rate_limited,
            row.rate_mac,
            prev_mac=row.prev_rate_mac,
        )
        if row.rate_limited > 0 and row.individual < self.retry_rate_limit_n:
            raise RetryRateIntegrityError(
                "retry rate side table rate_limited set before exhausting N for "
                f"escrow_id={row.escrow_id!r} window_id={row.window_id!r}: "
                f"individual={row.individual} rate_limited={row.rate_limited}; "
                "refuse to start"
            )
        if closing:
            return

    def _rebuild_retry_state(self) -> None:
        """
        Rebuild original_refusal_id from the ledger; reconcile the side store
        against the chain inside one read snapshot when SqliteLedger provides
        check_retry_rate_integrity. window_start is never rebased. Expired
        open windows get at most one tally. Disagreement → RetryRateIntegrityError
        (chain wins; no anomaly receipt).
        """
        self._rebuild_original_refusals_from_ledger()
        if getattr(self.ledger, "count_individual_denials", None) is None:
            self._rebuild_denial_count_cache()
        checker = getattr(self.ledger, "check_retry_rate_integrity", None)
        if checker is not None:
            checker(
                original_refusal_id_for=self._original_refusal_id,
                limit_n=self.retry_rate_limit_n,
            )

        now = self._clock()
        chain_tallies = self._chain_rate_tallies()
        chain_denials = self._chain_individual_denials()
        side_rows = self._rate_store.load_all()
        side_by_key = {(row.escrow_id, row.window_id): row for row in side_rows}
        side_keys = set(side_by_key)

        # In-memory path (no SQL snapshot helper): same checks.
        if checker is None:
            open_from_chain: dict[tuple[str, str], int] = {}
            for key, count in chain_denials.items():
                if key not in chain_tallies:
                    open_from_chain[key] = count
            for key, count in open_from_chain.items():
                row = side_by_key.get(key)
                if row is None:
                    raise RetryRateIntegrityError(
                        "retry rate side table missing open row derived from chain "
                        f"denials escrow_id={key[0]!r} window_id={key[1]!r} "
                        f"(chain_individual={count}); refuse to start"
                    )
                if row.tally_flushed:
                    raise RetryRateIntegrityError(
                        "retry rate side table marked flushed but chain has no tally "
                        f"for escrow_id={key[0]!r} window_id={key[1]!r}; refuse"
                    )
                self._reconcile_open_window_integrity(
                    row, chain_tallies, chain_denials
                )
            for key, receipt in chain_tallies.items():
                if key not in side_keys:
                    raise RetryRateIntegrityError(
                        "retry rate side table missing row for chain tally "
                        f"escrow_id={key[0]!r} window_id={key[1]!r} "
                        f"(seq={receipt.seq}); refuse to start"
                    )

        restored: dict[str, _RetryRateWindow] = {}
        for row in side_rows:
            key = (row.escrow_id, row.window_id)
            chain_tally = chain_tallies.get(key)
            state = _RetryRateWindow(
                window_id=row.window_id,
                window_start=row.window_start,
                individual=row.individual,
                rate_limited=row.rate_limited,
                last_already_reason=row.covered_reason,
                tally_flushed=row.tally_flushed,
            )

            if chain_tally is not None:
                if checker is None:
                    chain_count = int(chain_tally.payload.get("count", -1))
                    if row.rate_limited != chain_count:
                        raise RetryRateIntegrityError(
                            "retry rate side table count mismatch for "
                            f"escrow_id={row.escrow_id!r} "
                            f"window_id={row.window_id!r}: "
                            f"side={row.rate_limited} chain={chain_count}; "
                            "refuse to start"
                        )
                if not row.tally_flushed:
                    state.tally_flushed = True
                    self._persist_rate_window(row.escrow_id, state)
                continue

            if row.tally_flushed and checker is None:
                raise RetryRateIntegrityError(
                    "retry rate side table tally_flushed=1 but no chain tally for "
                    f"escrow_id={row.escrow_id!r} window_id={row.window_id!r}; "
                    "refuse to start"
                )
            if row.tally_flushed:
                continue

            # When checker ran, integrity was already validated in one
            # snapshot — do not re-check against separately loaded counts
            # (TOCTOU with concurrent writers). In-memory still reconciles.
            if checker is None:
                self._reconcile_open_window_integrity(
                    row, chain_tallies, chain_denials
                )
                verify_rate_limited_mac(
                    self._latest_denial_hash(row.escrow_id, row.window_id),
                    row.escrow_id,
                    row.window_id,
                    row.rate_limited,
                    row.rate_mac,
                    prev_mac=row.prev_rate_mac,
                )

            expired = (now - state.window_start) >= self.retry_rate_limit_w
            if expired:
                if checker is None:
                    self._reconcile_open_window_integrity(
                        row, chain_tallies, chain_denials, closing=True
                    )
                self._append_window_tally(row.escrow_id, state)
                state.tally_flushed = True
                self._persist_rate_window(row.escrow_id, state)
                continue
            restored[row.escrow_id] = state
        self._retry_rate_windows = restored

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
        else escrow-level VOIDED). O(1) via index — no log scan (REA F7)."""
        return self._original_refusal_by_escrow.get(escrow_id)

    def _lookup_window_tally(
        self, escrow_id: str, window_id: str
    ) -> Receipt | None:
        """Existing rate_limited tally for (escrow_id, window_id), if any."""
        finder = getattr(self.ledger, "find_rate_limited_tally", None)
        if finder is not None:
            found = finder(escrow_id, window_id)
            if found is not None:
                return found
        for r in self.ledger.receipts():
            if r.event_type != "REFUSED":
                continue
            if r.payload.get("reason") != "rate_limited":
                continue
            if (
                r.payload.get("escrow_id") == escrow_id
                and r.payload.get("window_id") == window_id
            ):
                return r
        return None

    def _append_window_tally(
        self, escrow_id: str, state: _RetryRateWindow
    ) -> Receipt | None:
        """Append the single combined tally for this window (once, idempotent)."""
        if state.rate_limited <= 0:
            return None
        existing = self._lookup_window_tally(escrow_id, state.window_id)
        if existing is not None:
            state.tally_flushed = True
            return existing
        if state.tally_flushed:
            return None
        original = self._original_refusal_id(escrow_id)
        receipt = self.ledger.append(
            "REFUSED",
            {
                "escrow_id": escrow_id,
                "reason": "rate_limited",
                "count": state.rate_limited,
                "window_id": state.window_id,
                "window_start": state.window_start,
                "covered_reason": state.last_already_reason,
                "receipt_id": f"rl_{uuid.uuid4().hex}",
                "original_refusal_id": original,
            },
        )
        state.tally_flushed = True
        return receipt

    def _close_rate_window(self, escrow_id: str, state: _RetryRateWindow) -> None:
        """Append at most one tally for the window and mark it flushed."""
        # Integrity vs chain before closing (individual denials must match).
        chain_denials = self._chain_individual_denials()
        chain_tallies = self._chain_rate_tallies()
        side = self._rate_store.get_open(escrow_id)
        if side is not None and side.window_id == state.window_id:
            rate_mac = side.rate_mac
            prev_mac = side.prev_rate_mac
        else:
            prev_mac = ""
            rate_mac = rate_limited_mac(
                self._latest_denial_hash(escrow_id, state.window_id),
                escrow_id,
                state.window_id,
                state.rate_limited,
                prev_mac=prev_mac,
                high_water=int(state.rate_limited),
            )
        row = RetryRateRow(
            escrow_id=escrow_id,
            window_id=state.window_id,
            window_start=state.window_start,
            individual=state.individual,
            rate_limited=state.rate_limited,
            covered_reason=state.last_already_reason,
            tally_flushed=state.tally_flushed,
            rate_mac=rate_mac,
            prev_rate_mac=prev_mac,
        )
        self._reconcile_open_window_integrity(
            row, chain_tallies, chain_denials, closing=True
        )
        if state.rate_limited > 0:
            self._append_window_tally(escrow_id, state)
        state.tally_flushed = True
        self._persist_rate_window(escrow_id, state)

    def _refresh_open_window_from_store(
        self, escrow_id: str
    ) -> _RetryRateWindow | None:
        """Read the open side-store row (authority); update soft mirror."""
        row = self._rate_store.get_open(escrow_id)
        if row is None:
            self._retry_rate_windows.pop(escrow_id, None)
            return None
        state = _RetryRateWindow(
            window_id=row.window_id,
            window_start=row.window_start,
            individual=row.individual,
            rate_limited=row.rate_limited,
            last_already_reason=row.covered_reason,
            tally_flushed=row.tally_flushed,
        )
        self._retry_rate_windows[escrow_id] = state
        return state

    def _retry_rate_window_locked(
        self, escrow_id: str, now: float
    ) -> _RetryRateWindow:
        """Active window from the side store; closes when now >= start + W.
        Caller holds the per-escrow rate lock. Memory is not the authority."""
        state = self._refresh_open_window_from_store(escrow_id)
        if state is not None and (now - state.window_start) >= self.retry_rate_limit_w:
            self._close_rate_window(escrow_id, state)
            self._retry_rate_windows.pop(escrow_id, None)
            state = None
        if state is None:
            # Another path may have created the open row; never invent a
            # second open window_id when one already exists in the store.
            adopted = self._refresh_open_window_from_store(escrow_id)
            if adopted is not None:
                return adopted
            state = _RetryRateWindow(
                window_id=f"rw_{uuid.uuid4().hex}",
                window_start=now,
            )
            try:
                # Brand-new window only — never recreate a missing sidecar
                # for an existing DB/side row.
                create_high_water(escrow_id, state.window_id, initial=0)
                self._persist_rate_window(escrow_id, state)
            except RuntimeError:
                adopted = self._refresh_open_window_from_store(escrow_id)
                if adopted is None:
                    raise
                return adopted
            adopted = self._refresh_open_window_from_store(escrow_id)
            return adopted if adopted is not None else state
        return state

    def _append_retry_denial(
        self,
        escrow_id: str,
        reason: str,
        window_id: str,
        window_start: float,
    ) -> Receipt:
        """REA F6: unique denial receipt for a refused retry; never captures."""
        original = self._original_refusal_id(escrow_id)
        return self.ledger.append(
            "REFUSED",
            {
                "escrow_id": escrow_id,
                "reason": reason,
                "window_id": window_id,
                "window_start": window_start,
                "receipt_id": f"den_{uuid.uuid4().hex}",
                "original_refusal_id": original,
            },
        )

    def flush_retry_rate_limits(self, escrow_id: str | None = None) -> None:
        """
        Clean-shutdown / test flush: append the one per-window tally for any
        open window with a pending over-limit count, then clear the window.
        """
        # Integrity before any close: side.individual must match chain denials.
        chain_denials = self._chain_individual_denials()
        chain_tallies = self._chain_rate_tallies()
        for row in self._rate_store.load_all():
            if row.tally_flushed:
                continue
            if escrow_id is not None and row.escrow_id != escrow_id:
                continue
            self._reconcile_open_window_integrity(
                row, chain_tallies, chain_denials, closing=True
            )

        flush = getattr(self.ledger, "flush_open_retry_windows", None)
        if flush is not None:
            flush(
                original_refusal_id_for=self._original_refusal_id,
                escrow_id=escrow_id,
            )
            sync = getattr(self.ledger, "sync_receipts_from_db", None)
            if sync is not None:
                sync()
            if escrow_id is not None:
                self._retry_rate_windows.pop(escrow_id, None)
            else:
                self._retry_rate_windows.clear()
            return

        if escrow_id is not None:
            targets = [escrow_id]
        else:
            targets = sorted(
                {
                    row.escrow_id
                    for row in self._rate_store.load_all()
                    if not row.tally_flushed
                }
            )
        for eid in targets:
            with self._rate_lock_for(eid):
                state = self._refresh_open_window_from_store(eid)
                if state is not None:
                    self._close_rate_window(eid, state)
                    self._retry_rate_windows.pop(eid, None)

    def _handle_terminal_retry(self, escrow_id: str, already_reason: str) -> VerifyResult:
        """
        REA F6 + F7: refused retry on VOIDED/REFUSED. Up to N individual
        denial receipts per window W; further retries return rate_limited.

        When the ledger supports record_terminal_retry (SqliteLedger), the
        denial receipt + side sync share one BEGIN IMMEDIATE; the allow/
        limit decision uses chain COUNT (not side.individual). Otherwise
        (in-memory), the per-escrow lock covers the same checks.
        """
        record = getattr(self.ledger, "record_terminal_retry", None)
        if record is not None:
            reason, _receipt = record(
                escrow_id,
                already_reason,
                limit_n=self.retry_rate_limit_n,
                window_w=self.retry_rate_limit_w,
                now=self._clock(),
                original_refusal_id=self._original_refusal_id(escrow_id),
            )
            # Soft mirror only — re-read from store when present.
            self._refresh_open_window_from_store(escrow_id)
            return VerifyResult(False, reason)

        with self._rate_lock_for(escrow_id):
            now = self._clock()
            # Live mid-window: deleted side row with chain denials → refuse now.
            open_row = self._rate_store.get_open(escrow_id)
            if open_row is None:
                chain_denials = self._chain_individual_denials()
                chain_tallies = self._chain_rate_tallies()
                for (eid, wid), n in chain_denials.items():
                    if eid != escrow_id:
                        continue
                    if (eid, wid) in chain_tallies:
                        continue
                    raise RetryRateIntegrityError(
                        "retry rate side table missing open row mid-window for "
                        f"escrow_id={eid!r} window_id={wid!r} "
                        f"(chain_individual={n}); refuse"
                    )
                chain_indiv_hint = 0
            else:
                # Hot path: cached chain count + latest-denial HMAC — no
                # full-log scans (bar 3 at 100k receipts).
                if not self._denial_count_by_window:
                    self._rebuild_denial_count_cache()
                expected = self._denial_count_by_window.get(
                    (open_row.escrow_id, open_row.window_id), 0
                )
                verify_rate_limited_mac(
                    self._latest_denial_hash(
                        open_row.escrow_id, open_row.window_id
                    ),
                    open_row.escrow_id,
                    open_row.window_id,
                    open_row.rate_limited,
                    open_row.rate_mac,
                    prev_mac=open_row.prev_rate_mac,
                    # Sidecar checked on over-limit increment / tally;
                    # skip file I/O on the individual-denial hot path (bar 4).
                    check_sidecar=False,
                )
                if open_row.individual != expected:
                    raise RetryRateIntegrityError(
                        "retry rate side table individual mismatch for "
                        f"escrow_id={open_row.escrow_id!r} "
                        f"window_id={open_row.window_id!r}: "
                        f"side={open_row.individual} chain={expected}; refuse"
                    )
                chain_indiv_hint = expected

            state = self._retry_rate_window_locked(escrow_id, now)
            state.last_already_reason = already_reason
            # Decision from chain COUNT (cached), not side.individual.
            chain_indiv = self._denial_count_by_window.get(
                (escrow_id, state.window_id), chain_indiv_hint
            )

            if chain_indiv < self.retry_rate_limit_n:
                denial = self._append_retry_denial(
                    escrow_id,
                    already_reason,
                    window_id=state.window_id,
                    window_start=state.window_start,
                )
                key = (escrow_id, state.window_id)
                self._remember_latest_denial(
                    escrow_id, state.window_id, denial.hash
                )
                self._denial_count_by_window[key] = chain_indiv + 1
                state.individual = chain_indiv + 1
                cur_mac = (
                    open_row.rate_mac
                    if open_row is not None
                    and open_row.window_id == state.window_id
                    else ""
                )
                hw0 = int(state.rate_limited)
                new_mac = rate_limited_mac(
                    denial.hash,
                    escrow_id,
                    state.window_id,
                    hw0,
                    prev_mac=cur_mac,
                    high_water=hw0,
                )
                self._persist_rate_window(
                    escrow_id,
                    state,
                    rate_mac=new_mac,
                    prev_rate_mac=cur_mac,
                )
                return VerifyResult(False, already_reason)

            # Verify on every over-limit step (loss bound 0).
            # Persist SQL/side row first, then raise the sidecar HW.
            anchor = self._latest_denial_hash(escrow_id, state.window_id)
            if (
                open_row is not None
                and open_row.window_id == state.window_id
            ):
                side_mac = open_row.rate_mac
                side_prev = open_row.prev_rate_mac
            else:
                side_prev = ""
                side_mac = rate_limited_mac(
                    anchor,
                    escrow_id,
                    state.window_id,
                    state.rate_limited,
                    prev_mac=side_prev,
                    high_water=int(state.rate_limited),
                )
            verify_rate_limited_mac(
                anchor,
                escrow_id,
                state.window_id,
                state.rate_limited,
                side_mac,
                prev_mac=side_prev,
                check_sidecar=False,
            )
            prev_for_new = side_mac
            with high_water_lock(escrow_id, state.window_id) as hwlock:
                cur = int(state.rate_limited)
                hwlock.reconcile(cur)
                hwlock.check(cur)
                new_count = cur + 1
                hwlock.write_intent(new_count)
                state.rate_limited = new_count
                new_mac = rate_limited_mac(
                    anchor,
                    escrow_id,
                    state.window_id,
                    state.rate_limited,
                    prev_mac=prev_for_new,
                    high_water=int(state.rate_limited),
                )
                self._persist_rate_window(
                    escrow_id,
                    state,
                    rate_mac=new_mac,
                    prev_rate_mac=prev_for_new,
                )
                # Re-read after persist so HW never tracks a clobbered-away count.
                side_now = self._rate_store.get_open(escrow_id)
                hw_val = (
                    int(side_now.rate_limited)
                    if side_now is not None
                    and side_now.window_id == state.window_id
                    else int(state.rate_limited)
                )
                hwlock.confirm(hw_val)
                publish_rate_mac_to_anchor(new_mac)
            return VerifyResult(False, "rate_limited")

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
                escrow.escrow_id, escrow.artifact_hash, escrow.amount_cents
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
        # Lock-free terminal short-circuit: flooded retries never take _lock.
        terminal_cached = self._terminal_reasons.get(escrow_id)
        if terminal_cached is not None:
            return self._handle_terminal_retry(escrow_id, terminal_cached)

        # ---- Phase 1: decide. Verifier lock held, no provider I/O. ----
        terminal_retry_reason: str | None = None
        with self._lock:
            escrow = self._escrows.get(escrow_id)
            if escrow is None:
                unknown_receipt = self.ledger.append(
                    "REFUSED", {"escrow_id": escrow_id, "reason": "unknown_escrow"}
                )
                self._remember_original_refusal(escrow_id, unknown_receipt.hash)
                return VerifyResult(False, "unknown_escrow")

            # Already resolved → return the recorded outcome, never re-capture.
            if escrow.state == "CAPTURED":
                return VerifyResult(True, "already_captured")
            if escrow.state in ("VOIDED", "REFUSED"):
                # F6/F7 rate-limit path runs outside the global verifier lock
                # (per-escrow counter lock + ledger append only).
                terminal_retry_reason = f"already_{escrow.state.lower()}"
                self._terminal_reasons[escrow_id] = terminal_retry_reason
            # Indeterminate states need an explicit operator step first:
            # reconcile() for UNKNOWN, retry_cleanup() for CLEANUP_PENDING.
            elif escrow.state == "UNKNOWN":
                return VerifyResult(False, "unknown_reconcile_first")
            elif escrow.state == "CLEANUP_PENDING":
                return VerifyResult(False, "cleanup_pending")
            # Transitional: another thread is already driving provider I/O
            # for this escrow. Single-flight — do not double-drive.
            elif escrow.state in ("CAPTURING", "REFUSING", "VOIDING"):
                return VerifyResult(False, "release_in_flight")
            else:
                # Admission recheck, chain verify, predicate — all local.
                admit_reason = self.permits.release_block_reason(escrow.permit_id)
                refuse_reason = None
                result_reason = None
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
                    refused_receipt = self.ledger.append(
                        "REFUSED", {"escrow_id": escrow_id, "reason": refuse_reason}
                    )
                    self._remember_original_refusal(escrow_id, refused_receipt.hash)
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

        if terminal_retry_reason is not None:
            return self._handle_terminal_retry(escrow_id, terminal_retry_reason)

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
                late_reason = self.permits.release_block_reason(permit_id)
                if late_reason is not None:
                    # Refuse: void the hold (I/O, no verifier lock).
                    late_receipt = self.ledger.append(
                        "REFUSED", {"escrow_id": escrow_id, "reason": late_reason}
                    )
                    with self._lock:
                        self._remember_original_refusal(escrow_id, late_receipt.hash)
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

        # ---- Phase 3: commit. Verifier lock held, no provider I/O. ----
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
                    if final_state in ("REFUSED", "VOIDED"):
                        self._terminal_reasons[escrow_id] = (
                            f"already_{final_state.lower()}"
                        )
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
                self._terminal_reasons[escrow_id] = "already_voided"
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
            self._terminal_reasons[escrow_id] = "already_voided"
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
            self._terminal_reasons[escrow_id] = "already_voided"
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
            self._terminal_reasons[escrow_id] = "already_voided"
            self.permits.settle_void(permit_id, auth_id)
            void_receipt = self.ledger.append("VOIDED", {"escrow_id": escrow_id})
            self._remember_original_refusal(escrow_id, void_receipt.hash)
            return True
