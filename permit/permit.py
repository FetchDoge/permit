"""
Permit: the authorization layer. Decides what an agent is ALLOWED to spend.

Authority check (Grok review fix — cumulative reservation):
    amount(a) <= remaining(P)
    AND merchant(a) IN allowlist(P)
    AND now < expiry(P)
    AND NOT revoked(P)

    remaining(P) = cap(P) − reserved(P) − captured(P)

An authorization hold RESERVES cap; capture moves reserved→captured;
void releases the reservation. Parallel attempts serialize on the permit
(per-permit lock), so concurrent attempts cannot exceed the cap (test C1).

A failed check writes a BLOCKED receipt and never reaches PayPal.
This module MUST NOT import any PayPal client (enforced by import test).

E-stop: revoke() flips the permit to revoked and returns the in-flight
authorization ids the settlement layer must void. The e-stop is itself
a receipted event.

Expiry semantics (authority definition — binding on all workstreams):
    Expiry is evaluated at BOTH boundaries, never just one:
    1. Check time — check()/eligible() block any attempt on an expired
       (or missing, or revoked) permit.
    2. Release/capture-admission time — the settlement layer MUST re-admit
       the permit via permits.get() immediately before capture and refuse
       when the permit is missing, revoked, or expired at that moment.
    Release after expiry therefore fails closed: an escrow authorized
    against a then-valid permit cannot capture once the permit has
    expired or been revoked. This module defines the rule; the settlement
    workstream enforces the admission check at capture time.

Amount discipline (P1-3 witness fix): amounts are positive integers.
_validate_amount() guards the authority boundary (check() and grant());
an invalid amount never reserves, never raises through check() — it is
recorded as a BLOCKED receipt with reason "invalid_amount".

Tighten-only min-gate (v4): a live permit can be NARROWED after issuance
via tighten() — lower cap, fewer merchants, sooner expiry — but never
widened. A tighten cascades to every descendant: each child keeps the
narrower of its own authority and the parent's new bound, so the whole
subtree obeys the tightened mandate with no ancestor walk at check time.
Every tighten writes a TIGHTEN receipt with old→new per narrowed clause;
cascaded applications carry cascade_from. A tighten that would widen or
leave authority unchanged is rejected.

Calibration tau (Sol 6.1, ADVISORY): each permit carries the tau its
advisory calibration score is compared against (permit/calibration.py).
The grant-time tau is the floor; raise_calibration_tau() may only raise
it. A lowering, a no-op or an out-of-range value is refused with a
TAU_REFUSED receipt and the stored tau is unchanged. Tau is NOT an
authority clause: _evaluate() never reads it.

check() records the advisory score on the ALLOWED/BLOCKED receipt it
writes (payload key "calibration"), computed AFTER the authority decision
is made. Any failure computing it is recorded as unavailable; it can
never change, block or allow a spend.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from . import calibration as _calibration
from .calibration import TAU_DEFAULT, validate_tau
from .ledger import Ledger, Receipt


class UnknownPermit(Exception):
    """Raised when an operation names a permit id the store does not hold."""


class UnknownAuthId(Exception):
    """
    Raised when a settlement operation names an auth id with no live
    reservation on the permit. An explicit exception (never assert):
    trust-boundary behavior must be identical under `python -O`.
    """


# Delegation depth bound (converged from the level-up line): a delegation
# tree cannot grow without limit. Depth 0 is a granted root; each carve
# adds one. Delegation past this depth is BLOCKED, not raised.
MAX_DELEGATION_DEPTH = 8


def _validate_amount(amount_cents) -> int:
    """
    Amount guard at the authority boundary: amount_cents must be an int
    (bool excluded) and strictly positive. Raises ValueError otherwise.
    """
    if isinstance(amount_cents, bool) or not isinstance(amount_cents, int):
        raise ValueError(
            "amount_cents must be a positive int, "
            f"got {type(amount_cents).__name__}: {amount_cents!r}"
        )
    if amount_cents <= 0:
        raise ValueError(f"amount_cents must be > 0, got {amount_cents}")
    return amount_cents


@dataclass
class CheckResult:
    allowed: bool
    reason: str
    # None for read-only evaluations (eligible()): no receipt is written.
    receipt: Receipt | None = None


@dataclass
class DelegateResult:
    ok: bool
    reason: str
    permit: Permit | None = None
    receipt: Receipt | None = None


@dataclass
class TauResult:
    """Outcome of raise_calibration_tau(). The receipt is always written."""
    ok: bool
    reason: str
    tau: float | None
    receipt: Receipt


@dataclass
class PendingApproval:
    """A principal-approval request for an above-threshold spend."""
    approval_id: str
    permit_id: str
    agent_id: str
    amount_cents: int
    merchant_id: str
    predicate_type: str  # PredicateType value, e.g. "D"
    artifact_hash: str
    # pending | approved | denied | expired | consumed
    status: str = "pending"
    created_at: str = ""
    expires_at: str = ""


@dataclass
class Permit:
    permit_id: str
    agent_id: str
    cap_cents: int
    allowlist: tuple[str, ...]
    expiry: datetime
    revoked: bool = False
    reserved_cents: int = 0
    captured_cents: int = 0
    # Authorization ids currently holding a reservation on this permit.
    in_flight: dict[str, int] = field(default_factory=dict)
    # Delegation: set when this permit was carved out of a parent permit.
    parent_id: str | None = None
    # Delegation depth: 0 for a granted root, parent.depth + 1 for a carve.
    # Bounded by MAX_DELEGATION_DEPTH at delegation time.
    depth: int = 0
    # Tighten overlays (v4 min-gate): post-issuance narrowings. Each is
    # None until the first tighten touches that clause; tighten() only
    # ever narrows, so the effective clause is the minimum/intersection
    # of the granted value and every tighten overlay in the lineage.
    tighten_cap_cents: int | None = None
    tighten_allowlist: tuple[str, ...] | None = None
    tighten_expiry: datetime | None = None
    # Principal-approval threshold: spends above this need a human word.
    # None = no threshold. Tighten-only via tighten().
    approval_threshold_cents: int | None = None
    tighten_approval_threshold_cents: int | None = None
    # Advisory calibration tau (Sol 6.1). Raise-only after grant; never
    # read by the authority check.
    calibration_tau: float = TAU_DEFAULT
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def remaining_cents(self) -> int:
        # Through the tighten-only min-gate: the principal sees the
        # remaining budget the authority actually enforces, not the
        # granted cap a tighten has since narrowed.
        cap = self.cap_cents
        if (
            self.tighten_cap_cents is not None
            and self.tighten_cap_cents < cap
        ):
            cap = self.tighten_cap_cents
        return cap - self.reserved_cents - self.captured_cents


class PermitStore:
    """Issues permits, evaluates spend attempts, handles e-stop."""

    def __init__(self, ledger: Ledger | None = None):
        # NOTE: explicit None check — an empty Ledger is falsy via __len__,
        # so `ledger or Ledger()` would silently discard a passed empty ledger.
        self.ledger = ledger if ledger is not None else Ledger()
        self._permits: dict[str, Permit] = {}
        # Delegation index: parent permit_id -> child permit_ids.
        self._children: dict[str, list[str]] = {}
        # Principal approvals: approval_id -> PendingApproval.
        self._approvals: dict[str, PendingApproval] = {}
        self._store_lock = threading.Lock()
        # Settlement gate: serializes every revocation (estop, cascade)
        # against the release-time admission recheck + provider capture.
        # Lock order: gate -> store -> permit. Never taken while holding a
        # store or permit lock.
        self.settlement_gate = threading.RLock()

    def grant(
        self,
        agent_id: str,
        cap_cents: int,
        allowlist: list[str],
        expiry: datetime,
        approval_threshold_cents: int | None = None,
        calibration_tau: float = TAU_DEFAULT,
    ) -> tuple[Permit, Receipt]:
        _validate_amount(cap_cents)
        if approval_threshold_cents is not None:
            _validate_amount(approval_threshold_cents)
        calibration_tau = validate_tau(calibration_tau)
        permit = Permit(
            permit_id=f"prm_{uuid.uuid4().hex[:12]}",
            agent_id=agent_id,
            cap_cents=cap_cents,
            allowlist=tuple(allowlist),
            expiry=expiry,
            approval_threshold_cents=approval_threshold_cents,
            calibration_tau=calibration_tau,
        )
        with self._store_lock:
            self._permits[permit.permit_id] = permit
        receipt = self.ledger.append(
            "GRANTED",
            {
                "permit_id": permit.permit_id,
                "agent_id": agent_id,
                "cap_cents": cap_cents,
                "allowlist": list(allowlist),
                "expiry": expiry.isoformat(),
                "approval_threshold_cents": approval_threshold_cents,
                "calibration_tau": calibration_tau,
            },
        )
        return permit, receipt

    def get(self, permit_id: str) -> Permit | None:
        with self._store_lock:
            return self._permits.get(permit_id)

    def children_of(self, permit_id: str) -> list[str]:
        """Child permit ids delegated from this permit (a copy)."""
        with self._store_lock:
            return list(self._children.get(permit_id, []))

    def permits_snapshot(self) -> list[dict]:
        """
        Read-only projection of all permits for dashboards and operators.
        Plain dicts, no live references — safe to serialize. The dashboard
        reads through this, never through _permits.
        """
        out = []
        with self._store_lock:
            permits = list(self._permits.values())
        for p in permits:
            with p._lock:
                eff_cap = p.cap_cents
                if (
                    p.tighten_cap_cents is not None
                    and p.tighten_cap_cents < eff_cap
                ):
                    eff_cap = p.tighten_cap_cents
                out.append({
                    "permit_id": p.permit_id,
                    "agent_id": p.agent_id,
                    "cap_cents": p.cap_cents,
                    "effective_cap_cents": eff_cap,
                    "reserved_cents": p.reserved_cents,
                    "captured_cents": p.captured_cents,
                    "remaining_cents": p.remaining_cents(),
                    "revoked": p.revoked,
                    "allowlist": list(p.allowlist),
                    "parent_id": p.parent_id,
                })
        return out

    def delegate(
        self,
        parent_permit_id: str,
        agent_id: str,
        cap_cents: int,
        allowlist: list[str],
        expiry: datetime,
        now: datetime | None = None,
    ) -> DelegateResult:
        """
        Carve a sub-permit out of a parent permit's remaining cap.

        Constraints — each violation writes a BLOCKED receipt:
          - parent exists, unrevoked, unexpired
          - delegation depth stays within MAX_DELEGATION_DEPTH
          - cap_cents <= parent remaining (can't delegate what isn't free)
          - allowlist ⊆ parent allowlist (no merchant escalation)
          - expiry <= parent expiry (can't outlive the parent)

        The carved cap is RESERVED on the parent, so the parent can never
        double-spend delegated budget. A child capture rolls up: each
        ancestor moves reserved→captured by the captured amount.
        """
        now = now or datetime.now(timezone.utc)
        try:
            _validate_amount(cap_cents)
        except ValueError:
            receipt = self.ledger.append(
                "BLOCKED",
                {
                    "permit_id": parent_permit_id,
                    "agent_id": agent_id,
                    "amount_cents": repr(cap_cents),
                    "reason": "invalid_amount",
                },
            )
            return DelegateResult(False, "invalid_amount", None, receipt)

        parent = self.get(parent_permit_id)
        if parent is None:
            receipt = self.ledger.append(
                "BLOCKED",
                {"permit_id": parent_permit_id, "reason": "unknown_parent"},
            )
            return DelegateResult(False, "unknown_parent", None, receipt)

        child_allowlist = tuple(allowlist)
        # Lock order: store -> parent. No path nests permit -> store,
        # so this ordering cannot deadlock.
        with self._store_lock:
            with parent._lock:
                # Carve against the parent's EFFECTIVE authority (tighten
                # overlays included): a tightened parent cannot delegate
                # what it can no longer spend.
                eff_cap, _, eff_allow, eff_expiry, _ = self._effective(parent)
                eff_remaining = eff_cap - parent.reserved_cents - parent.captured_cents
                if parent.revoked:
                    reason = "parent_revoked"
                elif now >= eff_expiry:
                    reason = "parent_expired"
                elif parent.depth + 1 > MAX_DELEGATION_DEPTH:
                    reason = "delegation_too_deep"
                elif cap_cents > eff_remaining:
                    reason = "over_parent_remaining"
                elif not set(child_allowlist) <= set(eff_allow):
                    reason = "allowlist_escalation"
                elif expiry > eff_expiry:
                    reason = "expiry_beyond_parent"
                else:
                    reason = None
                if reason is not None:
                    receipt = self.ledger.append(
                        "BLOCKED",
                        {
                            "permit_id": parent.permit_id,
                            "agent_id": agent_id,
                            "amount_cents": cap_cents,
                            "reason": reason,
                            "parent_remaining_cents": parent.remaining_cents(),
                        },
                    )
                    return DelegateResult(False, reason, None, receipt)
                # Carve: the child's cap is reserved on the parent.
                parent.reserved_cents += cap_cents
                child = Permit(
                    permit_id=f"prm_{uuid.uuid4().hex[:12]}",
                    agent_id=agent_id,
                    cap_cents=cap_cents,
                    allowlist=child_allowlist,
                    expiry=expiry,
                    parent_id=parent.permit_id,
                    depth=parent.depth + 1,
                    # Advisory tau: a carve starts at the parent's tau.
                    calibration_tau=parent.calibration_tau,
                )
                self._permits[child.permit_id] = child
                self._children.setdefault(parent.permit_id, []).append(
                    child.permit_id
                )
                receipt = self.ledger.append(
                    "DELEGATED",
                    {
                        "parent_permit_id": parent.permit_id,
                        "child_permit_id": child.permit_id,
                        "agent_id": agent_id,
                        "cap_cents": cap_cents,
                        "allowlist": list(child_allowlist),
                        "expiry": expiry.isoformat(),
                        "parent_remaining_cents": parent.remaining_cents(),
                        "depth": child.depth,
                    },
                )
                return DelegateResult(True, "delegated", child, receipt)

    # -- principal approvals ------------------------------------------------

    @staticmethod
    def _effective_threshold(permit: Permit) -> int | None:
        """
        The approval threshold through the tighten-only min-gate: the
        narrowest (smallest) of the granted threshold and the tighten
        overlay. None = no threshold. Caller must hold permit._lock.
        """
        t = permit.approval_threshold_cents
        o = permit.tighten_approval_threshold_cents
        if t is None:
            return o
        if o is None:
            return t
        return min(t, o)

    def approval_threshold(self, permit_id: str) -> int | None:
        """Effective principal-approval threshold, or None if unset."""
        permit = self.get(permit_id)
        if permit is None:
            return None
        with permit._lock:
            return self._effective_threshold(permit)

    def request_approval(
        self,
        permit_id: str,
        amount_cents: int,
        merchant_id: str,
        predicate_type: str,
        artifact_hash: str,
        ttl_minutes: int = 15,
        now: datetime | None = None,
    ) -> PendingApproval:
        """
        Request principal approval for an above-threshold spend. The
        4-clause authority check must already pass (via eligible()); no
        cap is reserved — the reservation happens only when an approved
        request is completed. Raises ValueError on misuse.
        """
        now = now or datetime.now(timezone.utc)
        _validate_amount(amount_cents)
        permit = self.get(permit_id)
        if permit is None:
            raise ValueError("unknown_permit")
        with permit._lock:
            if self._evaluate(permit, amount_cents, merchant_id, now) is not None:
                raise ValueError("authority_check_failed")
            threshold = self._effective_threshold(permit)
            if threshold is None or amount_cents <= threshold:
                raise ValueError("approval_not_required")
            approval = PendingApproval(
                approval_id=f"apr_{uuid.uuid4().hex[:12]}",
                permit_id=permit.permit_id,
                agent_id=permit.agent_id,
                amount_cents=amount_cents,
                merchant_id=merchant_id,
                predicate_type=predicate_type,
                artifact_hash=artifact_hash,
                created_at=now.isoformat(),
                expires_at=(now + timedelta(minutes=ttl_minutes)).isoformat(),
            )
            with self._store_lock:
                self._approvals[approval.approval_id] = approval
            receipt = self.ledger.append(
                "APPROVAL_REQUESTED",
                {
                    "approval_id": approval.approval_id,
                    "permit_id": permit.permit_id,
                    "agent_id": permit.agent_id,
                    "amount_cents": amount_cents,
                    "merchant_id": merchant_id,
                    "threshold_cents": threshold,
                    "expires_at": approval.expires_at,
                },
            )
            return approval

    def get_approval(self, approval_id: str) -> PendingApproval | None:
        with self._store_lock:
            return self._approvals.get(approval_id)

    def _expire_if_due(self, approval: PendingApproval,
                       now: datetime) -> bool:
        """Lazily expire a pending approval. Returns True if expired."""
        if approval.status == "pending" and now >= datetime.fromisoformat(
            approval.expires_at
        ):
            approval.status = "expired"
            self.ledger.append(
                "APPROVAL_DECIDED",
                {
                    "approval_id": approval.approval_id,
                    "permit_id": approval.permit_id,
                    "decision": "expired",
                    "actor": "system",
                },
            )
            return True
        return False

    def decide_approval(
        self,
        approval_id: str,
        approved: bool,
        actor: str = "human",
        now: datetime | None = None,
    ) -> PendingApproval:
        """
        The principal's word: approve or deny a pending request. Raises
        ValueError when the request is unknown, already decided, or
        expired. Approval does NOT reserve or move money — it only
        authorizes a later complete_approved_spend(), which re-runs the
        full authority check (fail-closed if the budget moved).
        """
        now = now or datetime.now(timezone.utc)
        with self._store_lock:
            approval = self._approvals.get(approval_id)
            if approval is None:
                raise ValueError("unknown_approval")
            if self._expire_if_due(approval, now):
                raise ValueError("approval_expired")
            if approval.status != "pending":
                raise ValueError(f"approval_already_{approval.status}")
            approval.status = "approved" if approved else "denied"
            self.ledger.append(
                "APPROVAL_DECIDED",
                {
                    "approval_id": approval.approval_id,
                    "permit_id": approval.permit_id,
                    "agent_id": approval.agent_id,
                    "amount_cents": approval.amount_cents,
                    "merchant_id": approval.merchant_id,
                    "decision": approval.status,
                    "actor": actor,
                },
            )
            return approval

    def consume_approval(self, approval_id: str) -> None:
        """Mark an approved request consumed after its spend reserves."""
        with self._store_lock:
            approval = self._approvals.get(approval_id)
            if approval is not None and approval.status == "approved":
                approval.status = "consumed"

    def pending_approvals(
        self, now: datetime | None = None
    ) -> list[PendingApproval]:
        """Live approval requests for the principal's dashboard."""
        now = now or datetime.now(timezone.utc)
        with self._store_lock:
            out = []
            for approval in self._approvals.values():
                self._expire_if_due(approval, now)
                if approval.status == "pending":
                    out.append(approval)
            return out

    def lineage(self, permit_id: str) -> list[Permit]:
        """
        Ancestor chain for a permit, nearest parent first. Snapshot of
        references only — liveness is evaluated separately under each
        ancestor's own lock. Permits are never deleted, so a missing
        ancestor is treated as a fail-closed block, not a skip.
        """
        chain: list[Permit] = []
        seen = {permit_id}
        with self._store_lock:
            cur = self._permits.get(permit_id)
            while cur is not None and cur.parent_id is not None:
                if cur.parent_id in seen:
                    break  # defensive: depth is strictly increasing, no cycles
                seen.add(cur.parent_id)
                parent = self._permits.get(cur.parent_id)
                if parent is None:
                    chain.append(None)  # type: ignore[arg-type]
                    break
                chain.append(parent)
                cur = parent
        return chain

    @staticmethod
    def _lineage_block_reason(
        chain: list[Permit], now: datetime
    ) -> str | None:
        """
        Fail-closed ancestor liveness: every ancestor must be unrevoked
        and unexpired, or the spend is blocked. Nearest ancestor first.
        Caller holds the spending permit's lock; ancestor locks are taken
        child -> ancestor, which cannot cycle (delegation depth strictly
        increases, and no path ever locks ancestor -> child).
        """
        for ancestor in chain:
            if ancestor is None:
                return "ancestor_missing"
            with ancestor._lock:
                if ancestor.revoked:
                    return "ancestor_revoked"
                if now >= ancestor.expiry:
                    return "ancestor_expired"
        return None

    def tighten(
        self,
        permit_id: str,
        *,
        cap_cents: int | None = None,
        remove_merchants: list[str] | None = None,
        expiry: datetime | None = None,
        approval_threshold_cents: int | None = None,
        actor: str = "human",
    ) -> tuple[Permit, Receipt]:
        """
        Narrow a live permit. Tighten-only: every supplied parameter must
        strictly narrow the permit's current effective authority, otherwise
        ValueError. At least one parameter is required.

        - cap_cents: new cap, a positive int strictly below the current
          effective cap. May go below reserved+captured (emergency):
          in-flight holds stand, but no new attempt can reserve.
        - remove_merchants: non-empty list; each must be in the current
          effective allowlist; the result must stay non-empty (to kill
          the permit, use e-stop).
        - expiry: timezone-aware datetime, strictly sooner than the current
          effective expiry and still in the future.
        - approval_threshold_cents: new principal-approval threshold, a
          positive int strictly below the current effective threshold
          (or any positive int when no threshold is set — setting one is
          itself a narrowing).
        - actor: who ordered the tighten (recorded on the receipt).

        Cannot tighten a revoked permit or one whose effective window has
        passed — fail closed. Writes a TIGHTEN receipt with old→new for
        every narrowed clause, then cascades to every descendant: each
        child keeps the narrower of its own authority and the new bound
        (cascade_from on the receipt). Tighten-only holds at every level —
        a descendant already narrower than the new bound is untouched.
        """
        now = datetime.now(timezone.utc)
        if (
            cap_cents is None
            and not remove_merchants
            and expiry is None
            and approval_threshold_cents is None
        ):
            raise ValueError(
                "tighten requires at least one of cap_cents, "
                "remove_merchants, expiry, approval_threshold_cents"
            )
        if not isinstance(actor, str) or not actor.strip():
            raise ValueError("actor must be a non-empty string")
        actor = actor.strip()

        # Validate the requested narrowing once, up front.
        if cap_cents is not None:
            _validate_amount(cap_cents)
        if approval_threshold_cents is not None:
            _validate_amount(approval_threshold_cents)
        if remove_merchants is not None and (
            not isinstance(remove_merchants, list)
            or not remove_merchants
            or not all(isinstance(m, str) and m.strip() for m in remove_merchants)
        ):
            raise ValueError(
                "remove_merchants must be a non-empty list of merchant id strings"
            )
        rm = {m.strip() for m in remove_merchants} if remove_merchants else set()
        if expiry is not None:
            if expiry.tzinfo is None:
                raise ValueError("expiry must be timezone-aware")
            if expiry <= now:
                raise ValueError("tighten expiry must be in the future")

        permit = self.get(permit_id)
        if permit is None:
            raise UnknownPermit(permit_id)

        # Apply to the target, then cascade breadth-first (parents before
        # children). Each permit is locked individually while updated — no
        # nested locking, so no new lock order is introduced.
        queue: list[tuple[str, str | None]] = [(permit_id, None)]
        seen = {permit_id}
        first_receipt: Receipt | None = None
        while queue:
            pid, cascade_from = queue.pop(0)
            target = self.get(pid)
            if target is None:
                continue
            with target._lock:
                if target.revoked:
                    continue
                eff_cap, _, eff_allow, eff_expiry, _ = self._effective(target)
                if now >= eff_expiry:
                    continue
                changes: dict[str, dict] = {}
                if cap_cents is not None and cap_cents < eff_cap:
                    changes["cap_cents"] = {"from": eff_cap, "to": cap_cents}
                if approval_threshold_cents is not None:
                    eff_threshold = self._effective_threshold(target)
                    if eff_threshold is None or (
                        approval_threshold_cents < eff_threshold
                    ):
                        changes["approval_threshold_cents"] = {
                            "from": eff_threshold,
                            "to": approval_threshold_cents,
                        }
                if rm:
                    if rm <= set(eff_allow):
                        new_allow = set(eff_allow) - rm
                        if new_allow:
                            changes["allowlist"] = {
                                "from": sorted(eff_allow),
                                "to": sorted(new_allow),
                                "removed": sorted(rm),
                            }
                if expiry is not None and expiry < eff_expiry:
                    changes["expiry"] = {
                        "from": eff_expiry.isoformat(),
                        "to": expiry.isoformat(),
                    }
                if not changes:
                    # Already narrower than the new bound (tighten-only):
                    # untouched, but the cascade still flows below.
                    pass
                else:
                    if "cap_cents" in changes:
                        target.tighten_cap_cents = cap_cents
                    if "allowlist" in changes:
                        base = (
                            set(target.tighten_allowlist)
                            if target.tighten_allowlist is not None
                            else set(target.allowlist)
                        )
                        target.tighten_allowlist = tuple(sorted(base - rm))
                    if "expiry" in changes:
                        target.tighten_expiry = expiry
                    if "approval_threshold_cents" in changes:
                        target.tighten_approval_threshold_cents = (
                            approval_threshold_cents
                        )
                    payload: dict = {
                        "permit_id": target.permit_id,
                        "agent_id": target.agent_id,
                        "actor": actor,
                        "changes": changes,
                    }
                    if cascade_from is not None:
                        payload["cascade_from"] = cascade_from
                    receipt = self.ledger.append("TIGHTEN", payload)
                    if first_receipt is None:
                        first_receipt = receipt
            # Queue children regardless of whether this level narrowed —
            # a grandchild may still be wider than the new bound.
            with self._store_lock:
                kids = list(self._children.get(pid, []))
            for cid in kids:
                if cid not in seen:
                    seen.add(cid)
                    queue.append((cid, pid))
        if first_receipt is None:
            # The target itself was already narrower than every requested
            # bound: tighten-only rejects the no-op.
            raise ValueError(
                "tighten changes nothing: permit is already at or below "
                "every requested bound (tighten-only)"
            )
        return permit, first_receipt

    def raise_calibration_tau(
        self, permit_id: str, tau, actor: str = "human"
    ) -> TauResult:
        """
        Raise the ADVISORY calibration tau on a live permit. Raise-only:
        the grant-time tau is the floor. Refusals (lowering, no-op, out
        of (0, 1], non-number, unknown/revoked/expired permit) write a
        TAU_REFUSED receipt and leave the stored tau unchanged; success
        writes TAU_RAISED with from/to. Never changes authority: tau is
        not a clause of the 4-clause check.
        """
        now = datetime.now(timezone.utc)
        actor = actor.strip() if isinstance(actor, str) and actor.strip() else "human"
        try:
            new_tau: float | None = validate_tau(tau)
        except ValueError:
            new_tau = None
        # Out-of-range / non-number requests are recorded by repr (keeps
        # NaN/inf out of the hashed JSON payload).
        requested = new_tau if new_tau is not None else repr(tau)

        def refuse(reason: str, current: float | None) -> TauResult:
            receipt = self.ledger.append(
                "TAU_REFUSED",
                {
                    "permit_id": permit_id,
                    "actor": actor,
                    "requested_tau": requested,
                    "current_tau": current,
                    "reason": reason,
                },
            )
            return TauResult(False, reason, current, receipt)

        permit = self.get(permit_id)
        if permit is None:
            return refuse("unknown_permit", None)
        if new_tau is None:
            with permit._lock:
                current = permit.calibration_tau
            return refuse("tau_out_of_range", current)
        with permit._lock:
            current = permit.calibration_tau
            if permit.revoked:
                reason = "revoked"
            elif now >= self._effective(permit)[3]:
                reason = "expired"
            elif new_tau < current:
                reason = "tau_lowering_refused"
            elif new_tau == current:
                reason = "tau_unchanged"
            else:
                reason = None
            if reason is not None:
                return refuse(reason, current)
            permit.calibration_tau = new_tau
            receipt = self.ledger.append(
                "TAU_RAISED",
                {
                    "permit_id": permit.permit_id,
                    "agent_id": permit.agent_id,
                    "actor": actor,
                    "from": current,
                    "to": new_tau,
                },
            )
            return TauResult(True, "raised", new_tau, receipt)

    @staticmethod
    def _effective(
        permit: Permit,
    ) -> tuple[int, bool, frozenset[str], datetime, bool]:
        """
        Per-permit min-gate: the narrowest of the granted clauses and the
        tighten overlays. Returns (cap_cents, cap_tightened, allowlist,
        expiry, expiry_tightened). Ancestor tightens arrive via cascade at
        tighten() time, so no lineage walk is needed at check time.
        Caller must hold permit._lock.
        """
        cap = permit.cap_cents
        cap_tightened = False
        if permit.tighten_cap_cents is not None and permit.tighten_cap_cents < cap:
            cap = permit.tighten_cap_cents
            cap_tightened = True
        allow = set(permit.allowlist)
        if permit.tighten_allowlist is not None:
            allow &= set(permit.tighten_allowlist)
        expiry = permit.expiry
        expiry_tightened = False
        if permit.tighten_expiry is not None and permit.tighten_expiry < expiry:
            expiry = permit.tighten_expiry
            expiry_tightened = True
        return cap, cap_tightened, frozenset(allow), expiry, expiry_tightened

    @staticmethod
    def _evaluate(permit: Permit, amount_cents: int, merchant_id: str, now: datetime) -> str | None:
        """
        The 4-clause authority evaluation through the tighten-only min-gate.
        Returns the block reason, or None when the attempt is allowed.
        Caller must hold permit._lock. Amount is assumed pre-validated by
        _validate_amount.
        """
        if permit.revoked:
            return "revoked"
        cap, cap_tightened, allow, expiry, expiry_tightened = (
            PermitStore._effective(permit)
        )
        if now >= expiry:
            return "tightened_expiry_passed" if expiry_tightened else "expired"
        if merchant_id not in allow:
            return "merchant_not_allowed"
        if amount_cents > cap - permit.reserved_cents - permit.captured_cents:
            return "tightened_cap_exceeded" if cap_tightened else "over_remaining_cap"
        return None

    def _advisory_calibration(self, permit: Permit, now: datetime) -> dict:
        """
        ADVISORY calibration record for a receipt payload. Called by check()
        only after the authority decision is final; the result is data on
        the receipt, never an input to the decision. Caller holds
        permit._lock. Never raises: a failure is recorded as unavailable.

        n_receipts = CAPTURED receipts on this permit (verified captures);
        chain_ok = the ledger's own verify_chain(). Fixture weights/scales.
        """
        try:
            cap, _, allow, expiry, _ = self._effective(permit)
            granted = set(permit.allowlist)
            coverage = len(allow & granted) / len(granted) if granted else 0.0
            x = _calibration.features(
                permit.remaining_cents(),
                permit.cap_cents,
                (expiry - now).total_seconds() / 3600.0,
                coverage,
            )
            n = sum(
                1
                for r in self.ledger.receipts()
                if r.event_type == "CAPTURED"
                and r.payload.get("permit_id") == permit.permit_id
            )
            chain_ok, _ = self.ledger.verify_chain()
            S = _calibration.score(
                x,
                _calibration.FIXTURE_SPEC_X,
                _calibration.FIXTURE_WEIGHTS,
                _calibration.FIXTURE_SCALES,
                n,
                chain_ok,
            )
            tau = permit.calibration_tau
            return {
                "advisory": True,
                "S": S,
                "tau": tau,
                "verdict": _calibration.advisory_verdict(S, tau),
                "n_receipts": n,
                "chain_ok": chain_ok,
            }
        except Exception as exc:  # advisory: must never affect the spend
            return {
                "advisory": True,
                "status": "unavailable",
                "error": type(exc).__name__,
            }

    def eligible(
        self,
        permit_id: str,
        amount_cents: int,
        merchant_id: str,
        now: datetime | None = None,
    ) -> CheckResult:
        """
        READ-ONLY authority evaluation: the same 4-clause logic as check()
        plus amount validation, but it reserves nothing and writes no
        receipt. The server's /check route uses this. receipt is None.
        """
        now = now or datetime.now(timezone.utc)
        try:
            _validate_amount(amount_cents)
        except ValueError:
            return CheckResult(False, "invalid_amount")

        permit = self.get(permit_id)
        if permit is None:
            return CheckResult(False, "unknown_permit")

        chain = self.lineage(permit_id)
        with permit._lock:
            reason = self._evaluate(permit, amount_cents, merchant_id, now)
            if reason is None:
                # Delegation lineage: a spend under a sub-permit is only
                # allowed while every ancestor is live. Fail closed.
                reason = self._lineage_block_reason(chain, now)
        if reason is not None:
            return CheckResult(False, reason)
        return CheckResult(True, "allowed")

    def check(
        self,
        permit_id: str,
        amount_cents: int,
        merchant_id: str,
        now: datetime | None = None,
    ) -> CheckResult:
        """
        Evaluate a spend attempt: validate → eligible() → reserve + ALLOWED
        receipt. On BLOCKED, writes a BLOCKED receipt and returns — PayPal
        is never touched. Invalid amounts do NOT raise: they are recorded
        as BLOCKED receipts with reason "invalid_amount".
        """
        now = now or datetime.now(timezone.utc)
        try:
            _validate_amount(amount_cents)
        except ValueError:
            receipt = self.ledger.append(
                "BLOCKED",
                {
                    "permit_id": permit_id,
                    "merchant_id": merchant_id,
                    "amount_cents": (
                        amount_cents
                        if isinstance(amount_cents, int)
                        and not isinstance(amount_cents, bool)
                        else repr(amount_cents)
                    ),
                    "reason": "invalid_amount",
                },
            )
            return CheckResult(False, "invalid_amount", receipt)

        permit = self.get(permit_id)
        if permit is None:
            receipt = self.ledger.append(
                "BLOCKED",
                {"permit_id": permit_id, "reason": "unknown_permit"},
            )
            return CheckResult(False, "unknown_permit", receipt)

        # Read-only authority evaluation first (no reservation, no receipt).
        # This is the shared logic the server's /check route also uses.
        probe = self.eligible(permit_id, amount_cents, merchant_id, now=now)

        chain = self.lineage(permit_id)
        with permit._lock:
            # Authoritative re-evaluation under the per-permit lock: the
            # probe is read-only, so the lock serializes reservation
            # against concurrent attempts (C1) and against e-stop. The
            # lock's view wins over the probe's (reservations may have
            # been released between the two).
            reason = self._evaluate(permit, amount_cents, merchant_id, now)
            if reason is None:
                # Delegation lineage gate, re-applied authoritatively:
                # ancestor liveness under each ancestor's own lock,
                # child -> ancestor order (cannot cycle: delegation depth
                # strictly increases).
                reason = self._lineage_block_reason(chain, now)
            # The authority decision (reason) is final above. The advisory
            # calibration score is recorded on the receipt and never read.
            calibration = self._advisory_calibration(permit, now)
            if reason is not None:
                receipt = self.ledger.append(
                    "BLOCKED",
                    {
                        "permit_id": permit.permit_id,
                        "agent_id": permit.agent_id,
                        "amount_cents": amount_cents,
                        "merchant_id": merchant_id,
                        "reason": reason,
                        "remaining_cents": permit.remaining_cents(),
                        "calibration": calibration,
                    },
                )
                return CheckResult(False, reason, receipt)

            # ALLOWED — reserve the amount against the cap.
            permit.reserved_cents += amount_cents
            auth_id = f"auth_{uuid.uuid4().hex[:12]}"
            permit.in_flight[auth_id] = amount_cents
            try:
                receipt = self.ledger.append(
                    "ALLOWED",
                    {
                        "permit_id": permit.permit_id,
                        "agent_id": permit.agent_id,
                        "amount_cents": amount_cents,
                        "merchant_id": merchant_id,
                        "auth_id": auth_id,
                        "remaining_cents": permit.remaining_cents(),
                        "calibration": calibration,
                    },
                )
            except Exception:
                # Fail closed: a ledger write failure must not leave a
                # phantom reservation without an ALLOWED receipt, and must
                # never look like a successful spend.
                permit.reserved_cents -= amount_cents
                permit.in_flight.pop(auth_id, None)
                raise
            return CheckResult(True, "allowed", receipt)

    def _rollup_capture(self, permit: Permit, amount_cents: int) -> None:
        """
        Walk the delegation chain: each ancestor moves reserved→captured
        by the captured amount. The delegation carve already encumbers the
        parent, so only captures (real money out) move the parent's books —
        child reserves and voids stay within the carve.
        """
        pid = permit.parent_id
        while pid is not None:
            parent = self.get(pid)
            if parent is None:
                break
            with parent._lock:
                parent.reserved_cents -= amount_cents
                parent.captured_cents += amount_cents
                pid = parent.parent_id

    def settle_capture(self, permit_id: str, auth_id: str) -> Receipt:
        """Move a reservation to captured (called by the settlement layer)."""
        permit = self.get(permit_id)
        if permit is None:
            raise UnknownPermit(permit_id)
        with permit._lock:
            amount = permit.in_flight.pop(auth_id, None)
            if amount is None:
                raise UnknownAuthId(auth_id)
            permit.reserved_cents -= amount
            permit.captured_cents += amount
            receipt = self.ledger.append(
                "CAPTURED",
                {
                    "permit_id": permit_id,
                    "auth_id": auth_id,
                    "amount_cents": amount,
                    "remaining_cents": permit.remaining_cents(),
                },
            )
        # Roll the capture up the delegation chain (outside the child lock:
        # lock order is always ancestor-after-descendant via get()).
        self._rollup_capture(permit, amount)
        return receipt

    def settle_void(self, permit_id: str, auth_id: str) -> Receipt:
        """Release a reservation (called by the settlement layer on void)."""
        permit = self.get(permit_id)
        if permit is None:
            raise UnknownPermit(permit_id)
        with permit._lock:
            amount = permit.in_flight.pop(auth_id, None)
            if amount is None:
                raise UnknownAuthId(auth_id)
            permit.reserved_cents -= amount
            return self.ledger.append(
                "VOIDED",
                {
                    "permit_id": permit_id,
                    "auth_id": auth_id,
                    "amount_cents": amount,
                    "remaining_cents": permit.remaining_cents(),
                },
            )

    def estop(self, permit_id: str) -> tuple[Receipt, list[str]]:
        """
        Emergency stop: revoke the permit immediately. Returns the e-stop
        receipt and the in-flight authorization ids the settlement layer
        must void. No further check() can pass after this.

        The e-stop cascades: every descendant permit is revoked too (see
        estop_cascade()); use estop_cascade() to get the descendants'
        in-flight holds as well.
        """
        receipt, in_flight = self.estop_cascade(permit_id)
        return receipt, in_flight.get(permit_id, [])

    def estop_cascade(
        self, permit_id: str
    ) -> tuple[Receipt, dict[str, list[str]]]:
        """
        E-stop a permit and revoke every descendant (REVOKED_CASCADE
        receipt each). Returns the E-STOP receipt and {permit_id:
        [in-flight auth_ids]} for the root and every descendant with
        holds, so the settlement layer can void in-flight child holds.

        Runs under the settlement gate, so it is atomic with respect to
        the release-time admission recheck + capture: an E-STOP receipt is
        either before the recheck (capture refused) or after CAPTURED.
        """
        root = self.get(permit_id)
        if root is None:
            raise UnknownPermit(permit_id)
        with self.settlement_gate:
            with root._lock:
                root.revoked = True
                root_ids = list(root.in_flight.keys())
                receipt = self.ledger.append(
                    "E-STOP",
                    {
                        "permit_id": permit_id,
                        "agent_id": root.agent_id,
                        "in_flight_auth_ids": root_ids,
                        "reserved_cents_released": root.reserved_cents,
                    },
                )
            in_flight: dict[str, list[str]] = {permit_id: root_ids}
            with self._store_lock:
                order: list[str] = []
                queue = list(self._children.get(permit_id, []))
                while queue:
                    pid = queue.pop(0)
                    order.append(pid)
                    queue.extend(self._children.get(pid, []))
            for pid in order:
                permit = self.get(pid)
                if permit is None:
                    continue
                with permit._lock:
                    ids = list(permit.in_flight.keys())
                    if ids:
                        in_flight[pid] = ids
                    if permit.revoked:
                        continue
                    permit.revoked = True
                    self.ledger.append(
                        "REVOKED_CASCADE",
                        {
                            "permit_id": pid,
                            "agent_id": permit.agent_id,
                            "in_flight_auth_ids": ids,
                            "parent_id": permit.parent_id,
                            "cascade_from": permit_id,
                        },
                    )
        return receipt, in_flight

    def release_block_reason(
        self, permit_id: str, now: datetime | None = None
    ) -> str | None:
        """
        Release-time admission: None if a hold on this permit may capture
        now, else the fail-closed reason. Checks the permit AND every
        ancestor for revocation/expiry. The settlement layer calls this
        under settlement_gate immediately before the provider capture.
        Caller must not hold any permit or store lock.
        """
        now = now or datetime.now(timezone.utc)
        permit = self.get(permit_id)
        if permit is None:
            return "unknown_permit"
        chain = self.lineage(permit_id)
        with permit._lock:
            if permit.revoked:
                return "revoked"
            if now >= permit.expiry:
                return "expired"
        return self._lineage_block_reason(chain, now)

    def revoke_subtree(
        self, permit_id: str
    ) -> tuple[Receipt, dict[str, list[str]]]:
        """
        Revoke a permit and every descendant permit (cascade). Returns the
        root receipt and {permit_id: [in-flight auth_ids]} for the whole
        subtree, so the settlement layer can void every outstanding hold.

        Unspent delegation carves are NOT released here — call
        release_carve() per revoked child after in-flight holds are voided
        (post-order: children before parents).

        Concurrency note: delegate() and revoke_subtree() are each atomic,
        but a delegate() racing revoke_subtree() may create a child after
        the subtree was collected. Callers must serialize permit-graph
        mutation (delegate vs revoke); spend-path races against revocation
        are closed by the per-permit lock + capture-time re-admission.
        """
        root = self.get(permit_id)
        if root is None:
            raise UnknownPermit(permit_id)
        # Collect the subtree (parents before children) under the store lock.
        with self._store_lock:
            order = [permit_id]
            queue = [permit_id]
            while queue:
                pid = queue.pop(0)
                for cid in self._children.get(pid, []):
                    order.append(cid)
                    queue.append(cid)
        in_flight: dict[str, list[str]] = {}
        root_receipt: Receipt | None = None
        # Under the settlement gate: atomic vs. release-time recheck + capture.
        with self.settlement_gate:
            for pid in order:
                permit = self.get(pid)
                if permit is None:
                    continue
                with permit._lock:
                    ids = list(permit.in_flight.keys())
                    if ids:
                        in_flight[pid] = ids
                    if permit.revoked:
                        continue
                    permit.revoked = True
                    event = "E-STOP" if pid == permit_id else "REVOKED_CASCADE"
                    receipt = self.ledger.append(
                        event,
                        {
                            "permit_id": pid,
                            "agent_id": permit.agent_id,
                            "in_flight_auth_ids": ids,
                            "parent_id": permit.parent_id,
                        },
                    )
                    if pid == permit_id:
                        root_receipt = receipt
        if root_receipt is None:
            # Unreachable: the root exists (checked above) and permits are
            # never deleted, so the loop always visits it. Loud failure
            # rather than an assert, so -O cannot silence it.
            raise RuntimeError("root permit vanished during revoke_subtree")
        return root_receipt, in_flight

    def release_carve(self, permit_id: str) -> Receipt | None:
        """
        Release a revoked child's unspent delegation carve back to its
        parent. Call after in-flight holds are voided (so reserved reflects
        only the carve), post-order: children before parents. Returns the
        CARVE_RELEASED receipt, or None when there is nothing to release.
        """
        permit = self.get(permit_id)
        if permit is None or permit.parent_id is None:
            return None
        parent = self.get(permit.parent_id)
        if parent is None:
            return None
        # Lock order: parent before child, consistent with delegate().
        with parent._lock:
            with permit._lock:
                if not permit.revoked:
                    return None
                if permit.parent_id is None:
                    # Already released (idempotent).
                    return None
                unspent = (
                    permit.cap_cents
                    - permit.captured_cents
                    - permit.reserved_cents
                )
                if unspent < 0:
                    raise RuntimeError(
                        "delegation carve accounting went negative"
                    )
                if parent.reserved_cents < unspent:
                    # Fail closed: the parent's books cannot cover the
                    # carve being returned. Loud, no money moves.
                    raise RuntimeError(
                        "parent reserved cannot cover carve release"
                    )
                parent.reserved_cents -= unspent
                parent_remaining = parent.remaining_cents()
                parent_id = permit.parent_id
                # Clear the link: a second call is a no-op.
                permit.parent_id = None
        with self._store_lock:
            kids = self._children.get(parent_id, [])
            if permit_id in kids:
                kids.remove(permit_id)
        return self.ledger.append(
            "CARVE_RELEASED",
            {
                "child_permit_id": permit_id,
                "parent_permit_id": parent_id,
                "released_cents": unspent,
                "parent_remaining_cents": parent_remaining,
            },
        )
