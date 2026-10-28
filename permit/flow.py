"""
Spend pipeline: the only path from a spend attempt to money movement.

    spend():   merchant binding -> permit.check -> BLOCKED? write receipt,
               STOP. PayPal is never touched (not even the authorize call).
               ALLOWED?  reserve cap, track the outstanding operation,
               take a PayPal AUTHORIZE hold, recheck the permit AFTER the
               external call (e-stop/expiry race), register the escrow
               with the release-verifier.
    release(): release-verifier's verify_and_capture - the sole capture path.
    estop():   revoke the permit, void every in-flight escrow AND every
               outstanding authorized-but-unregistered hold whose provider
               void is confirmed. Unconfirmed cleanup stays reserved and is
               reported on EstopResult.unresolved. Cascades to descendants.
    delegate(): carve a sub-permit out of a permit's remaining cap.
    revoke_cascade():
               revoke a permit and all descendants, void every in-flight
               hold in the subtree, release unspent delegation carves.

Invariant: no PayPal authorize or capture is reachable without an ALLOWED
receipt on the same permit for the same attempt. The pipeline is the only
caller of paypal.authorize() and verifier.register().

NeedsPayerApproval (sandbox): authorize() may raise a provider exception
named NeedsPayerApproval carrying order_id/approval_url. spend() converts
it to ApprovalRequired (a Permit-layer exception — no settlement import),
keeps the cap reservation held, and NEVER settles. The caller resumes the
SAME operation via resume_operation() after payer approval; calling
spend() again would double-reserve the cap.

The permit package's isolation still holds: this module may import from
settlement; permit/permit.py itself MUST NOT import any PayPal client
(enforced by import test). NeedsPayerApproval is caught duck-typed (by
class name), never imported.

Unregistered cleanup is in-memory only. A reservation is released only
after paypal.void returns the same provider auth id with status VOIDED.
Timeout, exception, a missing result, a mismatched id, PENDING, and any
other status keep the permit auth id, the provider auth id, and the
reservation. retry_cleanup() retries that same identity and does not
authorize or capture. A process restart drops the identity with the rest
of this process's state. This is not durable recovery and not a
production safety claim.
"""

from __future__ import annotations

import inspect
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .ledger import Ledger, Receipt
from .permit import PermitStore
from settlement.verifier import Escrow, PredicateType


@dataclass(frozen=True)
class SpendAttempt:
    allowed: bool
    reason: str
    escrow_id: str | None
    receipts: tuple[Receipt, ...]
    # Set when the attempt is gated on principal approval.
    approval_id: str | None = None


class ApprovalRequired(Exception):
    """
    Raised when the PayPal client needs payer approval before authorizing.

    The cap reservation STAYS HELD and the outstanding operation STAYS
    tracked — resume the same operation with resume_operation(); do NOT
    call spend() again (that would double-reserve the cap).
    """

    def __init__(
        self,
        permit_id: str,
        auth_id: str,
        order_id: str,
        approval_url: str,
        amount_cents: int,
        merchant_id: str,
        predicate_type,
        artifact_hash: str,
    ):
        super().__init__(
            f"payer approval required for order {order_id} "
            f"(permit {permit_id}, auth {auth_id})"
        )
        self.permit_id = permit_id
        self.auth_id = auth_id
        self.order_id = order_id
        self.approval_url = approval_url
        self.amount_cents = amount_cents
        self.merchant_id = merchant_id
        self.predicate_type = predicate_type
        self.artifact_hash = artifact_hash


@dataclass(frozen=True)
class EstopResult:
    """
    What estop() did to the money.

    receipt: the E-STOP event. The permit is revoked either way.
    voided: holds whose void PayPal confirmed. Those reservations are released.
    unknown_open: escrows in UNKNOWN state (a capture may still be settling).
        E-stop deliberately does NOT void these: racing a pending capture
        could double-move money. They stay reserved and reconcile() is the
        only way forward. Listed so the stop report never reads clean while
        money is still possibly in flight.

    unresolved: cleanup that is still open. Includes an outstanding hold
        with no provider id, an unconfirmed unregistered void, a registered
        escrow left in CLEANUP_PENDING, and a registered void that returned
        false while that reservation remains. These ids are not listed in
        voided. UNKNOWN capture uncertainty stays in unknown_open.
        The unresolved list lives only in this process.

    Iterates as (receipt, voided) so `receipt, voided = flow.estop(...)`
    keeps working at every existing call site.
    """

    receipt: Receipt
    voided: list[str]
    unknown_open: list[str]
    unresolved: list[str] = field(default_factory=list)

    def __iter__(self):
        yield self.receipt
        yield self.voided


def _is_needs_payer_approval(exc: BaseException) -> bool:
    """
    Duck-typed NeedsPayerApproval check. The sandbox client raises an
    exception of that name carrying order_id and approval_url; we match
    by class name so permit/flow.py needs no settlement import.
    """
    return type(exc).__name__ == "NeedsPayerApproval"


class SpendPipeline:
    """Wires the permit check to the PayPal hold and the release-verifier."""

    def __init__(self, permits: PermitStore, paypal, verifier, ledger: Ledger | None = None):
        self.permits = permits
        self.paypal = paypal
        self.verifier = verifier
        # NOTE: explicit None check - an empty Ledger is falsy via __len__.
        self.ledger = ledger if ledger is not None else permits.ledger
        # permit-level auth_id -> escrow_id, so e-stop can void in-flight holds.
        self._auth_to_escrow: dict[str, str] = {}
        # permit-level auth_id -> {"permit_id": ..., "paypal_auth_id": ...},
        # tracked BEFORE the external authorize call (P1-1 e-stop race fix).
        # Entries are removed once the escrow is registered (6f) or an
        # unregistered void is confirmed VOIDED (6e). An unconfirmed void
        # stays here with cleanup_pending set. In-memory only.
        self._outstanding: dict[str, dict] = {}
        self._outstanding_lock = threading.Lock()
        # Permit auth ids whose unregistered void was confirmed VOIDED.
        # Resume must not recreate these identities or authorize again.
        # In-memory only; a restart drops the set.
        self._cleanup_confirmed: set[str] = set()
        self._cleanup_committing: set[str] = set()
        # Whether this paypal client accepts the idempotency_key kwarg on
        # authorize(). Detected once from the bound method's signature.
        self._authorize_kw: bool | None = None

    # -- PayPal call helpers -------------------------------------------------

    def _authorize(self, amount_cents: int, merchant_id: str, idempotency_key: str):
        """Authorize via the paypal client, passing idempotency_key only if accepted."""
        if self._authorize_kw is None:
            try:
                params = inspect.signature(self.paypal.authorize).parameters
                self._authorize_kw = "idempotency_key" in params or any(
                    p.kind == inspect.Parameter.VAR_KEYWORD
                    for p in params.values()
                )
            except (TypeError, ValueError):
                self._authorize_kw = False
        if self._authorize_kw:
            return self.paypal.authorize(
                amount_cents, merchant_id, idempotency_key=idempotency_key
            )
        return self.paypal.authorize(amount_cents, merchant_id)

    def _track_outstanding(self, auth_id: str, permit_id: str) -> None:
        with self._outstanding_lock:
            self._outstanding[auth_id] = {"permit_id": permit_id}

    def _set_outstanding_paypal_auth(self, auth_id: str, paypal_auth_id: str) -> None:
        with self._outstanding_lock:
            entry = self._outstanding.get(auth_id)
            if entry is not None:
                entry["paypal_auth_id"] = paypal_auth_id

    def _drop_outstanding(self, auth_id: str) -> None:
        with self._outstanding_lock:
            self._outstanding.pop(auth_id, None)

    def _reservation_held(self, permit_id: str, auth_id: str) -> bool:
        permit = self.permits.get(permit_id)
        if permit is None:
            return False
        return auth_id in permit.in_flight

    def _hold_for_cleanup(
        self,
        auth_id: str,
        permit_id: str,
        paypal_auth_id: str | None,
    ) -> None:
        """Record the unregistered operation before the provider void is attempted."""
        with self._outstanding_lock:
            entry = self._outstanding.get(auth_id)
            if entry is None:
                entry = {"permit_id": permit_id}
                self._outstanding[auth_id] = entry
            entry["permit_id"] = permit_id
            if paypal_auth_id:
                entry["paypal_auth_id"] = paypal_auth_id
            entry["cleanup_pending"] = True

    def _provider_void_confirmed(self, paypal_auth_id: str):
        """
        Confirmation is Void(auth_id=<this id>, status='VOIDED') only.
        A missing result, mismatched id, PENDING, any other status, and any
        exception (including timeout) are unconfirmed. Does not authorize
        or capture.
        """
        try:
            result = self.paypal.void(paypal_auth_id)
        except Exception:
            return None
        if result is None:
            return None
        if getattr(result, "auth_id", None) != paypal_auth_id:
            return None
        if getattr(result, "status", None) != "VOIDED":
            return None
        return result

    def _commit_confirmed_void(self, permit_id: str, auth_id: str) -> bool:
        """Release the reservation once, then forget the outstanding identity."""
        with self._outstanding_lock:
            if auth_id in self._cleanup_confirmed:
                return True
            if auth_id in self._cleanup_committing:
                return False
            self._cleanup_committing.add(auth_id)
        released = False
        try:
            if self._reservation_held(permit_id, auth_id):
                self.permits.settle_void(permit_id, auth_id)
            released = True
        finally:
            with self._outstanding_lock:
                self._cleanup_committing.discard(auth_id)
                if released:
                    self._outstanding.pop(auth_id, None)
                    self._cleanup_confirmed.add(auth_id)
        return released

    def _release_if_void_confirmed(
        self,
        permit_id: str,
        auth_id: str,
        paypal_auth_id: str | None,
    ) -> bool:
        """
        Track the operation first. Release cap only when void is confirmed
        for that provider auth id. Otherwise keep the reservation and the
        identity for retry_cleanup().
        """
        self._hold_for_cleanup(auth_id, permit_id, paypal_auth_id)
        if not paypal_auth_id:
            return False
        if self._provider_void_confirmed(paypal_auth_id) is None:
            return False
        return self._commit_confirmed_void(permit_id, auth_id)

    def retry_cleanup(self, auth_id: str) -> bool:
        """
        Retry one unregistered void with the same provider auth id.

        True when that hold was already confirmed, or this call observes
        VOIDED and releases cap once. False while the void is unconfirmed;
        the reservation stays held. Does not call authorize, authorize_order,
        or capture. In-memory only: restart drops this identity.
        """
        with self._outstanding_lock:
            if auth_id in self._cleanup_confirmed:
                return True
            entry = self._outstanding.get(auth_id)
            if entry is None or not entry.get("cleanup_pending"):
                return False
            paypal_auth_id = entry.get("paypal_auth_id")
            permit_id = entry.get("permit_id")
        if not paypal_auth_id or not permit_id:
            return False
        if self._provider_void_confirmed(paypal_auth_id) is None:
            return False
        return self._commit_confirmed_void(permit_id, auth_id)

    def _find_check_receipt(self, auth_id: str) -> Receipt | None:
        """Locate the ALLOWED receipt for an outstanding auth_id, if any."""
        return self.ledger.allowed_receipt(auth_id)

    # -- spend ----------------------------------------------------------------

    def spend(
        self,
        permit_id: str,
        amount_cents: int,
        merchant_id: str,
        predicate_type,
        artifact_hash: str,
        approval_id: str | None = None,
    ) -> SpendAttempt:
        """
        One spend attempt. Returns ALLOWED + escrow_id on success, or
        BLOCKED with the receipt and zero PayPal traffic.

        Principal approvals: when the permit's approval threshold is set
        and amount_cents exceeds it, the attempt does NOT reserve — it
        returns pending_principal_approval with an approval_id. The
        principal approves/denies out of band; complete_approved_spend()
        then re-runs the full authority check (fail-closed if the budget
        moved). Pass approval_id to execute an already-approved request;
        the id binds the exact (permit, amount, merchant) — anything else
        is rejected as invalid_approval.

        With the real sandbox client, paypal.authorize() may raise
        NeedsPayerApproval: the cap reservation stays held and the caller
        resumes with resume_operation() after the payer approves - but
        must NOT call spend() again (that would double-reserve the cap).
        """
        # (6a) Merchant binding: the permit's allowlist is a label; the
        # binding to the actual PayPal payee happens here, before any
        # authority evaluation. No reservation is consumed.
        bound = getattr(self.paypal, "merchant_account_id", None)
        if bound is not None and merchant_id != bound:
            receipt = self.ledger.append(
                "BLOCKED",
                {
                    "permit_id": permit_id,
                    "amount_cents": amount_cents,
                    "merchant_id": merchant_id,
                    "bound_merchant_account_id": bound,
                    "reason": "merchant_not_bound",
                },
            )
            return SpendAttempt(False, "merchant_not_bound", None, (receipt,))

        # (6a2) Principal-approval gate. Runs BEFORE check() so a pending
        # request never reserves cap. claim_approval() is atomic under
        # _store_lock (approved → claimed) so two concurrent spends cannot
        # both observe the same approval as approved.
        claimed = False
        if approval_id is not None:
            if not self.permits.claim_approval(
                approval_id,
                permit_id=permit_id,
                amount_cents=amount_cents,
                merchant_id=merchant_id,
            ):
                receipt = self.ledger.append(
                    "BLOCKED",
                    {
                        "permit_id": permit_id,
                        "amount_cents": amount_cents
                        if isinstance(amount_cents, int)
                        else repr(amount_cents),
                        "merchant_id": merchant_id,
                        "reason": "invalid_approval",
                        "approval_id": approval_id,
                    },
                )
                return SpendAttempt(False, "invalid_approval", None, (receipt,))
            claimed = True
        else:
            threshold = self.permits.approval_threshold(permit_id)
            if (
                threshold is not None
                and isinstance(amount_cents, int)
                and not isinstance(amount_cents, bool)
                and self.permits.approval_needed(permit_id, amount_cents)
            ):
                # The 4-clause check must pass first: no approval request
                # for a spend the authority would refuse anyway.
                probe = self.permits.eligible(
                    permit_id, amount_cents, merchant_id
                )
                if probe.allowed:
                    predicate_value = (
                        predicate_type.value
                        if hasattr(predicate_type, "value")
                        else str(predicate_type)
                    )
                    approval = self.permits.request_approval(
                        permit_id,
                        amount_cents,
                        merchant_id,
                        predicate_value,
                        artifact_hash,
                    )
                    receipt = self.ledger.append(
                        "APPROVAL_PENDING",
                        {
                            "permit_id": permit_id,
                            "amount_cents": amount_cents,
                            "merchant_id": merchant_id,
                            "reason": "pending_principal_approval",
                            "approval_id": approval.approval_id,
                            "threshold_cents": threshold,
                        },
                    )
                    return SpendAttempt(
                        False,
                        "pending_principal_approval",
                        None,
                        (receipt,),
                        approval.approval_id,
                    )
                # else: fall through to check() for the authoritative BLOCKED.

        # (6b) check() as before (ALLOWED reserves cap).
        check = self.permits.check(permit_id, amount_cents, merchant_id)
        if not check.allowed:
            # BLOCKED: receipt written by check(). PayPal is never called.
            # Restore a claimed approval so the principal's word stands;
            # only the authority recheck failed. The agent may retry
            # complete_approved_spend() later.
            if claimed:
                self.permits.restore_approval(approval_id)
            return SpendAttempt(False, check.reason, None, (check.receipt,))

        if claimed:
            # The principal's word is now spent: single-consumption, so one
            # approval can never authorize two holds.
            self.permits.consume_approval(approval_id)

        auth_id = check.receipt.payload["auth_id"]
        # (6c) Track the outstanding operation BEFORE the external call,
        # so an e-stop landing mid-authorize can find and void it.
        self._track_outstanding(auth_id, permit_id)

        # (6d) The ONLY paypal.authorize call path in the codebase.
        try:
            pp_auth = self._authorize(
                amount_cents,
                merchant_id,
                idempotency_key=f"{permit_id}:{auth_id}:authorize",
            )
        except Exception as exc:
            if _is_needs_payer_approval(exc):
                # (6d-approval) Reservation stays held; do NOT settle.
                raise ApprovalRequired(
                    permit_id=permit_id,
                    auth_id=auth_id,
                    order_id=getattr(exc, "order_id", ""),
                    approval_url=getattr(exc, "approval_url", ""),
                    amount_cents=amount_cents,
                    merchant_id=merchant_id,
                    predicate_type=predicate_type,
                    artifact_hash=artifact_hash,
                ) from exc
            raise

        return self._complete_authorization(
            permit_id=permit_id,
            auth_id=auth_id,
            paypal_auth_id=pp_auth.auth_id,
            amount_cents=amount_cents,
            merchant_id=merchant_id,
            predicate_type=predicate_type,
            artifact_hash=artifact_hash,
            first_receipt=check.receipt,
        )

    def _complete_authorization(
        self,
        *,
        permit_id: str,
        auth_id: str,
        paypal_auth_id: str,
        amount_cents: int,
        merchant_id: str,
        predicate_type,
        artifact_hash: str,
        first_receipt: Receipt | None,
    ) -> SpendAttempt:
        """
        Shared tail of spend()/resume_operation(): record the PayPal auth
        id on the outstanding entry, recheck the permit AFTER the external
        call (6e), then register the escrow (6f).
        """
        self._set_outstanding_paypal_auth(auth_id, paypal_auth_id)

        # (6e) Post-authorize recheck (P1-1 fix): e-stop or expiry may have
        # landed while the external authorize was in flight.
        now = datetime.now(timezone.utc)
        permit = self.permits.get(permit_id)
        if permit is None or permit.revoked:
            reason = "revoked_during_auth"
        elif now >= permit.expiry:
            reason = "expired_during_auth"
        else:
            reason = None

        if reason is not None:
            # Release only on an explicit matching VOIDED. Anything else
            # keeps the reservation and the operation identity.
            self._release_if_void_confirmed(permit_id, auth_id, paypal_auth_id)
            return SpendAttempt(
                False, reason, None, (first_receipt,) if first_receipt else ()
            )

        # (6f) register_escrow as before, then drop the outstanding entry.
        # A rejection owns its cleanup entry; do not drop it here.
        try:
            escrow_id, authorized_receipt = self.register_escrow(
                permit_id=permit_id,
                auth_id=auth_id,
                paypal_auth_id=paypal_auth_id,
                amount_cents=amount_cents,
                merchant_id=merchant_id,
                predicate_type=predicate_type,
                artifact_hash=artifact_hash,
            )
        except RuntimeError:
            raise
        self._drop_outstanding(auth_id)
        receipts = tuple(r for r in (first_receipt, authorized_receipt) if r is not None)
        return SpendAttempt(True, "allowed", escrow_id, receipts)

    # -- approval continuation -------------------------------------------------

    def resume_operation(self, appr: ApprovalRequired) -> SpendAttempt:
        """
        Resume a spend paused on ApprovalRequired, after the payer has
        approved the order. Requires the paypal client to expose
        authorize_order(order_id, amount_cents, merchant_id); otherwise
        raises RuntimeError. If the order still needs approval, raises
        ApprovalRequired again (rebuilt from the same fields).

        A cleanup-pending identity retries that void and does not authorize.
        After the void is confirmed, a later call does not recreate the
        identity or authorize a new hold.
        """
        auth_id = appr.auth_id
        with self._outstanding_lock:
            if auth_id in self._cleanup_confirmed:
                phase = "confirmed"
            elif (self._outstanding.get(auth_id) or {}).get("cleanup_pending"):
                phase = "pending"
            else:
                phase = "approval"
        receipt = self._find_check_receipt(auth_id)
        receipts = (receipt,) if receipt is not None else ()
        if phase == "confirmed":
            return SpendAttempt(False, "cleanup_confirmed", None, receipts)
        if phase == "pending":
            if self.retry_cleanup(auth_id):
                return SpendAttempt(False, "cleanup_confirmed", None, receipts)
            return SpendAttempt(False, "cleanup_pending", None, receipts)

        authorize_order = getattr(self.paypal, "authorize_order", None)
        if authorize_order is None:
            raise RuntimeError(
                "paypal client does not expose authorize_order(); "
                "cannot resume an approval-required operation"
            )

        permit_id = appr.permit_id
        with self._outstanding_lock:
            if auth_id not in self._cleanup_confirmed:
                self._outstanding.setdefault(auth_id, {"permit_id": permit_id})

        try:
            pp_auth = authorize_order(
                appr.order_id, appr.amount_cents, appr.merchant_id
            )
        except Exception as exc:
            if _is_needs_payer_approval(exc):
                raise ApprovalRequired(
                    permit_id=appr.permit_id,
                    auth_id=appr.auth_id,
                    order_id=getattr(exc, "order_id", appr.order_id),
                    approval_url=getattr(exc, "approval_url", appr.approval_url),
                    amount_cents=appr.amount_cents,
                    merchant_id=appr.merchant_id,
                    predicate_type=appr.predicate_type,
                    artifact_hash=appr.artifact_hash,
                ) from exc
            raise

        return self._complete_authorization(
            permit_id=permit_id,
            auth_id=auth_id,
            paypal_auth_id=pp_auth.auth_id,
            amount_cents=appr.amount_cents,
            merchant_id=appr.merchant_id,
            predicate_type=appr.predicate_type,
            artifact_hash=appr.artifact_hash,
            first_receipt=self._find_check_receipt(auth_id),
        )

    # -- escrow registration ----------------------------------------------------

    def register_escrow(
        self,
        permit_id: str,
        auth_id: str,
        paypal_auth_id: str,
        amount_cents: int,
        merchant_id: str,
        predicate_type,
        artifact_hash: str,
    ) -> tuple[str, Receipt]:
        """
        Register an escrow for an already-authorized permit hold.
        Sandbox-mode resume path after NeedsPayerApproval: the PayPal hold
        exists but spend() raised before registration, so register here
        instead of re-spending.

        Fail closed (P1-1 fix): if the permit is missing, revoked, or
        expired at registration time, the operation identity is recorded
        before the void is attempted. Cap is released only when that void
        is confirmed VOIDED for the same provider auth id. RuntimeError is
        raised INSTEAD of registering. This covers the
        e-stop-between-authorize-and-register race.
        """
        now = datetime.now(timezone.utc)
        permit = self.permits.get(permit_id)
        if permit is None or permit.revoked or now >= permit.expiry:
            self._release_if_void_confirmed(permit_id, auth_id, paypal_auth_id)
            raise RuntimeError("permit revoked/expired during registration")

        escrow_id = f"esc_{uuid.uuid4().hex[:12]}"
        escrow = Escrow(
            escrow_id=escrow_id,
            permit_id=permit_id,
            auth_id=auth_id,
            paypal_auth_id=paypal_auth_id,
            amount_cents=amount_cents,
            merchant_id=merchant_id,
            predicate_type=predicate_type,
            artifact_hash=artifact_hash,
        )
        authorized_receipt = self.verifier.register(escrow)
        self._auth_to_escrow[auth_id] = escrow_id
        return escrow_id, authorized_receipt

    def release(self, escrow_id: str, evidence):
        """Evidence in, money out - or a REFUSED receipt. Pass-through."""
        return self.verifier.verify_and_capture(escrow_id, evidence)

    def approve_approval(
        self, approval_id: str, actor: str = "human"
    ):
        """
        The principal's word: approve a pending above-threshold spend.
        Approval alone moves no money; the agent completes it with
        complete_approved_spend(), which re-runs the authority check.
        """
        return self.permits.decide_approval(approval_id, True, actor=actor)

    def deny_approval(
        self, approval_id: str, actor: str = "human"
    ):
        """The principal refuses: the spend can never complete."""
        return self.permits.decide_approval(approval_id, False, actor=actor)

    def complete_approved_spend(self, approval_id: str) -> SpendAttempt:
        """
        Execute a principal-approved spend. The approval binds the exact
        (permit, amount, merchant, predicate, artifact): spend() re-runs
        the full authority check with the stored parameters, so a budget
        that moved since approval fails closed.
        """
        approval = self.permits.get_approval(approval_id)
        if approval is None or approval.status != "approved":
            receipt = self.ledger.append(
                "BLOCKED",
                {
                    "permit_id": approval.permit_id if approval else None,
                    "reason": "approval_not_approved",
                    "approval_id": approval_id,
                },
            )
            return SpendAttempt(False, "approval_not_approved", None, (receipt,))
        return self.spend(
            approval.permit_id,
            approval.amount_cents,
            approval.merchant_id,
            PredicateType(approval.predicate_type),
            approval.artifact_hash,
            approval_id=approval_id,
        )

    def delegate(
        self,
        parent_permit_id: str,
        agent_id: str,
        cap_cents: int,
        allowlist: list[str],
        expiry: datetime,
    ):
        """
        Carve a sub-permit out of a parent permit's remaining cap.
        Thin pass-through to the permit store; constraints are enforced
        there (unknown/revoked/expired parent, over-cap, merchant
        escalation, expiry beyond parent).
        """
        return self.permits.delegate(
            parent_permit_id, agent_id, cap_cents, allowlist, expiry
        )

    def _void_permit_holds(
        self, permit_id: str, in_flight_auth_ids: list[str]
    ) -> tuple[list[str], list[str], list[str]]:
        """
        Void one permit's in-flight holds: registered escrows via the
        verifier, plus outstanding authorized-but-unregistered holds
        (the P1-1 race window). Shared by estop() and revoke_cascade().

        Returns (voided, unknown_open, unresolved). Unconfirmed voids keep
        the reservation and are listed in unresolved; UNKNOWN escrows are
        listed in unknown_open and are not raced with a void. Failures are
        collected rather than raising mid-loop.
        """
        voided: list[str] = []
        unknown_open: list[str] = []
        unresolved: list[str] = []
        # Registered escrows first (existing behavior, plus unresolved reporting).
        for auth_id in in_flight_auth_ids:
            escrow_id = self._auth_to_escrow.get(auth_id)
            if escrow_id is None:
                continue
            escrow = self.verifier.get_escrow(escrow_id)
            state = getattr(escrow, "state", None) if escrow is not None else None
            if state == "UNKNOWN":
                # A capture may still be settling on the provider. Do not
                # race it with a void; leave the reservation held and point
                # the operator at reconcile(). Listed, never silent.
                unknown_open.append(escrow_id)
                continue
            if state == "CLEANUP_PENDING":
                # Pending void is not capture uncertainty. Report it and
                # leave registered settlement to retry_cleanup().
                unresolved.append(escrow_id)
                continue
            try:
                confirmed = self.verifier.void(escrow_id)
            except Exception:
                unresolved.append(escrow_id)
                continue
            if confirmed:
                voided.append(escrow_id)
            elif self._reservation_held(permit_id, auth_id):
                unresolved.append(escrow_id)
        # Outstanding authorized-but-unregistered holds, including those
        # whose provider id is not known yet.
        with self._outstanding_lock:
            pending = [
                (auth_id, entry.get("paypal_auth_id"))
                for auth_id, entry in self._outstanding.items()
                if entry.get("permit_id") == permit_id
                and auth_id not in self._auth_to_escrow
            ]
        for auth_id, paypal_auth_id in pending:
            if not paypal_auth_id:
                self._hold_for_cleanup(auth_id, permit_id, None)
                unresolved.append(auth_id)
                continue
            if self._release_if_void_confirmed(permit_id, auth_id, paypal_auth_id):
                voided.append(auth_id)
            else:
                unresolved.append(auth_id)
        return voided, unknown_open, unresolved

    def revoke_cascade(self, permit_id: str) -> tuple[Receipt, list[str]]:
        """
        Revoke a permit and every descendant permit, void every in-flight
        hold in the subtree, then release unspent delegation carves
        post-order (children before parents).

        Returns the root receipt and the voided ids, mirroring estop().
        """
        receipt, in_flight = self.permits.revoke_subtree(permit_id)
        voided: list[str] = []
        for pid, auth_ids in in_flight.items():
            v, _unknown, _unresolved = self._void_permit_holds(pid, auth_ids)
            voided.extend(v)
        # Release carves post-order: children before parents. The subtree
        # map is keyed by permit; a child's parent always appears earlier
        # in a BFS order, so reversed() yields children first. Permits
        # without a parent (the root) are skipped by release_carve().
        for pid in reversed(list(in_flight.keys())):
            self.permits.release_carve(pid)
        # Also release carves for revoked children that had no in-flight
        # holds (they are not in the in_flight map).
        for pid in reversed(self.permits.children_of(permit_id)):
            self._release_subtree_carves(pid)
        return receipt, voided

    def _release_subtree_carves(self, permit_id: str) -> None:
        """release_carve() for a permit and all its descendants, post-order."""
        for cid in self.permits.children_of(permit_id):
            self._release_subtree_carves(cid)
        self.permits.release_carve(permit_id)

    def estop(self, permit_id: str) -> EstopResult:
        """
        E-stop: revoke the permit, void every in-flight escrow, AND void
        every outstanding authorized-but-unregistered hold (the threaded
        case of the P1-1 race — the in-authorize case is caught by the
        post-authorize recheck in spend()).

        Returns an EstopResult: the e-stop receipt, the voided ids (escrow
        ids for registered escrows, permit auth_ids for outstanding
        unregistered holds), unknown_open — escrows in UNKNOWN state,
        which e-stop deliberately does not void (racing a pending capture
        could double-move money), and unresolved — cleanup that was not
        confirmed. Those stay reserved; reconcile() remains the path for
        UNKNOWN, and retry_cleanup() remains the path for an unregistered
        pending void. Failed or ambiguous voids are not listed as voided.

        The e-stop cascades: every descendant permit is revoked and its
        in-flight holds are voided too (parent first, then descendants).
        Failures are collected across the whole subtree rather than
        raising mid-loop.
        """
        receipt, in_flight = self.permits.estop_cascade(permit_id)
        voided: list[str] = []
        unknown_open: list[str] = []
        unresolved: list[str] = []
        for pid, auth_ids in in_flight.items():
            v, uo, ur = self._void_permit_holds(pid, auth_ids)
            voided.extend(v)
            unknown_open.extend(uo)
            unresolved.extend(ur)
        return EstopResult(receipt, voided, unknown_open, unresolved)

