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
               outstanding authorized-but-unregistered hold.
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
"""

from __future__ import annotations

import inspect
import threading
import uuid
from dataclasses import dataclass
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
        # Entries are removed once the escrow is registered (6f) or the hold
        # is voided after a failed post-authorize recheck (6e).
        self._outstanding: dict[str, dict] = {}
        self._outstanding_lock = threading.Lock()
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
        # request never reserves cap.
        if approval_id is not None:
            approval = self.permits.get_approval(approval_id)
            if (
                approval is None
                or approval.status != "approved"
                or approval.permit_id != permit_id
                or approval.amount_cents != amount_cents
                or approval.merchant_id != merchant_id
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
        else:
            threshold = self.permits.approval_threshold(permit_id)
            if (
                threshold is not None
                and isinstance(amount_cents, int)
                and not isinstance(amount_cents, bool)
                and amount_cents > threshold
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
            # An unconsumed approval stays approved: the principal's word
            # stands; only the authority recheck failed. The agent may
            # retry complete_approved_spend() later.
            return SpendAttempt(False, check.reason, None, (check.receipt,))

        if approval_id is not None:
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
            # Void the PayPal hold best-effort; cleanup of the provider
            # hold itself is the settlement layer's job, so ignore errors.
            try:
                self.paypal.void(paypal_auth_id)
            except Exception:
                pass
            self.permits.settle_void(permit_id, auth_id)
            self._drop_outstanding(auth_id)
            return SpendAttempt(
                False, reason, None, (first_receipt,) if first_receipt else ()
            )

        # (6f) register_escrow as before, then drop the outstanding entry.
        escrow_id, authorized_receipt = self.register_escrow(
            permit_id=permit_id,
            auth_id=auth_id,
            paypal_auth_id=paypal_auth_id,
            amount_cents=amount_cents,
            merchant_id=merchant_id,
            predicate_type=predicate_type,
            artifact_hash=artifact_hash,
        )
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
        """
        authorize_order = getattr(self.paypal, "authorize_order", None)
        if authorize_order is None:
            raise RuntimeError(
                "paypal client does not expose authorize_order(); "
                "cannot resume an approval-required operation"
            )

        auth_id = appr.auth_id
        permit_id = appr.permit_id
        with self._outstanding_lock:
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
        expired at registration time, the PayPal hold is voided
        (best-effort), the permit reservation is released, and
        RuntimeError is raised INSTEAD of registering. This covers the
        e-stop-between-authorize-and-register race.
        """
        now = datetime.now(timezone.utc)
        permit = self.permits.get(permit_id)
        if permit is None or permit.revoked or now >= permit.expiry:
            try:
                self.paypal.void(paypal_auth_id)
            except Exception:
                pass
            if permit is not None:
                self.permits.settle_void(permit_id, auth_id)
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
    ) -> list[str]:
        """
        Void one permit's in-flight holds: registered escrows via the
        verifier, plus outstanding authorized-but-unregistered holds
        (the P1-1 race window). Shared by estop() and revoke_cascade().
        """
        voided: list[str] = []
        for auth_id in in_flight_auth_ids:
            escrow_id = self._auth_to_escrow.get(auth_id)
            if escrow_id is not None and self.verifier.void(escrow_id):
                voided.append(escrow_id)
        with self._outstanding_lock:
            pending = [
                (auth_id, entry)
                for auth_id, entry in self._outstanding.items()
                if entry.get("permit_id") == permit_id
                and entry.get("paypal_auth_id")
                and auth_id not in self._auth_to_escrow
            ]
        for auth_id, entry in pending:
            try:
                self.paypal.void(entry["paypal_auth_id"])
            except Exception:
                pass  # best-effort; provider-hold cleanup is settlement's job
            self.permits.settle_void(permit_id, auth_id)
            self._drop_outstanding(auth_id)
            voided.append(auth_id)
        return voided

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
            voided.extend(self._void_permit_holds(pid, auth_ids))
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

    def estop(self, permit_id: str) -> tuple[Receipt, list[str]]:
        """
        E-stop: revoke the permit, void every in-flight escrow, AND void
        every outstanding authorized-but-unregistered hold (the threaded
        case of the P1-1 race — the in-authorize case is caught by the
        post-authorize recheck in spend()).

        Returns the e-stop receipt and the voided ids: escrow ids for
        registered escrows, permit auth_ids for outstanding unregistered
        holds.

        The e-stop cascades: every descendant permit is revoked and its
        in-flight holds are voided too (parent first, then descendants).
        """
        receipt, in_flight = self.permits.estop_cascade(permit_id)
        voided = self._void_permit_holds(permit_id, in_flight.get(permit_id, []))
        for pid, auth_ids in in_flight.items():
            if pid != permit_id:
                voided.extend(self._void_permit_holds(pid, auth_ids))
        return receipt, voided
