"""Authority-layer regression tests (ChatGPT outside-witness P1-1, P1-3).

Covers the shared contracts owned by the permit/authority workstream:
amount validation at the authority boundary, read-only eligible(),
merchant binding, post-authorize recheck, fail-closed registration,
ApprovalRequired + resume, and e-stop of outstanding holds.

Settlement-free by design: tiny local stubs stand in for the paypal
client and the release verifier (flow.py imports settlement in
production; these tests assert the pipeline's wiring, not the
settlement layer).
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from permit.flow import ApprovalRequired, SpendPipeline
from permit.ledger import Ledger
from permit.permit import PermitStore, _validate_amount


PRED = "delivery_hash"


class NeedsPayerApproval(Exception):
    """Duck-typed stand-in for settlement.sandbox_client.NeedsPayerApproval."""

    def __init__(self, order_id, approval_url):
        super().__init__(f"order {order_id} needs payer approval")
        self.order_id = order_id
        self.approval_url = approval_url


class TinyPayPal:
    """Minimal paypal stand-in: records calls, never touches the network."""

    def __init__(self):
        self.authorize_calls = []
        self.void_calls = []
        self.capture_calls = []
        self.merchant_account_id = None  # set to bind a payee
        self.raise_on_authorize = None

    def authorize(self, amount_cents, merchant_id, *args, **kwargs):
        self.authorize_calls.append((amount_cents, merchant_id, kwargs))
        if self.raise_on_authorize is not None:
            raise self.raise_on_authorize
        return SimpleNamespace(
            auth_id=f"tiny_auth_{len(self.authorize_calls)}",
            amount_cents=amount_cents,
            merchant_id=merchant_id,
            status="AUTHORIZED",
        )

    def void(self, auth_id):
        self.void_calls.append(auth_id)
        return SimpleNamespace(auth_id=auth_id, status="VOIDED")

    def capture(self, auth_id, amount_cents, **kwargs):
        self.capture_calls.append((auth_id, amount_cents))
        return SimpleNamespace(
            capture_id=f"tiny_cap_{len(self.capture_calls)}",
            auth_id=auth_id,
            amount_cents=amount_cents,
            status="COMPLETED",
        )


class TinyVerifier:
    """Minimal release-verifier stand-in: register/void bookkeeping only."""

    def __init__(self, permits, ledger):
        self.permits = permits
        self.ledger = ledger
        self.escrows = {}

    def register(self, escrow):
        self.escrows[escrow.escrow_id] = escrow
        return self.ledger.append(
            "AUTHORIZED",
            {
                "escrow_id": escrow.escrow_id,
                "permit_id": escrow.permit_id,
                "paypal_auth_id": escrow.paypal_auth_id,
                "amount_cents": escrow.amount_cents,
            },
        )

    def void(self, escrow_id):
        escrow = self.escrows.get(escrow_id)
        if escrow is None or escrow.state != "AUTHORIZED":
            return False
        escrow.state = "VOIDED"
        self.permits.settle_void(escrow.permit_id, escrow.auth_id)
        return True


def _permit_layer(paypal=None, cap_cents=5000, merchants=("merchant_1",)):
    ledger = Ledger()
    permits = PermitStore(ledger=ledger)
    paypal = paypal if paypal is not None else TinyPayPal()
    verifier = TinyVerifier(permits, ledger)
    flow = SpendPipeline(permits, paypal, verifier, ledger=ledger)
    permit, _ = permits.grant(
        agent_id="agent_1",
        cap_cents=cap_cents,
        allowlist=list(merchants),
        expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    return flow, paypal, permits, permit


def _future():
    return datetime.now(timezone.utc) + timedelta(hours=1)


# ---------------------------------------------------------------------------
# P1-1: e-stop / expiry race between authorize and registration
# ---------------------------------------------------------------------------


def test_p1_1_estop_inside_authorize_voids_hold_and_blocks():
    """E-stop landing INSIDE paypal.authorize: spend() must not register an
    escrow on the revoked permit; the hold is voided, the reservation
    released, and no capture is reachable."""
    flow, paypal, permits, permit = _permit_layer()

    def hostile_authorize(amount_cents, merchant_id, *args, **kwargs):
        paypal.authorize_calls.append((amount_cents, merchant_id, kwargs))
        flow.estop(permit.permit_id)  # e-stop lands mid-authorize
        return SimpleNamespace(
            auth_id="tiny_auth_estop",
            amount_cents=amount_cents,
            merchant_id=merchant_id,
            status="AUTHORIZED",
        )

    paypal.authorize = hostile_authorize

    attempt = flow.spend(permit.permit_id, 3000, "merchant_1", PRED, "hash")
    assert not attempt.allowed
    assert attempt.reason == "revoked_during_auth"
    assert attempt.escrow_id is None
    assert [r.event_type for r in attempt.receipts] == ["ALLOWED"]
    # The post-authorize recheck voided the PayPal hold ...
    assert paypal.void_calls == ["tiny_auth_estop"]
    # ... released the cap reservation ...
    assert permit.reserved_cents == 0
    assert permit.remaining_cents() == 5000
    # ... and no escrow exists, so release/capture is unreachable.
    assert verifier_escrows(flow) == {}
    assert flow._outstanding == {}
    assert len(paypal.capture_calls) == 0


def verifier_escrows(flow):
    return flow.verifier.escrows


def test_p1_1_expiry_inside_authorize_voids_hold_and_blocks():
    """Permit expiring while authorize is in flight: same fail-closed path,
    reason expired_during_auth."""
    flow, paypal, permits, permit = _permit_layer()

    def expiring_authorize(amount_cents, merchant_id, *args, **kwargs):
        paypal.authorize_calls.append((amount_cents, merchant_id, kwargs))
        permit.expiry = datetime.now(timezone.utc) - timedelta(seconds=1)
        return SimpleNamespace(
            auth_id="tiny_auth_expired",
            amount_cents=amount_cents,
            merchant_id=merchant_id,
            status="AUTHORIZED",
        )

    paypal.authorize = expiring_authorize

    attempt = flow.spend(permit.permit_id, 3000, "merchant_1", PRED, "hash")
    assert not attempt.allowed
    assert attempt.reason == "expired_during_auth"
    assert paypal.void_calls == ["tiny_auth_expired"]
    assert permit.reserved_cents == 0
    assert len(paypal.capture_calls) == 0


def test_p1_1_register_escrow_on_revoked_permit_raises_and_voids():
    """Forcing register_escrow() on a revoked permit raises RuntimeError
    instead of registering; the PayPal hold is voided and the reservation
    released — there is no escrow to release, so capture stays refused."""
    flow, paypal, permits, permit = _permit_layer()
    check = permits.check(permit.permit_id, 3000, "merchant_1")
    auth_id = check.receipt.payload["auth_id"]
    pp_auth = paypal.authorize(3000, "merchant_1")
    flow.estop(permit.permit_id)

    with pytest.raises(RuntimeError, match="revoked/expired during registration"):
        flow.register_escrow(
            permit_id=permit.permit_id,
            auth_id=auth_id,
            paypal_auth_id=pp_auth.auth_id,
            amount_cents=3000,
            merchant_id="merchant_1",
            predicate_type=PRED,
            artifact_hash="hash",
        )
    assert paypal.void_calls == [pp_auth.auth_id]
    assert permit.reserved_cents == 0
    assert flow.verifier.escrows == {}


def test_p1_1_estop_voids_outstanding_unregistered_hold():
    """Threaded case: e-stop lands after authorize returned but before the
    escrow is registered. flow.estop() must void the outstanding hold."""
    flow, paypal, permits, permit = _permit_layer()
    check = permits.check(permit.permit_id, 3000, "merchant_1")
    auth_id = check.receipt.payload["auth_id"]
    # Simulate post-authorize state before registration.
    flow._track_outstanding(auth_id, permit.permit_id)
    flow._set_outstanding_paypal_auth(auth_id, "tiny_auth_thread")

    receipt, voided = flow.estop(permit.permit_id)
    assert receipt.event_type == "E-STOP"
    assert paypal.void_calls == ["tiny_auth_thread"]
    assert auth_id in voided
    assert permit.reserved_cents == 0
    assert auth_id not in flow._outstanding


# ---------------------------------------------------------------------------
# P1-3: amount validation at the authority boundary
# ---------------------------------------------------------------------------


def test_p1_3_negative_amount_blocked_never_reserves():
    """check(-1000) on a 5000-cap permit: BLOCKED invalid_amount, nothing
    reserved — the witness's budget-increase exploit is closed."""
    flow, paypal, permits, permit = _permit_layer(cap_cents=5000)
    res = permits.check(permit.permit_id, -1000, "merchant_1")
    assert not res.allowed and res.reason == "invalid_amount"
    assert res.receipt.event_type == "BLOCKED"
    assert permit.reserved_cents == 0
    # ... so a follow-up +6000 is still over the untouched 5000 cap.
    res2 = permits.check(permit.permit_id, 6000, "merchant_1")
    assert not res2.allowed and res2.reason == "over_remaining_cap"
    assert permit.remaining_cents() == 5000


@pytest.mark.parametrize("bad", [True, 0, "100", 1.5, None, -1])
def test_p1_3_non_positive_int_amounts_are_invalid(bad):
    _, _, permits, permit = _permit_layer()
    before = len(permits.ledger)
    res = permits.check(permit.permit_id, bad, "merchant_1")
    assert not res.allowed and res.reason == "invalid_amount"
    assert res.receipt.event_type == "BLOCKED"
    assert permit.reserved_cents == 0
    assert len(permits.ledger) == before + 1  # audit trail records it


def test_p1_3_validate_amount_unit():
    assert _validate_amount(100) == 100
    for bad in (-5, 0, True, False, "100", 1.5, None):
        with pytest.raises(ValueError):
            _validate_amount(bad)


@pytest.mark.parametrize("bad_cap", [-5, 0, True, "5000", 2.5])
def test_p1_3_grant_rejects_non_positive_cap(bad_cap):
    s = PermitStore()
    with pytest.raises(ValueError):
        s.grant("agent_1", bad_cap, ["merchant_1"], _future())


# ---------------------------------------------------------------------------
# eligible(): read-only authority evaluation
# ---------------------------------------------------------------------------


def test_eligible_is_read_only():
    """eligible() evaluates the same 4-clause logic as check() but reserves
    nothing and writes no receipt."""
    _, _, permits, permit = _permit_layer()
    before = len(permits.ledger)
    res = permits.eligible(permit.permit_id, 3000, "merchant_1")
    assert res.allowed and res.reason == "allowed"
    assert res.receipt is None
    assert permit.reserved_cents == 0
    assert len(permits.ledger) == before


def test_eligible_reports_block_reasons_without_side_effects():
    _, _, permits, permit = _permit_layer()
    before = len(permits.ledger)
    assert permits.eligible(permit.permit_id, 6000, "merchant_1").reason == (
        "over_remaining_cap"
    )
    assert permits.eligible(permit.permit_id, 1000, "evil").reason == (
        "merchant_not_allowed"
    )
    assert permits.eligible(permit.permit_id, -5, "merchant_1").reason == (
        "invalid_amount"
    )
    assert permits.eligible("prm_nope", 100, "merchant_1").reason == "unknown_permit"
    assert permit.reserved_cents == 0
    assert len(permits.ledger) == before


def test_eligible_then_check_reserves_once():
    """eligible() must not pre-consume: a later check() reserves exactly once."""
    _, _, permits, permit = _permit_layer()
    assert permits.eligible(permit.permit_id, 3000, "merchant_1").allowed
    res = permits.check(permit.permit_id, 3000, "merchant_1")
    assert res.allowed
    assert permit.reserved_cents == 3000


# ---------------------------------------------------------------------------
# Merchant binding (witness P1-2 caller side)
# ---------------------------------------------------------------------------


def test_merchant_binding_blocks_unbound_payee():
    """Payee bound to ACCT_X, permit allowlist labels ALLOWLISTED: a spend
    naming ALLOWLISTED is BLOCKED merchant_not_bound before any reservation
    or PayPal traffic."""
    paypal = TinyPayPal()
    paypal.merchant_account_id = "ACCT_X"
    flow, _, permits, permit = _permit_layer(paypal=paypal, merchants=("ALLOWLISTED",))

    attempt = flow.spend(permit.permit_id, 1000, "ALLOWLISTED", PRED, "hash")
    assert not attempt.allowed
    assert attempt.reason == "merchant_not_bound"
    assert attempt.escrow_id is None
    assert attempt.receipts[0].event_type == "BLOCKED"
    assert paypal.authorize_calls == []
    assert permit.reserved_cents == 0


def test_merchant_binding_allows_bound_payee():
    """Bound payee matching the allowlist label proceeds normally."""
    paypal = TinyPayPal()
    paypal.merchant_account_id = "ACCT_X"
    flow, _, permits, permit = _permit_layer(paypal=paypal, merchants=("ACCT_X",))

    attempt = flow.spend(permit.permit_id, 1000, "ACCT_X", PRED, "hash")
    assert attempt.allowed
    assert attempt.escrow_id is not None
    assert paypal.authorize_calls != []


def test_merchant_binding_absent_skips_check():
    """Clients without merchant_account_id keep the old behavior."""
    flow, paypal, _, permit = _permit_layer()
    assert not hasattr(paypal, "merchant_account_id") or (
        paypal.merchant_account_id is None
    )
    attempt = flow.spend(permit.permit_id, 1000, "merchant_1", PRED, "hash")
    assert attempt.allowed


def test_authorize_gets_idempotency_key_when_supported():
    """The pipeline passes idempotency_key to clients that accept it."""
    seen = {}

    class IdemPayPal(TinyPayPal):
        def authorize(self, amount_cents, merchant_id, idempotency_key=None):
            seen["key"] = idempotency_key
            return super().authorize(amount_cents, merchant_id)

    flow, _, permits, permit = _permit_layer(paypal=IdemPayPal())
    attempt = flow.spend(permit.permit_id, 1000, "merchant_1", PRED, "hash")
    auth_id = attempt.receipts[0].payload["auth_id"]
    assert seen["key"] == f"{permit.permit_id}:{auth_id}:authorize"


# ---------------------------------------------------------------------------
# ApprovalRequired + resume_operation
# ---------------------------------------------------------------------------


def test_spend_needs_payer_approval_raises_and_holds_reservation():
    """Duck-typed NeedsPayerApproval -> ApprovalRequired with all fields;
    the cap reservation stays held and the op stays outstanding."""
    paypal = TinyPayPal()
    paypal.raise_on_authorize = NeedsPayerApproval("ord_1", "https://approve/1")
    flow, _, permits, permit = _permit_layer(paypal=paypal)

    with pytest.raises(ApprovalRequired) as exc_info:
        flow.spend(permit.permit_id, 3000, "merchant_1", PRED, "artifact_hash")
    appr = exc_info.value
    assert appr.permit_id == permit.permit_id
    assert appr.order_id == "ord_1"
    assert appr.approval_url == "https://approve/1"
    assert appr.amount_cents == 3000
    assert appr.merchant_id == "merchant_1"
    assert appr.predicate_type == PRED
    assert appr.artifact_hash == "artifact_hash"
    # Reservation held, op tracked, no escrow, no settle.
    assert permit.reserved_cents == 3000
    assert list(flow._outstanding) == [appr.auth_id]
    assert flow.verifier.escrows == {}


def test_resume_operation_after_approval_completes_spend():
    """After payer approval, resume_operation() authorizes the SAME order
    and completes the spend without a second reservation."""
    paypal = TinyPayPal()
    paypal.raise_on_authorize = NeedsPayerApproval("ord_1", "https://approve/1")
    flow, _, permits, permit = _permit_layer(paypal=paypal)

    with pytest.raises(ApprovalRequired) as exc_info:
        flow.spend(permit.permit_id, 3000, "merchant_1", PRED, "hash")
    appr = exc_info.value

    order_calls = []

    def fake_authorize_order(order_id, amount_cents, merchant_id):
        order_calls.append((order_id, amount_cents, merchant_id))
        return SimpleNamespace(
            auth_id="tiny_auth_resumed",
            amount_cents=amount_cents,
            merchant_id=merchant_id,
            status="AUTHORIZED",
        )

    paypal.raise_on_authorize = None
    paypal.authorize_order = fake_authorize_order

    attempt = flow.resume_operation(appr)
    assert attempt.allowed and attempt.reason == "allowed"
    assert attempt.escrow_id is not None
    assert [r.event_type for r in attempt.receipts] == ["ALLOWED", "AUTHORIZED"]
    # Same order resumed, cap reserved exactly once.
    assert order_calls == [("ord_1", 3000, "merchant_1")]
    assert permit.reserved_cents == 3000
    assert permit.remaining_cents() == 2000
    assert flow._outstanding == {}


def test_resume_operation_requires_authorize_order():
    appr = ApprovalRequired(
        permit_id="p",
        auth_id="a",
        order_id="o",
        approval_url="u",
        amount_cents=1,
        merchant_id="m",
        predicate_type=PRED,
        artifact_hash="h",
    )
    flow, _, _, _ = _permit_layer()  # TinyPayPal has no authorize_order
    with pytest.raises(RuntimeError, match="authorize_order"):
        flow.resume_operation(appr)


def test_resume_operation_re_raises_when_still_unapproved():
    """authorize_order raising NeedsPayerApproval again -> fresh
    ApprovalRequired from the same fields (approval_url refreshed)."""
    paypal = TinyPayPal()
    flow, _, _, _ = _permit_layer(paypal=paypal)
    appr = ApprovalRequired(
        permit_id="p",
        auth_id="a",
        order_id="ord_9",
        approval_url="https://approve/old",
        amount_cents=100,
        merchant_id="m",
        predicate_type=PRED,
        artifact_hash="h",
    )

    def still_pending(order_id, amount_cents, merchant_id):
        raise NeedsPayerApproval(order_id, "https://approve/new")

    paypal.authorize_order = still_pending
    with pytest.raises(ApprovalRequired) as exc_info:
        flow.resume_operation(appr)
    assert exc_info.value.order_id == "ord_9"
    assert exc_info.value.approval_url == "https://approve/new"
