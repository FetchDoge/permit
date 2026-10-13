"""M2 gate proof: every refusal path stops before the PayPal rail.

The SpendPipeline is the only path from a spend attempt to money movement.
This matrix proves, for EVERY block reason the authority layer can produce,
that flow.spend():
  - returns allowed=False with the exact reason,
  - makes ZERO PayPal calls (strict spy: authorize / capture / void all silent),
  - writes a BLOCKED receipt carrying the reason,
  - leaves the hash-chained ledger verifiable.

A positive control proves the spy is not vacuous: an allowed spend DOES
touch the rail exactly once.
"""

from datetime import datetime, timedelta, timezone

from permit.ledger import Ledger
from permit.permit import PermitStore
from permit.flow import SpendPipeline
from settlement.paypal_client import MockPayPalClient
from settlement.verifier import PredicateType, ReleaseVerifier


def _pipeline(cap_cents=5000, merchants=("merchant_1",),
              merchant_account_id=None, **grant_kw):
    ledger = Ledger()
    permits = PermitStore(ledger=ledger)
    paypal = MockPayPalClient(merchant_account_id=merchant_account_id)
    verifier = ReleaseVerifier(paypal, permits, ledger=ledger)
    flow = SpendPipeline(permits, paypal, verifier, ledger=ledger)
    permit, _ = permits.grant(
        agent_id="agent_1",
        cap_cents=cap_cents,
        allowlist=list(merchants),
        expiry=datetime.now(timezone.utc) + timedelta(hours=1),
        **grant_kw,
    )
    return flow, paypal, permits, permit


def _assert_gate_closed(flow, paypal, attempt, reason):
    """The gate held: refused, silent on the rail, receipted, chain intact."""
    assert not attempt.allowed
    assert attempt.reason == reason, f"expected {reason!r}, got {attempt.reason!r}"
    assert attempt.escrow_id is None
    # Strict rail spy: no PayPal call of any kind happened.
    assert paypal.authorize_calls == [], paypal.authorize_calls
    assert paypal.capture_calls == [], paypal.capture_calls
    assert paypal.authorizations == {}
    assert paypal.captures == {}
    assert paypal.voids == {}
    # A BLOCKED receipt carries the refusal reason...
    blocked = [
        r for r in flow.ledger.receipts()
        if r.event_type == "BLOCKED" and r.payload.get("reason") == reason
    ]
    assert blocked, f"no BLOCKED receipt with reason {reason!r}"
    # ...and it is the receipt the attempt hands back.
    assert attempt.receipts[0].event_type == "BLOCKED"
    assert attempt.receipts[0].payload["reason"] == reason
    ok, msg = flow.ledger.verify_chain()
    assert ok, msg


def _expire_under_lock(permits, permit_id):
    permit = permits.get(permit_id)
    with permit._lock:
        permit.expiry = datetime.now(timezone.utc) - timedelta(seconds=1)


def test_gate_invalid_amount():
    flow, paypal, permits, permit = _pipeline()
    for bad in (-100, 0, "100", 10.5, True, None):
        attempt = flow.spend(
            permit.permit_id, bad, "merchant_1", PredicateType.D, "hash")
        _assert_gate_closed(flow, paypal, attempt, "invalid_amount")


def test_gate_unknown_permit():
    flow, paypal, permits, permit = _pipeline()
    attempt = flow.spend(
        "prm_does_not_exist", 1000, "merchant_1", PredicateType.D, "hash")
    _assert_gate_closed(flow, paypal, attempt, "unknown_permit")


def test_gate_revoked():
    flow, paypal, permits, permit = _pipeline()
    flow.estop(permit.permit_id)
    attempt = flow.spend(
        permit.permit_id, 1000, "merchant_1", PredicateType.D, "hash")
    _assert_gate_closed(flow, paypal, attempt, "revoked")


def test_gate_expired():
    flow, paypal, permits, permit = _pipeline()
    _expire_under_lock(permits, permit.permit_id)
    attempt = flow.spend(
        permit.permit_id, 1000, "merchant_1", PredicateType.D, "hash")
    _assert_gate_closed(flow, paypal, attempt, "expired")


def test_gate_tightened_expiry_passed():
    flow, paypal, permits, permit = _pipeline()
    permits.tighten(
        permit.permit_id,
        expiry=datetime.now(timezone.utc) + timedelta(minutes=1),
    )
    # Push the tightened expiry into the past (white-box, same pattern as
    # the delegation lineage tests): the gate must honor the tightened
    # bound, not the granted one.
    target = permits.get(permit.permit_id)
    with target._lock:
        target.tighten_expiry = datetime.now(timezone.utc) - timedelta(seconds=1)
    attempt = flow.spend(
        permit.permit_id, 1000, "merchant_1", PredicateType.D, "hash")
    _assert_gate_closed(flow, paypal, attempt, "tightened_expiry_passed")


def test_gate_merchant_not_allowed():
    flow, paypal, permits, permit = _pipeline()
    attempt = flow.spend(
        permit.permit_id, 1000, "evil_merchant", PredicateType.D, "hash")
    _assert_gate_closed(flow, paypal, attempt, "merchant_not_allowed")


def test_gate_over_remaining_cap():
    flow, paypal, permits, permit = _pipeline()
    attempt = flow.spend(
        permit.permit_id, 99999, "merchant_1", PredicateType.D, "hash")
    _assert_gate_closed(flow, paypal, attempt, "over_remaining_cap")


def test_gate_tightened_cap_exceeded():
    flow, paypal, permits, permit = _pipeline()
    permits.tighten(permit.permit_id, cap_cents=2000)
    # 3000 is inside the granted 5000 cap but above the tightened 2000:
    # the min-gate, not the grant, decides.
    attempt = flow.spend(
        permit.permit_id, 3000, "merchant_1", PredicateType.D, "hash")
    _assert_gate_closed(flow, paypal, attempt, "tightened_cap_exceeded")


def test_gate_ancestor_revoked():
    flow, paypal, permits, permit = _pipeline()
    child = flow.delegate(
        parent_permit_id=permit.permit_id,
        agent_id="agent_2",
        cap_cents=2000,
        allowlist=["merchant_1"],
        expiry=datetime.now(timezone.utc) + timedelta(minutes=30),
    ).permit
    # Revoke the parent through a path that does not cascade, so the
    # child itself stays live and only the lineage gate can refuse.
    with permit._lock:
        permit.revoked = True
    attempt = flow.spend(
        child.permit_id, 100, "merchant_1", PredicateType.D, "hash")
    _assert_gate_closed(flow, paypal, attempt, "ancestor_revoked")


def test_gate_ancestor_expired():
    flow, paypal, permits, permit = _pipeline()
    child = flow.delegate(
        parent_permit_id=permit.permit_id,
        agent_id="agent_2",
        cap_cents=2000,
        allowlist=["merchant_1"],
        expiry=datetime.now(timezone.utc) + timedelta(minutes=30),
    ).permit
    _expire_under_lock(permits, permit.permit_id)
    attempt = flow.spend(
        child.permit_id, 100, "merchant_1", PredicateType.D, "hash")
    _assert_gate_closed(flow, paypal, attempt, "ancestor_expired")


def test_gate_merchant_not_bound():
    # The rail is bound to a real PayPal merchant account id; the
    # allowlist label alone is not enough to reach it.
    flow, paypal, permits, permit = _pipeline(
        merchant_account_id="acct_bound_paypal")
    attempt = flow.spend(
        permit.permit_id, 1000, "merchant_1", PredicateType.D, "hash")
    _assert_gate_closed(flow, paypal, attempt, "merchant_not_bound")


def test_gate_invalid_approval():
    flow, paypal, permits, permit = _pipeline()
    attempt = flow.spend(
        permit.permit_id, 1000, "merchant_1", PredicateType.D, "hash",
        approval_id="apr_bogus",
    )
    _assert_gate_closed(flow, paypal, attempt, "invalid_approval")


def test_gate_approval_pending_never_touches_paypal():
    # Not a BLOCKED refusal, but the same gate property: a spend gated on
    # the principal's word must not reach PayPal before that word lands.
    flow, paypal, permits, permit = _pipeline(approval_threshold_cents=1000)
    attempt = flow.spend(
        permit.permit_id, 1500, "merchant_1", PredicateType.D, "hash")
    assert not attempt.allowed
    assert attempt.reason == "pending_principal_approval"
    assert attempt.approval_id is not None
    assert paypal.authorize_calls == []
    assert paypal.capture_calls == []
    pending = [
        r for r in flow.ledger.receipts()
        if r.event_type == "APPROVAL_PENDING"
        and r.payload.get("reason") == "pending_principal_approval"
    ]
    assert pending
    ok, msg = flow.ledger.verify_chain()
    assert ok, msg


def test_gate_allowed_spend_touches_paypal_once():
    # Positive control: the spy is not vacuous. An allowed spend reaches
    # the rail exactly once and carries an ALLOWED receipt.
    flow, paypal, permits, permit = _pipeline()
    attempt = flow.spend(
        permit.permit_id, 3000, "merchant_1", PredicateType.D, "hash")
    assert attempt.allowed
    assert len(paypal.authorize_calls) == 1
    assert attempt.receipts[0].event_type == "ALLOWED"
    ok, msg = flow.ledger.verify_chain()
    assert ok, msg
