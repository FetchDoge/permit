"""
Principal-approval thresholds: spends above a permit's threshold need a
human word before any reservation is made. No approval -> no reservation,
no PayPal traffic. Approval re-runs the authority check at completion
(fail-closed if the budget moved).
"""
import hashlib
import threading
from datetime import datetime, timedelta, timezone

import pytest

from permit.flow import SpendPipeline
from permit.ledger import Ledger
from permit.permit import PermitStore
from settlement.paypal_client import MockPayPalClient
from settlement.verifier import Evidence, PredicateType, ReleaseVerifier


def make_store(cap=10000, threshold=2500, **grant_kw):
    ledger = Ledger()
    store = PermitStore(ledger)
    expiry = datetime.now(timezone.utc) + timedelta(hours=1)
    permit, _ = store.grant(
        "buyer", cap, ["m1"], expiry,
        approval_threshold_cents=threshold, **grant_kw,
    )
    return store, ledger, permit


def make_flow(store, ledger):
    paypal = MockPayPalClient()
    return SpendPipeline(store, paypal, ReleaseVerifier(paypal, store, ledger=ledger)), paypal


def ah():
    return hashlib.sha256(b"artifact").hexdigest()


def deliver_all(flow, escrow_id):
    return flow.release(escrow_id, Evidence(delivered_bytes=b"artifact"))


def test_below_threshold_is_normally_allowed():
    store, ledger, permit = make_store()
    flow, paypal = make_flow(store, ledger)
    a = flow.spend(permit.permit_id, 2000, "m1", PredicateType.D, ah(), agent_id=permit.agent_id)
    assert a.allowed and a.approval_id is None
    assert store.get(permit.permit_id).reserved_cents == 2000
    assert len(paypal.authorize_calls) == 1


def test_no_threshold_means_no_gate():
    ledger = Ledger()
    store = PermitStore(ledger)
    expiry = datetime.now(timezone.utc) + timedelta(hours=1)
    permit, _ = store.grant("buyer", 10000, ["m1"], expiry)
    assert store.approval_threshold(permit.permit_id) is None
    flow, paypal = make_flow(store, ledger)
    a = flow.spend(permit.permit_id, 9000, "m1", PredicateType.D, ah(), agent_id=permit.agent_id)
    assert a.allowed  # backwards compatible: no threshold, no PENDING


def test_at_threshold_is_allowed_not_pending():
    store, ledger, permit = make_store(threshold=2500)
    flow, paypal = make_flow(store, ledger)
    a = flow.spend(permit.permit_id, 2500, "m1", PredicateType.D, ah(), agent_id=permit.agent_id)
    assert a.allowed and a.approval_id is None


def test_above_threshold_pends_without_reservation_or_paypal():
    store, ledger, permit = make_store()
    flow, paypal = make_flow(store, ledger)
    a = flow.spend(permit.permit_id, 4000, "m1", PredicateType.D, ah(), agent_id=permit.agent_id)
    assert not a.allowed
    assert a.reason == "pending_principal_approval"
    assert a.approval_id
    # Nothing reserved, PayPal never touched.
    assert store.get(permit.permit_id).reserved_cents == 0
    assert paypal.authorize_calls == []
    kinds = [r.event_type for r in ledger.receipts()]
    assert "APPROVAL_REQUESTED" in kinds
    assert "APPROVAL_PENDING" in kinds
    assert "ALLOWED" not in kinds


def test_approve_then_complete_captures():
    store, ledger, permit = make_store()
    flow, paypal = make_flow(store, ledger)
    a = flow.spend(permit.permit_id, 4000, "m1", PredicateType.D, ah(), agent_id=permit.agent_id)
    flow.approve_approval(a.approval_id)
    c = flow.complete_approved_spend(a.approval_id)
    assert c.allowed and c.escrow_id
    assert store.get_approval(a.approval_id).status == "consumed"
    r = deliver_all(flow, c.escrow_id)
    assert r.released
    assert store.get(permit.permit_id).captured_cents == 4000


def test_deny_blocks_completion():
    store, ledger, permit = make_store()
    flow, paypal = make_flow(store, ledger)
    a = flow.spend(permit.permit_id, 4000, "m1", PredicateType.D, ah(), agent_id=permit.agent_id)
    flow.deny_approval(a.approval_id)
    c = flow.complete_approved_spend(a.approval_id)
    assert not c.allowed and c.reason == "approval_not_approved"
    assert store.get(permit.permit_id).reserved_cents == 0
    assert paypal.authorize_calls == []


def test_approval_is_single_use():
    store, ledger, permit = make_store()
    flow, paypal = make_flow(store, ledger)
    a = flow.spend(permit.permit_id, 4000, "m1", PredicateType.D, ah(), agent_id=permit.agent_id)
    flow.approve_approval(a.approval_id)
    c1 = flow.complete_approved_spend(a.approval_id)
    assert c1.allowed
    c2 = flow.complete_approved_spend(a.approval_id)
    assert not c2.allowed and c2.reason == "approval_not_approved"
    # One approval authorized exactly one hold.
    assert len(paypal.authorize_calls) == 1


def test_approval_binds_exact_params():
    store, ledger, permit = make_store()
    flow, paypal = make_flow(store, ledger)
    a = flow.spend(permit.permit_id, 4000, "m1", PredicateType.D, ah(), agent_id=permit.agent_id)
    flow.approve_approval(a.approval_id)
    # Same approval id, different amount -> rejected.
    b = flow.spend(permit.permit_id, 3000, "m1", PredicateType.D, ah(),
                   approval_id=a.approval_id, agent_id=permit.agent_id)
    assert not b.allowed and b.reason == "invalid_approval"
    # Different merchant -> rejected.
    c = flow.spend(permit.permit_id, 4000, "m2", PredicateType.D, ah(),
                   approval_id=a.approval_id, agent_id=permit.agent_id)
    assert not c.allowed and c.reason == "invalid_approval"
    assert paypal.authorize_calls == []


def test_approval_fails_closed_when_budget_moved():
    # Explicit per_spend: the setup spends 3 x $25 at-threshold without
    # approval, which the (default) cumulative mode would correctly hold.
    store, ledger, permit = make_store(cap=10000, threshold=2500,
                                       approval_mode="per_spend")
    flow, paypal = make_flow(store, ledger)
    # Principal approves a $40 spend...
    a = flow.spend(permit.permit_id, 4000, "m1", PredicateType.D, ah(), agent_id=permit.agent_id)
    flow.approve_approval(a.approval_id)
    # ...but the agent spends $75 first (three at-threshold spends).
    for _ in range(3):
        s = flow.spend(permit.permit_id, 2500, "m1", PredicateType.D, ah(), agent_id=permit.agent_id)
        assert s.allowed
        deliver_all(flow, s.escrow_id)
    assert store.get(permit.permit_id).remaining_cents() == 2500
    # The approved $40 no longer fits: fail closed, PayPal untouched.
    before = len(paypal.authorize_calls)
    c = flow.complete_approved_spend(a.approval_id)
    assert not c.allowed and c.reason == "over_remaining_cap"
    assert len(paypal.authorize_calls) == before
    # The approval itself was NOT consumed: the principal's word stands,
    # only the authority recheck failed.
    assert store.get_approval(a.approval_id).status == "approved"


def test_revoke_subtree_between_approval_and_completion_blocks_spend():
    """Issue #7: the principal approved, then the parent permit was revoked
    via revoke_subtree() before the agent completed. Completion re-runs the
    authority check, so it must come back BLOCKED (revoked) with zero PayPal
    traffic, and the principal's approval must stay unconsumed."""
    ledger = Ledger()
    store = PermitStore(ledger)
    parent, _ = store.grant(
        "buyer", 8000, ["m1"],
        datetime.now(timezone.utc) + timedelta(minutes=30),
        approval_threshold_cents=1000,
    )
    rail = MockPayPalClient()
    pipeline = SpendPipeline(store, rail, ReleaseVerifier(rail, store, ledger=ledger))

    pending = pipeline.spend(parent.permit_id, 3500, "m1", PredicateType.D, ah(), agent_id=parent.agent_id)
    assert pending.reason == "pending_principal_approval"
    approval_id = pending.approval_id
    pipeline.approve_approval(approval_id)
    assert store.get_approval(approval_id).status == "approved"

    store.revoke_subtree(parent.permit_id)
    assert store.get(parent.permit_id).revoked

    # Completing twice proves the failed recheck did not use up the approval.
    for _ in range(2):
        outcome = pipeline.complete_approved_spend(approval_id)
        assert outcome.allowed is False
        assert outcome.escrow_id is None
        assert outcome.reason == "revoked"
        assert [r.event_type for r in outcome.receipts][-1] == "BLOCKED"
        assert store.get_approval(approval_id).status == "approved"

    assert rail.authorize_calls == []
    assert store.get(parent.permit_id).reserved_cents == 0


def test_expired_approval_cannot_be_decided_or_completed():
    store, ledger, permit = make_store()
    flow, paypal = make_flow(store, ledger)
    a = flow.spend(permit.permit_id, 4000, "m1", PredicateType.D, ah(), agent_id=permit.agent_id)
    # Force expiry by backdating.
    appr = store.get_approval(a.approval_id)
    appr.expires_at = (datetime.now(timezone.utc)
                       - timedelta(seconds=1)).isoformat()
    with pytest.raises(ValueError, match="approval_expired"):
        flow.approve_approval(a.approval_id)
    assert store.get_approval(a.approval_id).status == "expired"
    c = flow.complete_approved_spend(a.approval_id)
    assert not c.allowed


def test_double_decide_rejected():
    store, ledger, permit = make_store()
    flow, _ = make_flow(store, ledger)
    a = flow.spend(permit.permit_id, 4000, "m1", PredicateType.D, ah(), agent_id=permit.agent_id)
    flow.approve_approval(a.approval_id)
    with pytest.raises(ValueError, match="approval_already_approved"):
        flow.deny_approval(a.approval_id)


def test_request_approval_requires_threshold_exceeded():
    store, ledger, permit = make_store()
    # Below threshold -> misuse.
    with pytest.raises(ValueError, match="approval_not_required"):
        store.request_approval(permit.permit_id, 2000, "m1", "D", ah())
    # A spend the authority would refuse -> misuse, not an approval.
    with pytest.raises(ValueError, match="authority_check_failed"):
        store.request_approval(permit.permit_id, 4000, "m2", "D", ah())


def test_tighten_can_set_and_lower_threshold():
    store, ledger, permit = make_store(threshold=None)
    assert store.approval_threshold(permit.permit_id) is None
    # Setting a threshold from None is a narrowing.
    store.tighten(permit.permit_id, approval_threshold_cents=3000)
    assert store.approval_threshold(permit.permit_id) == 3000
    # Lowering is allowed.
    store.tighten(permit.permit_id, approval_threshold_cents=1000)
    assert store.approval_threshold(permit.permit_id) == 1000
    # Raising is not a tightening.
    with pytest.raises(ValueError):
        store.tighten(permit.permit_id, approval_threshold_cents=2000)


def test_threshold_applies_through_min_gate_after_tighten():
    # Explicit per_spend: "small spends still flow" is per-spend semantics;
    # under the cumulative default the earlier $10 hold counts.
    store, ledger, permit = make_store(threshold=None,
                                       approval_mode="per_spend")
    flow, _ = make_flow(store, ledger)
    # No threshold: a $10 spend goes straight through.
    a = flow.spend(permit.permit_id, 1000, "m1", PredicateType.D, ah(), agent_id=permit.agent_id)
    assert a.allowed
    # Tighten a threshold onto the live permit: the next big spend pends.
    store.tighten(permit.permit_id, approval_threshold_cents=2500)
    b = flow.spend(permit.permit_id, 3000, "m1", PredicateType.D, ah(), agent_id=permit.agent_id)
    assert not b.allowed and b.reason == "pending_principal_approval"
    # ...while small spends still flow.
    c = flow.spend(permit.permit_id, 2000, "m1", PredicateType.D, ah(), agent_id=permit.agent_id)
    assert c.allowed


def test_pending_approvals_lists_live_only():
    store, ledger, permit = make_store()
    flow, _ = make_flow(store, ledger)
    a1 = flow.spend(permit.permit_id, 3000, "m1", PredicateType.D, ah(), agent_id=permit.agent_id)
    a2 = flow.spend(permit.permit_id, 3000, "m1", PredicateType.D, ah(), agent_id=permit.agent_id)
    flow.deny_approval(a2.approval_id)
    live = store.pending_approvals()
    assert [a.approval_id for a in live] == [a1.approval_id]


def test_receipt_chain_survives_approval_flow():
    store, ledger, permit = make_store()
    flow, _ = make_flow(store, ledger)
    a = flow.spend(permit.permit_id, 4000, "m1", PredicateType.D, ah(), agent_id=permit.agent_id)
    flow.approve_approval(a.approval_id)
    c = flow.complete_approved_spend(a.approval_id)
    deliver_all(flow, c.escrow_id)
    ok, reason = ledger.verify_chain()
    assert ok, reason
    kinds = [r.event_type for r in ledger.receipts()]
    for k in ("APPROVAL_REQUESTED", "APPROVAL_PENDING", "APPROVAL_DECIDED",
              "ALLOWED", "AUTHORIZED", "CAPTURED"):
        assert k in kinds


def test_remaining_cents_reflects_tightened_cap():
    store, ledger, permit = make_store(cap=10000, threshold=None)
    flow, _ = make_flow(store, ledger)
    a = flow.spend(permit.permit_id, 6000, "m1", PredicateType.D, ah(), agent_id=permit.agent_id)
    deliver_all(flow, a.escrow_id)
    assert store.get(permit.permit_id).remaining_cents() == 4000
    store.tighten(permit.permit_id, cap_cents=7000)
    # The principal sees the enforced remainder, not the granted cap.
    assert store.get(permit.permit_id).remaining_cents() == 1000


def test_approval_single_use_under_concurrency():
    """F2: N threads race the same approval_id; exactly one ALLOWED.

    A short pause inside check() widens the pre-claim TOCTOU window so the
    race reproduces on unfixed code; with claim_approval() only one thread
    reaches check(), so the pause is harmless on the fix.
    """
    import time

    n_threads = 8
    n_trials = 30
    for trial in range(n_trials):
        store, ledger, permit = make_store(cap=100_000, threshold=100)
        flow, paypal = make_flow(store, ledger)
        pending = flow.spend(
            permit.permit_id, 500, "m1", PredicateType.D, ah(),
            agent_id=permit.agent_id,
        )
        assert pending.reason == "pending_principal_approval"
        flow.approve_approval(pending.approval_id)
        orig_check = store.check

        def check_with_yield(*args, **kwargs):
            time.sleep(0.005)
            return orig_check(*args, **kwargs)

        store.check = check_with_yield  # type: ignore[method-assign]
        barrier = threading.Barrier(n_threads)
        results: list = []
        lock = threading.Lock()

        def worker():
            barrier.wait()
            attempt = flow.spend(
                permit.permit_id,
                500,
                "m1",
                PredicateType.D,
                ah(),
                approval_id=pending.approval_id,
                agent_id=permit.agent_id,
            )
            with lock:
                results.append(attempt)

        threads = [threading.Thread(target=worker) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        allowed = [r for r in results if r.allowed]
        blocked = [r for r in results if not r.allowed]
        assert len(allowed) == 1, (
            f"trial {trial}: expected 1 ALLOWED, got {len(allowed)}"
        )
        assert len(blocked) == n_threads - 1
        assert all(r.reason == "invalid_approval" for r in blocked)
        assert store.get_approval(pending.approval_id).status == "consumed"
        assert len(paypal.authorize_calls) == 1
