"""Spend-pipeline tests: the check->hold->escrow path, e-stop wiring, resume."""

import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from permit.ledger import Ledger
from permit.permit import PermitStore
from permit.flow import SpendPipeline
from settlement.paypal_client import MockPayPalClient
from settlement.verifier import Evidence, PredicateType, ReleaseVerifier


def _pipeline(cap_cents=5000, merchants=("merchant_1",)):
    ledger = Ledger()
    permits = PermitStore(ledger=ledger)
    paypal = MockPayPalClient()
    verifier = ReleaseVerifier(paypal, permits, ledger=ledger)
    flow = SpendPipeline(permits, paypal, verifier, ledger=ledger)
    permit, _ = permits.grant(
        agent_id="agent_1",
        cap_cents=cap_cents,
        allowlist=list(merchants),
        expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    return flow, paypal, permits, permit


def _artifact():
    b = b"delivered work product"
    return b, hashlib.sha256(b).hexdigest()


def test_blocked_spend_never_touches_paypal():
    flow, paypal, permits, permit = _pipeline()
    attempt = flow.spend(permit.permit_id, 99999, "merchant_1", PredicateType.D, "hash")
    assert not attempt.allowed
    assert attempt.reason == "over_remaining_cap"
    assert attempt.escrow_id is None
    assert attempt.receipts[0].event_type == "BLOCKED"
    # Not even the authorize call happened.
    assert len(paypal.authorizations) == 0
    assert len(paypal.capture_calls) == 0


def test_blocked_wrong_merchant_never_touches_paypal():
    flow, paypal, permits, permit = _pipeline()
    attempt = flow.spend(permit.permit_id, 1000, "evil_merchant", PredicateType.D, "hash")
    assert not attempt.allowed
    assert attempt.reason == "merchant_not_allowed"
    assert len(paypal.authorizations) == 0


def test_allowed_spend_registers_escrow():
    flow, paypal, permits, permit = _pipeline()
    _, digest = _artifact()
    attempt = flow.spend(permit.permit_id, 3000, "merchant_1", PredicateType.D, digest)
    assert attempt.allowed
    assert attempt.escrow_id is not None
    assert [r.event_type for r in attempt.receipts] == ["ALLOWED", "AUTHORIZED"]
    assert permit.remaining_cents() == 2000
    ok, _ = flow.ledger.verify_chain()
    assert ok


def test_happy_path_release_captures():
    flow, paypal, permits, permit = _pipeline()
    artifact, digest = _artifact()
    attempt = flow.spend(permit.permit_id, 3000, "merchant_1", PredicateType.D, digest)
    result = flow.release(attempt.escrow_id, Evidence(delivered_bytes=artifact))
    assert result.released
    assert result.capture.status == "COMPLETED"
    assert permit.remaining_cents() == 2000  # reserved -> captured
    assert permit.captured_cents == 3000


def test_bad_evidence_refuses_and_never_captures():
    flow, paypal, permits, permit = _pipeline()
    _, digest = _artifact()
    attempt = flow.spend(permit.permit_id, 3000, "merchant_1", PredicateType.D, digest)
    result = flow.release(attempt.escrow_id, Evidence(delivered_bytes=b"wrong bytes"))
    assert not result.released
    assert result.reason.startswith("predicate:")
    assert len(paypal.capture_calls) == 0
    # Refused release cleans up: PayPal hold voided, reservation released.
    assert permit.remaining_cents() == 5000


def test_estop_voids_in_flight_escrow():
    flow, paypal, permits, permit = _pipeline()
    _, digest = _artifact()
    attempt = flow.spend(permit.permit_id, 3000, "merchant_1", PredicateType.D, digest)
    receipt, voided = flow.estop(permit.permit_id)
    assert receipt.event_type == "E-STOP"
    assert voided == [attempt.escrow_id]
    assert permit.revoked
    # Release after e-stop is refused: the escrow is VOIDED.
    artifact, _ = _artifact()
    result = flow.release(attempt.escrow_id, Evidence(delivered_bytes=artifact))
    assert not result.released
    assert result.reason == "already_voided"
    assert len(paypal.capture_calls) == 0


def test_spend_after_estop_blocked():
    flow, paypal, permits, permit = _pipeline()
    flow.estop(permit.permit_id)
    attempt = flow.spend(permit.permit_id, 1000, "merchant_1", PredicateType.D, "hash")
    assert not attempt.allowed
    assert attempt.reason == "revoked"
    assert len(paypal.authorizations) == 0


def test_register_escrow_resume_does_not_double_reserve():
    """Sandbox-mode resume path after NeedsPayerApproval."""
    flow, paypal, permits, permit = _pipeline()
    _, digest = _artifact()
    # Simulate: check() passed, PayPal hold taken, spend() raised before
    # registration. Resume registers the escrow directly.
    check = permits.check(permit.permit_id, 3000, "merchant_1")
    auth_id = check.receipt.payload["auth_id"]
    pp_auth = paypal.authorize(3000, "merchant_1")
    escrow_id, receipt = flow.register_escrow(
        permit_id=permit.permit_id,
        auth_id=auth_id,
        paypal_auth_id=pp_auth.auth_id,
        amount_cents=3000,
        merchant_id="merchant_1",
        predicate_type=PredicateType.D,
        artifact_hash=digest,
    )
    assert receipt.event_type == "AUTHORIZED"
    assert permit.reserved_cents == 3000  # single reservation, not doubled
    # E-stop still voids it through the mapping.
    _, voided = flow.estop(permit.permit_id)
    assert voided == [escrow_id]


# -- e-stop at release time / cascade to in-flight child holds ----------------
# Regression tests for Gauntlet cases estop-parent-child-inflight and
# estop-during-release (Permit 2e08ab2: both SILENTLY_EXECUTED).


def _child(flow, permits, parent, cap_cents=1500):
    res = flow.delegate(
        parent.permit_id, "child_agent", cap_cents, ["merchant_1"],
        datetime.now(timezone.utc) + timedelta(minutes=30),
    )
    assert res.ok
    return res.permit


def test_parent_estop_voids_in_flight_child_hold():
    """Gauntlet estop-parent-child-inflight: a parent e-stop cascades to the
    child's open hold — child revoked, hold voided, no capture."""
    flow, paypal, permits, parent = _pipeline()
    child = _child(flow, permits, parent)
    artifact, digest = _artifact()
    attempt = flow.spend(child.permit_id, 200, "merchant_1", PredicateType.D, digest)
    assert attempt.allowed
    receipt, voided = flow.estop(parent.permit_id)
    assert receipt.event_type == "E-STOP"
    assert voided == [attempt.escrow_id]
    assert child.revoked
    cascade = [r for r in permits.ledger.receipts() if r.event_type == "REVOKED_CASCADE"]
    assert [r.payload["permit_id"] for r in cascade] == [child.permit_id]
    assert cascade[0].payload["cascade_from"] == parent.permit_id
    result = flow.release(attempt.escrow_id, Evidence(delivered_bytes=artifact))
    assert not result.released
    assert result.reason == "already_voided"
    assert len(paypal.capture_calls) == 0
    assert child.reserved_cents == 0
    assert permits.ledger.verify_chain()[0]


def test_release_refused_when_ancestor_revoked():
    """Release-time admission checks every ancestor, not just the permit."""
    flow, paypal, permits, parent = _pipeline()
    child = _child(flow, permits, parent)
    artifact, digest = _artifact()
    attempt = flow.spend(child.permit_id, 200, "merchant_1", PredicateType.D, digest)
    parent.revoked = True  # ancestor dead, child flag untouched
    result = flow.release(attempt.escrow_id, Evidence(delivered_bytes=artifact))
    assert not result.released
    assert result.reason == "ancestor_revoked"
    assert len(paypal.capture_calls) == 0
    assert child.reserved_cents == 0
    refused = [r for r in permits.ledger.receipts() if r.event_type == "REFUSED"]
    assert refused[-1].payload == {
        "escrow_id": attempt.escrow_id, "reason": "ancestor_revoked"}


def test_estop_between_admission_and_capture_refuses_capture():
    """Gauntlet estop-during-release: an e-stop landing after the release was
    admitted (here: during predicate evaluation) still stops the capture."""
    flow, paypal, permits, permit = _pipeline()
    artifact, digest = _artifact()
    attempt = flow.spend(permit.permit_id, 500, "merchant_1", PredicateType.D, digest)
    verifier = flow.verifier
    real_predicate = verifier._predicate_passes

    def predicate_then_estop(escrow, evidence):
        out = real_predicate(escrow, evidence)
        permits.estop(permit.permit_id)  # lands after admission, before capture
        return out

    verifier._predicate_passes = predicate_then_estop
    result = flow.release(attempt.escrow_id, Evidence(delivered_bytes=artifact))
    assert not result.released
    assert result.reason == "revoked"
    assert len(paypal.capture_calls) == 0
    assert permit.reserved_cents == 0
    events = [r.event_type for r in permits.ledger.receipts()]
    assert "CAPTURED" not in events
    assert events.index("E-STOP") < events.index("REFUSED")


def test_estop_during_capture_is_ordered_after_captured():
    """An e-stop that arrives while the capture is already at the provider
    waits for it: the ledger never shows E-STOP before CAPTURED."""
    import threading

    flow, paypal, permits, permit = _pipeline()
    artifact, digest = _artifact()
    attempt = flow.spend(permit.permit_id, 500, "merchant_1", PredicateType.D, digest)
    in_capture, finish = threading.Event(), threading.Event()
    real_capture = paypal.capture

    def slow_capture(*a, **kw):
        in_capture.set()
        assert finish.wait(5)
        return real_capture(*a, **kw)

    paypal.capture = slow_capture
    out = {}
    rel = threading.Thread(target=lambda: out.setdefault(
        "r", flow.release(attempt.escrow_id, Evidence(delivered_bytes=artifact))))
    rel.start()
    assert in_capture.wait(5)
    stop = threading.Thread(target=lambda: flow.estop(permit.permit_id))
    stop.start()
    stop.join(0.2)
    assert stop.is_alive()  # gated behind the in-flight capture
    finish.set()
    rel.join(5)
    stop.join(5)
    assert out["r"].released
    events = [r.event_type for r in permits.ledger.receipts()]
    assert events.index("CAPTURED") < events.index("E-STOP")
