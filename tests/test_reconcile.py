"""Reconcile tests: UNKNOWN escrows resolved against provider truth.

A timed-out capture leaves provider state unknown. verify_and_capture()
marks the escrow UNKNOWN and NEVER guesses; reconcile() queries
paypal.get_authorization() and either records a completed capture or
fails closed by voiding. Covers the P1 timeout findings end to end.
"""

import hashlib
from datetime import datetime, timedelta, timezone

from permit.ledger import Ledger
from permit.permit import PermitStore
from settlement.paypal_client import MockPayPalClient
from settlement.verifier import (
    Escrow,
    Evidence,
    PredicateType,
    ReleaseVerifier,
)


def _setup(amount_cents=3000):
    ledger = Ledger()
    permits = PermitStore(ledger=ledger)
    paypal = MockPayPalClient()
    verifier = ReleaseVerifier(paypal, permits, ledger=ledger)
    permit, _ = permits.grant(
        agent_id="agent_1",
        cap_cents=5000,
        allowlist=["merchant_1"],
        expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    check = permits.check(permit.permit_id, amount_cents, "merchant_1", agent_id=permit.agent_id)
    assert check.allowed
    auth_id = check.receipt.payload["auth_id"]
    pp_auth = paypal.authorize(amount_cents, "merchant_1")
    artifact = b"delivered work product"
    artifact_hash = hashlib.sha256(artifact).hexdigest()
    escrow = Escrow(
        escrow_id="esc_1",
        permit_id=permit.permit_id,
        auth_id=auth_id,
        paypal_auth_id=pp_auth.auth_id,
        amount_cents=amount_cents,
        merchant_id="merchant_1",
        predicate_type=PredicateType.D,
        artifact_hash=artifact_hash,
    )
    verifier.register(escrow)
    return verifier, paypal, permits, escrow, artifact


def _calls(paypal):
    return (len(paypal.capture_calls), len(paypal.voids), len(paypal.authorize_calls))


def test_reconcile_a_timeout_before_apply_stays_unknown():
    """(a) Timeout before the provider applied anything: UNKNOWN, the
    reservation unchanged, no capture recorded."""
    verifier, paypal, permits, escrow, artifact = _setup()
    paypal.inject_capture_timeout = "before_apply"
    result = verifier.verify_and_capture("esc_1", Evidence(delivered_bytes=artifact))
    assert not result.released
    assert result.reason == "unknown_after_timeout"
    assert escrow.state == "UNKNOWN"
    permit = permits.get(escrow.permit_id)
    assert permit.reserved_cents == 3000, "reservation unchanged after timeout"
    assert permit.captured_cents == 0
    assert paypal.capture_calls == [], "request never reached the provider"
    unknown = [r for r in verifier.ledger.receipts() if r.event_type == "UNKNOWN"]
    assert len(unknown) == 1
    assert unknown[0].payload["reason"] == "capture_timeout"


def test_reconcile_b_timeout_after_apply_no_double_capture():
    """(b) Lost response after the provider applied the capture: reconcile
    finds provider truth CAPTURED and records it WITHOUT a second capture
    call — the money moves at most once."""
    verifier, paypal, permits, escrow, artifact = _setup()
    paypal.inject_capture_timeout = "after_apply"
    result = verifier.verify_and_capture("esc_1", Evidence(delivered_bytes=artifact))
    assert not result.released
    assert escrow.state == "UNKNOWN"

    rec = verifier.reconcile("esc_1")
    assert rec.resolved is True
    assert rec.outcome == "captured"
    assert rec.capture is not None
    assert rec.capture.status == "COMPLETED"
    # Reconcile must NOT re-capture: exactly one capture call total.
    assert len(paypal.capture_calls) == 1
    assert escrow.state == "CAPTURED"
    permit = permits.get(escrow.permit_id)
    assert permit.captured_cents == 3000
    assert permit.reserved_cents == 0
    assert rec.receipt is not None and rec.receipt.event_type == "CAPTURED"


def test_reconcile_c_timeout_before_apply_voids_and_releases():
    """(c) Timeout before apply + reconcile: provider truth is AUTHORIZED
    with no capture recorded → fail closed: void the hold, release the
    reservation, VOIDED."""
    verifier, paypal, permits, escrow, artifact = _setup()
    paypal.inject_capture_timeout = "before_apply"
    verifier.verify_and_capture("esc_1", Evidence(delivered_bytes=artifact))
    assert escrow.state == "UNKNOWN"

    rec = verifier.reconcile("esc_1")
    assert rec.resolved is True
    assert rec.outcome == "voided"
    assert escrow.state == "VOIDED"
    assert escrow.paypal_auth_id in paypal.voids
    permit = permits.get(escrow.permit_id)
    assert permit.reserved_cents == 0, "reservation released on fail-closed void"
    assert permit.captured_cents == 0
    assert paypal.capture_calls == [], "no capture ever reached the provider"


def test_reconcile_d_verify_on_unknown_makes_no_paypal_calls():
    """(d) A second verify_and_capture() on an UNKNOWN escrow refuses
    immediately — zero PayPal traffic until reconcile() runs."""
    verifier, paypal, permits, escrow, artifact = _setup()
    paypal.inject_capture_timeout = "before_apply"
    verifier.verify_and_capture("esc_1", Evidence(delivered_bytes=artifact))
    before = _calls(paypal)

    result = verifier.verify_and_capture("esc_1", Evidence(delivered_bytes=artifact))
    assert not result.released
    assert result.reason == "unknown_reconcile_first"
    assert _calls(paypal) == before, "no PayPal calls on an UNKNOWN escrow"
    assert escrow.state == "UNKNOWN"


def test_reconcile_e_second_reconcile_is_already_resolved():
    """(e) Reconcile is idempotent: the second call returns already_resolved
    with no side effects."""
    verifier, paypal, permits, escrow, artifact = _setup()
    paypal.inject_capture_timeout = "before_apply"
    verifier.verify_and_capture("esc_1", Evidence(delivered_bytes=artifact))

    first = verifier.reconcile("esc_1")
    assert first.resolved is True and first.outcome == "voided"
    void_count = len(paypal.voids)

    second = verifier.reconcile("esc_1")
    assert second.resolved is False
    assert second.outcome == "already_resolved"
    assert second.capture is None and second.receipt is None
    assert len(paypal.voids) == void_count, "no second void"
    assert len(paypal.capture_calls) == 0


def test_reconcile_non_unknown_escrow_is_already_resolved():
    """An AUTHORIZED escrow is not eligible: reconcile() is a no-op."""
    verifier, paypal, permits, escrow, artifact = _setup()
    before = _calls(paypal)
    rec = verifier.reconcile("esc_1")
    assert rec.resolved is False
    assert rec.outcome == "already_resolved"
    assert _calls(paypal) == before
    assert escrow.state == "AUTHORIZED"
