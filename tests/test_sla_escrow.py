"""SLA escrow scenario tests: delegation tree x predicate settlement."""

import hashlib
from datetime import datetime, timedelta, timezone

from permit.flow import SpendPipeline
from permit.ledger import Ledger
from permit.permit import PermitStore
from scenarios.sla_escrow import MERCHANT, run_sla_escrow
from settlement.paypal_client import MockPayPalClient
from settlement.verifier import (
    Evidence,
    PredicateType,
    ReleaseVerifier,
    sign_acceptance,
)

EXPIRY = datetime.now(timezone.utc) + timedelta(hours=1)


def _rig():
    ledger = Ledger()
    permits = PermitStore(ledger=ledger)
    paypal = MockPayPalClient()
    verifier = ReleaseVerifier(paypal, permits, ledger=ledger)
    pipeline = SpendPipeline(permits, paypal, verifier, ledger=ledger)
    return ledger, permits, paypal, verifier, pipeline


def test_grant_fence_blocks_over_delegation():
    """Two carves cannot exceed the root cap: the second is refused."""
    _, permits, _, _, pipeline = _rig()
    parent, _ = permits.grant("client", 10000, [MERCHANT], EXPIRY)
    d1 = pipeline.delegate(parent.permit_id, "worker", 4000, [MERCHANT], EXPIRY)
    assert d1.ok
    d2 = pipeline.delegate(parent.permit_id, "worker", 7000, [MERCHANT], EXPIRY)
    assert not d2.ok
    assert d2.reason == "over_parent_remaining"
    assert d2.receipt is not None
    # The carve is fenced on the parent: $40 of $100 is spoken for.
    assert permits.get(parent.permit_id).remaining_cents() == 6000


def test_capture_rolls_up_through_delegation():
    """A worker's capture moves the parent's books reserved->captured."""
    _, permits, paypal, verifier, pipeline = _rig()
    parent, _ = permits.grant("client", 10000, [MERCHANT], EXPIRY)
    dlg = pipeline.delegate(parent.permit_id, "worker", 4000, [MERCHANT], EXPIRY)
    child = dlg.permit
    artifact_hash = hashlib.sha256(b"Q3 revenue report: final").hexdigest()
    attempt = pipeline.spend(
        child.permit_id, 4000, MERCHANT, PredicateType.A, artifact_hash
    )
    assert attempt.allowed
    sig = sign_acceptance(attempt.escrow_id, artifact_hash, 4000)
    result = pipeline.release(
        attempt.escrow_id, Evidence(acceptance_signature=sig)
    )
    assert result.released
    assert result.capture is not None
    p = permits.get(parent.permit_id)
    assert p.captured_cents == 4000
    assert p.reserved_cents == 0
    assert p.remaining_cents() == 6000


def test_forged_acceptance_is_refused_and_released():
    """A forged signature releases nothing; the hold is voided."""
    _, permits, paypal, verifier, pipeline = _rig()
    parent, _ = permits.grant("client", 10000, [MERCHANT], EXPIRY)
    dlg = pipeline.delegate(parent.permit_id, "worker", 3000, [MERCHANT], EXPIRY)
    child = dlg.permit
    artifact_hash = hashlib.sha256(b"appendix draft").hexdigest()
    attempt = pipeline.spend(
        child.permit_id, 3000, MERCHANT, PredicateType.A, artifact_hash
    )
    assert attempt.allowed
    forged = hashlib.sha256(b"worker says trust me").hexdigest()
    result = pipeline.release(
        attempt.escrow_id, Evidence(acceptance_signature=forged)
    )
    assert not result.released
    assert result.capture is None
    assert paypal.capture_calls == []
    # Hold voided, reservation released, carve intact on the child.
    c = permits.get(child.permit_id)
    assert c.reserved_cents == 0
    assert c.remaining_cents() == 3000
    refused = [
        r for r in permits.ledger.receipts() if r.event_type == "REFUSED"
    ]
    assert len(refused) == 1


def test_cascade_revoke_releases_carves_parent_whole():
    """After cascade + carve release, the parent holds exactly what settled."""
    ledger, permits, _, _, pipeline = _rig()
    parent, _ = permits.grant("client", 10000, [MERCHANT], EXPIRY)
    d1 = pipeline.delegate(parent.permit_id, "w1", 4000, [MERCHANT], EXPIRY)
    d2 = pipeline.delegate(parent.permit_id, "w2", 3000, [MERCHANT], EXPIRY)
    assert d1.ok and d2.ok
    receipt, voided = pipeline.revoke_cascade(parent.permit_id)
    assert receipt.event_type == "E-STOP"
    p = permits.get(parent.permit_id)
    assert p.revoked
    # Both $40 and $30 carves returned: parent whole at $100 free.
    assert p.reserved_cents == 0
    assert p.remaining_cents() == 10000
    carve_releases = [
        r for r in ledger.receipts() if r.event_type == "CARVE_RELEASED"
    ]
    assert len(carve_releases) == 2


def test_end_to_end_transcript():
    """The full scenario runs beat to beat with a complete receipt chain."""
    paypal = MockPayPalClient()
    t = run_sla_escrow(paypal)
    assert [b["beat"] for b in t["beats"]] == [
        "grant",
        "delegate",
        "capture",
        "forged_refused",
        "fence",
        "cascade",
    ]
    beats = {b["beat"]: b for b in t["beats"]}
    assert beats["capture"]["parent_captured_cents"] == 4000
    assert beats["forged_refused"]["paypal_captures"] == 1  # beat 3 only
    assert beats["fence"]["ok"] is False
    assert beats["fence"]["reason"] == "over_parent_remaining"
    assert beats["cascade"]["parent_remaining_cents"] == 6000
    assert beats["cascade"]["parent_reserved_cents"] == 0
    for rt in (
        "GRANTED",
        "DELEGATED",
        "ALLOWED",
        "CAPTURED",
        "REFUSED",
        "BLOCKED",
    ):
        assert rt in t["receipt_types"], f"missing receipt type {rt}"
