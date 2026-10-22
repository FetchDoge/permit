"""M4 e-stop race proof: revocation wins at every point in a spend's life.

The individual race windows are covered elsewhere (P1-1 in
test_authority_layer.py, the capture-time ledger ordering in
test_estop_ledger_order.py). This file proves the three timings as one
claim, on the mock rail, and pins the judge-runnable demo
(demos/demo_estop.py) that shows the same beats:

  1. revoked BEFORE the spend: BLOCKED, zero rail calls;
  2. e-stop INSIDE authorize: revoked_during_auth, the hold is voided,
     the reservation is released, no escrow exists, capture unreachable;
  3. e-stop AFTER authorize: the in-flight escrow is voided, a late
     delivery is refused, zero captures, audit shows $0 captured.
"""

import hashlib
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from permit.audit import audit_summary
from permit.flow import SpendPipeline
from permit.ledger import Ledger
from permit.permit import PermitStore
from settlement.paypal_client import MockPayPalClient
from settlement.verifier import Evidence, PredicateType, ReleaseVerifier

ROOT = Path(__file__).resolve().parents[1]
MERCHANT = "coffee-shop"
DATA = b"dataset-license-bytes"
HASH = hashlib.sha256(DATA).hexdigest()


def _build(cap_cents=5000):
    ledger = Ledger()
    permits = PermitStore(ledger=ledger)
    paypal = MockPayPalClient()
    verifier = ReleaseVerifier(paypal, permits, ledger=ledger, allow_demo_key=True)
    flow = SpendPipeline(permits, paypal, verifier, ledger=ledger)
    permit, _ = permits.grant(
        agent_id="agent",
        cap_cents=cap_cents,
        allowlist=[MERCHANT],
        expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    return flow, paypal, permits, verifier, permit


def test_revoked_before_spend_never_reaches_rail():
    flow, paypal, permits, verifier, permit = _build()
    flow.estop(permit.permit_id)
    attempt = flow.spend(permit.permit_id, 3000, MERCHANT, PredicateType.D, HASH)
    assert not attempt.allowed
    assert attempt.reason == "revoked"
    assert attempt.escrow_id is None
    assert paypal.authorize_calls == []
    assert paypal.capture_calls == []
    ok, _ = permits.ledger.verify_chain()
    assert ok


def test_estop_inside_authorize_wins_the_race():
    flow, paypal, permits, verifier, permit = _build()
    real_authorize = paypal.authorize

    def hostile_authorize(amount_cents, merchant_id, idempotency_key=None):
        auth = real_authorize(amount_cents, merchant_id, idempotency_key)
        flow.estop(permit.permit_id)  # stop lands while authorize is in flight
        return auth

    paypal.authorize = hostile_authorize
    attempt = flow.spend(permit.permit_id, 3000, MERCHANT, PredicateType.D, HASH)
    assert not attempt.allowed
    assert attempt.reason == "revoked_during_auth"
    assert attempt.escrow_id is None
    # The in-flight hold was voided and the reservation released.
    assert len(paypal.voids) == 1
    assert permit.reserved_cents == 0
    assert permit.remaining_cents() == 5000
    # No escrow was registered, so capture has nothing to act on.
    assert verifier._escrows == {}
    assert paypal.capture_calls == []
    ok, _ = permits.ledger.verify_chain()
    assert ok


def test_estop_after_authorize_voids_inflight_and_refuses_release():
    flow, paypal, permits, verifier, permit = _build()
    attempt = flow.spend(permit.permit_id, 3000, MERCHANT, PredicateType.D, HASH)
    assert attempt.allowed and attempt.escrow_id

    result = flow.estop(permit.permit_id)
    assert result.voided == [attempt.escrow_id]
    assert result.unresolved == []
    assert permit.reserved_cents == 0
    assert permit.remaining_cents() == 5000

    release = flow.release(attempt.escrow_id, Evidence(delivered_bytes=DATA))
    assert not release.released
    assert release.reason == "already_voided"
    assert paypal.capture_calls == []

    summary = audit_summary(permits.ledger)
    assert summary["chain"]["ok"]
    assert summary["totals"]["captured_cents"] == 0


def test_estop_demo_exits_clean():
    proc = subprocess.run(
        [sys.executable, "demos/demo_estop.py"],
        cwd=ROOT, capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "reason=revoked_during_auth" in proc.stdout
    assert "already_voided" in proc.stdout
    assert "over_remaining_cap" in proc.stdout
    assert proc.stdout.count("VERIFIED") == 4  # one chain line per beat
