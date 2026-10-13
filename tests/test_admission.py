"""Admission-gating proofs (M4 acceptance criteria, additive).

The gate refuses a spend BEFORE anything is created: no order, no hold,
no escrow, no PayPal call. When the prepaid budget is exhausted, a
runaway agent loop hits a wall at admission: the budget-overrun story
is a blocked admission, not a declined settlement. And under concurrency
the cap is atomic: parallel overspend attempts cannot exceed it
(fail-closed).
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

from permit.flow import SpendPipeline
from permit.ledger import Ledger
from permit.permit import PermitStore
from settlement.paypal_client import MockPayPalClient
from settlement.verifier import PredicateType, ReleaseVerifier

MERCHANT = "coffee-shop"
ARTIFACT_HASH = "ab" * 32


def _pipeline(cap_cents=5000):
    ledger = Ledger()
    permits = PermitStore(ledger=ledger)
    paypal = MockPayPalClient()
    verifier = ReleaseVerifier(paypal, permits, ledger=ledger)
    flow = SpendPipeline(permits, paypal, verifier, ledger=ledger)
    permit, _ = permits.grant(
        agent_id="runaway-agent",
        cap_cents=cap_cents,
        allowlist=[MERCHANT],
        expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    return flow, paypal, permits, permit


def _spend(flow, permit_id, amount_cents):
    return flow.spend(
        permit_id, amount_cents, MERCHANT,
        PredicateType.D, ARTIFACT_HASH,
    )


def test_runaway_loop_refused_at_budget_exhaustion():
    """Criterion (a): 10 x $10 attempts against a $50 cap. The last five
    are refused at admission, before any spend is created."""
    flow, paypal, permits, permit = _pipeline(cap_cents=5000)
    results = [_spend(flow, permit.permit_id, 1000) for _ in range(10)]

    allowed = [r for r in results if r.allowed]
    blocked = [r for r in results if not r.allowed]
    assert len(allowed) == 5
    assert len(blocked) == 5

    for attempt in blocked:
        assert attempt.reason == "over_remaining_cap"
        assert attempt.escrow_id is None
        # Refused at admission: exactly one BLOCKED receipt, no ALLOWED
        # receipt, no auth_id minted, nothing registered.
        assert len(attempt.receipts) == 1
        receipt = attempt.receipts[0]
        assert receipt.event_type == "BLOCKED"
        assert receipt.payload["reason"] == "over_remaining_cap"
        assert receipt.payload["remaining_cents"] == 0
        assert "auth_id" not in receipt.payload

    # The rail only ever saw the five admitted spends.
    assert len(paypal.authorize_calls) == 5
    for amount, merchant, _key in paypal.authorize_calls:
        assert amount == 1000
        assert merchant == MERCHANT
    assert paypal.captures == {}

    # The five admitted holds hold the whole budget; nothing leaked.
    assert permits.get(permit.permit_id).reserved_cents == 5000
    ok, _ = permits.ledger.verify_chain()
    assert ok


def test_blocked_admission_creates_no_operation_or_order():
    """Criterion (a), sharper: at an exhausted budget the attempt writes a
    single BLOCKED receipt and allocates nothing else. The $5,000 surprise
    becomes a blocked admission, never an order."""
    flow, paypal, permits, permit = _pipeline(cap_cents=3000)
    first = _spend(flow, permit.permit_id, 3000)
    assert first.allowed and first.escrow_id is not None

    attempts_before = len(paypal.authorize_calls)
    escrows_before = len(paypal.authorizations)

    denied = _spend(flow, permit.permit_id, 1)
    assert not denied.allowed
    assert denied.reason == "over_remaining_cap"
    assert denied.receipts[0].payload["remaining_cents"] == 0

    # No new authorization call, no new order/authorization record.
    assert len(paypal.authorize_calls) == attempts_before
    assert len(paypal.authorizations) == escrows_before
    ok, _ = permits.ledger.verify_chain()
    assert ok


def test_concurrent_overspend_cannot_exceed_cap():
    """Criterion (b): 8 threads x 3 x $20 against a $50 cap ($480
    attempted). Atomic admission: the admitted total never exceeds the
    cap, every refusal is rail-silent, fail-closed."""
    flow, paypal, permits, permit = _pipeline(cap_cents=5000)
    results = []
    results_lock = threading.Lock()

    def worker():
        local = []
        for _ in range(3):
            local.append(_spend(flow, permit.permit_id, 2000))
        with results_lock:
            results.extend(local)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == 24
    allowed = [r for r in results if r.allowed]
    blocked = [r for r in results if not r.allowed]

    admitted_cents = sum(
        r.receipts[0].payload["amount_cents"] for r in allowed
    )
    # Serialized reservation: exactly two $20 holds fit a $50 cap.
    assert len(allowed) == 2
    assert admitted_cents == 4000
    assert admitted_cents <= 5000

    assert all(r.reason == "over_remaining_cap" for r in blocked)
    for r in blocked:
        assert len(r.receipts) == 1
        assert r.receipts[0].event_type == "BLOCKED"
        assert "auth_id" not in r.receipts[0].payload

    # The rail saw exactly the admitted spends: no phantom calls.
    assert len(paypal.authorize_calls) == len(allowed)
    assert permits.get(permit.permit_id).reserved_cents == 4000
    ok, _ = permits.ledger.verify_chain()
    assert ok
