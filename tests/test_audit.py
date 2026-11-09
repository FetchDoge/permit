"""M4 audit view: the ledger rollup an auditor reads.

audit_summary() derives everything from receipts alone: what the gate
allowed, what it blocked and why, how much money actually moved, and
whether the hash chain still verifies. These tests pin the derivation
rules, including the double-count trap: one capture writes TWO CAPTURED
receipts (permit-scoped from settle_capture, escrow-scoped from the
verifier), and the audit money totals must count it once.
"""

import json
import urllib.request
from datetime import datetime, timedelta, timezone

from agent.tools import SpendTools
from dashboard.server import Dashboard
from permit.audit import audit_summary
from permit.flow import SpendPipeline
from permit.ledger import Ledger
from permit.permit import PermitStore
from settlement.paypal_client import MockPayPalClient
from settlement.verifier import PredicateType, ReleaseVerifier


def _pipeline(cap_cents=5000):
    ledger = Ledger()
    permits = PermitStore(ledger=ledger)
    paypal = MockPayPalClient()
    verifier = ReleaseVerifier(paypal, permits, ledger=ledger)
    flow = SpendPipeline(permits, paypal, verifier, ledger=ledger)
    permit, _ = permits.grant(
        agent_id="agent_1",
        cap_cents=cap_cents,
        allowlist=["merchant_1"],
        expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    return flow, permits, ledger, permit


def test_audit_empty_ledger_is_zeroed_and_chain_ok():
    summary = audit_summary(Ledger())
    assert summary["chain"] == {"ok": True, "reason": "ok"}
    assert summary["total_receipts"] == 0
    assert summary["events"] == {}
    assert summary["blocked"] == {"total": 0, "by_reason": {}, "attempts": []}
    assert summary["permits"] == {}
    assert summary["totals"] == {"allowed_cents": 0, "captured_cents": 0}


def test_audit_allowed_and_blocked_rollup():
    flow, permits, ledger, permit = _pipeline()
    ok_attempt = flow.spend(
        permit.permit_id, 1000, "merchant_1", PredicateType.D, "hash", agent_id=permit.agent_id)
    assert ok_attempt.allowed
    blocked = flow.spend(
        permit.permit_id, 999999, "merchant_1", PredicateType.D, "hash", agent_id=permit.agent_id)
    assert not blocked.allowed and blocked.reason == "over_remaining_cap"
    wrong_merchant = flow.spend(
        permit.permit_id, 100, "merchant_evil", PredicateType.D, "hash", agent_id=permit.agent_id)
    assert not wrong_merchant.allowed
    assert wrong_merchant.reason == "merchant_not_allowed"

    summary = audit_summary(ledger)
    assert summary["chain"]["ok"]
    entry = summary["permits"][permit.permit_id]
    assert entry["allowed_count"] == 1
    assert entry["allowed_cents"] == 1000
    assert entry["blocked_count"] == 2
    assert summary["totals"]["allowed_cents"] == 1000
    assert summary["blocked"]["total"] == 2
    assert summary["blocked"]["by_reason"] == {
        "merchant_not_allowed": 1,
        "over_remaining_cap": 1,
    }
    attempts = {(a["reason"], a["merchant_id"]) for a in summary["blocked"]["attempts"]}
    assert attempts == {
        ("over_remaining_cap", "merchant_1"),
        ("merchant_not_allowed", "merchant_evil"),
    }
    over_cap = next(
        a for a in summary["blocked"]["attempts"]
        if a["reason"] == "over_remaining_cap")
    assert over_cap["amount_cents"] == 999999
    assert over_cap["permit_id"] == permit.permit_id


def test_audit_capture_counted_once_despite_two_captured_receipts():
    # The real release path: spend -> deliver -> capture writes a
    # permit-scoped CAPTURED (settle_capture) AND an escrow-scoped
    # CAPTURED (verifier) for the same $30.
    ledger = Ledger()
    permits = PermitStore(ledger=ledger)
    paypal = MockPayPalClient()
    verifier = ReleaseVerifier(paypal, permits, ledger=ledger)
    flow = SpendPipeline(permits, paypal, verifier, ledger=ledger)
    permit, _ = permits.grant(
        agent_id="t", cap_cents=5000, allowlist=["m"],
        expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    tools = SpendTools(flow, permit.permit_id, "m", {"widget": b"widget-bytes"})
    obs = json.loads(tools.attempt_spend(3000, "widget"))
    assert obs["decision"] == "ALLOWED"
    obs2 = json.loads(tools.deliver(obs["escrow_id"]))
    assert obs2["released"] is True

    captured_receipts = [
        r for r in ledger.receipts() if r.event_type == "CAPTURED"]
    assert len(captured_receipts) == 2  # the trap is real, not vacuous

    summary = audit_summary(ledger)
    assert summary["events"]["CAPTURED"] == 2
    assert summary["totals"]["captured_cents"] == 3000
    entry = summary["permits"][permit.permit_id]
    assert entry["captured_count"] == 1
    assert entry["captured_cents"] == 3000
    # The escrow-scoped receipt is not invisible: it is unscoped.
    assert summary["unscoped_receipts"] >= 1


def test_audit_reports_tampered_chain():
    flow, permits, ledger, permit = _pipeline()
    attempt = flow.spend(
        permit.permit_id, 100, "merchant_1", PredicateType.D, "hash", agent_id=permit.agent_id)
    assert attempt.allowed
    assert audit_summary(ledger)["chain"]["ok"]
    # Tamper with a recorded payload in place; the chain must break and
    # the audit must say so instead of rolling up trusted numbers.
    ledger.receipts()[0].payload["amount_cents"] = 999999
    summary = audit_summary(ledger)
    assert summary["chain"]["ok"] is False
    assert "tampered" in summary["chain"]["reason"]


def test_audit_is_read_only_and_served_by_dashboard():
    flow, permits, ledger, permit = _pipeline()
    attempt = flow.spend(
        permit.permit_id, 700, "merchant_1", PredicateType.D, "hash", agent_id=permit.agent_id)
    assert attempt.allowed
    before = [(r.seq, r.hash) for r in ledger.receipts()]

    summary = audit_summary(ledger)
    assert summary["totals"]["allowed_cents"] == 700
    assert [(r.seq, r.hash) for r in ledger.receipts()] == before

    dash = Dashboard(permits=permits, ledger=ledger, flow=flow, port=0).start()
    try:
        port = dash._server.server_address[1]
        with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/api/audit", timeout=5) as resp:
            served = json.loads(resp.read())
        assert served["totals"]["allowed_cents"] == 700
        assert served["chain"]["ok"] is True
        assert served["permits"][permit.permit_id]["allowed_count"] == 1
    finally:
        dash.stop()
    assert [(r.seq, r.hash) for r in ledger.receipts()] == before
