"""Permit core tests: 4-clause independence, cumulative cap (C1–C3), e-stop."""

import threading
from datetime import datetime, timedelta, timezone

import pytest

from permit.ledger import Ledger
from permit.permit import PermitStore


def _store(cap_cents=5000, merchants=("merchant_1",)):
    s = PermitStore()
    permit, _ = s.grant(
        agent_id="agent_1",
        cap_cents=cap_cents,
        allowlist=list(merchants),
        expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    return s, permit


def test_grant_writes_receipt():
    s, permit = _store()
    assert len(s.ledger) == 1
    r = s.ledger.receipts()[0]
    assert r.event_type == "GRANTED"
    assert r.payload["permit_id"] == permit.permit_id


def test_allowed_attempt_reserves_cap():
    s, permit = _store()
    res = s.check(permit.permit_id, 3000, "merchant_1", agent_id=permit.agent_id)
    assert res.allowed
    assert res.receipt.event_type == "ALLOWED"
    assert permit.remaining_cents() == 2000


def test_clause_over_cap_blocks():
    s, permit = _store()
    res = s.check(permit.permit_id, 6000, "merchant_1", agent_id=permit.agent_id)
    assert not res.allowed and res.reason == "over_remaining_cap"
    assert res.receipt.event_type == "BLOCKED"
    assert permit.remaining_cents() == 5000  # nothing reserved


def test_clause_merchant_not_allowed_blocks():
    s, permit = _store()
    res = s.check(permit.permit_id, 1000, "evil_merchant", agent_id=permit.agent_id)
    assert not res.allowed and res.reason == "merchant_not_allowed"


def test_clause_expired_blocks():
    s = PermitStore()
    permit, _ = s.grant(
        agent_id="agent_1",
        cap_cents=5000,
        allowlist=["merchant_1"],
        expiry=datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    res = s.check(permit.permit_id, 1000, "merchant_1", agent_id=permit.agent_id)
    assert not res.allowed and res.reason == "expired"


def test_clause_revoked_blocks():
    s, permit = _store()
    s.estop(permit.permit_id)
    res = s.check(permit.permit_id, 1000, "merchant_1", agent_id=permit.agent_id)
    assert not res.allowed and res.reason == "revoked"


def test_c1_concurrent_attempts_cannot_exceed_cap():
    """Five concurrent $30 attempts against a $50 cap: at most $50 reserved."""
    s, permit = _store(cap_cents=5000)
    results = []

    def attempt():
        results.append(s.check(permit.permit_id, 3000, "merchant_1", agent_id=permit.agent_id))

    threads = [threading.Thread(target=attempt) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    allowed = [r for r in results if r.allowed]
    blocked = [r for r in results if not r.allowed]
    # Only one $30 can fit in $50.
    assert len(allowed) == 1
    assert len(blocked) == 4
    assert all(r.reason == "over_remaining_cap" for r in blocked)
    assert permit.reserved_cents == 3000
    assert permit.remaining_cents() == 2000


def test_c2_void_releases_reservation():
    s, permit = _store()
    res = s.check(permit.permit_id, 3000, "merchant_1", agent_id=permit.agent_id)
    auth_id = res.receipt.payload["auth_id"]
    assert permit.remaining_cents() == 2000
    s.settle_void(permit.permit_id, auth_id)
    assert permit.remaining_cents() == 5000
    assert permit.reserved_cents == 0


def test_c3_capture_decrements_remaining():
    s, permit = _store()
    res = s.check(permit.permit_id, 3000, "merchant_1", agent_id=permit.agent_id)
    auth_id = res.receipt.payload["auth_id"]
    s.settle_capture(permit.permit_id, auth_id)
    assert permit.captured_cents == 3000
    assert permit.reserved_cents == 0
    assert permit.remaining_cents() == 2000
    # A further $30 attempt now exceeds remaining.
    res2 = s.check(permit.permit_id, 3000, "merchant_1", agent_id=permit.agent_id)
    assert not res2.allowed and res2.reason == "over_remaining_cap"


def test_estop_returns_in_flight_and_blocks_further():
    s, permit = _store()
    r1 = s.check(permit.permit_id, 2000, "merchant_1", agent_id=permit.agent_id)
    r2 = s.check(permit.permit_id, 2000, "merchant_1", agent_id=permit.agent_id)
    assert r1.allowed and r2.allowed
    receipt, in_flight = s.estop(permit.permit_id)
    assert receipt.event_type == "E-STOP"
    assert set(in_flight) == {
        r1.receipt.payload["auth_id"],
        r2.receipt.payload["auth_id"],
    }
    # No further check can pass.
    r3 = s.check(permit.permit_id, 100, "merchant_1", agent_id=permit.agent_id)
    assert not r3.allowed and r3.reason == "revoked"


def test_chain_verifies():
    s, permit = _store()
    s.check(permit.permit_id, 1000, "merchant_1", agent_id=permit.agent_id)
    s.check(permit.permit_id, 9000, "merchant_1", agent_id=permit.agent_id)  # blocked
    ok, reason = s.ledger.verify_chain()
    assert ok, reason


def test_chain_detects_tampering():
    s, permit = _store()
    s.check(permit.permit_id, 1000, "merchant_1", agent_id=permit.agent_id)
    receipts = s.ledger.receipts()
    # Tamper with a payload in the stored list (simulates disk tampering).
    object.__setattr__(
        receipts[1], "payload", {**receipts[1].payload, "amount_cents": 1}
    )
    # Reach into the ledger's internal list to simulate a stored tamper.
    s.ledger._receipts[1] = receipts[1]
    ok, reason = s.ledger.verify_chain()
    assert not ok
    assert "tampered" in reason or "mismatch" in reason


def test_no_paypal_imports_in_permit_module():
    import ast

    import permit.permit as pm
    import permit.ledger as lg

    for mod in (pm, lg):
        tree = ast.parse(open(mod.__file__).read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert "paypal" not in alias.name.lower(), (
                        f"PayPal import in {mod.__name__}: {alias.name}"
                    )
                    assert "settlement" not in alias.name.lower(), (
                        f"settlement import in {mod.__name__}: {alias.name}"
                    )
            elif isinstance(node, ast.ImportFrom):
                assert not (node.module and "paypal" in node.module.lower()), (
                    f"PayPal import in {mod.__name__}: {node.module}"
                )
                assert not (node.module and "settlement" in node.module.lower()), (
                    f"settlement import in {mod.__name__}: {node.module}"
                )
