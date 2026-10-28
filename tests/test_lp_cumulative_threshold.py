"""Least-privilege fix 2: cumulative approval threshold (now the default)."""
import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from permit.ledger import Ledger
from permit.permit import PermitStore
from permit.flow import SpendPipeline
from settlement.paypal_client import MockPayPalClient
from settlement.verifier import Evidence, PredicateType as PT, ReleaseVerifier

ART = b"deliverable"
DIG = hashlib.sha256(ART).hexdigest()
M = "m_shop"


def _env():
    led = Ledger()
    ps = PermitStore(ledger=led)
    pp = MockPayPalClient()
    ver = ReleaseVerifier(pp, ps, ledger=led, allow_demo_key=True)
    return SpendPipeline(ps, pp, ver, ledger=led), ps


def _grant(ps, **kw):
    return ps.grant(agent_id="agent_a", cap_cents=10000, allowlist=[M],
                    expiry=datetime.now(timezone.utc) + timedelta(hours=1),
                    approval_threshold_cents=2000, **kw)[0]


def _spend_capture(fl, pid, amt):
    a = fl.spend(pid, amt, M, PT.D, DIG, agent_id="agent_a")
    if not a.allowed:
        return a
    fl.release(a.escrow_id, Evidence(delivered_bytes=ART))
    return a


def test_explicit_per_spend_mode():
    # per_spend is no longer the default; it stays available explicitly.
    fl, ps = _env()
    p = _grant(ps, approval_mode="per_spend")
    assert p.approval_mode == "per_spend"
    for _ in range(3):
        assert _spend_capture(fl, p.permit_id, 2000).allowed
    assert ps.get(p.permit_id).captured_cents == 6000


def test_cumulative_holds_split_spend():
    fl, ps = _env()
    p = _grant(ps, approval_mode="cumulative")
    assert _spend_capture(fl, p.permit_id, 2000).allowed
    a = fl.spend(p.permit_id, 2000, M, PT.D, DIG, agent_id="agent_a")
    assert not a.allowed and a.reason == "pending_principal_approval"
    assert ps.get(p.permit_id).captured_cents == 2000


def test_cumulative_counts_reserved_holds():
    fl, ps = _env()
    p = _grant(ps, approval_mode="cumulative")
    assert fl.spend(p.permit_id, 1500, M, PT.D, DIG, agent_id="agent_a").allowed  # held, not captured
    a = fl.spend(p.permit_id, 600, M, PT.D, DIG, agent_id="agent_a")
    assert a.reason == "pending_principal_approval"


def test_cumulative_approved_spend_completes():
    fl, ps = _env()
    p = _grant(ps, approval_mode="cumulative")
    _spend_capture(fl, p.permit_id, 2000)
    a = fl.spend(p.permit_id, 500, M, PT.D, DIG, agent_id="agent_a")
    fl.approve_approval(a.approval_id, actor="human")
    assert fl.complete_approved_spend(a.approval_id).allowed


def test_default_is_cumulative():
    fl, ps = _env()
    p = _grant(ps)
    assert p.approval_mode == "cumulative"
    # 3 x $20 against a $20 threshold: the first captures, the second
    # goes to the principal (split-payment bypass closed by default).
    assert _spend_capture(fl, p.permit_id, 2000).allowed
    a = fl.spend(p.permit_id, 2000, M, PT.D, DIG, agent_id="agent_a")
    assert a.reason == "pending_principal_approval"
    assert ps.get(p.permit_id).captured_cents == 2000


def test_invalid_mode_rejected():
    _, ps = _env()
    with pytest.raises(ValueError, match="invalid_approval_mode"):
        _grant(ps, approval_mode="sometimes")
