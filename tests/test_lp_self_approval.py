"""Least-privilege fix 1: an agent cannot approve its own spend."""
import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from permit.ledger import Ledger
from permit.permit import PermitStore
from permit.flow import SpendPipeline
from settlement.paypal_client import MockPayPalClient
from settlement.verifier import PredicateType as PT, ReleaseVerifier

DIG = hashlib.sha256(b"deliverable").hexdigest()
M = "m_shop"


def _env():
    led = Ledger()
    ps = PermitStore(ledger=led)
    pp = MockPayPalClient()
    ver = ReleaseVerifier(pp, ps, ledger=led, allow_demo_key=True)
    return SpendPipeline(ps, pp, ver, ledger=led), ps


def _pending(fl, ps, **grant_kw):
    p, _ = ps.grant(agent_id="agent_a", cap_cents=5000, allowlist=[M],
                    expiry=datetime.now(timezone.utc) + timedelta(hours=1),
                    approval_threshold_cents=1000, **grant_kw)
    a = fl.spend(p.permit_id, 1500, M, PT.D, DIG)
    assert a.reason == "pending_principal_approval"
    return p, a.approval_id


def test_self_approval_is_refused_with_receipt():
    fl, ps = _env()
    _, aid = _pending(fl, ps)
    with pytest.raises(ValueError, match="self_approval"):
        fl.approve_approval(aid, actor="agent_a")
    assert ps.get_approval(aid).status == "pending"
    r = ps.ledger.receipts()[-1]
    assert r.event_type == "APPROVAL_REFUSED"
    assert r.payload["reason"] == "self_approval"
    s = fl.complete_approved_spend(aid)
    assert not s.allowed


def test_self_denial_also_refused():
    fl, ps = _env()
    _, aid = _pending(fl, ps)
    with pytest.raises(ValueError, match="self_approval"):
        fl.deny_approval(aid, actor="agent_a")


def test_other_actor_still_approves_by_default():
    fl, ps = _env()
    _, aid = _pending(fl, ps)
    fl.approve_approval(aid, actor="human")
    assert fl.complete_approved_spend(aid).allowed


def test_principal_id_binds_the_approver():
    fl, ps = _env()
    _, aid = _pending(fl, ps, principal_id="marcus")
    with pytest.raises(ValueError, match="principal_mismatch"):
        fl.approve_approval(aid, actor="human")
    assert ps.ledger.receipts()[-1].payload["reason"] == "principal_mismatch"
    assert ps.get_approval(aid).status == "pending"
    fl.approve_approval(aid, actor="marcus")
    assert fl.complete_approved_spend(aid).allowed


def test_principal_id_equal_to_agent_rejected_at_grant():
    _, ps = _env()
    with pytest.raises(ValueError, match="principal_is_agent"):
        ps.grant(agent_id="agent_a", cap_cents=100, allowlist=[M],
                 expiry=datetime.now(timezone.utc) + timedelta(hours=1),
                 principal_id="agent_a")
