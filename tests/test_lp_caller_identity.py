"""Least-privilege fix 3: caller identity on check()/spend()."""
import hashlib
from datetime import datetime, timedelta, timezone

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
    return SpendPipeline(ps, pp, ver, ledger=led), ps, pp


def _grant(ps, **kw):
    return ps.grant(agent_id="agent_a", cap_cents=5000, allowlist=[M],
                    expiry=datetime.now(timezone.utc) + timedelta(hours=1),
                    **kw)[0]


def test_check_agent_mismatch_denied_with_receipt():
    _, ps, _ = _env()
    p = _grant(ps)
    r = ps.check(p.permit_id, 1000, M, agent_id="agent_b")
    assert not r.allowed and r.reason == "agent_mismatch"
    assert r.receipt.event_type == "BLOCKED"
    assert r.receipt.payload["reason"] == "agent_mismatch"
    assert ps.get(p.permit_id).reserved_cents == 0


def test_check_matching_agent_allowed():
    _, ps, _ = _env()
    p = _grant(ps)
    assert ps.check(p.permit_id, 1000, M, agent_id="agent_a").allowed


def test_opt_out_omitted_agent_still_allowed():
    # require_agent_id is now True by default; the explicit opt-out keeps
    # the old behaviour available.
    _, ps, _ = _env()
    p = _grant(ps, require_agent_id=False)
    assert ps.check(p.permit_id, 1000, M).allowed


def test_default_requires_agent_id():
    fl, ps, pp = _env()
    p = _grant(ps)
    assert p.require_agent_id is True
    r = ps.check(p.permit_id, 1000, M)
    assert not r.allowed and r.reason == "agent_id_required"
    assert ps.get(p.permit_id).reserved_cents == 0
    a = fl.spend(p.permit_id, 1000, M, PT.D, DIG)
    assert not a.allowed and a.reason == "agent_id_required"
    assert ps.eligible(p.permit_id, 1000, M).reason == "agent_id_required"


def test_default_require_agent_id_inherited_by_carve():
    _, ps, _ = _env()
    p = _grant(ps)
    res = ps.delegate(p.permit_id, "agent_c", 1000, [M],
                      p.expiry - timedelta(minutes=5))
    assert res.ok and res.permit.require_agent_id is True
    assert ps.check(res.permit.permit_id, 500, M).reason == "agent_id_required"
    assert ps.check(res.permit.permit_id, 500, M, agent_id="agent_c").allowed


def test_strict_permit_requires_agent_id():
    fl, ps, pp = _env()
    p = _grant(ps, require_agent_id=True)
    r = ps.check(p.permit_id, 1000, M)
    assert not r.allowed and r.reason == "agent_id_required"
    a = fl.spend(p.permit_id, 1000, M, PT.D, DIG)
    assert not a.allowed and a.reason == "agent_id_required"
    assert fl.spend(p.permit_id, 1000, M, PT.D, DIG, agent_id="agent_a").allowed


def test_spend_mismatch_blocked_before_approval_request():
    fl, ps, pp = _env()
    p = _grant(ps, approval_threshold_cents=500)
    a = fl.spend(p.permit_id, 1000, M, PT.D, DIG, agent_id="agent_b")
    assert not a.allowed and a.reason == "agent_mismatch"
    assert a.approval_id is None
    kinds = [r.event_type for r in ps.ledger.receipts()]
    assert "APPROVAL_REQUESTED" not in kinds
    assert not pp.authorizations if hasattr(pp, "authorizations") else True


def test_strict_approved_spend_completes():
    fl, ps, _ = _env()
    p = _grant(ps, approval_threshold_cents=500, require_agent_id=True)
    a = fl.spend(p.permit_id, 1000, M, PT.D, DIG, agent_id="agent_a")
    assert a.reason == "pending_principal_approval"
    fl.approve_approval(a.approval_id, actor="human")
    assert fl.complete_approved_spend(a.approval_id).allowed


def test_eligible_mirrors_agent_mismatch():
    _, ps, _ = _env()
    p = _grant(ps)
    r = ps.eligible(p.permit_id, 1000, M, agent_id="agent_b")
    assert not r.allowed and r.reason == "agent_mismatch"


def test_fold_preserves_least_privilege_fields():
    """A store rebuilt from receipts keeps the grant's opt-outs and the
    lineage's strict caller identity (durable reload path)."""
    from permit.sqlite_ledger import fold_receipts
    _, ps, _ = _env()
    loose = _grant(ps, require_agent_id=False, approval_mode="per_spend")
    strict = _grant(ps)
    res = ps.delegate(strict.permit_id, "agent_c", 1000, [M],
                      strict.expiry - timedelta(minutes=5))
    folded = fold_receipts(ps.ledger.receipts())
    assert folded.get(loose.permit_id).require_agent_id is False
    assert folded.get(loose.permit_id).approval_mode == "per_spend"
    assert folded.get(strict.permit_id).require_agent_id is True
    assert folded.get(strict.permit_id).approval_mode == "cumulative"
    assert folded.get(res.permit.permit_id).require_agent_id is True
