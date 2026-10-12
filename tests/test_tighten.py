"""
Tighten-only min-gate (v4): post-issuance narrowing of a live permit.
"""
import pytest
from datetime import datetime, timedelta, timezone

from permit.permit import PermitStore
from permit.ledger import Ledger


def make_store():
    return PermitStore(ledger=Ledger())


def grant(store, **kw):
    kw.setdefault("agent_id", "agent-1")
    kw.setdefault("cap_cents", 5000)
    kw.setdefault("allowlist", ["m1", "m2", "m3"])
    kw.setdefault("expiry", datetime.now(timezone.utc) + timedelta(hours=2))
    permit, _receipt = store.grant(**kw)
    return permit


def test_tighten_cap_narrows_and_blocks():
    store = make_store()
    p = grant(store)
    p2, receipt = store.tighten(p.permit_id, cap_cents=2000)
    assert p2.tighten_cap_cents == 2000
    assert receipt.event_type == "TIGHTEN"
    assert receipt.payload["changes"]["cap_cents"] == {"from": 5000, "to": 2000}
    r = store.check(p.permit_id, 2500, "m1")
    assert not r.allowed and r.reason == "tightened_cap_exceeded"
    r = store.check(p.permit_id, 1500, "m1")
    assert r.allowed


def test_tighten_widen_rejected():
    store = make_store()
    p = grant(store)
    with pytest.raises(ValueError):
        store.tighten(p.permit_id, cap_cents=6000)
    with pytest.raises(ValueError):
        store.tighten(p.permit_id, cap_cents=5000)  # no-op


def test_tighten_requires_param():
    store = make_store()
    p = grant(store)
    with pytest.raises(ValueError):
        store.tighten(p.permit_id)


def test_tighten_allowlist_removes_merchant():
    store = make_store()
    p = grant(store)
    store.tighten(p.permit_id, remove_merchants=["m3"])
    assert store.get(p.permit_id).tighten_allowlist == ("m1", "m2")
    r = store.check(p.permit_id, 100, "m3")
    assert not r.allowed and r.reason == "merchant_not_allowed"
    r = store.check(p.permit_id, 100, "m1")
    assert r.allowed


def test_tighten_allowlist_cannot_empty():
    store = make_store()
    p = grant(store)
    with pytest.raises(ValueError):
        store.tighten(p.permit_id, remove_merchants=["m1", "m2", "m3"])


def test_tighten_allowlist_unknown_merchant_rejected():
    store = make_store()
    p = grant(store)
    with pytest.raises(ValueError):
        store.tighten(p.permit_id, remove_merchants=["nope"])


def test_tighten_expiry_blocks_late_attempt():
    store = make_store()
    p = grant(store)
    new_exp = datetime.now(timezone.utc) + timedelta(minutes=1)
    store.tighten(p.permit_id, expiry=new_exp)
    assert store.get(p.permit_id).tighten_expiry == new_exp
    future = new_exp + timedelta(seconds=1)
    r = store.check(p.permit_id, 100, "m1", now=future)
    assert not r.allowed and r.reason == "tightened_expiry_passed"
    r = store.check(p.permit_id, 100, "m1")
    assert r.allowed


def test_tighten_expiry_must_be_future_and_sooner():
    store = make_store()
    p = grant(store)
    past = datetime.now(timezone.utc) - timedelta(minutes=1)
    with pytest.raises(ValueError):
        store.tighten(p.permit_id, expiry=past)
    later = datetime.now(timezone.utc) + timedelta(hours=5)
    with pytest.raises(ValueError):
        store.tighten(p.permit_id, expiry=later)


def test_tighten_revoked_or_expired_rejected():
    store = make_store()
    p = grant(store)
    store.revoke_subtree(p.permit_id)
    with pytest.raises(ValueError):
        store.tighten(p.permit_id, cap_cents=1000)


def test_tighten_unknown_permit():
    store = make_store()
    with pytest.raises(Exception):
        store.tighten("nope", cap_cents=100)


def test_tighten_cascades_to_children():
    store = make_store()
    parent = grant(store, cap_cents=5000, allowlist=["m1", "m2"])
    res = store.delegate(
        parent.permit_id,
        agent_id="agent-2",
        cap_cents=3000,
        allowlist=["m1", "m2"],
        expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    assert res.ok
    child = res.permit
    store.tighten(parent.permit_id, cap_cents=2000)
    # Child keeps the narrower of its own cap and the new parent bound.
    assert store.get(child.permit_id).tighten_cap_cents == 2000
    r = store.check(child.permit_id, 2500, "m1")
    assert not r.allowed and r.reason == "tightened_cap_exceeded"


def test_tighten_cascade_skips_narrower_child():
    store = make_store()
    parent = grant(store, cap_cents=5000, allowlist=["m1", "m2"])
    res = store.delegate(
        parent.permit_id,
        agent_id="agent-2",
        cap_cents=1500,
        allowlist=["m1", "m2"],
        expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    child = res.permit
    store.tighten(parent.permit_id, cap_cents=2000)
    # Child already narrower: untouched.
    assert store.get(child.permit_id).tighten_cap_cents is None
    r = store.check(child.permit_id, 1400, "m1")
    assert r.allowed


def test_tighten_cascade_allowlist_and_expiry():
    store = make_store()
    parent = grant(store, cap_cents=5000, allowlist=["m1", "m2", "m3"])
    res = store.delegate(
        parent.permit_id,
        agent_id="agent-2",
        cap_cents=3000,
        allowlist=["m1", "m2", "m3"],
        expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    child = res.permit
    new_exp = datetime.now(timezone.utc) + timedelta(minutes=30)
    store.tighten(parent.permit_id, remove_merchants=["m3"], expiry=new_exp)
    cc = store.get(child.permit_id)
    assert set(cc.tighten_allowlist or ()) == {"m1", "m2"}
    assert cc.tighten_expiry == new_exp
    r = store.check(child.permit_id, 100, "m3")
    assert not r.allowed
    r = store.check(child.permit_id, 100, "m1", now=new_exp + timedelta(seconds=1))
    assert not r.allowed and r.reason == "tightened_expiry_passed"


def test_tighten_receipt_has_cascade_from():
    store = make_store()
    parent = grant(store, cap_cents=5000)
    res = store.delegate(
        parent.permit_id,
        agent_id="agent-2",
        cap_cents=3000,
        allowlist=["m1"],
        expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    store.tighten(parent.permit_id, cap_cents=2000)
    kinds = [
        e.event_type
        for e in store.ledger.receipts()
        if e.event_type == "TIGHTEN"
    ]
    assert len(kinds) == 2
    cascaded = [
        e for e in store.ledger.receipts()
        if e.event_type == "TIGHTEN" and e.payload.get("cascade_from") == parent.permit_id
    ]
    assert len(cascaded) == 1


def test_tighten_does_not_touch_inflight_hold():
    store = make_store()
    p = grant(store)
    r = store.check(p.permit_id, 4000, "m1")
    assert r.allowed
    store.tighten(p.permit_id, cap_cents=2000)
    # The 4000 hold stands; new attempts are capped at 2000.
    assert store.get(p.permit_id).reserved_cents == 4000
    r = store.check(p.permit_id, 100, "m1")
    assert not r.allowed and r.reason == "tightened_cap_exceeded"


def test_tighten_then_estop_still_cascades():
    store = make_store()
    parent = grant(store, cap_cents=5000)
    res = store.delegate(
        parent.permit_id,
        agent_id="agent-2",
        cap_cents=3000,
        allowlist=["m1"],
        expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    child = res.permit
    store.tighten(parent.permit_id, cap_cents=2000)
    store.revoke_subtree(parent.permit_id)
    assert store.get(child.permit_id).revoked


def test_delegate_respects_tightened_parent():
    store = make_store()
    parent = grant(store, cap_cents=5000, allowlist=["m1", "m2"])
    store.tighten(parent.permit_id, cap_cents=2000)
    res = store.delegate(
        parent.permit_id,
        agent_id="agent-2",
        cap_cents=3000,
        allowlist=["m1"],
        expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    assert not res.ok and res.reason == "over_parent_remaining"


def test_tighten_actor_recorded():
    store = make_store()
    p = grant(store)
    _, receipt = store.tighten(p.permit_id, cap_cents=1000, actor="policy")
    assert receipt.payload["actor"] == "policy"
    with pytest.raises(ValueError):
        store.tighten(p.permit_id, cap_cents=500, actor="  ")


def test_tighten_route():
    import json, os, threading, urllib.request
    from http.server import ThreadingHTTPServer
    import server as srv

    os.environ["PERMIT_API_TOKEN"] = "test-tighten-token"
    token_headers = {"Content-Type": "application/json",
                     "Authorization": "Bearer test-tighten-token"}

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), srv.Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        def post(path, payload):
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}{path}",
                data=json.dumps(payload).encode(),
                headers=token_headers,
                method="POST",
            )
            try:
                with urllib.request.urlopen(req) as r:
                    return r.status, json.loads(r.read())
            except urllib.error.HTTPError as e:
                return e.code, json.loads(e.read())

        s, body = post("/api/permits", {
            "agent_id": "a1", "cap_cents": 5000,
            "allowlist": ["m1", "m2"], "expiry_hours": 1,
        })
        assert s == 201
        pid = body["permit_id"]
        s, body = post(f"/api/permits/{pid}/tighten", {"cap_cents": 2000})
        assert s == 200, body
        assert body["tightened"] is True
        assert body["changes"]["cap_cents"] == {"from": 5000, "to": 2000}
        # Widen rejected.
        s, body = post(f"/api/permits/{pid}/tighten", {"cap_cents": 9000})
        assert s == 400
        # Unknown permit.
        s, body = post("/api/permits/nope/tighten", {"cap_cents": 100})
        assert s == 404
    finally:
        httpd.shutdown()
