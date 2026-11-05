"""Server entrypoint tests: the HTTP verbs over the real pipeline."""

import base64
import hashlib
import json
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

import server
from settlement.paypal_client import MockPayPalClient
from settlement.verifier import ReleaseVerifier
from permit.flow import SpendPipeline
from permit.ledger import Ledger
from permit.permit import PermitStore

TEST_TOKEN = "test-token-not-a-secret"


@pytest.fixture()
def live_server(monkeypatch):
    # Fresh in-memory state per test; the server's globals get rebound.
    ledger = Ledger()
    permits = PermitStore(ledger=ledger)
    paypal = MockPayPalClient()
    verifier = ReleaseVerifier(paypal, permits, ledger=ledger)
    flow = SpendPipeline(permits, paypal, verifier, ledger=ledger)
    monkeypatch.setattr(server, "ledger", ledger)
    monkeypatch.setattr(server, "permits", permits)
    monkeypatch.setattr(server, "paypal", paypal)
    monkeypatch.setattr(server, "verifier", verifier)
    monkeypatch.setattr(server, "flow", flow)
    monkeypatch.setattr(server, "MOCK_MODE", True)
    monkeypatch.setenv("PERMIT_API_TOKEN", TEST_TOKEN)
    # Clean slate for the pending-ops registry between tests.
    monkeypatch.setattr(server, "PENDING_OPS", {})
    monkeypatch.setattr(server, "_PENDING_META", {})
    srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    yield base, paypal
    srv.shutdown()


def call(base, method, path, body=None, token=TEST_TOKEN):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    r = urllib.request.Request(base + path, data=data, method=method,
                               headers=headers)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def test_issue_check_spend_release(live_server):
    base, _ = live_server
    _, grant = call(base, "POST", "/api/permits",
                    {"agent_id": "a", "cap_cents": 10000,
                     "allowlist": ["m"], "expiry_hours": 1})
    pid = grant["permit_id"]
    _, check = call(base, "POST", f"/api/permits/{pid}/check",
                    {"agent_id": "a", "amount_cents": 1000, "merchant_id": "m"})
    assert check["allowed"]
    artifact = b"bytes"
    digest = hashlib.sha256(artifact).hexdigest()
    _, spend = call(base, "POST", f"/api/permits/{pid}/spend",
                    {"agent_id": "a", "amount_cents": 1000, "merchant_id": "m",
                     "predicate": "delivery_hash", "artifact_hash": digest})
    assert spend["allowed"] and spend["escrow_id"]
    _, rel = call(base, "POST", f"/api/escrows/{spend['escrow_id']}/release",
                  {"delivered_bytes_b64": base64.b64encode(artifact).decode()})
    assert rel["released"] and rel["capture_id"]


def test_blocked_never_touches_paypal(live_server):
    base, paypal = live_server
    _, grant = call(base, "POST", "/api/permits",
                    {"agent_id": "a", "cap_cents": 1000,
                     "allowlist": ["m"], "expiry_hours": 1})
    pid = grant["permit_id"]
    before = dict(paypal.authorizations)
    _, blocked = call(base, "POST", f"/api/permits/{pid}/spend",
                      {"agent_id": "a", "amount_cents": 9999, "merchant_id": "m",
                       "predicate": "delivery_hash", "artifact_hash": "x" * 64})
    assert not blocked["allowed"] and blocked["reason"] == "over_remaining_cap"
    assert blocked["escrow_id"] is None
    assert paypal.authorizations == before


def test_estop_voids_in_flight(live_server):
    base, paypal = live_server
    _, grant = call(base, "POST", "/api/permits",
                    {"agent_id": "a", "cap_cents": 5000,
                     "allowlist": ["m"], "expiry_hours": 1})
    pid = grant["permit_id"]
    _, spend = call(base, "POST", f"/api/permits/{pid}/spend",
                    {"agent_id": "a", "amount_cents": 1000, "merchant_id": "m",
                     "predicate": "delivery_hash", "artifact_hash": "y" * 64})
    escrow_id = spend["escrow_id"]
    _, estop = call(base, "POST", f"/api/permits/{pid}/estop", {})
    assert estop["revoked"] and escrow_id in estop["voided_escrows"]
    _, refused = call(base, "POST", f"/api/escrows/{escrow_id}/release",
                      {"delivered_bytes_b64": base64.b64encode(b"nope").decode()})
    assert not refused["released"]
    _, check = call(base, "POST", f"/api/permits/{pid}/check",
                    {"agent_id": "a", "amount_cents": 100, "merchant_id": "m"})
    assert not check["allowed"] and check["reason"] == "revoked"
    assert len(paypal.voids) == 1


def test_ledger_chain_verifies(live_server):
    base, _ = live_server
    call(base, "POST", "/api/permits",
         {"agent_id": "a", "cap_cents": 1000, "allowlist": ["m"], "expiry_hours": 1})
    _, led = call(base, "GET", "/api/ledger")
    assert led["chain"]["ok"]
    assert led["receipts"][0]["event"] == "GRANTED"


def call_expect_error(base, method, path, body, want_status, token=TEST_TOKEN):
    """Like call(), but for routes that must answer with an HTTP error."""
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    r = urllib.request.Request(base + path, data=data, method=method,
                               headers=headers)
    try:
        with urllib.request.urlopen(r, timeout=10):
            raise AssertionError(f"expected HTTP {want_status}, got 2xx")
    except urllib.error.HTTPError as e:
        assert e.code == want_status, f"expected {want_status}, got {e.code}"
        return json.loads(e.read().decode())


def test_check_is_read_only(live_server):
    """P1-3: /check evaluates authority without reserving or receipting."""
    base, paypal = live_server
    _, grant = call(base, "POST", "/api/permits",
                    {"agent_id": "a", "cap_cents": 5000,
                     "allowlist": ["m"], "expiry_hours": 1})
    pid = grant["permit_id"]
    _, led_before = call(base, "GET", "/api/ledger")
    _, check = call(base, "POST", f"/api/permits/{pid}/check",
                    {"agent_id": "a", "amount_cents": 1000, "merchant_id": "m"})
    assert check["allowed"] and check["reason"] == "allowed"
    _, led_after = call(base, "GET", "/api/ledger")
    assert len(led_after["receipts"]) == len(led_before["receipts"]), \
        "check must write no receipt"
    _, state = call(base, "GET", f"/api/permits/{pid}")
    assert state["reserved_cents"] == 0, "check must not reserve"
    assert paypal.authorizations == {}


def test_http_rejects_non_positive_amounts(live_server):
    """P1-3: the HTTP adapter rejects non-positive amounts with 400."""
    base, _ = live_server
    _, grant = call(base, "POST", "/api/permits",
                    {"agent_id": "a", "cap_cents": 5000,
                     "allowlist": ["m"], "expiry_hours": 1})
    pid = grant["permit_id"]
    err = call_expect_error(base, "POST", f"/api/permits/{pid}/check",
                            {"agent_id": "a", "amount_cents": -1000, "merchant_id": "m"}, 400)
    assert "positive integer" in err["error"]
    err = call_expect_error(base, "POST", f"/api/permits/{pid}/spend",
                            {"agent_id": "a", "amount_cents": 0, "merchant_id": "m",
                             "predicate": "delivery_hash",
                             "artifact_hash": "x" * 64}, 400)
    assert "positive integer" in err["error"]
    _, state = call(base, "GET", f"/api/permits/{pid}")
    assert state["remaining_cents"] == 5000, "rejected amounts gain no capacity"


def test_reconcile_route_converges_unknown(live_server):
    """Timeout → UNKNOWN → POST /reconcile → captured, one capture."""
    base, paypal = live_server
    _, grant = call(base, "POST", "/api/permits",
                    {"agent_id": "a", "cap_cents": 5000,
                     "allowlist": ["m"], "expiry_hours": 1})
    pid = grant["permit_id"]
    artifact = b"goods"
    digest = hashlib.sha256(artifact).hexdigest()
    _, spend = call(base, "POST", f"/api/permits/{pid}/spend",
                    {"agent_id": "a", "amount_cents": 2500, "merchant_id": "m",
                     "predicate": "delivery_hash", "artifact_hash": digest})
    escrow_id = spend["escrow_id"]
    paypal.inject_capture_timeout = "after_apply"  # response lost on the wire
    _, rel = call(base, "POST", f"/api/escrows/{escrow_id}/release",
                  {"delivered_bytes_b64": base64.b64encode(artifact).decode()})
    paypal.inject_capture_timeout = None
    assert not rel["released"] and rel["reason"] == "unknown_after_timeout"
    _, rec = call(base, "POST", f"/api/escrows/{escrow_id}/reconcile", {})
    assert rec["resolved"] and rec["outcome"] == "captured"
    assert rec["capture_id"] is not None
    assert len(paypal.capture_calls) == 1, "exactly one capture on the rail"
    _, state = call(base, "GET", f"/api/permits/{pid}")
    assert state["captured_cents"] == 2500 and state["reserved_cents"] == 0


def test_retry_cleanup_route_clears_stranded_void(live_server):
    """P1-4: void timeout strands cleanup → /retry-cleanup clears it."""
    base, paypal = live_server
    _, grant = call(base, "POST", "/api/permits",
                    {"agent_id": "a", "cap_cents": 5000,
                     "allowlist": ["m"], "expiry_hours": 1})
    pid = grant["permit_id"]
    digest = hashlib.sha256(b"goods").hexdigest()
    _, spend = call(base, "POST", f"/api/permits/{pid}/spend",
                    {"agent_id": "a", "amount_cents": 3000, "merchant_id": "m",
                     "predicate": "delivery_hash", "artifact_hash": digest})
    escrow_id = spend["escrow_id"]
    paypal.inject_void_timeout = True
    _, rel = call(base, "POST", f"/api/escrows/{escrow_id}/release",
                  {"delivered_bytes_b64": base64.b64encode(b"tampered").decode()})
    paypal.inject_void_timeout = False
    assert not rel["released"] and rel["reason"] == "predicate:hash_mismatch"
    _, state = call(base, "GET", f"/api/permits/{pid}")
    assert state["reserved_cents"] == 3000, "reservation held while void unconfirmed"
    _, retry = call(base, "POST", f"/api/escrows/{escrow_id}/retry-cleanup", {})
    assert retry["cleanup_cleared"] is True
    _, state = call(base, "GET", f"/api/permits/{pid}")
    assert state["reserved_cents"] == 0 and state["remaining_cents"] == 5000


def test_delegate_and_parent_revoke_cascades(live_server):
    base, paypal = live_server
    _, grant = call(base, "POST", "/api/permits",
                    {"agent_id": "budget_owner", "cap_cents": 5000,
                     "allowlist": ["m"], "expiry_hours": 1})
    parent_id = grant["permit_id"]
    _, child = call(base, "POST", f"/api/permits/{parent_id}/delegate",
                    {"agent_id": "buying_agent", "cap_cents": 1500,
                     "allowlist": ["m"], "expiry_hours": 0.5})
    assert child["parent_id"] == parent_id
    assert child["receipt"]["event"] == "DELEGATED"
    child_id = child["permit_id"]
    _, spend = call(base, "POST", f"/api/permits/{child_id}/spend",
                    {"agent_id": "buying_agent", "amount_cents": 1000, "merchant_id": "m",
                     "predicate": "delivery_hash", "artifact_hash": "y" * 64})
    assert spend["allowed"]
    escrow_id = spend["escrow_id"]
    _, cascade = call(base, "POST", f"/api/permits/{parent_id}/revoke-cascade", {})
    assert cascade["revoked"] is True
    assert child_id in cascade["cascaded_to"]
    assert escrow_id in cascade["voided_escrows"]
    _, child_state = call(base, "GET", f"/api/permits/{child_id}")
    assert child_state["revoked"] is True
    _, parent_state = call(base, "GET", f"/api/permits/{parent_id}")
    assert parent_state["revoked"] is True
    assert parent_state["remaining_cents"] == 5000  # unspent carve released
    _, led = call(base, "GET", "/api/ledger")
    events = [r["event"] for r in led["receipts"]]
    assert "DELEGATED" in events
    assert "REVOKED_CASCADE" in events
    assert "CARVE_RELEASED" in events
    assert len(paypal.voids) == 1


def test_delegate_cannot_widen_allowlist(live_server):
    base, _ = live_server
    _, grant = call(base, "POST", "/api/permits",
                    {"agent_id": "budget_owner", "cap_cents": 5000,
                     "allowlist": ["m"], "expiry_hours": 1})
    err = call_expect_error(
        base, "POST", f"/api/permits/{grant['permit_id']}/delegate",
        {"agent_id": "buying_agent", "cap_cents": 100,
         "allowlist": ["other"], "expiry_hours": 0.5},
        400,
    )
    assert "allowlist_escalation" in err["error"]


def test_delegate_cannot_oversubscribe_parent(live_server):
    # The carve-out guarantee: the parent's remaining cap is partitioned at
    # delegation, so sibling sub-permits can never authorize more than the
    # parent holds. Regression test for the attenuation-model hole.
    base, _ = live_server
    _, grant = call(base, "POST", "/api/permits",
                    {"agent_id": "budget_owner", "cap_cents": 5000,
                     "allowlist": ["m"], "expiry_hours": 1})
    parent_id = grant["permit_id"]
    _, first = call(base, "POST", f"/api/permits/{parent_id}/delegate",
                    {"agent_id": "a1", "cap_cents": 5000,
                     "allowlist": ["m"], "expiry_hours": 0.5})
    assert first["receipt"]["event"] == "DELEGATED"
    err = call_expect_error(
        base, "POST", f"/api/permits/{parent_id}/delegate",
        {"agent_id": "a2", "cap_cents": 5000,
         "allowlist": ["m"], "expiry_hours": 0.5},
        400,
    )
    assert "over_parent_remaining" in err["error"]


def test_mutating_routes_require_bearer_token(live_server):
    """Audit item 6: no token / wrong token -> 401 on every POST route."""
    base, _ = live_server
    body = {"agent_id": "a", "cap_cents": 1000, "allowlist": ["m"],
            "expiry_hours": 1}
    for tok in (None, "wrong-token"):
        status, err = call(base, "POST", "/api/permits", body, token=tok)
        assert status == 401, f"token={tok!r}: got {status}"
        assert "unauthorized" in err["error"]
    # GET routes stay open (read-only).
    status, _ = call(base, "GET", "/api/ledger", token=None)
    assert status == 200


def _needs_approval_exc(order_id="ord_1", url="https://approve/1"):
    """Duck-typed NeedsPayerApproval: flow matches on the class name."""
    cls = type("NeedsPayerApproval", (Exception,), {})
    exc = cls(f"order {order_id} needs payer approval")
    exc.order_id = order_id
    exc.approval_url = url
    return exc


@pytest.fixture()
def approval_server(live_server, monkeypatch):
    """live_server whose PayPal client demands payer approval on authorize."""
    base, paypal = live_server
    def _raise(amount_cents, merchant_id, idempotency_key=None):
        raise _needs_approval_exc()
    monkeypatch.setattr(paypal, "authorize", _raise)
    return base, paypal


def test_expired_pending_op_releases_reservation(approval_server):
    """Audit item 5: a TTL-expired payer-approval op is reaped fail-closed."""
    base, paypal = approval_server

    _, grant = call(base, "POST", "/api/permits",
                    {"agent_id": "a", "cap_cents": 10000,
                     "allowlist": ["m"], "expiry_hours": 1})
    pid = grant["permit_id"]
    _, spend = call(base, "POST", f"/api/permits/{pid}/spend",
                    {"agent_id": "a", "amount_cents": 3000, "merchant_id": "m",
                     "predicate": "delivery_hash",
                     "artifact_hash": "ab" * 32})
    assert spend["status"] == "approval_required"
    op_id = spend["operation_id"]

    # Reservation is held.
    _, state = call(base, "GET", f"/api/permits/{pid}")
    assert state["reserved_cents"] == 3000

    # Age the operation past the TTL.
    server._PENDING_META[op_id] = time.monotonic() - 16 * 60

    # Resume on an expired op: 410, and the reservation is released.
    status, err = call(base, "POST", f"/api/operations/{op_id}/resume", {})
    assert status == 410, f"got {status}: {err}"
    _, state = call(base, "GET", f"/api/permits/{pid}")
    assert state["reserved_cents"] == 0
    # Expiry is receipted.
    _, led = call(base, "GET", "/api/ledger")
    events = [r["event"] for r in led["receipts"]]
    assert "OPERATION_EXPIRED" in events


def test_sweep_reaps_without_resume_hit(approval_server):
    """The background sweep path releases reservations on its own."""
    base, paypal = approval_server

    _, grant = call(base, "POST", "/api/permits",
                    {"agent_id": "a", "cap_cents": 10000,
                     "allowlist": ["m"], "expiry_hours": 1})
    pid = grant["permit_id"]
    _, spend = call(base, "POST", f"/api/permits/{pid}/spend",
                    {"agent_id": "a", "amount_cents": 2000, "merchant_id": "m",
                     "predicate": "delivery_hash",
                     "artifact_hash": "cd" * 32})
    op_id = spend["operation_id"]
    server._PENDING_META[op_id] = time.monotonic() - 16 * 60

    reaped = server.sweep_expired_pending()
    assert reaped == 1
    assert op_id not in server.PENDING_OPS
    _, state = call(base, "GET", f"/api/permits/{pid}")
    assert state["reserved_cents"] == 0


def test_advisory_calibration_visible_read_only_and_spend_unblocked(live_server):
    """A fresh permit scores S = 0 (empty ledger); the spend is still
    allowed and the advisory score is visible on the ledger receipt."""
    base, _ = live_server
    _, grant = call(base, "POST", "/api/permits",
                    {"agent_id": "a", "cap_cents": 10000,
                     "allowlist": ["m"], "expiry_hours": 1})
    pid = grant["permit_id"]
    _, permit = call(base, "GET", f"/api/permits/{pid}")
    assert permit["calibration_tau"] == 0.70
    _, spend = call(base, "POST", f"/api/permits/{pid}/spend",
                    {"agent_id": "a", "amount_cents": 1000, "merchant_id": "m",
                     "predicate": "delivery_hash", "artifact_hash": "x" * 64})
    assert spend["allowed"] and spend["reason"] == "allowed"
    _, led = call(base, "GET", "/api/ledger")
    assert led["chain"]["ok"]
    allowed = [r for r in led["receipts"] if r["event"] == "ALLOWED"]
    assert len(allowed) == 1
    cal = allowed[0]["payload"]["calibration"]
    assert cal["advisory"] is True and cal["S"] == 0.0 and cal["verdict"] == "BELOW"


# -- least-privilege defaults over HTTP ------------------------------------

def _lp_grant(base, **extra):
    body = {"agent_id": "a", "cap_cents": 5000, "allowlist": ["m"],
            "expiry_hours": 1}
    body.update(extra)
    return call(base, "POST", "/api/permits", body)


def test_http_defaults_require_agent_id(live_server):
    base, paypal = live_server
    status, grant = _lp_grant(base)
    assert status == 201
    pid = grant["permit_id"]
    _, state = call(base, "GET", f"/api/permits/{pid}")
    assert state["require_agent_id"] is True
    assert state["approval_mode"] == "cumulative"
    assert state["principal_id"] is None
    before = dict(paypal.authorizations)
    status, check = call(base, "POST", f"/api/permits/{pid}/check",
                         {"amount_cents": 100, "merchant_id": "m"})
    assert status == 200
    assert not check["allowed"] and check["reason"] == "agent_id_required"
    status, spend = call(base, "POST", f"/api/permits/{pid}/spend",
                         {"amount_cents": 100, "merchant_id": "m",
                          "predicate": "delivery_hash", "artifact_hash": "x" * 64})
    assert status == 200
    assert not spend["allowed"] and spend["reason"] == "agent_id_required"
    assert spend["receipts"][0]["event"] == "BLOCKED"
    status, spend = call(base, "POST", f"/api/permits/{pid}/spend",
                         {"agent_id": "b", "amount_cents": 100, "merchant_id": "m",
                          "predicate": "delivery_hash", "artifact_hash": "x" * 64})
    assert not spend["allowed"] and spend["reason"] == "agent_mismatch"
    assert paypal.authorizations == before
    _, state = call(base, "GET", f"/api/permits/{pid}")
    assert state["reserved_cents"] == 0


def test_http_agent_id_type_checked(live_server):
    base, _ = live_server
    _, grant = _lp_grant(base)
    pid = grant["permit_id"]
    for bad in ("", 7, ["a"]):
        err = call_expect_error(base, "POST", f"/api/permits/{pid}/check",
                                {"agent_id": bad, "amount_cents": 100,
                                 "merchant_id": "m"}, 400)
        assert "agent_id" in err["error"]


def test_http_grant_opt_outs_and_validation(live_server):
    base, _ = live_server
    status, grant = _lp_grant(base, require_agent_id=False,
                              approval_mode="per_spend")
    assert status == 201
    pid = grant["permit_id"]
    _, state = call(base, "GET", f"/api/permits/{pid}")
    assert state["require_agent_id"] is False
    assert state["approval_mode"] == "per_spend"
    _, check = call(base, "POST", f"/api/permits/{pid}/check",
                    {"amount_cents": 100, "merchant_id": "m"})
    assert check["allowed"]
    err = call_expect_error(base, "POST", "/api/permits",
                            {"agent_id": "a", "cap_cents": 5000,
                             "allowlist": ["m"], "approval_mode": "sometimes"}, 400)
    assert err["error"] == "invalid_approval_mode"
    err = call_expect_error(base, "POST", "/api/permits",
                            {"agent_id": "a", "cap_cents": 5000,
                             "allowlist": ["m"], "require_agent_id": "no"}, 400)
    assert "require_agent_id" in err["error"]
    err = call_expect_error(base, "POST", "/api/permits",
                            {"agent_id": "a", "cap_cents": 5000,
                             "allowlist": ["m"], "principal_id": "a"}, 400)
    assert err["error"] == "principal_is_agent"
