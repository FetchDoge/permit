"""M3 conjunction proof: the agent spender, end to end, on the sandbox rail.

What was already proven before this file:
  - The agent loop stays inside its permit on the MOCK rail
    (tests/test_agent.py: allowed spend captures, rogue over-cap blocked
    rail-silent, tamper tool refused, merchant binding holds).
  - The real SandboxPayPalClient order lifecycle works against stubbed
    HTTP (tests/test_sandbox_client.py), and the pipeline's
    ApprovalRequired + resume flow works against a fake client
    (tests/test_authority_layer.py).
  - A live sandbox payment captured on 2026-10-05 (launch beats, scripted,
    not driven by the agent loop).

What was NOT proven: the conjunction. The agent's SpendTools driving a
SpendPipeline backed by the REAL SandboxPayPalClient class, through
authorize, payer-approval resume, and capture. That is the M3 milestone
wording ("AI agent spender inside its permit, end-to-end allowed sandbox
payment"), so this file proves it at the transport boundary: the sandbox
client's HTTP is stubbed (no network, no credentials), but every layer
above the wire is the real code - agent tools, pipeline, release
verifier, and the sandbox client's own order/authorize/capture logic,
including its trust binding against the GET order response.

The live-wire version of this same path is the sandbox_live tier
(tests/test_agent_sandbox_live.py, credentials-gated, never in CI). It
runs the agent loop against the real sandbox up to PayPal's
payer-approval gate; the post-approval resume and capture below that
gate remain proven here, at the transport boundary.
"""

import io
import json
import urllib.request
from datetime import datetime, timedelta, timezone

import pytest

from agent.tools import SpendTools
from permit.flow import ApprovalRequired, SpendPipeline
from permit.ledger import Ledger
from permit.permit import PermitStore
from settlement.sandbox_client import SandboxPayPalClient
from settlement.verifier import Evidence, ReleaseVerifier

MERCHANT = "ACCOUNT_X"  # the sandbox client's trusted merchant account

ORDER = {
    "id": "ORDER123",
    "status": "CREATED",
    "links": [
        {"rel": "approve", "href": "https://sandbox.paypal.com/approve/ORDER123"},
        {"rel": "self", "href": "https://api.sandbox/orders/ORDER123"},
    ],
}

# Provider shape for a $30.00 CAD authorization to the trusted merchant.
AUTH_BODY = {
    "id": "ORDER123",
    "status": "APPROVED",
    "purchase_units": [{
        "payee": {"merchant_id": MERCHANT},
        "amount": {"currency_code": "CAD", "value": "30.00"},
        "payments": {"authorizations": [{
            "id": "AUTH999",
            "create_time": "2026-10-20T00:00:00Z",
        }]},
    }],
    "links": [
        {"rel": "approve", "href": "https://sandbox.paypal.com/approve/ORDER123"},
    ],
}

NOT_APPROVED = {
    "name": "UNPROCESSABLE_ENTITY",
    "details": [{"issue": "ORDER_NOT_APPROVED"}],
}


class _FakeResponse(io.BytesIO):
    """Minimal urlopen context-manager stand-in for the capture call."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def _sandbox_tools(monkeypatch, http_script, cap_cents=5000):
    """SpendTools wired to a real SandboxPayPalClient with stubbed wire.

    http_script: queue of (status, body) replayed by client._http.
    Capture bypasses _http in the sandbox client (it builds its own
    urllib request), so urlopen is stubbed separately and recorded.
    Returns (tools, client, http_calls, capture_requests).
    """
    ledger = Ledger()
    permits = PermitStore(ledger=ledger)
    client = SandboxPayPalClient(
        "test-client-id", "test-secret", merchant_account_id=MERCHANT
    )
    client._token = "tok"  # skip the OAuth call, as in test_sandbox_client

    http_calls = []

    def fake_http(method, path, body=None, auth=None, **kwargs):
        http_calls.append((method, path))
        assert http_script, f"unexpected sandbox HTTP call: {method} {path}"
        return http_script.pop(0)

    client._http = fake_http

    capture_requests = []

    def fake_urlopen(req, timeout=None):
        capture_requests.append(req.full_url)
        payload = json.dumps({"id": "CAP999", "status": "COMPLETED"}).encode()
        return _FakeResponse(payload)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    verifier = ReleaseVerifier(client, permits, ledger=ledger)
    flow = SpendPipeline(permits, client, verifier, ledger=ledger)
    permit, _ = permits.grant(
        agent_id="m3-agent", cap_cents=cap_cents, allowlist=[MERCHANT],
        expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    catalog = {"widget": b"widget-bytes"}
    tools = SpendTools(flow, permit.permit_id, MERCHANT, catalog)
    return tools, client, http_calls, capture_requests


def test_agent_spend_and_deliver_captures_on_sandbox_client(monkeypatch):
    """Agent attempt_spend -> ALLOWED on the sandbox client, deliver ->
    capture COMPLETED. Every layer above the stubbed wire is real code,
    including the sandbox client's payee/amount trust binding."""
    tools, _client, http_calls, capture_requests = _sandbox_tools(
        monkeypatch,
        [
            (201, ORDER),      # create_order
            (201, AUTH_BODY),  # POST authorize
            (200, AUTH_BODY),  # GET order (trust-bind source of truth)
        ],
    )

    obs = json.loads(tools.attempt_spend(3000, "widget"))
    assert obs["decision"] == "ALLOWED"
    assert obs["paypal_auth_id"] == "AUTH999"
    assert http_calls == [
        ("POST", "/v2/checkout/orders"),
        ("POST", "/v2/checkout/orders/ORDER123/authorize"),
        ("GET", "/v2/checkout/orders/ORDER123"),
    ]

    obs2 = json.loads(tools.deliver(obs["escrow_id"]))
    assert obs2["released"] is True
    assert obs2["capture_id"] == "CAP999"
    # The capture went to the sandbox payments endpoint for AUTH999.
    assert len(capture_requests) == 1
    assert "/v2/payments/authorizations/AUTH999/capture" in capture_requests[0]

    permit_view = json.loads(tools.check_permit())
    assert permit_view["captured_cents"] == 3000
    assert permit_view["remaining_cents"] == 2000
    ok, msg = tools.flow.ledger.verify_chain()
    assert ok, msg


def test_agent_over_cap_blocked_never_touches_sandbox_wire(monkeypatch):
    """The gate fires before the rail on the sandbox client too: an
    over-cap agent attempt writes a BLOCKED receipt and makes zero
    sandbox HTTP calls and zero capture requests."""
    tools, _client, http_calls, capture_requests = _sandbox_tools(
        monkeypatch, http_script=[]
    )

    obs = json.loads(tools.attempt_spend(6000, "widget"))
    assert obs["decision"] == "BLOCKED"
    assert obs["reason"] == "over_remaining_cap"
    assert obs["paypal_called"] is False
    assert http_calls == []
    assert capture_requests == []

    blocked = [r for r in tools.flow.ledger.receipts()
               if r.event_type == "BLOCKED"
               and r.payload.get("reason") == "over_remaining_cap"]
    assert blocked, "no BLOCKED receipt for the over-cap sandbox attempt"
    ok, msg = tools.flow.ledger.verify_chain()
    assert ok, msg


def test_agent_sandbox_spend_resumes_same_order_after_payer_approval(monkeypatch):
    """The interactive sandbox beat, through the agent's own spend call:
    authorize answers ORDER_NOT_APPROVED, the pipeline raises
    ApprovalRequired with the reservation held, and after the payer
    approves, resume_operation authorizes the SAME order (no second
    create) and the escrow captures."""
    tools, _client, http_calls, capture_requests = _sandbox_tools(
        monkeypatch,
        [
            (201, ORDER),        # create_order
            (422, NOT_APPROVED), # POST authorize: payer has not approved
            (200, ORDER),        # GET order: approval_url refetch
            (201, AUTH_BODY),    # resumed POST authorize after approval
            (200, AUTH_BODY),    # GET order (trust-bind source of truth)
        ],
    )

    with pytest.raises(ApprovalRequired) as exc_info:
        tools.attempt_spend(3000, "widget")
    appr = exc_info.value
    assert appr.order_id == "ORDER123"
    assert appr.approval_url == "https://sandbox.paypal.com/approve/ORDER123"
    # The cap reservation stays held while approval is outstanding.
    assert json.loads(tools.check_permit())["remaining_cents"] == 2000
    assert capture_requests == []

    attempt = tools.flow.resume_operation(appr)
    assert attempt.allowed is True
    assert attempt.escrow_id is not None
    # Exactly one order was created across spend + resume.
    assert http_calls.count(("POST", "/v2/checkout/orders")) == 1

    result = tools.flow.release(
        attempt.escrow_id, Evidence(delivered_bytes=b"widget-bytes"))
    assert result.released is True
    assert result.capture.capture_id == "CAP999"
    assert len(capture_requests) == 1
    ok, msg = tools.flow.ledger.verify_chain()
    assert ok, msg
