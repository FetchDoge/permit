"""M3 live-wire tier: the agent spender against the real PayPal sandbox.

What the transport-boundary proof (tests/test_agent_sandbox_e2e.py)
already covers: every layer above the wire, with the sandbox client's
HTTP stubbed. What it cannot cover: that the agent loop works against
the sandbox as PayPal actually runs it - real OAuth, a real order on
PayPal's side, a real ORDER_NOT_APPROVED answer.

This file is that tier. It is marked ``sandbox_live`` and is skipped
unless PERMIT_PAYPAL_CLIENT_ID and PERMIT_PAYPAL_CLIENT_SECRET are set
(see tests/conftest.py); PERMIT_PAYPAL_MERCHANT_ID is also required.
It never runs in CI.

Honest boundary: a sandbox order cannot be authorized until a human
buyer approves it at PayPal's checkout (that sign-in is the principal's
tap, the same one the 2026-10-05 launch beats used). So the allowed
spend here runs end to end up to exactly that gate: the agent's spend
creates a real order on the real wire, the authorize attempt is refused
by PayPal with ORDER_NOT_APPROVED, the pipeline raises ApprovalRequired
with the cap reservation held, and the order is read back over the wire
in CREATED state. No authorization, no capture, no money moves in this
tier. The post-approval resume and capture are proven at the transport
boundary in tests/test_agent_sandbox_e2e.py.
"""

import json
import os
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import pytest

from agent.tools import SpendTools
from permit.flow import ApprovalRequired, SpendPipeline
from permit.ledger import Ledger
from permit.permit import PermitStore
from settlement.sandbox_client import SandboxPayPalClient
from settlement.verifier import ReleaseVerifier

pytestmark = pytest.mark.sandbox_live

CAP_CENTS = 5000
SPEND_CENTS = 3000


@pytest.fixture()
def live_tools():
    merchant = os.environ.get("PERMIT_PAYPAL_MERCHANT_ID")
    if not merchant:
        pytest.skip("sandbox-live: PERMIT_PAYPAL_MERCHANT_ID not set")
    ledger = Ledger()
    permits = PermitStore(ledger=ledger)
    client = SandboxPayPalClient(
        os.environ["PERMIT_PAYPAL_CLIENT_ID"],
        os.environ["PERMIT_PAYPAL_CLIENT_SECRET"],
        merchant_account_id=merchant,
    )
    verifier = ReleaseVerifier(client, permits, ledger=ledger)
    flow = SpendPipeline(permits, client, verifier, ledger=ledger)
    permit, _ = permits.grant(
        agent_id="m3-live-agent", cap_cents=CAP_CENTS, allowlist=[merchant],
        expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    tools = SpendTools(flow, permit.permit_id, merchant,
                       {"widget": b"widget-bytes"})
    return tools, client


def test_live_agent_over_cap_blocked_before_any_wire(live_tools, monkeypatch):
    """The gate fires before the rail on the live client too: an over-cap
    agent attempt is BLOCKED, writes its receipt, and touches the sandbox
    zero times - not even an OAuth token is fetched."""
    tools, client = live_tools
    calls = []
    real_http = client._http

    def counting_http(*args, **kwargs):
        calls.append(args)
        return real_http(*args, **kwargs)

    monkeypatch.setattr(client, "_http", counting_http)

    obs = json.loads(tools.attempt_spend(CAP_CENTS + 1000, "widget"))
    assert obs["decision"] == "BLOCKED"
    assert obs["reason"] == "over_remaining_cap"
    assert obs["paypal_called"] is False
    assert calls == []
    assert client._token is None

    blocked = [r for r in tools.flow.ledger.receipts()
               if r.event_type == "BLOCKED"
               and r.payload.get("reason") == "over_remaining_cap"]
    assert blocked, "no BLOCKED receipt for the live over-cap attempt"
    ok, msg = tools.flow.ledger.verify_chain()
    assert ok, msg


def test_live_agent_spend_reaches_payer_approval_on_real_wire(live_tools):
    """The agent's allowed spend, live: a real order is created on the
    PayPal sandbox, PayPal itself refuses the authorize with
    ORDER_NOT_APPROVED, and the pipeline surfaces ApprovalRequired with
    the reservation held and a real approval URL. The order is then read
    back over the wire in CREATED state - created by the agent loop,
    awaiting the human buyer approval that is the principal's tap."""
    tools, client = live_tools

    with pytest.raises(ApprovalRequired) as exc_info:
        tools.attempt_spend(SPEND_CENTS, "widget")
    appr = exc_info.value
    assert appr.order_id
    assert urlparse(appr.approval_url).hostname in (
        "www.sandbox.paypal.com", "sandbox.paypal.com"
    )

    # The cap reservation stays held while approval is outstanding.
    permit_view = json.loads(tools.check_permit())
    assert permit_view["remaining_cents"] == CAP_CENTS - SPEND_CENTS

    # The order is real: PayPal's API reports it, in CREATED state.
    assert client.order_status(appr.order_id) == "CREATED"

    ok, msg = tools.flow.ledger.verify_chain()
    assert ok, msg
