"""
Tests for SandboxPayPalClient's explicit order lifecycle.

No network: _http is stubbed per test. These pin the resume-after-approval
flow that the 2026-10-02 stuck-button episode forced: approval is confirmed
by polling order state, and authorize_order() resumes the SAME order -
never a second one.
"""

import pytest

from settlement.sandbox_client import (
    ApprovalTimeout,
    MerchantMismatch,
    NeedsPayerApproval,
    SandboxPayPalClient,
)


ORDER = {
    "id": "ORDER123",
    "status": "CREATED",
    "links": [
        {"rel": "approve", "href": "https://sandbox.paypal.com/approve/ORDER123"},
        {"rel": "self", "href": "https://api.sandbox/orders/ORDER123"},
    ],
}

AUTH_BODY = {
    "purchase_units": [{
        # Provider trust binding (P1-2): authorize_order() checks these.
        "payee": {"merchant_id": "ACCOUNT_X"},
        "amount": {"currency_code": "CAD", "value": "30.00"},
        "payments": {"authorizations": [{
            "id": "AUTH999",
            "create_time": "2026-10-02T00:00:00Z",
        }]},
    }],
}


def make_client(responses):
    """Stub _http to replay a script of (status, body) per call."""
    client = SandboxPayPalClient("id", "secret")
    client._token = "tok"  # skip the OAuth call
    calls = []

    def fake_http(method, path, body=None, auth=None, **kwargs):
        calls.append((method, path))
        return responses.pop(0)

    client._http = fake_http
    client._calls = calls
    return client


def test_create_order_returns_id_and_approval_url():
    c = make_client([(201, ORDER)])
    order_id, url = c.create_order(3000)
    assert order_id == "ORDER123"
    assert url == "https://sandbox.paypal.com/approve/ORDER123"
    assert c._calls == [("POST", "/v2/checkout/orders")]


def test_order_status_reports_api_state():
    c = make_client([(200, {**ORDER, "status": "APPROVED"})])
    assert c.order_status("ORDER123") == "APPROVED"
    assert c._calls == [("GET", "/v2/checkout/orders/ORDER123")]


def test_authorize_order_on_approved_order():
    c = make_client([(201, AUTH_BODY), (200, AUTH_BODY)])
    auth = c.authorize_order("ORDER123", 3000, "merchant_x")
    assert auth.auth_id == "AUTH999"
    assert auth.amount_cents == 3000
    assert auth.merchant_id == "merchant_x"
    assert c._calls == [
        ("POST", "/v2/checkout/orders/ORDER123/authorize"),
        ("GET", "/v2/checkout/orders/ORDER123"),
    ]


def test_authorize_order_merchant_mismatch():
    """P1-2: the provider's payee must match the trusted merchant account.

    merchant_account_id="ACCOUNT_X" is trusted; the stubbed authorize
    response carries payee.merchant_id="ACTUAL_OTHER" -> MerchantMismatch,
    fail closed. No hold is usable.
    """
    import copy

    mismatch_body = copy.deepcopy(AUTH_BODY)
    mismatch_body["purchase_units"][0]["payee"]["merchant_id"] = "ACTUAL_OTHER"

    client = SandboxPayPalClient(
        "id", "secret", merchant_account_id="ACCOUNT_X"
    )
    client._token = "tok"  # skip the OAuth call
    seen_headers = []

    def fake_http(method, path, body=None, auth=None, **kwargs):
        seen_headers.append(kwargs.get("request_id"))
        return 201, mismatch_body

    client._http = fake_http
    with pytest.raises(MerchantMismatch):
        client.authorize_order("ORDER123", 3000, "merchant_x")


def test_authorize_order_trusted_payee_passes():
    """Same stubbed body with the trusted payee authorizes normally."""
    c = SandboxPayPalClient("id", "secret", merchant_account_id="ACCOUNT_X")
    c._token = "tok"
    c._http = lambda method, path, body=None, auth=None, **kw: (201, AUTH_BODY)
    auth = c.authorize_order("ORDER123", 3000, "merchant_x")
    assert auth.auth_id == "AUTH999"


def test_authorize_order_amount_mismatch():
    """P1-2 companion: a wrong currency or value also raises MerchantMismatch."""
    import copy

    bad_body = copy.deepcopy(AUTH_BODY)
    bad_body["purchase_units"][0]["amount"] = {
        "currency_code": "USD", "value": "30.00"
    }
    c = SandboxPayPalClient("id", "secret", merchant_account_id="ACCOUNT_X")
    c._token = "tok"
    c._http = lambda method, path, body=None, auth=None, **kw: (201, bad_body)
    with pytest.raises(MerchantMismatch):
        c.authorize_order("ORDER123", 3000, "merchant_x")


def test_authorize_order_unapproved_raises_with_same_order_id():
    not_approved = {
        "name": "UNPROCESSABLE_ENTITY",
        "details": [{"issue": "ORDER_NOT_APPROVED"}],
    }
    c = make_client([
        (422, not_approved),
        (200, ORDER),  # _approval_url refetch
    ])
    with pytest.raises(NeedsPayerApproval) as exc:
        c.authorize_order("ORDER123", 3000, "merchant_x")
    # Resume uses the SAME order id - no second order is created.
    assert exc.value.order_id == "ORDER123"
    assert exc.value.approval_url == "https://sandbox.paypal.com/approve/ORDER123"
    assert all(call[0] != "POST" or "orders" not in call[1]
               or call[1].endswith("authorize")
               for call in c._calls)


def test_wait_for_approval_polls_until_approved():
    c = make_client([
        (200, {**ORDER, "status": "CREATED"}),
        (200, {**ORDER, "status": "CREATED"}),
        (200, {**ORDER, "status": "APPROVED"}),
    ])
    assert c.wait_for_approval("ORDER123", timeout_s=60, poll_s=0) == "APPROVED"
    assert len(c._calls) == 3


def test_wait_for_approval_times_out():
    c = make_client([(200, {**ORDER, "status": "CREATED"})] * 50)
    with pytest.raises(ApprovalTimeout) as exc:
        c.wait_for_approval("ORDER123", timeout_s=0.05, poll_s=0.01)
    assert exc.value.order_id == "ORDER123"
    assert exc.value.last_status == "CREATED"


def test_void_tolerates_empty_204_body():
    c = make_client([(204, None)])  # void answers 204 with no body
    void = c.void("AUTH999")
    assert void.auth_id == "AUTH999"
    assert void.status == "VOIDED"


def test_authorize_order_already_authorized_recovers_via_get():
    """P0 (live 2026-10-05): when the payer's browser completes the
    authorization itself (normal hermes flow for intent=AUTHORIZE), POST
    /authorize answers 422 ORDER_ALREADY_AUTHORIZED. authorize_order()
    must recover idempotently from the order instead of crashing."""
    already = {
        "name": "UNPROCESSABLE_ENTITY",
        "details": [{"issue": "ORDER_ALREADY_AUTHORIZED"}],
    }
    c = make_client([(422, already), (200, AUTH_BODY)])
    auth = c.authorize_order("ORDER123", 3000, "merchant_x")
    assert auth.auth_id == "AUTH999"
    assert auth.amount_cents == 3000
    assert c._calls == [
        ("POST", "/v2/checkout/orders/ORDER123/authorize"),
        ("GET", "/v2/checkout/orders/ORDER123"),
    ]


def test_authorize_order_binds_trust_against_get_when_post_omits_payee():
    """P0 (live 2026-10-05): the POST /authorize response can omit
    payee on some flows, which used to trip _bind_trust into a false
    MerchantMismatch. Trust is now bound against the GET order response,
    the source of truth."""
    import copy

    post_body = copy.deepcopy(AUTH_BODY)
    del post_body["purchase_units"][0]["payee"]
    c = make_client([(201, post_body), (200, AUTH_BODY)])
    auth = c.authorize_order("ORDER123", 3000, "merchant_x")
    assert auth.auth_id == "AUTH999"
