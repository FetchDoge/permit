"""
Sandbox PayPal client: the real REST implementation of PayPalClient.

Flow (Orders API, AUTHORIZE intent):
    1. create_order(amount) -> (order_id, approval_url)
    2. payer approves via approval_url (browser; sandbox buyer account)
    3. authorize_order(order_id) -> authorization_id (the hold)
    4. capture or void the authorization_id

The payer-approval step is interactive, and the browser UI is not a
reliable witness: on 2026-10-02 the sandbox checkout page never visually
advanced past "Continue to Review Order", yet the order had already been
APPROVED server-side. So approval is confirmed by polling the order's API
state (order_status / wait_for_approval) - never by what the page shows.
authorize_order() raises NeedsPayerApproval carrying the approval URL
when PayPal reports ORDER_NOT_APPROVED.

Endpoints (verified in spike 2026-10-02):
    POST /v1/oauth2/token (Basic client_id:secret)
    POST /v2/checkout/orders
    GET  /v2/checkout/orders/{id}
    POST /v2/checkout/orders/{id}/authorize
    POST /v2/payments/authorizations/{auth_id}/capture
    POST /v2/payments/authorizations/{auth_id}/void
    GET  /v2/payments/authorizations/{auth_id}

Merchant identity (spike VERIFIED): order payee carries
    email_address (sandbox merchant email) and merchant_id (stable).
The permit allowlist compares against payee.merchant_id.
authorize_order() binds trust: when merchant_account_id is configured,
the response's payee.merchant_id MUST equal it, the purchase unit
currency MUST be CAD, and the amount MUST equal the requested cents —
any mismatch raises MerchantMismatch and the hold is unusable.

Timeout semantics (P1 settlement fixes, 2026-10-02): any network timeout
(URLError non-HTTP, socket.timeout / TimeoutError) raises PayPalTimeout —
a timed-out call has UNKNOWN provider state, so the verifier marks the
escrow UNKNOWN and reconciles instead of guessing. HTTP errors keep
their existing handling (status/body passthrough, RuntimeError on
failed capture).
"""

from __future__ import annotations

import base64
import json
import socket
import time
import urllib.request
import urllib.error

from .paypal_client import (
    PayPalClient,
    PayPalTimeout,
    MerchantMismatch,
    Authorization,
    Capture,
    Void,
)


BASE = "https://api-m.sandbox.paypal.com"


class NeedsPayerApproval(Exception):
    """Raised when the order needs payer approval before authorize."""

    def __init__(self, order_id: str, approval_url: str):
        super().__init__(f"order {order_id} needs payer approval")
        self.order_id = order_id
        self.approval_url = approval_url


class ApprovalTimeout(Exception):
    """Raised when the order is not approved within the polling window."""

    def __init__(self, order_id: str, timeout_s: float, last_status: str):
        super().__init__(
            f"order {order_id} not approved after {timeout_s}s "
            f"(last status: {last_status})"
        )
        self.order_id = order_id
        self.timeout_s = timeout_s
        self.last_status = last_status


def _is_network_timeout(exc: BaseException) -> bool:
    """True for transport-level failures that leave provider state unknown.

    HTTPError is a URLError subclass but is an HTTP response, not a
    transport failure — it must NOT match here.
    """
    if isinstance(exc, urllib.error.HTTPError):
        return False
    return isinstance(exc, (urllib.error.URLError, socket.timeout, TimeoutError))


class SandboxPayPalClient(PayPalClient):
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        merchant_account_id: str | None = None,
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.merchant_account_id = merchant_account_id
        self._token: str | None = None

    def _http(self, method: str, path: str, body: dict | None = None,
              auth: str | None = None, request_id: str | None = None):
        """Returns (status, body). Empty response bodies come back as None."""
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(BASE + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if auth:
            req.add_header("Authorization", auth)
        elif self._token:
            req.add_header("Authorization", f"Bearer {self._token}")
        if request_id is not None:
            req.add_header("PayPal-Request-Id", request_id)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, self._parse(r.read())
        except urllib.error.HTTPError as e:
            return e.code, self._parse(e.read())
        except Exception as e:
            if _is_network_timeout(e):
                raise PayPalTimeout(
                    f"{method} {path} timed out: {e}"
                ) from e
            raise

    @staticmethod
    def _parse(raw: bytes):
        text = raw.decode().strip()
        return json.loads(text) if text else None

    def _ensure_token(self):
        if self._token:
            return
        creds = base64.b64encode(
            f"{self.client_id}:{self.client_secret}".encode()
        ).decode()
        req = urllib.request.Request(
            BASE + "/v1/oauth2/token",
            data=b"grant_type=client_credentials",
            method="POST",
        )
        req.add_header("Authorization", f"Basic {creds}")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                self._token = json.loads(r.read().decode())["access_token"]
        except Exception as e:
            if _is_network_timeout(e):
                raise PayPalTimeout(f"oauth token fetch timed out: {e}") from e
            raise

    # -- order lifecycle (explicit, resumable) ------------------------------

    def create_order(
        self, amount_cents: int, idempotency_key: str | None = None
    ) -> tuple[str, str]:
        """
        Create an AUTHORIZE-intent order. Returns (order_id, approval_url).
        The caller gets payer approval at the URL, then calls authorize_order.
        """
        self._ensure_token()
        dollars = f"{amount_cents / 100:.2f}"
        status, order = self._http(
            "POST",
            "/v2/checkout/orders",
            {
                "intent": "AUTHORIZE",
                "purchase_units": [{
                    "amount": {"currency_code": "CAD", "value": dollars}
                }],
            },
            request_id=idempotency_key,
        )
        assert status in (200, 201), f"order create failed: {status} {order}"
        approval_url = next(
            l["href"] for l in order["links"] if l["rel"] == "approve"
        )
        return order["id"], approval_url

    def order_status(self, order_id: str) -> str:
        """
        The API is the source of truth for approval - not the browser page.
        Returns the order's status string (e.g. CREATED, APPROVED).
        """
        self._ensure_token()
        status, order = self._http("GET", f"/v2/checkout/orders/{order_id}")
        assert status == 200, f"order fetch failed: {status} {order}"
        return order["status"]

    def wait_for_approval(self, order_id: str, timeout_s: float = 120,
                          poll_s: float = 5) -> str:
        """
        Poll the order's API state until it is APPROVED or the timeout
        elapses. Returns the final status ("APPROVED"); raises
        ApprovalTimeout otherwise.
        """
        deadline = time.monotonic() + timeout_s
        last = ""
        while time.monotonic() < deadline:
            last = self.order_status(order_id)
            if last == "APPROVED":
                return last
            time.sleep(poll_s)
        raise ApprovalTimeout(order_id, timeout_s, last)

    def _bind_trust(self, auth_body: dict, amount_cents: int) -> None:
        """
        Provider-side trust binding (P1-2 fix): the hold must be payable
        to the trusted merchant account, denominated in CAD, for exactly
        the authorized cents. Any mismatch raises MerchantMismatch and
        the hold is unusable — the caller must void it.
        """
        pu = auth_body["purchase_units"][0]
        if self.merchant_account_id is not None:
            payee_merchant = pu.get("payee", {}).get("merchant_id")
            if payee_merchant != self.merchant_account_id:
                raise MerchantMismatch(
                    f"payee.merchant_id {payee_merchant!r} != trusted "
                    f"{self.merchant_account_id!r}"
                )
        amount = pu.get("amount", {})
        value_cents = round(float(amount.get("value", "0")) * 100)
        if amount.get("currency_code") != "CAD" or value_cents != amount_cents:
            raise MerchantMismatch(
                f"purchase_unit amount {amount!r} != "
                f"authorized {amount_cents} cents CAD"
            )

    def authorize_order(
        self,
        order_id: str,
        amount_cents: int,
        merchant_id: str,
        idempotency_key: str | None = None,
    ) -> Authorization:
        """
        Authorize an existing (already approved) order -> the hold.
        Raises NeedsPayerApproval if the order isn't approved yet; the
        caller should get approval and retry this same method - never
        create a second order for the same spend.
        Raises MerchantMismatch if the provider's payee/amount binding
        does not match the trusted configuration.
        """
        self._ensure_token()
        status, auth_body = self._http(
            "POST",
            f"/v2/checkout/orders/{order_id}/authorize",
            {},
            request_id=idempotency_key,
        )
        if status == 422 and any(
            d.get("issue") == "ORDER_NOT_APPROVED"
            for d in (auth_body or {}).get("details", [])
        ):
            raise NeedsPayerApproval(order_id, self._approval_url(order_id))
        if status == 422 and any(
            d.get("issue") == "ORDER_ALREADY_AUTHORIZED"
            for d in (auth_body or {}).get("details", [])
        ):
            # The payer's browser completed the authorization itself (the
            # normal hermes flow for intent=AUTHORIZE). Recover
            # idempotently from the order instead of failing.
            pass
        else:
            assert status in (200, 201), f"authorize failed: {status} {auth_body}"

        # Trust-bind against the GET order response: it is the source of
        # truth and carries the full purchase-unit shape (the POST
        # /authorize response omits payee on some flows, which used to
        # trip _bind_trust into a false MerchantMismatch).
        _, order = self._http("GET", f"/v2/checkout/orders/{order_id}")
        self._bind_trust(order, amount_cents)

        # The authorization lives in purchase_units[0].payments.authorizations[0].
        pu = order["purchase_units"][0]
        auth = pu["payments"]["authorizations"][0]
        return Authorization(
            auth_id=auth["id"],
            amount_cents=amount_cents,
            merchant_id=merchant_id,
            status="AUTHORIZED",
            created_at=auth.get("create_time", ""),
        )

    def _approval_url(self, order_id: str) -> str:
        _, order = self._http("GET", f"/v2/checkout/orders/{order_id}")
        return next(l["href"] for l in order["links"] if l["rel"] == "approve")

    # -- PayPalClient interface ----------------------------------------------

    def authorize(
        self,
        amount_cents: int,
        merchant_id: str,
        idempotency_key: str | None = None,
    ) -> Authorization:
        """
        Convenience: create an order and authorize it in one call.
        Raises NeedsPayerApproval with (order_id, approval_url) when the
        payer hasn't approved yet; the caller then calls authorize_order()
        with the same order_id after approval - it must NOT call this
        method again (that would create a second order and double-reserve).
        """
        order_id, _ = self.create_order(amount_cents, idempotency_key)
        return self.authorize_order(order_id, amount_cents, merchant_id,
                                    idempotency_key)

    def get_authorization(self, auth_id: str) -> Authorization:
        """
        Provider truth for one authorization. The verifier's reconcile()
        queries this after a timeout — never guesses.
        """
        self._ensure_token()
        status, body = self._http(
            "GET", f"/v2/payments/authorizations/{auth_id}"
        )
        assert status == 200, f"authorization fetch failed: {status} {body}"
        amount = body.get("amount", {})
        return Authorization(
            auth_id=body.get("id", auth_id),
            amount_cents=round(float(amount.get("value", "0")) * 100),
            merchant_id=self.merchant_account_id or "",
            status=body.get("status", "UNKNOWN"),
            created_at=body.get("create_time", ""),
        )

    def capture(self, auth_id: str, amount_cents: int,
                idempotency_key: str) -> Capture:
        self._ensure_token()
        dollars = f"{amount_cents / 100:.2f}"
        req = urllib.request.Request(
            BASE + f"/v2/payments/authorizations/{auth_id}/capture",
            data=json.dumps(
                {"amount": {"currency_code": "CAD", "value": dollars}}
            ).encode(),
            method="POST",
        )
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Bearer {self._token}")
        req.add_header("PayPal-Request-Id", idempotency_key)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                body = json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            body = json.loads(e.read().decode())
            raise RuntimeError(f"capture failed: {e.code} {body}")
        except Exception as e:
            if _is_network_timeout(e):
                raise PayPalTimeout(
                    f"capture {auth_id} timed out: {e}"
                ) from e
            raise
        return Capture(
            capture_id=body["id"],
            auth_id=auth_id,
            amount_cents=amount_cents,
            status=body["status"],
            idempotency_key=idempotency_key,
        )

    def void(self, auth_id: str) -> Void:
        self._ensure_token()
        status, body = self._http(
            "POST", f"/v2/payments/authorizations/{auth_id}/void", {})
        # Void answers 204 with an empty body on success.
        assert status in (200, 201, 204), f"void failed: {status} {body}"
        return Void(auth_id=auth_id, status="VOIDED")
