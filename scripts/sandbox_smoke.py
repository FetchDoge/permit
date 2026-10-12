"""
PayPal sandbox rail smoke test.

This is the one-command proof that the Permit sandbox rail is live:
OAuth token -> create a small AUTHORIZE-intent order -> read the order's
API state. If the order is already payer-approved (or becomes approved
during the optional wait), it authorizes the SAME order and immediately
voids the hold — no capture is ever performed, so no money moves.

Credentials come from the environment, never from the repo:
    PERMIT_PAYPAL_CLIENT_ID / PERMIT_PAYPAL_CLIENT_SECRET
    (optional) PERMIT_PAYPAL_MERCHANT_ID for merchant trust binding.

Exit codes: 0 = rail live, 1 = rail broken, 2 = credentials missing.
No network is touched until credentials are present.
"""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from settlement.sandbox_client import (
    NeedsPayerApproval,
    SandboxPayPalClient,
    ApprovalTimeout,
)

# Smallest realistic test hold: $1.00 CAD. Nothing is captured, so even the
# authorized hold is voided at the end of a successful smoke.
SMOKE_AMOUNT_CENTS = 100
# How long to wait for payer approval before reporting "awaiting approval".
# Zero means: report approval_url and stop; the rail proof (auth + order
# creation + order read) is complete either way.
APPROVAL_WAIT_S = float(os.environ.get("PERMIT_SMOKE_WAIT_S", "0"))


def fail(msg: str) -> int:
    print(f"SMOKE FAIL: {msg}")
    return 1


def main() -> int:
    client_id = os.environ.get("PERMIT_PAYPAL_CLIENT_ID")
    client_secret = os.environ.get("PERMIT_PAYPAL_CLIENT_SECRET")
    if not client_id or not client_secret:
        print(
            "SMOKE SKIP (exit 2): sandbox credentials not set. "
            "Set PERMIT_PAYPAL_CLIENT_ID and PERMIT_PAYPAL_CLIENT_SECRET "
            "(sandbox app) to exercise the live rail. "
            "(Optional: PERMIT_PAYPAL_MERCHANT_ID enables merchant binding.)"
        )
        return 2

    merchant_id = os.environ.get("PERMIT_PAYPAL_MERCHANT_ID")
    client = SandboxPayPalClient(
        client_id, client_secret, merchant_account_id=merchant_id
    )

    # 1. OAuth: proves the credentials are valid.
    try:
        client._ensure_token()
    except Exception as e:  # noqa: BLE001 - smoke reports, never crashes
        return fail(f"oauth token fetch failed: {e}")
    print("SMOKE 1/4: oauth token OK")

    # 2. Create a $1.00 AUTHORIZE-intent order: proves order creation.
    try:
        order_id, approval_url = client.create_order(
            SMOKE_AMOUNT_CENTS,
            idempotency_key=f"permit-smoke-{int(time.time())}",
        )
    except Exception as e:  # noqa: BLE001
        return fail(f"order creation failed: {e}")
    print(f"SMOKE 2/4: order created: {order_id}")

    # 3. Read the order's API state: proves order reads work.
    try:
        status = client.order_status(order_id)
    except Exception as e:  # noqa: BLE001
        return fail(f"order status read failed: {e}")
    print(f"SMOKE 3/4: order status: {status}")

    if status != "APPROVED":
        if APPROVAL_WAIT_S > 0:
            print(
                f"waiting up to {APPROVAL_WAIT_S}s for payer approval "
                f"(approve at {approval_url})..."
            )
            try:
                status = client.wait_for_approval(
                    order_id, timeout_s=APPROVAL_WAIT_S
                )
            except ApprovalTimeout as e:
                print(f"SMOKE: approval not received: {e}")
                print("rail is live through order creation and order reads;")
                print(f"approve {approval_url} and rerun to finish the cycle.")
                return 0
            print(f"SMOKE: order approved: {status}")
        else:
            print("SMOKE 4/4: rail live through order creation and order reads.")
            print(f"approve at {approval_url} (set PERMIT_SMOKE_WAIT_S>0 to wait)")
            print("then rerun to authorize and void the hold.")
            return 0

    # 4. Authorize the SAME order, then void the hold immediately.
    # No capture is performed: no money moves.
    try:
        auth = client.authorize_order(
            order_id, SMOKE_AMOUNT_CENTS, merchant_id or "smoke"
        )
    except NeedsPayerApproval as e:
        return fail(f"order still needs approval: {e.approval_url}")
    except Exception as e:  # noqa: BLE001
        return fail(f"authorize failed: {e}")
    print(f"SMOKE 4/4: authorized: {auth.auth_id} ({auth.status})")

    try:
        void = client.void(auth.auth_id)
    except Exception as e:  # noqa: BLE001
        return fail(f"void failed (hold may be live in the sandbox!): {e}")
    print(f"SMOKE: hold voided: {void.status}. no capture performed, no money moved.")
    print("SANDBOX RAIL LIVE: oauth, order create, order read, authorize, void.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
