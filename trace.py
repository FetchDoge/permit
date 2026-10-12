#!/usr/bin/env python3
"""
trace.py — start the Permit service and capture runnable evidence:

  1. an allowed payment flows through the 4-clause gate (issue -> check -> spend -> release -> capture)
  2. an over-authority attempt is BLOCKED and never touches the PayPal client:
       - via the running server: /debug/paypal call counts unchanged across the block
       - in-process: an assertion-level spy whose authorize() raises AssertionError if called;
         the gate must return BLOCKED without ever calling it
  3. a parent delegates a narrowed sub-permit; the child spends; revoke on
     the parent cascades. The child's in-flight hold is voided, the unspent
     carve is released, and post-cascade release is refused.

The gate under test is the real gate (permit/permit.py, permit/flow.py) —
nothing here is mocked except the PayPal rail itself. Any assertion failure
exits non-zero. Output doubles as the run's evidence log.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

def _free_port():
    """An ephemeral loopback port. trace.py must never assume the default
    8741 is free: a live server there would answer the readiness probe and
    the trace would run against (and pollute) the wrong server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


PORT = _free_port()
BASE = f"http://127.0.0.1:{PORT}"


TRACE_TOKEN = "trace-token-not-a-secret"


def req(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(
        BASE + path, data=data, method=method,
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {TRACE_TOKEN}"})
    with urllib.request.urlopen(r, timeout=10) as resp:
        return resp.status, json.loads(resp.read().decode())


def show(tag, obj):
    print(f"[{tag}] {json.dumps(obj)}")


def main():
    env = dict(os.environ, PERMIT_API_TOKEN=TRACE_TOKEN)
    srv = subprocess.Popen(
        [sys.executable, str(HERE / "server.py"), "--port", str(PORT)],
        cwd=HERE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        env=env,
    )
    try:
        # wait for the listener; also verify the child is still alive so a
        # bind failure can never be mistaken for a foreign server answering
        # the probe.
        for _ in range(50):
            if srv.poll() is not None:
                raise SystemExit(
                    f"server died on startup (exit {srv.returncode}); "
                    "not probing the port further")
            try:
                req("GET", "/api/ledger")
                break
            except Exception:
                time.sleep(0.1)
        else:
            raise SystemExit("server did not start")

        merchant = "trace_merchant"
        artifact = b"trace deliverable " + datetime.now(timezone.utc).isoformat().encode()
        digest = hashlib.sha256(artifact).hexdigest()

        # ---- 1. issue + check + spend (allowed) ---------------------------
        # NOTE: an ALLOWED check() RESERVES cap (cumulative reservation), so
        # the trace accounts for it: $100 cap, check $30 (reserves), spend $30.
        _, grant = req("POST", "/api/permits", {
            "agent_id": "trace_agent", "cap_cents": 10000,
            "allowlist": [merchant], "expiry_hours": 1})
        pid = grant["permit_id"]
        show("grant", {"permit_id": pid, "receipt_seq": grant["receipt"]["seq"]})

        _, check = req("POST", f"/api/permits/{pid}/check",
                       {"amount_cents": 3000, "merchant_id": merchant})
        show("check", {"allowed": check["allowed"], "reason": check["reason"]})
        assert check["allowed"] and check["reason"] == "allowed", "check should pass"
        # /check is read-only: it does not reserve cap and writes no receipt.
        # The spend below is what reserves $30 of the $100 cap.
        _, after_check = req("GET", f"/api/permits/{pid}")
        assert after_check["reserved_cents"] == 0, "check must not reserve"
        assert after_check["remaining_cents"] == 10000

        _, spend = req("POST", f"/api/permits/{pid}/spend", {
            "amount_cents": 3000, "merchant_id": merchant,
            "predicate": "delivery_hash", "artifact_hash": digest})
        show("spend", {"allowed": spend["allowed"], "reason": spend["reason"],
                       "escrow_id": spend["escrow_id"]})
        assert spend["allowed"] and spend["escrow_id"], "spend should be allowed"
        escrow_id = spend["escrow_id"]

        _, state = req("GET", f"/api/permits/{pid}")
        show("permit-state", {"reserved_cents": state["reserved_cents"],
                              "remaining_cents": state["remaining_cents"]})
        assert state["remaining_cents"] == 7000  # 10000 - 3000(spend); check reserves nothing

        _, paypal = req("GET", "/debug/paypal")
        show("paypal-after-allowed", paypal)
        assert paypal["authorizations"] == 1, "exactly one PayPal authorize expected"

        # ---- 2. blocked path: over-authority attempt -----------------------
        # remaining is $40 (100 - 30 check - 30 spend); $50 must block.
        # ---- 2. blocked path: over-authority attempt -----------------------
        # /check reserved nothing, so $70 of the $100 cap is still free.
        # $80 must block, and the PayPal client must not be called.
        _, paypal_before = req("GET", "/debug/paypal")
        _, blocked = req("POST", f"/api/permits/{pid}/spend", {
            "amount_cents": 8000, "merchant_id": merchant,
            "predicate": "delivery_hash", "artifact_hash": digest})
        _, paypal_after = req("GET", "/debug/paypal")
        show("blocked", {"allowed": blocked["allowed"], "reason": blocked["reason"],
                         "escrow_id": blocked["escrow_id"],
                         "paypal_calls_before": paypal_before,
                         "paypal_calls_after": paypal_after})
        assert not blocked["allowed"] and blocked["reason"] == "over_remaining_cap"
        assert blocked["escrow_id"] is None
        assert paypal_before == paypal_after, "PayPal client touched on blocked path!"
        print("[proof] over-authority attempt BLOCKED; PayPal rail untouched (call counts identical)")

        # ---- 2b. assertion-level spy: the gate itself must never call ------
        from permit.flow import SpendPipeline
        from permit.ledger import Ledger
        from permit.permit import PermitStore
        from settlement.paypal_client import PayPalClient
        from settlement.verifier import PredicateType, ReleaseVerifier

        class StrictSpy(PayPalClient):
            merchant_account_id = None
            def authorize(self, amount_cents, merchant_id, idempotency_key=None):
                raise AssertionError("GATE FAILURE: PayPal.authorize called on a blocked attempt")
            def capture(self, auth_id, amount_cents, idempotency_key):
                raise AssertionError("GATE FAILURE: PayPal.capture called on a blocked attempt")
            def void(self, auth_id):
                raise AssertionError("GATE FAILURE: PayPal.void called on a blocked attempt")
            def get_authorization(self, auth_id):
                raise AssertionError("GATE FAILURE: PayPal.get_authorization called on a blocked attempt")

        lg = Ledger()
        ps = PermitStore(ledger=lg)
        spy = StrictSpy()
        vf = ReleaseVerifier(spy, ps, ledger=lg)
        fl = SpendPipeline(ps, spy, vf, ledger=lg)
        p2, _ = ps.grant("spy_agent", 1000, [merchant],
                         datetime.now(timezone.utc) + timedelta(hours=1))
        attempt = fl.spend(p2.permit_id, 9999, merchant, PredicateType.D, digest)
        assert not attempt.allowed and attempt.reason == "over_remaining_cap"
        assert attempt.escrow_id is None
        print("[proof] assertion-spy survived: blocked spend never called PayPal (authorize would have raised)")

        # ---- 3. release the allowed escrow, then delegate + cascade revoke --
        _, rel = req("POST", f"/api/escrows/{escrow_id}/release",
                     {"delivered_bytes_b64": base64.b64encode(artifact).decode()})
        show("release", rel)
        assert rel["released"] and rel["capture_id"], "release should capture"

        _, grant2 = req("POST", "/api/permits", {
            "agent_id": "budget_owner", "cap_cents": 5000,
            "allowlist": [merchant], "expiry_hours": 1})
        parent_id = grant2["permit_id"]
        _, delegated = req("POST", f"/api/permits/{parent_id}/delegate", {
            "agent_id": "buying_agent", "cap_cents": 1500,
            "allowlist": [merchant], "expiry_hours": 0.5})
        show("delegate", delegated)
        child_id = delegated["permit_id"]
        assert delegated["parent_id"] == parent_id
        assert delegated["receipt"]["event"] == "DELEGATED"

        _, spend2 = req("POST", f"/api/permits/{child_id}/spend", {
            "amount_cents": 1000, "merchant_id": merchant,
            "predicate": "delivery_hash", "artifact_hash": digest})
        assert spend2["allowed"]
        escrow2 = spend2["escrow_id"]

        # lineage is visible pre-cascade; the cascade releases the carve and
        # clears the link (idempotent release), so check it here
        _, child_pre = req("GET", f"/api/permits/{child_id}")
        assert child_pre["parent_id"] == parent_id
        assert child_pre["revoked"] is False

        _, cascade = req("POST", f"/api/permits/{parent_id}/revoke-cascade", {})
        show("revoke-cascade", cascade)
        assert cascade["revoked"] and escrow2 in cascade["voided_escrows"], (
            "cascade must void the child's in-flight escrow"
        )
        assert child_id in (cascade.get("cascaded_to") or []), (
            "cascade must name the child in cascaded_to"
        )

        _, refused = req("POST", f"/api/escrows/{escrow2}/release",
                         {"delivered_bytes_b64": base64.b64encode(artifact).decode()})
        show("post-cascade-release", refused)
        assert not refused["released"], "release after cascade must be refused"

        # post-cascade checks must fail on both permits (revoked)
        _, check_child = req("POST", f"/api/permits/{child_id}/check",
                             {"amount_cents": 100, "merchant_id": merchant})
        assert not check_child["allowed"] and check_child["reason"] == "revoked"
        _, check_parent = req("POST", f"/api/permits/{parent_id}/check",
                             {"amount_cents": 100, "merchant_id": merchant})
        assert not check_parent["allowed"] and check_parent["reason"] == "revoked"

        _, child_state = req("GET", f"/api/permits/{child_id}")
        assert child_state["revoked"] is True
        # the carve release clears the link by design (idempotent); lineage
        # lives on the DELEGATED + REVOKED_CASCADE receipts (checked below)

        # ---- ledger integrity ------------------------------------------------
        _, led = req("GET", "/api/ledger")
        events = [r["event"] for r in led["receipts"]]
        show("ledger", {
            "chain": led["chain"],
            "receipt_count": len(led["receipts"]),
            "events": events,
        })
        assert led["chain"]["ok"], f"ledger chain broken: {led['chain']['reason']}"
        assert "DELEGATED" in events, "ledger missing DELEGATED"
        assert "REVOKED_CASCADE" in events, "ledger missing REVOKED_CASCADE"
        assert "CARVE_RELEASED" in events, "ledger missing CARVE_RELEASED"

        print("\nTRACE COMPLETE: allowed flows, blocked never touches PayPal, delegate + cascade revoke. All green.")
    finally:
        srv.terminate()
        out, _ = srv.communicate(timeout=10)
        if out:
            print("--- server log ---")
            print(out.strip())


if __name__ == "__main__":
    main()
