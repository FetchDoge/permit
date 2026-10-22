#!/usr/bin/env python3
"""E-stop adversarial demo (mock rail, no credentials, no network).

M4 demo: revocation wins the race, at every point in a spend's life.

  beat 1: the permit is revoked BEFORE the spend. The attempt is
          BLOCKED with reason "revoked" and PayPal is never called.
  beat 2: the e-stop lands INSIDE paypal.authorize, while the external
          call is in flight. The post-authorize recheck kills the
          spend (revoked_during_auth), the hold is voided, the cap
          reservation is released, and no escrow is ever registered,
          so capture is unreachable.
  beat 3: the e-stop lands AFTER authorize, while the hold is in
          flight. The escrow is voided, a later delivery is refused
          (already_voided), and zero captures reach the rail.
  beat 4: over-authority attempts on a live permit (over the remaining
          cap, and a merchant outside the allowlist) are BLOCKED at
          the gate with zero PayPal calls.

Every beat asserts its invariants and exits non-zero if one breaks:
nothing in the printed verdict is decoration. The audit summary at
the end is derived from the hash-chained ledger receipts only, and
each ledger's chain is verified.
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))

import hashlib
from datetime import datetime, timedelta, timezone

from permit.audit import audit_summary
from permit.flow import SpendPipeline
from permit.ledger import Ledger
from permit.permit import PermitStore
from settlement.paypal_client import MockPayPalClient
from settlement.verifier import Evidence, PredicateType, ReleaseVerifier

MERCHANT = "coffee-shop"
DATA = b"dataset-license-bytes"
ARTIFACT_HASH = hashlib.sha256(DATA).hexdigest()


def require(cond, msg):
    if not cond:
        raise SystemExit(f"demo requirement failed: {msg}")


def build(cap_cents=5000):
    ledger = Ledger()
    permits = PermitStore(ledger=ledger)
    paypal = MockPayPalClient()
    verifier = ReleaseVerifier(paypal, permits, ledger=ledger, allow_demo_key=True)
    flow = SpendPipeline(permits, paypal, verifier, ledger=ledger)
    permit, _ = permits.grant(
        agent_id="demo-agent",
        cap_cents=cap_cents,
        allowlist=[MERCHANT],
        expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    return flow, paypal, permits, verifier, permit


def beat_revoked_before_spend():
    print("=== beat 1: revoked before the spend ===")
    flow, paypal, permits, verifier, permit = build()
    flow.estop(permit.permit_id)
    attempt = flow.spend(permit.permit_id, 3000, MERCHANT, PredicateType.D, ARTIFACT_HASH)
    require(not attempt.allowed and attempt.reason == "revoked",
            f"beat 1 expected BLOCKED/revoked, got {attempt.allowed}/{attempt.reason}")
    require(len(paypal.authorize_calls) == 0 and len(paypal.capture_calls) == 0,
            "beat 1 blocked attempt reached the rail")
    print("  human e-stops the permit, then the agent tries to spend $30.00")
    print("  attempt: BLOCKED  reason=revoked  PayPal calls: 0")
    print("  verdict: a dead permit spends nothing; the rail is never touched.")
    return permits


def beat_estop_inside_authorize():
    print("=== beat 2: e-stop lands inside authorize ===")
    flow, paypal, permits, verifier, permit = build()
    real_authorize = paypal.authorize

    def hostile_authorize(amount_cents, merchant_id, idempotency_key=None):
        auth = real_authorize(amount_cents, merchant_id, idempotency_key)
        flow.estop(permit.permit_id)  # the stop lands mid-flight
        return auth

    paypal.authorize = hostile_authorize
    attempt = flow.spend(permit.permit_id, 3000, MERCHANT, PredicateType.D, ARTIFACT_HASH)
    require(not attempt.allowed and attempt.reason == "revoked_during_auth",
            f"beat 2 expected revoked_during_auth, got {attempt.allowed}/{attempt.reason}")
    require(attempt.escrow_id is None and len(verifier._escrows) == 0,
            "beat 2 registered an escrow on a revoked permit")
    require(len(paypal.voids) == 1,
            f"beat 2 expected the in-flight hold to be voided, voids={list(paypal.voids)}")
    require(len(paypal.capture_calls) == 0, "beat 2 reached capture")
    require(permit.reserved_cents == 0 and permit.remaining_cents() == 5000,
            "beat 2 did not release the cap reservation")
    print("  agent spends $30.00; the human e-stops while PayPal authorize is in flight")
    print("  attempt: BLOCKED  reason=revoked_during_auth  hold voided, reservation released")
    print("  verdict: revocation wins the race; no escrow exists, so capture is unreachable.")
    return permits


def beat_estop_after_authorize():
    print("=== beat 3: e-stop voids an in-flight hold ===")
    flow, paypal, permits, verifier, permit = build()
    attempt = flow.spend(permit.permit_id, 3000, MERCHANT, PredicateType.D, ARTIFACT_HASH)
    require(attempt.allowed and attempt.escrow_id, "beat 3 setup spend was not allowed")
    result = flow.estop(permit.permit_id)
    require(result.voided == [attempt.escrow_id],
            f"beat 3 e-stop did not void the in-flight escrow: {result.voided}")
    require(permit.reserved_cents == 0 and permit.remaining_cents() == 5000,
            "beat 3 did not release the cap reservation")
    release = flow.release(attempt.escrow_id, Evidence(delivered_bytes=DATA))
    require(not release.released and release.reason == "already_voided",
            f"beat 3 delivery after e-stop was not refused: {release}")
    require(len(paypal.capture_calls) == 0, "beat 3 reached capture after the stop")
    print("  agent holds $30.00 (AUTHORIZED); the human e-stops before delivery")
    print("  e-stop: escrow voided, reservation released; late delivery refused (already_voided)")
    print("  verdict: money that was only held never moves after the stop.")
    summary = audit_summary(permits.ledger)
    require(summary["chain"]["ok"], "beat 3 ledger chain does not verify")
    require(summary["totals"]["captured_cents"] == 0,
            "beat 3 audit shows captured money after an e-stop")
    print(f"  audit: {summary['total_receipts']} receipts, captured ${summary['totals']['captured_cents'] / 100:.2f}, "
          f"events {summary['events']}")
    return permits


def beat_over_authority():
    print("=== beat 4: over-authority attempts never reach the rail ===")
    flow, paypal, permits, verifier, permit = build()
    over = flow.spend(permit.permit_id, 6000, MERCHANT, PredicateType.D, ARTIFACT_HASH)
    wrong = flow.spend(permit.permit_id, 1000, "unknown-merchant", PredicateType.D, ARTIFACT_HASH)
    require(not over.allowed and over.reason == "over_remaining_cap",
            f"beat 4 over-cap attempt: {over.allowed}/{over.reason}")
    require(not wrong.allowed and wrong.reason == "merchant_not_allowed",
            f"beat 4 wrong-merchant attempt: {wrong.allowed}/{wrong.reason}")
    require(len(paypal.authorize_calls) == 0 and len(paypal.capture_calls) == 0,
            "beat 4 blocked attempt reached the rail")
    print("  agent tries $60.00 against a $50.00 cap, then $10.00 at an unlisted merchant")
    print("  attempts: BLOCKED  reason=over_remaining_cap / merchant_not_allowed  PayPal calls: 0")
    print("  verdict: over-authority is refused at admission, not declined at settlement.")
    return permits


def main():
    print("Permit e-stop adversarial demo (mock rail)")
    stores = [
        ("beat 1", beat_revoked_before_spend()),
        ("beat 2", beat_estop_inside_authorize()),
        ("beat 3", beat_estop_after_authorize()),
        ("beat 4", beat_over_authority()),
    ]
    print()
    for label, permits in stores:
        ok, reason = permits.ledger.verify_chain()
        require(ok, f"{label} ledger chain BROKEN: {reason}")
        print(f"ledger chain ({label}): VERIFIED")


if __name__ == "__main__":
    main()
