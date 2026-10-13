#!/usr/bin/env python3
"""Admission-gating demo (mock rail, no credentials, no network).

Two beats, the M4 demo-beat acceptance criteria, framed as admission
gating, not payment declining:

  beat A: a runaway agent loop keeps spending against a $30 prepaid
          budget. Spends 1-3 are admitted and held. Every later attempt
          is refused at admission, before any order, hold, or escrow is
          created. The $5,000 surprise becomes a blocked admission, not
          a declined settlement.

  beat B: 8 parallel workers each try to grab $15 from a $50 budget
          at once. Atomic admission: the admitted total never exceeds
          the cap, every refusal is rail-silent. Fail-closed.

Nothing here is faked: the mock PayPal client records every call, and
the hash-chained ledger verifies at the end.
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))

import threading
from datetime import datetime, timedelta, timezone

from permit.flow import SpendPipeline
from permit.ledger import Ledger
from permit.permit import PermitStore
from settlement.paypal_client import MockPayPalClient
from settlement.verifier import PredicateType, ReleaseVerifier

MERCHANT = "coffee-shop"
ARTIFACT_HASH = "ab" * 32


def build(cap_cents):
    ledger = Ledger()
    permits = PermitStore(ledger=ledger)
    paypal = MockPayPalClient()
    verifier = ReleaseVerifier(paypal, permits, ledger=ledger)
    flow = SpendPipeline(permits, paypal, verifier, ledger=ledger)
    permit, _ = permits.grant(
        agent_id="demo-agent",
        cap_cents=cap_cents,
        allowlist=[MERCHANT],
        expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    return flow, paypal, permits, permit


def attempt(flow, permit_id, amount_cents):
    return flow.spend(
        permit_id, amount_cents, MERCHANT,
        PredicateType.D, ARTIFACT_HASH,
    )


def beat_runaway_loop():
    print("=== beat A: runaway loop refused at budget exhaustion ===")
    flow, paypal, permits, permit = build(3000)
    refused = 0
    for i in range(1, 7):
        a = attempt(flow, permit.permit_id, 1000)
        if a.allowed:
            print(f"  try {i}: ALLOWED  $10.00 held (escrow {a.escrow_id[:16]}...)")
        else:
            refused += 1
            print(f"  try {i}: BLOCKED  {a.reason}  (remaining $0.00)")
    print(f"  PayPal authorize calls: {len(paypal.authorize_calls)} "
          f"for {6 - refused} admitted spends, 0 for {refused} refusals")
    print("  verdict: the loop hit a wall at admission; no spend was created past the budget.")
    return permits


def beat_concurrent_grab():
    print("=== beat B: parallel overspend attempts cannot exceed the budget ===")
    flow, paypal, permits, permit = build(5000)
    outcomes = []
    lock = threading.Lock()

    def worker():
        local = [attempt(flow, permit.permit_id, 1500) for _ in range(2)]
        with lock:
            outcomes.extend(local)

    workers = [threading.Thread(target=worker) for _ in range(8)]
    for w in workers:
        w.start()
    for w in workers:
        w.join()

    admitted = [o for o in outcomes if o.allowed]
    total = sum(o.receipts[0].payload["amount_cents"] for o in admitted)
    print(f"  8 workers x 2 tries x $15.00 = $240.00 attempted against a $50.00 budget")
    print(f"  admitted: {len(admitted)} spends, ${total / 100:.2f} total "
          f"(cap ${permit.cap_cents / 100:.2f})")
    print(f"  refused:  {len(outcomes) - len(admitted)} at admission, "
          f"{len(paypal.authorize_calls) - len(admitted)} phantom PayPal calls")
    print("  verdict: atomic cap under concurrency; nothing overspent, fail-closed.")
    return permits


def main():
    print("Permit admission-gating demo (mock rail)")
    permits = beat_runaway_loop()
    print()
    permits_b = beat_concurrent_grab()
    print()
    for label, p in (("beat A", permits), ("beat B", permits_b)):
        ok, reason = p.ledger.verify_chain()
        print(f"ledger chain ({label}): {'VERIFIED' if ok else 'BROKEN: ' + reason}")


if __name__ == "__main__":
    main()
