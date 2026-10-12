"""
SLA escrow demo (mock mode: no credentials, no network).

A client hires a worker agent for a deliverable. The client delegates a
fenced sub-permit; the worker's pay goes on hold in escrow; the CLIENT's
acceptance signature is the only key that releases it.

Beats:
  1. Principal grants the client agent a $100 permit.
  2. Client delegates a $40 sub-permit to the worker agent.
  3. Worker delivers -> $40 hold -> client signs acceptance -> CAPTURED.
     The capture rolls up to the parent.
  4. Second $30 carve; the worker FORGES an acceptance signature ->
     REFUSED, the hold is voided, the reservation released. PayPal never
     captures.
  5. Client tries to delegate $70 more (only $60 free) -> BLOCKED.
     Cascade revoke + carve release leaves the parent whole.

Usage:
  python3 demo_sla_escrow.py [--fast]
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))

import argparse
import time

from permit.ledger import Ledger
from scenarios.sla_escrow import money, run_sla_escrow
from settlement.paypal_client import MockPayPalClient

TITLES = {
    "grant": "Principal grants the client a $100 permit",
    "delegate": "Client delegates a $40 carve to the worker",
    "capture": "Worker delivers; client accepts; $40 captured",
    "forged_refused": "Worker forges acceptance -> REFUSED, hold voided",
    "fence": "Over-delegation refused: the grant fence holds",
    "cascade": "Cascade revoke: carves released, parent whole",
}


def beat(n: int, title: str, fast: bool) -> None:
    print(f"\n{'='*60}\nBEAT {n}: {title}\n{'='*60}")
    if not fast:
        time.sleep(1.2)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fast", action="store_true")
    args = ap.parse_args()

    paypal = MockPayPalClient()
    ledger = Ledger()
    print("Running SLA escrow on the mock rail (no network, no credentials).")
    t = run_sla_escrow(paypal, ledger=ledger)

    for i, b in enumerate(t["beats"], 1):
        beat(i, TITLES[b["beat"]], args.fast)
        for k, v in b.items():
            if k == "beat":
                continue
            print(f"  {k}: {v}")

    print(f"\n{'='*60}")
    print(f"Receipts: {t['n_receipts']} ({', '.join(t['receipt_types'])})")
    print(f"PayPal captures: {len(paypal.capture_calls)} (beat 3 only)")
    print(f"PayPal voids: {len(paypal.voids)} (beat 4)")
    print("Demo complete: every dollar is accounted for.")


if __name__ == "__main__":
    main()
