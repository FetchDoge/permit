"""
Permit delegation demo (mock mode: no credentials, no network).

A buyer agent holds a $50 permit. It delegates a $20 sub-permit to a
researcher sub-agent — a REAL LLM agent deciding on its own. The
researcher spends within its carve; captures roll up to the parent.
Over-cap attempts are refused at both levels; revoking the parent
cascades: the child is revoked, its hold voided, its unspent carve
released.

Beats:
  1. Principal grants the buyer agent a $50 permit.
  2. Buyer agent delegates a $20 sub-permit to the researcher.
  3. Researcher buys the $12 report -> captured; parent rolls up.
  4. Researcher tries $15 (has $8) -> BLOCKED. Buyer tries to delegate
     $40 (has $30 free) -> rejected.
  5. Principal revokes the parent -> cascade revoke, carve released.

Usage:
  python3 demo_delegation.py [--fast] [--port 8471]
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))

import argparse
import json
import time
from datetime import datetime, timedelta, timezone

from agent.react import run_agent
from agent.tools import SpendTools
from dashboard.server import Dashboard
from permit.flow import SpendPipeline
from permit.ledger import Ledger
from permit.permit import PermitStore
from settlement.paypal_client import MockPayPalClient
from settlement.verifier import ReleaseVerifier

MERCHANT = "dataset_mart"
CATALOG = {
    "dataset license": b"dataset-license-v1::dataset_mart",
    "premium tier": b"dataset-license-premium::dataset_mart",
    "api credits": b"api-credits-1000::dataset_mart",
    "report": b"quarterly-report-q3::dataset_mart",
}


def beat(n: int, title: str, fast: bool):
    print(f"\n{'='*60}\nBEAT {n}: {title}\n{'='*60}")
    if not fast:
        time.sleep(1.5)


def money(cents) -> str:
    try:
        return f"${float(cents) / 100:.2f}"
    except (TypeError, ValueError):
        return "$?"


def show_receipts(ledger, since: int):
    for r in ledger.receipts()[since:]:
        p = r.payload
        detail = p.get("reason", "")
        if r.event_type in ("ALLOWED", "BLOCKED"):
            detail = f"{money(p.get('amount_cents', 0))} {detail}"
        elif r.event_type == "DELEGATED":
            detail = (f"{money(p['cap_cents'])} -> {p['agent_id']} "
                      f"(parent remaining {money(p['parent_remaining_cents'])})")
        elif r.event_type == "CARVE_RELEASED":
            detail = (f"{money(p['released_cents'])} back to parent "
                      f"(remaining {money(p['parent_remaining_cents'])})")
        elif r.event_type in ("E-STOP", "REVOKED_CASCADE"):
            detail = f"permit {p['permit_id'][:12]}..."
        print(f"  #{r.seq:02d} {r.event_type:14s} {detail}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fast", action="store_true")
    ap.add_argument("--port", type=int, default=8471)
    args = ap.parse_args()

    ledger = Ledger()
    permits = PermitStore(ledger=ledger)
    paypal = MockPayPalClient()
    verifier = ReleaseVerifier(paypal, permits, ledger=ledger)
    flow = SpendPipeline(permits, paypal, verifier, ledger=ledger)
    dash = Dashboard(permits, ledger, flow, verifier, port=args.port).start()
    print(f"dashboard: http://127.0.0.1:{args.port}")
    transcript = "demo_delegation_transcript.jsonl"
    open(transcript, "w").close()

    # -- beat 1: the human grants --------------------------------------
    beat(1, "principal grants the buyer agent a $50 permit", args.fast)
    mark = len(ledger)
    parent, _ = permits.grant(
        agent_id="buyer", cap_cents=5000, allowlist=[MERCHANT],
        expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    show_receipts(ledger, mark)
    print(f"  remaining: {money(parent.remaining_cents())}")
    buyer_tools = SpendTools(flow, parent.permit_id, MERCHANT, CATALOG)

    # -- beat 2: buyer delegates ----------------------------------------
    beat(2, "buyer agent delegates a $20 sub-permit to the researcher", args.fast)
    mark = len(ledger)
    answer = run_agent(
        buyer_tools,
        "Delegate a $20.00 sub-permit to your researcher sub-agent "
        "(agent_id 'researcher'). It needs to buy a dataset license from "
        "dataset_mart within the hour.",
        transcript, beat=2)
    show_receipts(ledger, mark)
    print(f"  buyer agent: {answer}")
    children = permits.children_of(parent.permit_id)
    assert len(children) == 1, "delegation did not land"
    child_id = children[0]
    child = permits.get(child_id)
    print(f"  parent remaining: {money(parent.remaining_cents())} "
          f"(carved {money(child.cap_cents)})")
    researcher_tools = SpendTools(flow, child_id, MERCHANT, CATALOG)

    # -- beat 3: researcher spends ---------------------------------------
    beat(3, "researcher buys the $12 report (capture rolls up)", args.fast)
    mark = len(ledger)
    answer = run_agent(
        researcher_tools,
        "Buy the quarterly report for $12.00 from dataset_mart.",
        transcript, beat=3)
    show_receipts(ledger, mark)
    print(f"  researcher: {answer}")
    print(f"  child remaining: {money(child.remaining_cents())} | "
          f"parent remaining: {money(parent.remaining_cents())} "
          f"(captured {money(parent.captured_cents)})")

    # -- beat 4: refusals at both levels ----------------------------------
    beat(4, "over-cap attempts refused at child and parent", args.fast)
    mark = len(ledger)
    answer = run_agent(
        researcher_tools,
        "Buy the premium tier dataset license for $15.00 from dataset_mart.",
        transcript, beat=4)
    print(f"  researcher: {answer}")
    answer = run_agent(
        buyer_tools,
        "Delegate a $40.00 sub-permit to a second researcher "
        "(agent_id 'researcher2').",
        transcript, beat=4)
    print(f"  buyer agent: {answer}")
    show_receipts(ledger, mark)
    print(f"  PayPal authorize calls: {len(paypal.authorizations)} "
          f"(only the honest $12)")

    # -- beat 5: cascade revoke -------------------------------------------
    beat(5, "principal revokes the parent: cascade", args.fast)
    mark = len(ledger)
    receipt, voided = flow.revoke_cascade(parent.permit_id)
    show_receipts(ledger, mark)
    print(f"  voided: {voided}")
    print(f"  child revoked: {permits.get(child_id).revoked}")
    print(f"  parent: captured {money(parent.captured_cents)}, "
          f"remaining {money(parent.remaining_cents())}")

    # -- close out ----------------------------------------------------------
    print(f"\n{'='*60}")
    ok, reason = ledger.verify_chain()
    print(f"ledger chain: {'VERIFIED' if ok else 'BROKEN ' + reason} "
          f"({len(ledger)} receipts)")
    print(f"transcript: {transcript}")
    print(f"dashboard: http://127.0.0.1:{args.port} (still live)")


if __name__ == "__main__":
    main()
