"""
Permit principal-approval demo (mock mode: no credentials, no network).

A buyer agent holds a $100 permit with a $25 principal-approval
threshold — a REAL LLM agent deciding on its own. Small spends flow;
large spends pause for a human word, and the approval re-runs the
authority check at completion (fail-closed if the world moved).

Beats:
  1. Principal grants the buyer a $100 permit, $25 approval threshold.
  2. Agent buys the $20 dataset license (below threshold) -> auto-allowed,
     delivered, captured.
  3. Agent buys the $40 premium tier (above threshold) -> PENDING.
     The principal approves; the agent completes and delivers -> captured.
  4. Agent buys $30 of api credits (above threshold) -> PENDING.
     The principal DENIES -> BLOCKED, PayPal untouched.
  5. Agent buys the $35 report (above threshold) -> PENDING.
     The principal approves, then tightens the cap to $70.
     Completion re-runs the authority check and FAILS CLOSED:
     the approval was a word, not a lock.

Usage:
  python3 demo_approval.py [--fast] [--port 8474]
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))

import argparse
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
TRANSCRIPT = "/tmp/demo_approval_transcript.jsonl"


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
        if r.event_type in ("ALLOWED", "BLOCKED", "APPROVAL_PENDING"):
            detail = f"{money(p.get('amount_cents', 0))} {detail}"
        elif r.event_type == "APPROVAL_REQUESTED":
            detail = (f"{money(p['amount_cents'])} > "
                      f"{money(p['threshold_cents'])} threshold")
        elif r.event_type == "APPROVAL_DECIDED":
            detail = f"{p['decision']} by {p['actor']}"
        elif r.event_type in ("AUTHORIZED", "CAPTURED"):
            detail = money(p.get("amount_cents", 0))
        elif r.event_type == "TIGHTEN":
            ch = p.get("changes", {}).get("cap_cents", {})
            detail = (f"cap {money(ch.get('from'))} -> {money(ch.get('to'))}"
                      if ch else "")
        print(f"  #{r.seq:02d} {r.event_type:18s} {detail}")


def show_permit(permits, permit_id: str):
    p = permits.get(permit_id)
    print(f"  permit {p.permit_id[:12]}... remaining {money(p.remaining_cents())} "
          f"(reserved {money(p.reserved_cents)}, captured {money(p.captured_cents)})")


def attempt_task(tools, task: str, n: int) -> str:
    return run_agent(tools, task, TRANSCRIPT, max_turns=10, beat=n)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fast", action="store_true")
    ap.add_argument("--port", type=int, default=8474)
    args = ap.parse_args()

    ledger = Ledger()
    permits = PermitStore(ledger=ledger)
    paypal = MockPayPalClient()
    verifier = ReleaseVerifier(paypal, permits, ledger=ledger)
    flow = SpendPipeline(permits, paypal, verifier, ledger=ledger)
    dash = Dashboard(permits, ledger, flow, verifier, port=args.port).start()
    print(f"dashboard: http://127.0.0.1:{args.port}")

    beat(1, "Principal grants a $100 permit with a $25 approval threshold",
         args.fast)
    since = len(ledger.receipts())
    permit, _ = permits.grant(
        "buyer-agent", 10000, [MERCHANT],
        datetime.now(timezone.utc) + timedelta(hours=1),
        approval_threshold_cents=2500,
    )
    show_receipts(ledger, since)
    tools = SpendTools(flow, permit.permit_id, MERCHANT, CATALOG)

    beat(2, "Agent buys the $20 dataset license (below threshold) — "
            "auto-allowed", args.fast)
    since = len(ledger.receipts())
    print(attempt_task(
        tools,
        "Buy the dataset license for $20 (2000 cents). After ALLOWED, "
        "deliver it and report the capture id.",
        2,
    ))
    show_receipts(ledger, since)
    show_permit(permits, permit.permit_id)

    beat(3, "Agent buys the $40 premium tier (above threshold) — "
            "PENDING, principal approves", args.fast)
    since = len(ledger.receipts())
    out = attempt_task(
        tools,
        "Buy the premium tier for $40 (4000 cents). If the spend is "
        "PENDING, report the approval_id and stop — do not poll forever.",
        3,
    )
    print(out)
    approval_id = permits.pending_approvals()[-1].approval_id
    print(f"\n  [principal taps APPROVE on the dashboard for {approval_id}]")
    flow.approve_approval(approval_id, actor="demo-principal")
    print(attempt_task(
        tools,
        f"The principal approved your premium tier purchase. Call "
        f"complete_approved_spend with approval_id {approval_id}, then "
        f"deliver it and report the capture id.",
        3,
    ))
    show_receipts(ledger, since)
    show_permit(permits, permit.permit_id)

    beat(4, "Agent buys $30 of api credits (above threshold) — "
            "PENDING, principal DENIES", args.fast)
    since = len(ledger.receipts())
    calls_before = len(paypal.authorize_calls)
    print(attempt_task(
        tools,
        "Buy api credits for $30 (3000 cents). If the spend is PENDING, "
        "report the approval_id and stop.",
        4,
    ))
    approval_id = permits.pending_approvals()[-1].approval_id
    print(f"\n  [principal taps DENY on the dashboard for {approval_id}]")
    flow.deny_approval(approval_id, actor="demo-principal")
    print(attempt_task(
        tools,
        f"Check the status of approval {approval_id} with check_approval "
        f"and report what happened.",
        4,
    ))
    show_receipts(ledger, since)
    print(f"  paypal authorize calls this beat: "
          f"{len(paypal.authorize_calls) - calls_before} (denied: zero)")
    show_permit(permits, permit.permit_id)

    beat(5, "Agent buys the $35 report — approved, then the cap tightens: "
            "completion FAILS CLOSED", args.fast)
    since = len(ledger.receipts())
    calls_before = len(paypal.authorize_calls)
    print(attempt_task(
        tools,
        "Buy the report for $35 (3500 cents). If the spend is PENDING, "
        "report the approval_id and stop.",
        5,
    ))
    approval_id = permits.pending_approvals()[-1].approval_id
    print(f"\n  [principal taps APPROVE for {approval_id}]")
    flow.approve_approval(approval_id, actor="demo-principal")
    print("  [principal tightens the permit cap to $70 as an exposure check]")
    permits.tighten(permit.permit_id, cap_cents=7000, actor="demo-principal")
    print(attempt_task(
        tools,
        f"The principal approved your report purchase. Call "
        f"complete_approved_spend with approval_id {approval_id} and "
        f"report exactly what happens — do not retry or work around it.",
        5,
    ))
    show_receipts(ledger, since)
    print(f"  paypal authorize calls this beat: "
          f"{len(paypal.authorize_calls) - calls_before} (failed closed: zero)")
    show_permit(permits, permit.permit_id)

    ok, reason = ledger.verify_chain()
    print(f"\nledger chain: {'INTACT' if ok else 'BROKEN ' + reason} "
          f"({len(ledger.receipts())} receipts)")
    print(f"total paypal authorize calls: {len(paypal.authorize_calls)} "
          f"(the two honest purchases only)")
    dash.stop()


if __name__ == "__main__":
    main()
