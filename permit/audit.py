"""
Audit view: a read-only summary of the ledger, derived from receipts only.

M4 calls for an audit view: an auditor (or a judge) should be able to see,
without replaying the demo, what the gate allowed, what it blocked and why,
and how much money actually moved, plus whether the hash chain still
verifies. The dashboard already streams raw receipts; this module is the
rollup over them.

Derivation rules (receipt payloads are the only source of truth):

- BLOCKED receipts carry {permit_id, amount_cents, merchant_id, reason};
  amount_cents is passed through untouched (the invalid_amount path stores
  repr(amount), and an audit must show what was actually attempted).
- Money totals count CAPTURED receipts that carry a permit_id. Those are
  written exactly once per capture by PermitStore.settle_capture(). The
  settlement verifier ALSO appends an escrow-scoped CAPTURED receipt
  ({escrow_id, paypal_capture_id, amount_cents}, no permit_id) for the
  same capture, so summing every CAPTURED receipt would double-count
  real money. Escrow-scoped receipts still appear in the event counts.
- Receipts with no permit_id are counted under "unscoped_receipts" so
  nothing in the ledger is invisible to the audit.

The summary never mutates the ledger: it reads receipts() (a copy) and
verify_chain(), both read-only.
"""

from __future__ import annotations


def _empty_permit() -> dict:
    return {
        "allowed_count": 0,
        "allowed_cents": 0,
        "blocked_count": 0,
        "captured_count": 0,
        "captured_cents": 0,
        "last_seq": -1,
    }


def audit_summary(ledger) -> dict:
    """Roll the ledger's receipts up into an audit summary dict."""
    receipts = ledger.receipts() if ledger is not None else []
    chain_ok, chain_reason = (
        ledger.verify_chain() if ledger is not None else (True, "no ledger bound")
    )

    events: dict[str, int] = {}
    permits: dict[str, dict] = {}
    blocked_by_reason: dict[str, int] = {}
    blocked_attempts: list[dict] = []
    unscoped = 0
    total_captured_cents = 0
    total_allowed_cents = 0

    for r in receipts:
        events[r.event_type] = events.get(r.event_type, 0) + 1
        payload = r.payload or {}
        permit_id = payload.get("permit_id")
        if not isinstance(permit_id, str):
            unscoped += 1
            continue
        entry = permits.setdefault(permit_id, _empty_permit())
        entry["last_seq"] = r.seq
        amount = payload.get("amount_cents")
        if r.event_type == "ALLOWED":
            entry["allowed_count"] += 1
            if isinstance(amount, int) and not isinstance(amount, bool):
                entry["allowed_cents"] += amount
                total_allowed_cents += amount
        elif r.event_type == "BLOCKED":
            entry["blocked_count"] += 1
            reason = payload.get("reason", "unknown")
            blocked_by_reason[reason] = blocked_by_reason.get(reason, 0) + 1
            blocked_attempts.append({
                "seq": r.seq,
                "permit_id": permit_id,
                "merchant_id": payload.get("merchant_id"),
                "amount_cents": amount,
                "reason": reason,
            })
        elif r.event_type == "CAPTURED":
            # Permit-scoped CAPTURED only (see module docstring): exactly
            # one per capture, written by PermitStore.settle_capture().
            entry["captured_count"] += 1
            if isinstance(amount, int) and not isinstance(amount, bool):
                entry["captured_cents"] += amount
                total_captured_cents += amount

    return {
        "chain": {"ok": chain_ok, "reason": chain_reason},
        "total_receipts": len(receipts),
        "unscoped_receipts": unscoped,
        "events": dict(sorted(events.items())),
        "blocked": {
            "total": sum(blocked_by_reason.values()),
            "by_reason": dict(sorted(blocked_by_reason.items())),
            "attempts": blocked_attempts,
        },
        "permits": permits,
        "totals": {
            "allowed_cents": total_allowed_cents,
            "captured_cents": total_captured_cents,
        },
    }
