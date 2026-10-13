"""
SLA escrow: agent-to-agent settlement through a delegation tree.

The story: a client hires a worker agent for a deliverable. The client
delegates a fenced sub-permit to the worker; the worker's pay goes on
hold in escrow; the CLIENT's acceptance signature is the only key that
releases it. No signature, no money — even though the work is done and
the hold exists.

This exercises, in one scenario: delegation carve-outs, the grant fence
(over-delegation refused), predicate-gated settlement (acceptance
signature), forged-evidence refusal, capture roll-up, and cascade
revocation with carve release.

Beats (run_sla_escrow):
  1. GRANT: principal -> client agent, $100 @ report_foundry, 1h.
  2. DELEGATE: client -> worker agent, $40 carve for "Q3 revenue report".
  3. HAPPY: worker delivers; $40 hold authorized; escrow registered with
     predicate A (acceptance_signature); client inspects and signs ->
     CAPTURED. The capture rolls up: the parent shows $40 captured.
  4. ADVERSARIAL: second $30 carve for "appendix"; worker forges an
     acceptance signature -> REFUSED, the hold is voided, the reservation
     released. PayPal capture is never called.
  5. FENCE: client tries to delegate $70 more (only $60 free) ->
     BLOCKED over_parent_remaining. Then cascade revoke of the parent
     plus carve release leaves the parent whole: $40 captured, $60 free.

Mock rail only: pass a MockPayPalClient. No credentials, no network.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from permit.flow import SpendPipeline
from permit.ledger import Ledger
from permit.permit import PermitStore
from settlement.verifier import (
    Evidence,
    PredicateType,
    ReleaseVerifier,
    sign_acceptance,
)

MERCHANT = "report_foundry"
DELIVERABLE = b"Q3 revenue report: final"


def money(cents: int) -> str:
    return f"${cents / 100:.2f}"


def run_sla_escrow(paypal, ledger: Ledger | None = None) -> dict:
    """Run the SLA escrow scenario. Returns a transcript dict of beats."""
    ledger = ledger if ledger is not None else Ledger()
    permits = PermitStore(ledger=ledger)
    verifier = ReleaseVerifier(paypal, permits, ledger=ledger)
    pipeline = SpendPipeline(permits, paypal, verifier, ledger=ledger)
    beats: list[dict] = []
    now = datetime.now(timezone.utc)
    expiry = now + timedelta(hours=1)

    def record(name: str, **kw) -> None:
        beats.append({"beat": name, **kw})

    # -- Beat 1: grant ---------------------------------------------------
    client_permit, _ = permits.grant("client_agent", 10000, [MERCHANT], expiry)
    record("grant", permit_id=client_permit.permit_id, cap_cents=10000)

    # -- Beat 2: delegate the $40 carve -----------------------------------
    dlg = pipeline.delegate(
        client_permit.permit_id, "worker_agent", 4000, [MERCHANT], expiry
    )
    assert dlg.ok, f"delegation refused: {dlg.reason}"
    worker_permit = dlg.permit
    record(
        "delegate",
        child_id=worker_permit.permit_id,
        carve_cents=4000,
        parent_remaining_cents=permits.get(client_permit.permit_id).remaining_cents(),
    )

    # -- Beat 3: happy path — deliver, hold, accept, capture ---------------
    artifact_hash = hashlib.sha256(DELIVERABLE).hexdigest()
    attempt = pipeline.spend(
        worker_permit.permit_id, 4000, MERCHANT, PredicateType.A, artifact_hash
    )
    assert attempt.allowed, f"spend blocked: {attempt.reason}"
    escrow_id = attempt.escrow_id
    sig = sign_acceptance(escrow_id, artifact_hash, 4000)
    result = pipeline.release(escrow_id, Evidence(acceptance_signature=sig))
    assert result.released, f"release failed: {result.reason}"
    parent = permits.get(client_permit.permit_id)
    record(
        "capture",
        escrow_id=escrow_id,
        released=result.released,
        parent_captured_cents=parent.captured_cents,
        parent_remaining_cents=parent.remaining_cents(),
    )

    # -- Beat 4: adversarial — forged acceptance signature ----------------
    dlg2 = pipeline.delegate(
        client_permit.permit_id, "worker_agent", 3000, [MERCHANT], expiry
    )
    assert dlg2.ok, f"second delegation refused: {dlg2.reason}"
    worker2 = dlg2.permit
    artifact2 = hashlib.sha256(b"appendix draft").hexdigest()
    attempt2 = pipeline.spend(
        worker2.permit_id, 3000, MERCHANT, PredicateType.A, artifact2
    )
    assert attempt2.allowed, f"second spend blocked: {attempt2.reason}"
    forged = hashlib.sha256(b"worker says trust me").hexdigest()
    result2 = pipeline.release(
        attempt2.escrow_id, Evidence(acceptance_signature=forged)
    )
    assert not result2.released, "forged signature must not release"
    child2 = permits.get(worker2.permit_id)
    record(
        "forged_refused",
        escrow_id=attempt2.escrow_id,
        reason=result2.reason,
        child_reserved_cents=child2.reserved_cents,
        paypal_captures=len(paypal.capture_calls),
    )

    # -- Beat 5: fence — over-delegation refused, then cascade -------------
    # Parent: $100 cap, $40 captured. Remaining $60.
    over = pipeline.delegate(
        client_permit.permit_id, "worker_agent", 7000, [MERCHANT], expiry
    )
    assert not over.ok, "over-delegation must be refused"
    record(
        "fence",
        attempted_cents=7000,
        ok=over.ok,
        reason=over.reason,
        parent_remaining_cents=permits.get(client_permit.permit_id).remaining_cents(),
    )

    # Cascade: revoke the parent; the pipeline voids in-flight holds and
    # releases unspent carves post-order (children before parents).
    receipt, voided = pipeline.revoke_cascade(client_permit.permit_id)
    parent = permits.get(client_permit.permit_id)
    record(
        "cascade",
        revoked=True,
        voided=voided,
        parent_captured_cents=parent.captured_cents,
        parent_reserved_cents=parent.reserved_cents,
        parent_remaining_cents=parent.remaining_cents(),
    )

    return {
        "beats": beats,
        "receipt_types": sorted({r.event_type for r in ledger.receipts()}),
        "n_receipts": len(ledger.receipts()),
    }
