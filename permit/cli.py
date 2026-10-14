"""Credential-free, headless command-line demonstrations for Permit."""

from __future__ import annotations

import argparse
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Sequence

from settlement.paypal_client import MockPayPalClient
from settlement.verifier import Evidence, PredicateType, ReleaseVerifier

from .flow import SpendPipeline
from .ledger import Ledger
from .permit import PermitStore


class DemoInvariantError(RuntimeError):
    """Raised when an offline scenario does not establish its claims."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise DemoInvariantError(message)


def _pipeline() -> tuple[
    SpendPipeline, MockPayPalClient, PermitStore, ReleaseVerifier, Ledger
]:
    ledger = Ledger()
    permits = PermitStore(ledger=ledger)
    provider = MockPayPalClient()
    verifier = ReleaseVerifier(provider, permits, ledger=ledger)
    flow = SpendPipeline(permits, provider, verifier, ledger=ledger)
    return flow, provider, permits, verifier, ledger


def _grant(permits: PermitStore, cap_cents: int, merchant: str):
    return permits.grant(
        agent_id="offline_demo_agent",
        cap_cents=cap_cents,
        allowlist=[merchant],
        expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )[0]


def run_demo() -> None:
    """Exercise capture, cap blocking, and e-stop using only in-memory mocks."""
    flow, provider, permits, _verifier, ledger = _pipeline()
    merchant = "offline_demo_merchant"
    artifact = b"offline demo deliverable"
    digest = hashlib.sha256(artifact).hexdigest()

    permit = _grant(permits, 5_000, merchant)
    allowed = flow.spend(
        permit.permit_id, 3_000, merchant, PredicateType.D, digest
    )
    _require(allowed.allowed and allowed.escrow_id is not None, "spend was not allowed")
    released = flow.release(allowed.escrow_id, Evidence(delivered_bytes=artifact))
    _require(released.released, "valid mock delivery was not captured")
    _require(len(provider.capture_calls) == 1, "expected one mock capture call")
    print("CAPTURED: $30.00 recorded by the in-memory mock provider")

    authorizations_before = len(provider.authorize_calls)
    blocked = flow.spend(
        permit.permit_id, 3_000, merchant, PredicateType.D, digest
    )
    _require(not blocked.allowed, "over-cap spend was unexpectedly allowed")
    _require(blocked.reason == "over_remaining_cap", "wrong cap-block reason")
    _require(
        len(provider.authorize_calls) == authorizations_before,
        "blocked spend reached the mock provider",
    )
    print("CAP BLOCK: $30.00 refused with only $20.00 remaining; no authorization")

    stopped_permit = _grant(permits, 5_000, merchant)
    pending = flow.spend(
        stopped_permit.permit_id, 1_000, merchant, PredicateType.D, digest
    )
    _require(pending.allowed and pending.escrow_id is not None, "e-stop setup failed")
    stop = flow.estop(stopped_permit.permit_id)
    _require(pending.escrow_id in stop.voided, "e-stop did not void mock escrow")
    refused = flow.release(pending.escrow_id, Evidence(delivered_bytes=artifact))
    _require(not refused.released, "release succeeded after e-stop")
    _require(stopped_permit.revoked, "e-stop did not revoke permit")
    print("E-STOP: permit revoked, mock authorization voided, release refused")

    verified, reason = ledger.verify_chain()
    _require(verified, f"ledger verification failed: {reason}")
    print(f"LEDGER VERIFIED: {len(ledger)} in-memory receipts")
    print("OFFLINE MOCK ONLY: no network, credentials, or real money were used")


def run_recovery_demo() -> None:
    """Exercise dropped-response reconciliation using only the mock provider."""
    flow, provider, permits, verifier, ledger = _pipeline()
    merchant = "offline_demo_merchant"
    artifact = b"offline recovery deliverable"
    digest = hashlib.sha256(artifact).hexdigest()
    permit = _grant(permits, 5_000, merchant)

    attempt = flow.spend(
        permit.permit_id, 2_500, merchant, PredicateType.D, digest
    )
    _require(attempt.allowed and attempt.escrow_id is not None, "spend was not allowed")

    provider.inject_capture_timeout = "after_apply"
    result = flow.release(attempt.escrow_id, Evidence(delivered_bytes=artifact))
    provider.inject_capture_timeout = None
    escrow = verifier.get_escrow(attempt.escrow_id)
    _require(not result.released, "dropped response was reported as released")
    _require(result.reason == "unknown_after_timeout", "expected timeout uncertainty")
    _require(escrow is not None and escrow.state == "UNKNOWN", "escrow is not UNKNOWN")
    _require(len(provider.capture_calls) == 1, "expected one mock capture request")
    print("UNKNOWN: mock capture applied but its response was deliberately dropped")

    reconciled = verifier.reconcile(attempt.escrow_id)
    _require(reconciled.resolved, "reconciliation did not resolve the escrow")
    _require(reconciled.outcome == "captured", "provider truth was not CAPTURED")
    _require(escrow.state == "CAPTURED", "escrow did not become CAPTURED")
    _require(len(provider.capture_calls) == 1, "reconciliation duplicated capture")

    second = verifier.reconcile(attempt.escrow_id)
    _require(
        not second.resolved and second.outcome == "already_resolved",
        "second reconciliation changed state",
    )
    _require(len(provider.capture_calls) == 1, "second reconciliation duplicated capture")
    print("CAPTURED: reconciled from in-memory mock provider truth")
    print("NO DUPLICATE MOCK CAPTURE: exactly one capture request was recorded")

    verified, reason = ledger.verify_chain()
    _require(verified, f"ledger verification failed: {reason}")
    print(f"LEDGER VERIFIED: {len(ledger)} in-memory receipts")
    print("OFFLINE MOCK ONLY: this is not restart recovery and no real money moved")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="permit",
        description="Run credential-free, headless Permit mock demonstrations.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser(
        "demo",
        help="show mock capture, cap blocking, e-stop, and ledger verification",
    )
    commands.add_parser(
        "demo-recovery",
        help="show mock UNKNOWN-to-CAPTURED reconciliation without duplicate capture",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "demo":
            run_demo()
        elif args.command == "demo-recovery":
            run_recovery_demo()
    except DemoInvariantError as exc:
        print(f"DEMO FAILED: {exc}")
        return 1
    return 0
