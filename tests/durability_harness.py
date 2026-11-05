"""Durability harness tests — crash-resume gate (Charter Gate 1).

Offline, mock provider only, no network. Four kill points plus supporting
assertions. Each test forks a child, SIGKILLs mid-flight, reloads fresh
instances from the same durable_dir, and asserts spec §4.

Run: python -m pytest tests/durability_harness.py -v
"""

from __future__ import annotations

import os
import sys
import hashlib
import tempfile
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from harness.durability_harness import _run_kill_point, _build, _artifact
from settlement.verifier import Evidence, PredicateType


def test_k1_before_authorize_retains_reservation(tmp_path: Path):
    res = _run_kill_point("K1", tmp_path / "K1")
    assert res["pass"], "\n".join(res.get("details", [])) + f"\nerror: {res.get('error')}"


def test_k2_after_authorize_before_register(tmp_path: Path):
    res = _run_kill_point("K2", tmp_path / "K2")
    assert res["pass"], "\n".join(res.get("details", [])) + f"\nerror: {res.get('error')}"


def test_k3_after_register_before_capture_response(tmp_path: Path):
    res = _run_kill_point("K3", tmp_path / "K3")
    assert res["pass"], "\n".join(res.get("details", [])) + f"\nerror: {res.get('error')}"


def test_k4_timeout_unknown_reconcile(tmp_path: Path):
    res = _run_kill_point("K4", tmp_path / "K4")
    assert res["pass"], "\n".join(res.get("details", [])) + f"\nerror: {res.get('error')}"


def test_reload_preserves_ledger_chain(tmp_path: Path):
    ledger, permits, paypal, verifier, flow = _build(tmp_path)
    from datetime import datetime, timedelta, timezone

    permit, _ = permits.grant(
        agent_id="a1", cap_cents=5000, allowlist=["merchant_1"], expiry=datetime.now(timezone.utc) + timedelta(hours=1)
    )
    _, digest = _artifact()
    flow.spend(permit.permit_id, 3000, "merchant_1", PredicateType.D, digest, agent_id=permit.agent_id)
    ok, reason = ledger.verify_chain()
    assert ok, reason
    n = len(ledger)
    # Reload (must release writer lock first)
    from permit.durability import DurableLedger
    from harness.durability_harness import _close_ledger

    _close_ledger(ledger)
    ledger2 = DurableLedger(durable_dir=tmp_path)
    ok2, reason2 = ledger2.verify_chain()
    assert ok2, reason2
    assert len(ledger2) == n, f"ledger len {len(ledger2)} != {n}"
    _close_ledger(ledger2)


def test_no_duplicate_authorize_on_resume(tmp_path: Path):
    """Explicit authorize_calls count check after K2 reload."""
    res = _run_kill_point("K2", tmp_path / "K2dup")
    assert res["pass"], res
    # Also verify directly: authorize_calls == 1 and second spend with same auth not doubling
    from permit.durability import DurableMockPayPalClient

    paypal = DurableMockPayPalClient(durable_dir=tmp_path / "K2dup")
    assert len(paypal.authorize_calls) == 1, f"authorize_calls={paypal.authorize_calls}"


def test_no_duplicate_capture_on_reconcile(tmp_path: Path):
    res = _run_kill_point("K4", tmp_path / "K4dup")
    assert res["pass"], res
    from permit.durability import DurableMockPayPalClient

    paypal = DurableMockPayPalClient(durable_dir=tmp_path / "K4dup")
    assert len(paypal.capture_calls) == 1
    assert len(paypal.captures) == 1


def test_unknown_reconcile_converges(tmp_path: Path):
    """K4 full loop: UNKNOWN -> reconcile -> CAPTURED, no duplicate."""
    res = _run_kill_point("K4", tmp_path / "K4conv")
    assert res["pass"], res


def test_fresh_process_resume_via_reloaded_state(tmp_path: Path):
    """Fresh instances (new object graph) reload state and can release."""
    ledger, permits, paypal, verifier, flow = _build(tmp_path)
    from datetime import datetime, timedelta, timezone

    permit, _ = permits.grant(
        agent_id="a1", cap_cents=5000, allowlist=["merchant_1"], expiry=datetime.now(timezone.utc) + timedelta(hours=1)
    )
    _, digest = _artifact()
    attempt = flow.spend(permit.permit_id, 3000, "merchant_1", PredicateType.D, digest, agent_id=permit.agent_id)
    escrow_id = attempt.escrow_id
    # Simulate restart: new objects, same dir (release writer lock first)
    from harness.durability_harness import _close_ledger

    _close_ledger(ledger)
    ledger2, permits2, paypal2, verifier2, flow2 = _build(tmp_path)
    permit2 = permits2.get(permit.permit_id)
    assert permit2 is not None
    assert permit2.reserved_cents == 3000
    assert escrow_id in verifier2._escrows
    assert verifier2._escrows[escrow_id].state == "AUTHORIZED"
    # Release via fresh flow
    artifact, _ = _artifact()
    result = flow2.release(escrow_id, Evidence(delivered_bytes=artifact))
    assert result.released
    # Verify no duplicate on second load
    from permit.durability import DurableMockPayPalClient

    paypal3 = DurableMockPayPalClient(durable_dir=tmp_path)
    assert len(paypal3.capture_calls) == 1
    assert len(paypal3.captures) == 1
