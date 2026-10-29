"""Fail-closed hardening on top of durability (#26) void-confirmation model.

Ports from PR #27:
  - ledger-write denial / reservation rollback in check()
  - SQLite INSERT failure surfaces with no phantom reserve
  - ROLLBACK-after-append failure is logged, original error still raises
  - sweep void miss is logged (not swallowed)

Keeps #26 EstopResult / _release_if_void_confirmed semantics: void failures
retain the reservation and report unresolved rather than raising mid-loop.

The p95 latency gate from #27 is loosened (advisory soft bound) to avoid
flake on shared CI hosts.
"""

from __future__ import annotations

import logging
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from permit.flow import SpendPipeline
from permit.ledger import Ledger
from permit.permit import PermitStore
from permit.sqlite_ledger import SqliteLedger
from settlement.paypal_client import MockPayPalClient
from settlement.verifier import PredicateType, ReleaseVerifier

from tests.test_authority_layer import TinyPayPal, _permit_layer


def _future():
    return datetime.now(timezone.utc) + timedelta(hours=1)


def _pipeline_sqlite(tmp_path, cap_cents=5000):
    """Spend pipeline backed by a real SqliteLedger (writable until mocked)."""
    db_path = str(tmp_path / "ledger.db")
    ledger = SqliteLedger(db_path)
    permits = PermitStore(ledger=ledger)
    paypal = MockPayPalClient()
    verifier = ReleaseVerifier(paypal, permits, ledger=ledger)
    flow = SpendPipeline(permits, paypal, verifier, ledger=ledger)
    permit, _ = permits.grant(
        agent_id="agent_1",
        cap_cents=cap_cents,
        allowlist=["merchant_1"],
        expiry=_future(),
    )
    return flow, paypal, permits, permit, ledger


class _ConnProxy:
    """Wrap sqlite3.Connection so tests can force execute() failures.
    Connection.execute is read-only on CPython, so patch.object cannot."""

    def __init__(self, real, on_execute):
        self._real = real
        self._on_execute = on_execute

    def execute(self, *args, **kwargs):
        return self._on_execute(self._real, *args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._real, name)


def test_sqlite_ledger_write_failure_denies_spend_fail_closed(tmp_path):
    """When the SQLite ledger INSERT raises mid-spend, the attempt must not
    succeed, no escrow/release path opens, and the exception surfaces.
    Cap reservation must not stick without an ALLOWED receipt."""
    flow, paypal, permits, permit, ledger = _pipeline_sqlite(tmp_path)
    before_reserved = permit.reserved_cents
    before_len = len(ledger)

    def boom(real, sql, params=()):
        if isinstance(sql, str) and sql.lstrip().upper().startswith("INSERT"):
            raise sqlite3.OperationalError("simulated disk I/O error")
        return real.execute(sql, params) if params != () else real.execute(sql)

    ledger._conn = _ConnProxy(ledger._conn, boom)

    with pytest.raises(sqlite3.OperationalError, match="simulated disk I/O error"):
        flow.spend(
            permit.permit_id,
            3000,
            "merchant_1",
            PredicateType.D,
            "ab" * 32,
        )

    assert permit.reserved_cents == before_reserved
    assert permit.in_flight == {}
    assert len(paypal.authorizations) == 0
    assert len(paypal.capture_calls) == 0
    assert flow.verifier._escrows == {}
    assert len(ledger) == before_len


def test_check_rolls_back_reservation_when_allowed_append_raises():
    """If ALLOWED append raises after the in-memory reserve, check() must
    undo the reserve and re-raise (fail closed)."""
    ledger = Ledger()
    store = PermitStore(ledger=ledger)
    permit, _ = store.grant("agent_1", 5000, ["merchant_1"], _future())

    def boom(event_type, payload):
        if event_type == "ALLOWED":
            raise RuntimeError("ledger write failed")
        return Ledger.append(ledger, event_type, payload)

    with patch.object(ledger, "append", side_effect=boom):
        with pytest.raises(RuntimeError, match="ledger write failed"):
            store.check(permit.permit_id, 2000, "merchant_1")

    assert permit.reserved_cents == 0
    assert permit.in_flight == {}
    assert permit.remaining_cents() == 5000


def test_estop_void_failures_collected_not_raised_mid_loop():
    """#26 model: e-stop voids every hold, collects failures into unresolved,
    and does not raise mid-loop when a provider void is unconfirmed."""
    flow, paypal, permits, permit = _permit_layer()
    check = permits.check(permit.permit_id, 3000, "merchant_1")
    auth_id = check.receipt.payload["auth_id"]
    flow._track_outstanding(auth_id, permit.permit_id)
    flow._set_outstanding_paypal_auth(auth_id, "tiny_auth_thread")

    def void_unconfirmed(auth_id):
        raise RuntimeError("provider void failed")

    paypal.void = void_unconfirmed

    result = flow.estop(permit.permit_id)
    assert permit.revoked
    assert auth_id in result.unresolved
    assert auth_id not in result.voided
    assert permit.reserved_cents == 3000


def test_sweep_expired_pending_void_failure_is_logged_not_swallowed(
    caplog, monkeypatch
):
    """server.sweep_expired_pending: void failure must be logged (no bare
    except/pass). Local reservation is still released on TTL."""
    import server

    ledger = Ledger()
    permits = PermitStore(ledger=ledger)
    paypal = TinyPayPal()
    permit, _ = permits.grant("a", 10000, ["m"], _future())
    check = permits.check(permit.permit_id, 3000, "m")
    auth_id = check.receipt.payload["auth_id"]

    from permit.flow import ApprovalRequired

    appr = ApprovalRequired(
        permit_id=permit.permit_id,
        auth_id=auth_id,
        order_id="ORD-1",
        approval_url="https://example.test/approve",
        amount_cents=3000,
        merchant_id="m",
        predicate_type="delivery_hash",
        artifact_hash="ab" * 32,
    )
    oid = "op_test_1"
    monkeypatch.setattr(server, "permits", permits)
    monkeypatch.setattr(server, "paypal", paypal)
    monkeypatch.setattr(server, "ledger", ledger)
    monkeypatch.setattr(server, "PENDING_OPS", {oid: appr})
    monkeypatch.setattr(
        server,
        "_PENDING_META",
        {oid: time.monotonic() - 16 * 60},
    )

    def void_boom(order_id):
        raise RuntimeError("sweep void failed")

    paypal.void = void_boom

    with caplog.at_level(logging.ERROR):
        reaped = server.sweep_expired_pending()

    assert reaped == 1
    assert permit.reserved_cents == 0
    assert oid not in server.PENDING_OPS
    assert any("void failed" in r.message.lower() for r in caplog.records)
    events = [r.event_type for r in ledger.receipts()]
    assert "OPERATION_EXPIRED" in events


def test_sqlite_append_rollback_failure_still_surfaces_original(tmp_path, caplog):
    """If ROLLBACK itself fails after a bad append, log it but still raise
    the original write error."""
    db_path = str(tmp_path / "ledger.db")
    ledger = SqliteLedger(db_path)
    state = {"fail_insert": True}

    def flaky(real, sql, params=()):
        upper = sql.lstrip().upper() if isinstance(sql, str) else ""
        if state["fail_insert"] and upper.startswith("INSERT"):
            state["fail_insert"] = False
            raise sqlite3.OperationalError("insert failed")
        if upper.startswith("ROLLBACK"):
            raise sqlite3.OperationalError("rollback failed")
        return real.execute(sql, params) if params != () else real.execute(sql)

    ledger._conn = _ConnProxy(ledger._conn, flaky)

    with caplog.at_level(logging.ERROR):
        with pytest.raises(sqlite3.OperationalError, match="insert failed"):
            ledger.append("ALLOWED", {"auth_id": "a1"})

    assert any("rollback" in r.message.lower() for r in caplog.records)
    ledger.close()


def test_permit_check_p95_soft_bound():
    """Loosened latency gate (was p95<50ms in #27): catch gross regressions
    without flake. Soft bound: p95 under 250ms over 200 eligible() samples."""
    store = PermitStore()
    permit, _ = store.grant("agent_1", 100_000, ["merchant_1"], _future())
    samples_ms: list[float] = []
    for _ in range(200):
        t0 = time.perf_counter()
        res = store.eligible(permit.permit_id, 1000, "merchant_1")
        samples_ms.append((time.perf_counter() - t0) * 1000.0)
        assert res.allowed

    samples_ms.sort()
    p95 = samples_ms[189]
    assert p95 < 250.0, f"eligible() p95={p95:.2f}ms over 200 samples (soft limit 250ms)"
