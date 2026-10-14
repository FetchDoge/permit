"""Fail-closed hardening: ledger-write denial, cleanup that must not
swallow exceptions, and a permit-check latency regression gate.

No feature changes — these tests pin defence-in-depth behaviour.
"""

from __future__ import annotations

import logging
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
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


# ---------------------------------------------------------------------------
# 1) Ledger write failure → spend denied, nothing released, error surfaces
# ---------------------------------------------------------------------------


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

    # Fail closed: no phantom reservation, no PayPal authorize, no escrow.
    assert permit.reserved_cents == before_reserved
    assert permit.in_flight == {}
    assert len(paypal.authorizations) == 0
    assert len(paypal.capture_calls) == 0
    assert flow.verifier._escrows == {}
    # No ALLOWED (or any new) receipt committed.
    assert len(ledger) == before_len


def test_check_rolls_back_reservation_when_allowed_append_raises():
    """In-memory twin: if ALLOWED append raises after the in-memory
    reserve, check() must undo the reserve and re-raise (fail closed)."""
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


# ---------------------------------------------------------------------------
# 2) Cleanup paths that previously swallowed void failures
# ---------------------------------------------------------------------------


def test_post_authorize_void_failure_retains_reservation_and_surfaces(caplog):
    """revoked_during_auth cleanup: if paypal.void raises, do not settle_void;
    log and re-raise so the hold stays encumbered (fail closed)."""
    flow, paypal, permits, permit = _permit_layer()

    def hostile_authorize(amount_cents, merchant_id, *args, **kwargs):
        paypal.authorize_calls.append((amount_cents, merchant_id, kwargs))
        # Revoke via the store only so flow._void_permit_holds is not yet
        # involved; the post-authorize recheck must void the PayPal hold.
        permits.estop(permit.permit_id)
        return SimpleNamespace(
            auth_id="tiny_auth_estop",
            amount_cents=amount_cents,
            merchant_id=merchant_id,
            status="AUTHORIZED",
        )

    def void_boom(auth_id):
        paypal.void_calls.append(auth_id)
        raise RuntimeError("provider void failed")

    paypal.authorize = hostile_authorize
    paypal.void = void_boom

    with caplog.at_level(logging.ERROR):
        with pytest.raises(RuntimeError, match="provider void failed"):
            flow.spend(permit.permit_id, 3000, "merchant_1", "delivery_hash", "hash")

    # Reservation retained — money not released on a failed void.
    assert permit.reserved_cents == 3000
    assert any("void failed" in r.message.lower() for r in caplog.records)


def test_register_escrow_void_failure_retains_reservation_and_surfaces(caplog):
    """register_escrow fail-closed path: void failure must not settle_void."""
    flow, paypal, permits, permit = _permit_layer()
    check = permits.check(permit.permit_id, 3000, "merchant_1")
    auth_id = check.receipt.payload["auth_id"]
    pp_auth = paypal.authorize(3000, "merchant_1")
    permits.estop(permit.permit_id)  # revoke; reservation still held

    def void_boom(auth_id):
        raise RuntimeError("void during register failed")

    paypal.void = void_boom

    with caplog.at_level(logging.ERROR):
        with pytest.raises(RuntimeError, match="void during register failed"):
            flow.register_escrow(
                permit_id=permit.permit_id,
                auth_id=auth_id,
                paypal_auth_id=pp_auth.auth_id,
                amount_cents=3000,
                merchant_id="merchant_1",
                predicate_type="delivery_hash",
                artifact_hash="hash",
            )

    assert permit.reserved_cents == 3000
    assert flow.verifier.escrows == {}
    assert any("void failed" in r.message.lower() for r in caplog.records)


def test_void_permit_holds_void_failure_retains_reservation_and_surfaces(caplog):
    """Outstanding-hold cleanup in estop: void failure must not settle_void."""
    flow, paypal, permits, permit = _permit_layer()
    check = permits.check(permit.permit_id, 3000, "merchant_1")
    auth_id = check.receipt.payload["auth_id"]
    flow._track_outstanding(auth_id, permit.permit_id)
    flow._set_outstanding_paypal_auth(auth_id, "tiny_auth_thread")

    def void_boom(auth_id):
        raise RuntimeError("void outstanding failed")

    paypal.void = void_boom

    with caplog.at_level(logging.ERROR):
        with pytest.raises(RuntimeError, match="void outstanding failed"):
            flow.estop(permit.permit_id)

    assert permit.reserved_cents == 3000
    assert auth_id in flow._outstanding
    assert any("void failed" in r.message.lower() for r in caplog.records)


def test_sweep_expired_pending_void_failure_is_logged_not_swallowed(
    caplog, monkeypatch
):
    """server.sweep_expired_pending: void failure must be logged (no bare
    except/pass). Payer-approval ops have no auth hold yet, so the local
    reservation is still released on TTL — fail closed against leaks."""
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
    the original write error (cleanup must not swallow the failure)."""
    db_path = str(tmp_path / "ledger.db")
    ledger = SqliteLedger(db_path)
    ledger.append("GRANTED", {"permit_id": "p1"})

    state = {"fail_insert": True}

    def flaky(real, sql, params=()):
        text = sql if isinstance(sql, str) else ""
        upper = text.lstrip().upper()
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


# ---------------------------------------------------------------------------
# 3) Permit check latency: p95 under 50 ms
# ---------------------------------------------------------------------------


def test_permit_check_p95_under_50ms():
    """A single eligible() authority check stays under 50 ms at p95 over a
    reasonable sample (N=200). Guards against accidental O(n^2) regressions
    in the hot check path."""
    store = PermitStore()
    permit, _ = store.grant("agent_1", 100_000, ["merchant_1"], _future())
    samples_ms: list[float] = []
    for _ in range(200):
        t0 = time.perf_counter()
        res = store.eligible(permit.permit_id, 1000, "merchant_1")
        samples_ms.append((time.perf_counter() - t0) * 1000.0)
        assert res.allowed

    samples_ms.sort()
    # Nearest-rank p95 for N=200 → index 189 (0-based).
    p95 = samples_ms[189]
    assert p95 < 50.0, f"eligible() p95={p95:.2f}ms over 200 samples (limit 50ms)"
