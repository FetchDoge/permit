"""REA F7 timing / isolation benchmarks — run only in the `perf-f7` CI job.

Excluded from the required `test` aggregate so duration/flakiness report
separately from the functional suite.
"""

from __future__ import annotations

import hashlib
import statistics
import threading
import time
from datetime import datetime, timedelta, timezone

from permit.ledger import Ledger
from permit.permit import PermitStore
from settlement.paypal_client import MockPayPalClient
from settlement.verifier import (
    DEFAULT_RETRY_RATE_LIMIT_N,
    Escrow,
    Evidence,
    PredicateType,
    ReleaseVerifier,
)


def _setup():
    ledger = Ledger()
    permits = PermitStore(ledger=ledger)
    paypal = MockPayPalClient()
    verifier = ReleaseVerifier(paypal, permits, ledger=ledger)
    permit, _ = permits.grant(
        agent_id="agent_1",
        cap_cents=5000,
        allowlist=["merchant_1"],
        expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    check = permits.check(permit.permit_id, 3000, "merchant_1")
    auth_id = check.receipt.payload["auth_id"]
    pp_auth = paypal.authorize(3000, "merchant_1")
    artifact = b"delivered work product"
    escrow = Escrow(
        escrow_id="esc_1",
        permit_id=permit.permit_id,
        auth_id=auth_id,
        paypal_auth_id=pp_auth.auth_id,
        amount_cents=3000,
        merchant_id="merchant_1",
        predicate_type=PredicateType.D,
        artifact_hash=hashlib.sha256(artifact).hexdigest(),
    )
    verifier.register(escrow)
    return verifier, paypal, permits, escrow, artifact


def test_perf_f7_over_limit_median_100k_vs_100():
    """Over-limit retry median with 100k receipts is at most 2x with 100."""
    n = DEFAULT_RETRY_RATE_LIMIT_N

    def _median_over_limit_ns(pad: int) -> float:
        verifier, paypal, permits, escrow, artifact = _setup()
        verifier.verify_and_capture("esc_1", Evidence(delivered_bytes=b"tampered"))
        for i in range(pad):
            verifier.ledger.append(
                "BLOCKED",
                {"escrow_id": f"pad_{i}", "reason": "benchmark_pad"},
            )
        evidence = Evidence(delivered_bytes=artifact)
        for _ in range(n):
            r = verifier.verify_and_capture("esc_1", evidence)
            assert r.reason == "already_refused"
        warm = verifier.verify_and_capture("esc_1", evidence)
        assert warm.reason == "rate_limited"
        samples = []
        for _ in range(40):
            t0 = time.perf_counter_ns()
            result = verifier.verify_and_capture("esc_1", evidence)
            t1 = time.perf_counter_ns()
            assert result.reason == "rate_limited"
            samples.append(t1 - t0)
        return statistics.median(samples)

    median_100 = _median_over_limit_ns(100)
    median_100k = _median_over_limit_ns(100_000)
    assert median_100 > 0
    assert median_100k <= 2.0 * median_100, (
        f"over-limit median@100k={median_100k} ns exceeds 2x @100={median_100} ns"
    )


def test_perf_f7_isolation_b_median_during_a_flood():
    """Flooding escrow A leaves escrow B's median within 2x of baseline."""
    verifier, paypal, permits, escrow_a, artifact = _setup()
    check = permits.check(escrow_a.permit_id, 1000, "merchant_1")
    assert check.allowed
    auth2 = check.receipt.payload["auth_id"]
    pp_auth2 = paypal.authorize(1000, "merchant_1")
    escrow_b = Escrow(
        escrow_id="esc_2",
        permit_id=escrow_a.permit_id,
        auth_id=auth2,
        paypal_auth_id=pp_auth2.auth_id,
        amount_cents=1000,
        merchant_id="merchant_1",
        predicate_type=PredicateType.D,
        artifact_hash=escrow_a.artifact_hash,
    )
    verifier.register(escrow_b)
    verifier.verify_and_capture("esc_1", Evidence(delivered_bytes=b"tampered"))
    verifier.verify_and_capture("esc_2", Evidence(delivered_bytes=b"tampered"))
    evidence = Evidence(delivered_bytes=artifact)

    def _median_b(samples: int = 30) -> float:
        times = []
        for _ in range(samples):
            t0 = time.perf_counter_ns()
            r = verifier.verify_and_capture("esc_2", evidence)
            t1 = time.perf_counter_ns()
            assert not r.released
            assert r.reason == "already_refused"
            times.append(t1 - t0)
        return statistics.median(times)

    baseline_b = _median_b()
    errors: list[BaseException] = []
    b_during: list[float] = []

    def flood_a():
        try:
            for _ in range(10_000):
                r = verifier.verify_and_capture("esc_1", evidence)
                assert not r.released
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    def poke_b():
        try:
            for _ in range(40):
                t0 = time.perf_counter_ns()
                r = verifier.verify_and_capture("esc_2", evidence)
                t1 = time.perf_counter_ns()
                assert not r.released
                assert r.reason == "already_refused"
                b_during.append(t1 - t0)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    t_a = threading.Thread(target=flood_a)
    t_b = threading.Thread(target=poke_b)
    t_a.start()
    t_b.start()
    t_a.join()
    t_b.join()
    assert errors == []
    median_during = statistics.median(b_during)
    assert median_during <= 2.0 * baseline_b, (
        f"B median during flood={median_during} exceeds 2x baseline={baseline_b}"
    )
