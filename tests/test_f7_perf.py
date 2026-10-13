"""REA F7 timing / isolation benchmarks — run only in the `perf-f7` CI job.

Excluded from the required `test` aggregate so duration/flakiness report
separately from the functional suite.

Bars mirrored here: 200 samples, a real 100k-receipt log, individual-receipt
path timing, hostile concurrent load on the 100k log, escrow B's first N
denials get receipts, isolation, 2x threshold. Also the shipping
SqliteLedger path (indexed chain COUNT + side-row MAC) at 100k / 200 / 2x.
"""

from __future__ import annotations

import hashlib
import statistics
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone

from permit.ledger import Ledger
from permit.permit import PermitStore
from permit.sqlite_ledger import SqliteLedger
from settlement.paypal_client import MockPayPalClient
from settlement.verifier import (
    DEFAULT_RETRY_RATE_LIMIT_N,
    Escrow,
    Evidence,
    PredicateType,
    ReleaseVerifier,
)


SAMPLES = 200
THRESHOLD_X = 2.0


def _setup(ledger=None):
    if ledger is None:
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


def _second_escrow(verifier, paypal, permits, escrow_a, escrow_id: str = "esc_2"):
    check = permits.check(escrow_a.permit_id, 1000, "merchant_1")
    assert check.allowed
    auth2 = check.receipt.payload["auth_id"]
    pp_auth2 = paypal.authorize(1000, "merchant_1")
    escrow_b = Escrow(
        escrow_id=escrow_id,
        permit_id=escrow_a.permit_id,
        auth_id=auth2,
        paypal_auth_id=pp_auth2.auth_id,
        amount_cents=1000,
        merchant_id="merchant_1",
        predicate_type=PredicateType.D,
        artifact_hash=escrow_a.artifact_hash,
    )
    verifier.register(escrow_b)
    return escrow_b


def _pad_to_receipt_count(ledger, target: int) -> None:
    """Grow the hash chain to exactly `target` receipts (real log length)."""
    while len(ledger) < target:
        i = len(ledger)
        ledger.append(
            "BLOCKED",
            {"escrow_id": f"pad_{i}", "reason": "benchmark_pad", "i": i},
        )


def test_perf_f7_over_limit_median_100k_vs_100():
    """Bar 3: over-limit median with a real 100k-receipt log ≤ 2x @100."""
    n = DEFAULT_RETRY_RATE_LIMIT_N

    def _median_over_limit_ns(target_len: int) -> float:
        verifier, paypal, permits, escrow, artifact = _setup()
        verifier.verify_and_capture("esc_1", Evidence(delivered_bytes=b"tampered"))
        _pad_to_receipt_count(verifier.ledger, target_len)
        assert len(verifier.ledger) == target_len
        evidence = Evidence(delivered_bytes=artifact)
        for _ in range(n):
            r = verifier.verify_and_capture("esc_1", evidence)
            assert r.reason == "already_refused"
        warm = verifier.verify_and_capture("esc_1", evidence)
        assert warm.reason == "rate_limited"
        samples = []
        for _ in range(SAMPLES):
            t0 = time.perf_counter_ns()
            result = verifier.verify_and_capture("esc_1", evidence)
            t1 = time.perf_counter_ns()
            assert result.reason == "rate_limited"
            samples.append(t1 - t0)
        assert len(samples) == SAMPLES
        return statistics.median(samples)

    median_100 = _median_over_limit_ns(100)
    median_100k = _median_over_limit_ns(100_000)
    assert median_100 > 0
    assert median_100k <= THRESHOLD_X * median_100, (
        f"over-limit median@100k={median_100k} ns exceeds "
        f"{THRESHOLD_X}x @100={median_100} ns"
    )


def test_perf_f7_individual_receipt_path_100k_vs_100():
    """Individual-denial receipt path median @100k ≤ 2x @100 (200 samples)."""
    n = DEFAULT_RETRY_RATE_LIMIT_N

    def _median_individual_ns(target_len: int) -> float:
        # Fresh escrow each sample-batch so we stay inside the individual budget.
        # Measure the first min(SAMPLES, n) already_refused appends.
        samples = []
        while len(samples) < SAMPLES:
            verifier, paypal, permits, escrow, artifact = _setup()
            verifier.verify_and_capture(
                "esc_1", Evidence(delivered_bytes=b"tampered")
            )
            _pad_to_receipt_count(verifier.ledger, target_len)
            evidence = Evidence(delivered_bytes=artifact)
            budget = min(n, SAMPLES - len(samples))
            for _ in range(budget):
                t0 = time.perf_counter_ns()
                r = verifier.verify_and_capture("esc_1", evidence)
                t1 = time.perf_counter_ns()
                assert r.reason == "already_refused"
                samples.append(t1 - t0)
        assert len(samples) == SAMPLES
        return statistics.median(samples)

    median_100 = _median_individual_ns(100)
    median_100k = _median_individual_ns(100_000)
    assert median_100 > 0
    assert median_100k <= THRESHOLD_X * median_100, (
        f"individual median@100k={median_100k} ns exceeds "
        f"{THRESHOLD_X}x @100={median_100} ns"
    )


def test_perf_f7_hostile_on_100k_log():
    """Hostile A flood against a real 100k-receipt log; B median ≤ 2x, first N receipts."""
    n = DEFAULT_RETRY_RATE_LIMIT_N

    # Quiet over-limit baseline for B (no flood, short log).
    v0, paypal0, permits0, escrow_a0, artifact0 = _setup()
    _second_escrow(v0, paypal0, permits0, escrow_a0)
    v0.verify_and_capture("esc_1", Evidence(delivered_bytes=b"tampered"))
    v0.verify_and_capture("esc_2", Evidence(delivered_bytes=b"tampered"))
    evidence0 = Evidence(delivered_bytes=artifact0)
    for _ in range(n):
        assert v0.verify_and_capture("esc_2", evidence0).reason == "already_refused"
    assert v0.verify_and_capture("esc_2", evidence0).reason == "rate_limited"
    baseline_samples = []
    for _ in range(SAMPLES):
        t0 = time.perf_counter_ns()
        r = v0.verify_and_capture("esc_2", evidence0)
        t1 = time.perf_counter_ns()
        assert r.reason == "rate_limited"
        baseline_samples.append(t1 - t0)
    baseline_b = statistics.median(baseline_samples)

    # Hostile phase on a real 100k log.
    verifier, paypal, permits, escrow_a, artifact = _setup()
    escrow_b = _second_escrow(verifier, paypal, permits, escrow_a)
    verifier.verify_and_capture("esc_1", Evidence(delivered_bytes=b"tampered"))
    verifier.verify_and_capture("esc_2", Evidence(delivered_bytes=b"tampered"))
    _pad_to_receipt_count(verifier.ledger, 100_000)
    assert len(verifier.ledger) == 100_000
    evidence = Evidence(delivered_bytes=artifact)
    for _ in range(n):
        assert verifier.verify_and_capture("esc_1", evidence).reason == "already_refused"
    assert verifier.verify_and_capture("esc_1", evidence).reason == "rate_limited"

    errors: list[BaseException] = []
    b_over_limit_samples: list[float] = []
    b_reasons: list[str] = []
    b_before = len(verifier.ledger)
    stop = threading.Event()

    def flood_a_hostile():
        try:
            # Hostile but cooperative: yield so the 2x isolation bar measures
            # lock/store contention, not pure GIL starvation from a spin loop.
            while not stop.is_set():
                r = verifier.verify_and_capture("esc_1", evidence)
                assert not r.released
                assert r.reason == "rate_limited"
                time.sleep(0)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    def poke_b():
        try:
            for _ in range(n):
                r = verifier.verify_and_capture("esc_2", evidence)
                assert not r.released
                assert r.reason == "already_refused"
                b_reasons.append(r.reason)
            for _ in range(SAMPLES):
                t0 = time.perf_counter_ns()
                r = verifier.verify_and_capture("esc_2", evidence)
                t1 = time.perf_counter_ns()
                assert not r.released
                assert r.reason == "rate_limited"
                b_over_limit_samples.append(t1 - t0)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)
        finally:
            stop.set()

    t_a = threading.Thread(target=flood_a_hostile)
    t_b = threading.Thread(target=poke_b)
    t_a.start()
    t_b.start()
    t_b.join()
    stop.set()
    t_a.join()
    assert errors == []

    assert b_reasons == ["already_refused"] * n
    b_denials = [
        r
        for r in verifier.ledger.receipts()[b_before:]
        if r.event_type == "REFUSED"
        and r.payload.get("escrow_id") == "esc_2"
        and r.payload.get("reason") == "already_refused"
    ]
    assert len(b_denials) == n

    median_during = statistics.median(b_over_limit_samples)
    assert median_during <= THRESHOLD_X * baseline_b, (
        f"B median during flood on 100k log={median_during} exceeds "
        f"{THRESHOLD_X}x baseline={baseline_b}"
    )
    assert escrow_b.state == "REFUSED"
    assert escrow_a.state == "REFUSED"


def test_perf_f7_hostile_flood_isolation_and_b_receipts():
    """Hostile A flood: B's first N retries get receipts; B median ≤ 2x baseline."""
    n = DEFAULT_RETRY_RATE_LIMIT_N

    v0, paypal0, permits0, escrow_a0, artifact0 = _setup()
    _second_escrow(v0, paypal0, permits0, escrow_a0)
    v0.verify_and_capture("esc_1", Evidence(delivered_bytes=b"tampered"))
    v0.verify_and_capture("esc_2", Evidence(delivered_bytes=b"tampered"))
    evidence0 = Evidence(delivered_bytes=artifact0)
    for _ in range(n):
        assert v0.verify_and_capture("esc_2", evidence0).reason == "already_refused"
    assert v0.verify_and_capture("esc_2", evidence0).reason == "rate_limited"
    baseline_samples = []
    for _ in range(SAMPLES):
        t0 = time.perf_counter_ns()
        r = v0.verify_and_capture("esc_2", evidence0)
        t1 = time.perf_counter_ns()
        assert r.reason == "rate_limited"
        baseline_samples.append(t1 - t0)
    baseline_b = statistics.median(baseline_samples)

    verifier, paypal, permits, escrow_a, artifact = _setup()
    escrow_b = _second_escrow(verifier, paypal, permits, escrow_a)
    verifier.verify_and_capture("esc_1", Evidence(delivered_bytes=b"tampered"))
    verifier.verify_and_capture("esc_2", Evidence(delivered_bytes=b"tampered"))
    evidence = Evidence(delivered_bytes=artifact)
    for _ in range(n):
        assert verifier.verify_and_capture("esc_1", evidence).reason == "already_refused"
    assert verifier.verify_and_capture("esc_1", evidence).reason == "rate_limited"

    errors: list[BaseException] = []
    b_over_limit_samples: list[float] = []
    b_reasons: list[str] = []
    b_before = len(verifier.ledger)
    stop = threading.Event()

    def flood_a_hostile():
        try:
            while not stop.is_set():
                r = verifier.verify_and_capture("esc_1", evidence)
                assert not r.released
                assert r.reason == "rate_limited"
                time.sleep(0)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    def poke_b():
        try:
            for _ in range(n):
                r = verifier.verify_and_capture("esc_2", evidence)
                assert not r.released
                assert r.reason == "already_refused"
                b_reasons.append(r.reason)
            for _ in range(SAMPLES):
                t0 = time.perf_counter_ns()
                r = verifier.verify_and_capture("esc_2", evidence)
                t1 = time.perf_counter_ns()
                assert not r.released
                assert r.reason == "rate_limited"
                b_over_limit_samples.append(t1 - t0)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)
        finally:
            stop.set()

    t_a = threading.Thread(target=flood_a_hostile)
    t_b = threading.Thread(target=poke_b)
    t_a.start()
    t_b.start()
    t_b.join()
    stop.set()
    t_a.join()
    assert errors == []

    assert b_reasons == ["already_refused"] * n
    b_denials = [
        r
        for r in verifier.ledger.receipts()[b_before:]
        if r.event_type == "REFUSED"
        and r.payload.get("escrow_id") == "esc_2"
        and r.payload.get("reason") == "already_refused"
    ]
    assert len(b_denials) == n

    median_during = statistics.median(b_over_limit_samples)
    assert median_during <= THRESHOLD_X * baseline_b, (
        f"B median during flood={median_during} exceeds "
        f"{THRESHOLD_X}x baseline={baseline_b}"
    )
    assert escrow_b.state == "REFUSED"
    assert escrow_a.state == "REFUSED"


def test_perf_f7_sqlite_over_limit_median_100k_vs_100():
    """Shipping SqliteLedger path: over-limit median @100k ≤ 2x @100 (200 samples)."""
    n = DEFAULT_RETRY_RATE_LIMIT_N

    def _median_over_limit_ns(target_len: int) -> float:
        with tempfile.TemporaryDirectory() as td:
            ledger = SqliteLedger(td + "/ledger.sqlite")
            try:
                verifier, paypal, permits, escrow, artifact = _setup(ledger)
                verifier.verify_and_capture(
                    "esc_1", Evidence(delivered_bytes=b"tampered")
                )
                _pad_to_receipt_count(verifier.ledger, target_len)
                assert len(verifier.ledger) == target_len
                evidence = Evidence(delivered_bytes=artifact)
                for _ in range(n):
                    r = verifier.verify_and_capture("esc_1", evidence)
                    assert r.reason == "already_refused"
                warm = verifier.verify_and_capture("esc_1", evidence)
                assert warm.reason == "rate_limited"
                samples = []
                for _ in range(SAMPLES):
                    t0 = time.perf_counter_ns()
                    result = verifier.verify_and_capture("esc_1", evidence)
                    t1 = time.perf_counter_ns()
                    assert result.reason == "rate_limited"
                    samples.append(t1 - t0)
                assert len(samples) == SAMPLES
                return statistics.median(samples)
            finally:
                ledger.close()

    median_100 = _median_over_limit_ns(100)
    median_100k = _median_over_limit_ns(100_000)
    assert median_100 > 0
    assert median_100k <= THRESHOLD_X * median_100, (
        f"SqliteLedger over-limit median@100k={median_100k} ns exceeds "
        f"{THRESHOLD_X}x @100={median_100} ns"
    )


def test_perf_f7_sqlite_individual_receipt_path_100k_vs_100():
    """Shipping SqliteLedger path: individual-denial median @100k ≤ 2x @100."""
    n = DEFAULT_RETRY_RATE_LIMIT_N

    def _median_individual_ns(target_len: int) -> float:
        samples = []
        while len(samples) < SAMPLES:
            with tempfile.TemporaryDirectory() as td:
                ledger = SqliteLedger(td + "/ledger.sqlite")
                try:
                    verifier, paypal, permits, escrow, artifact = _setup(ledger)
                    verifier.verify_and_capture(
                        "esc_1", Evidence(delivered_bytes=b"tampered")
                    )
                    _pad_to_receipt_count(verifier.ledger, target_len)
                    evidence = Evidence(delivered_bytes=artifact)
                    budget = min(n, SAMPLES - len(samples))
                    for _ in range(budget):
                        t0 = time.perf_counter_ns()
                        r = verifier.verify_and_capture("esc_1", evidence)
                        t1 = time.perf_counter_ns()
                        assert r.reason == "already_refused"
                        samples.append(t1 - t0)
                finally:
                    ledger.close()
        assert len(samples) == SAMPLES
        return statistics.median(samples)

    median_100 = _median_individual_ns(100)
    median_100k = _median_individual_ns(100_000)
    assert median_100 > 0
    assert median_100k <= THRESHOLD_X * median_100, (
        f"SqliteLedger individual median@100k={median_100k} ns exceeds "
        f"{THRESHOLD_X}x @100={median_100} ns"
    )


def test_perf_f7_sqlite_hostile_on_100k_log():
    """Bar 4: hostile A flood on SqliteLedger 100k log; B median ≤ 2x, first N receipts."""
    n = DEFAULT_RETRY_RATE_LIMIT_N

    with tempfile.TemporaryDirectory() as td0:
        ledger0 = SqliteLedger(td0 + "/base.sqlite")
        try:
            v0, paypal0, permits0, escrow_a0, artifact0 = _setup(ledger0)
            _second_escrow(v0, paypal0, permits0, escrow_a0)
            v0.verify_and_capture("esc_1", Evidence(delivered_bytes=b"tampered"))
            v0.verify_and_capture("esc_2", Evidence(delivered_bytes=b"tampered"))
            evidence0 = Evidence(delivered_bytes=artifact0)
            for _ in range(n):
                assert (
                    v0.verify_and_capture("esc_2", evidence0).reason
                    == "already_refused"
                )
            assert v0.verify_and_capture("esc_2", evidence0).reason == "rate_limited"
            baseline_samples = []
            for _ in range(SAMPLES):
                t0 = time.perf_counter_ns()
                r = v0.verify_and_capture("esc_2", evidence0)
                t1 = time.perf_counter_ns()
                assert r.reason == "rate_limited"
                baseline_samples.append(t1 - t0)
            baseline_b = statistics.median(baseline_samples)
        finally:
            ledger0.close()

    with tempfile.TemporaryDirectory() as td:
        ledger = SqliteLedger(td + "/ledger.sqlite")
        try:
            verifier, paypal, permits, escrow_a, artifact = _setup(ledger)
            escrow_b = _second_escrow(verifier, paypal, permits, escrow_a)
            verifier.verify_and_capture(
                "esc_1", Evidence(delivered_bytes=b"tampered")
            )
            verifier.verify_and_capture(
                "esc_2", Evidence(delivered_bytes=b"tampered")
            )
            _pad_to_receipt_count(verifier.ledger, 100_000)
            assert len(verifier.ledger) == 100_000
            evidence = Evidence(delivered_bytes=artifact)
            for _ in range(n):
                assert (
                    verifier.verify_and_capture("esc_1", evidence).reason
                    == "already_refused"
                )
            assert (
                verifier.verify_and_capture("esc_1", evidence).reason
                == "rate_limited"
            )

            errors: list[BaseException] = []
            b_over_limit_samples: list[float] = []
            b_reasons: list[str] = []
            b_before = len(verifier.ledger)
            stop = threading.Event()

            def flood_a_hostile():
                try:
                    while not stop.is_set():
                        r = verifier.verify_and_capture("esc_1", evidence)
                        assert not r.released
                        assert r.reason == "rate_limited"
                        time.sleep(0)
                except BaseException as exc:  # noqa: BLE001
                    errors.append(exc)

            def poke_b():
                try:
                    for _ in range(n):
                        r = verifier.verify_and_capture("esc_2", evidence)
                        assert not r.released
                        assert r.reason == "already_refused"
                        b_reasons.append(r.reason)
                    for _ in range(SAMPLES):
                        t0 = time.perf_counter_ns()
                        r = verifier.verify_and_capture("esc_2", evidence)
                        t1 = time.perf_counter_ns()
                        assert not r.released
                        assert r.reason == "rate_limited"
                        b_over_limit_samples.append(t1 - t0)
                except BaseException as exc:  # noqa: BLE001
                    errors.append(exc)
                finally:
                    stop.set()

            t_a = threading.Thread(target=flood_a_hostile)
            t_b = threading.Thread(target=poke_b)
            t_a.start()
            t_b.start()
            t_b.join()
            stop.set()
            t_a.join()
            assert errors == []

            assert b_reasons == ["already_refused"] * n
            b_denials = [
                r
                for r in verifier.ledger.receipts()[b_before:]
                if r.event_type == "REFUSED"
                and r.payload.get("escrow_id") == "esc_2"
                and r.payload.get("reason") == "already_refused"
            ]
            assert len(b_denials) == n

            median_during = statistics.median(b_over_limit_samples)
            assert median_during <= THRESHOLD_X * baseline_b, (
                f"SqliteLedger B median during flood on 100k log="
                f"{median_during} exceeds {THRESHOLD_X}x baseline={baseline_b}"
            )
            assert escrow_b.state == "REFUSED"
            assert escrow_a.state == "REFUSED"
        finally:
            ledger.close()
