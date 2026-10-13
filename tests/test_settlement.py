"""Settlement tests: N1, N2, replay, idempotency, chain-break, void, happy path."""

import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from permit.ledger import Ledger
from permit.permit import PermitStore
from settlement.paypal_client import MockPayPalClient
from settlement.verifier import (
    Escrow,
    Evidence,
    PredicateType,
    ReleaseVerifier,
    sign_acceptance,
)


def _setup(predicate=PredicateType.D, amount_cents=3000):
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
    check = permits.check(permit.permit_id, amount_cents, "merchant_1")
    assert check.allowed
    auth_id = check.receipt.payload["auth_id"]
    pp_auth = paypal.authorize(amount_cents, "merchant_1")
    artifact = b"delivered work product"
    artifact_hash = hashlib.sha256(artifact).hexdigest()
    escrow = Escrow(
        escrow_id="esc_1",
        permit_id=permit.permit_id,
        auth_id=auth_id,
        paypal_auth_id=pp_auth.auth_id,
        amount_cents=amount_cents,
        merchant_id="merchant_1",
        predicate_type=predicate,
        artifact_hash=artifact_hash,
    )
    verifier.register(escrow)
    return verifier, paypal, permits, escrow, artifact


def test_happy_path_type_d():
    verifier, paypal, permits, escrow, artifact = _setup(PredicateType.D)
    result = verifier.verify_and_capture("esc_1", Evidence(delivered_bytes=artifact))
    assert result.released
    assert result.capture is not None
    assert result.capture.status == "COMPLETED"
    assert len(paypal.capture_calls) == 1
    # Permit accounting: reserved moved to captured.
    permit = permits.get(escrow.permit_id)
    assert permit.captured_cents == 3000
    assert permit.reserved_cents == 0


def test_happy_path_type_a():
    verifier, paypal, permits, escrow, artifact = _setup(PredicateType.A)
    sig = sign_acceptance("esc_1", escrow.artifact_hash, 3000)
    result = verifier.verify_and_capture("esc_1", Evidence(acceptance_signature=sig))
    assert result.released
    assert len(paypal.capture_calls) == 1


def test_n1_hash_mismatch_no_capture():
    """N1: mismatched artifact hash → no capture → REFUSED receipt."""
    verifier, paypal, permits, escrow, artifact = _setup(PredicateType.D)
    result = verifier.verify_and_capture(
        "esc_1", Evidence(delivered_bytes=b"tampered work product")
    )
    assert not result.released
    assert result.reason == "predicate:hash_mismatch"
    assert result.capture is None
    assert paypal.capture_calls == [], "capture must NEVER be called on N1"
    # REFUSED receipt exists.
    refused = [r for r in verifier.ledger.receipts() if r.event_type == "REFUSED"]
    assert len(refused) == 1
    # The refused release must not leave money encumbered: the PayPal hold
    # is voided and the permit reservation released together.
    assert escrow.paypal_auth_id in paypal.voids
    voided = [r for r in verifier.ledger.receipts() if r.event_type == "VOIDED"]
    assert len(voided) == 1
    permit = permits.get(escrow.permit_id)
    assert permit.reserved_cents == 0
    assert permit.captured_cents == 0
    assert permit.remaining_cents() == 5000


def test_n2_worker_signature_without_acceptance_no_capture():
    """N2: worker signature without valid acceptance → no capture → REFUSED."""
    verifier, paypal, permits, escrow, artifact = _setup(PredicateType.A)
    # A worker-signed value that is NOT the acceptance key's signature.
    fake_sig = hashlib.sha256(b"worker says trust me").hexdigest()
    result = verifier.verify_and_capture(
        "esc_1", Evidence(acceptance_signature=fake_sig)
    )
    assert not result.released
    assert result.reason == "predicate:invalid_acceptance_signature"
    assert paypal.capture_calls == [], "capture must NEVER be called on N2"
    refused = [r for r in verifier.ledger.receipts() if r.event_type == "REFUSED"]
    assert len(refused) == 1


def test_replay_signature_on_other_escrow_fails():
    """Acceptance signature is bound to escrow id; replay fails."""
    verifier, paypal, permits, escrow, artifact = _setup(PredicateType.A)
    sig_for_esc1 = sign_acceptance("esc_1", escrow.artifact_hash, 3000)
    # Attacker replays esc_1's signature against a different escrow id.
    escrow.escrow_id = "esc_2"
    result = verifier.verify_and_capture(
        "esc_2", Evidence(acceptance_signature=sig_for_esc1)
    )
    assert not result.released
    assert paypal.capture_calls == []


def test_idempotent_capture_single_charge():
    verifier, paypal, permits, escrow, artifact = _setup(PredicateType.D)
    r1 = verifier.verify_and_capture("esc_1", Evidence(delivered_bytes=artifact))
    r2 = verifier.verify_and_capture("esc_1", Evidence(delivered_bytes=artifact))
    assert r1.released and r2.released
    assert r2.reason == "already_captured"
    # Only one capture call reached PayPal (second was short-circuited).
    assert len(paypal.capture_calls) == 1


def test_broken_chain_refuses_capture():
    verifier, paypal, permits, escrow, artifact = _setup(PredicateType.D)
    receipts = verifier.ledger.receipts()
    tampered = receipts[1]
    object.__setattr__(tampered, "payload", {**tampered.payload, "amount_cents": 1})
    verifier.ledger._receipts[1] = tampered
    result = verifier.verify_and_capture("esc_1", Evidence(delivered_bytes=artifact))
    assert not result.released
    assert result.reason == "broken_chain"
    assert paypal.capture_calls == []


def test_void_releases_permit_reservation():
    verifier, paypal, permits, escrow, artifact = _setup(PredicateType.D)
    assert verifier.void("esc_1")
    assert paypal.capture_calls == []
    assert escrow.paypal_auth_id in paypal.voids
    permit = permits.get(escrow.permit_id)
    assert permit.remaining_cents() == 5000
    # Capture after void is refused.
    result = verifier.verify_and_capture("esc_1", Evidence(delivered_bytes=artifact))
    assert not result.released


def _retry_denials(ledger):
    return [
        r
        for r in ledger.receipts()
        if r.event_type == "REFUSED"
        and isinstance(r.payload.get("reason"), str)
        and r.payload["reason"].startswith("already_")
    ]


def _original_refusal_hash(ledger, escrow_id: str) -> str | None:
    """First original REFUSED hash for escrow, else escrow-level VOIDED hash."""
    refused = voided = None
    for r in ledger.receipts():
        if r.payload.get("escrow_id") != escrow_id:
            continue
        if r.event_type == "REFUSED":
            reason = r.payload.get("reason", "")
            if isinstance(reason, str) and reason.startswith("already_"):
                continue
            if refused is None:
                refused = r.hash
        elif r.event_type == "VOIDED" and voided is None:
            voided = r.hash
    return refused or voided


def test_retry_on_refused_or_voided_writes_denial_receipt():
    """REA F6: every refused retry on an already REFUSED/VOIDED escrow must
    append a denial receipt with a unique receipt_id referencing the original
    refusal; capture must never run; hash chain stays valid."""
    for terminal, expected_reason, first_release in (
        (
            "REFUSED",
            "already_refused",
            lambda v, art: v.verify_and_capture(
                "esc_1", Evidence(delivered_bytes=b"tampered")
            ),
        ),
        (
            "VOIDED",
            "already_voided",
            lambda v, art: (v.void("esc_1"), None)[1],
        ),
    ):
        verifier, paypal, permits, escrow, artifact = _setup(PredicateType.D)
        first_release(verifier, artifact)
        assert escrow.state == terminal
        original_id = _original_refusal_hash(verifier.ledger, "esc_1")
        assert original_id is not None
        captures_before = len(paypal.capture_calls)

        result = verifier.verify_and_capture(
            "esc_1", Evidence(delivered_bytes=artifact)
        )

        assert not result.released
        assert result.reason == expected_reason
        assert result.capture is None
        assert len(paypal.capture_calls) == captures_before
        denials = _retry_denials(verifier.ledger)
        assert len(denials) == 1
        denial = denials[0]
        assert denial.payload["escrow_id"] == "esc_1"
        assert denial.payload["reason"] == expected_reason
        assert denial.payload["receipt_id"].startswith("den_")
        assert denial.payload["original_refusal_id"] == original_id
        assert denial.payload["original_refusal_id"] != denial.payload["receipt_id"]
        ok, reason = verifier.ledger.verify_chain()
        assert ok, reason
        assert escrow.state == terminal


def test_retry_denial_receipts_serial_and_parallel():
    """REA F6 concurrency: 25 serial + 25 parallel refused retries each write a
    unique denial receipt referencing the original refusal; none capture."""
    import threading

    verifier, paypal, permits, escrow, artifact = _setup(PredicateType.D)
    first = verifier.verify_and_capture(
        "esc_1", Evidence(delivered_bytes=b"tampered")
    )
    assert not first.released
    assert escrow.state == "REFUSED"
    original_id = _original_refusal_hash(verifier.ledger, "esc_1")
    assert original_id is not None
    captures_before = len(paypal.capture_calls)

    for _ in range(25):
        result = verifier.verify_and_capture(
            "esc_1", Evidence(delivered_bytes=artifact)
        )
        assert not result.released
        assert result.reason == "already_refused"
        assert result.capture is None

    barrier = threading.Barrier(25)
    errors: list[BaseException] = []

    def worker():
        try:
            barrier.wait(timeout=5)
            result = verifier.verify_and_capture(
                "esc_1", Evidence(delivered_bytes=artifact)
            )
            assert not result.released
            assert result.reason == "already_refused"
            assert result.capture is None
        except BaseException as exc:  # noqa: BLE001 — collect for join
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(25)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []

    denials = _retry_denials(verifier.ledger)
    assert len(denials) == 50
    receipt_ids = [d.payload["receipt_id"] for d in denials]
    assert len(set(receipt_ids)) == 50
    assert all(rid.startswith("den_") for rid in receipt_ids)
    assert all(d.payload["original_refusal_id"] == original_id for d in denials)
    assert len(paypal.capture_calls) == captures_before == 0
    ok, reason = verifier.ledger.verify_chain()
    assert ok, reason
    assert escrow.state == "REFUSED"


def _rate_limited_receipts(ledger):
    return [
        r
        for r in ledger.receipts()
        if r.event_type == "REFUSED" and r.payload.get("reason") == "rate_limited"
    ]


def _refuse_escrow(verifier, artifact=b"tampered"):
    result = verifier.verify_and_capture(
        "esc_1", Evidence(delivered_bytes=artifact)
    )
    assert not result.released
    return result


def test_retry_rate_limit_flood_serial():
    """REA F7: 10_000 serial retries on one refused escrow grow the log by at
    most N individual denials + one aggregated rate-limited receipt; count
    equals covered retries; nothing captured; chain valid."""
    import settlement.verifier as vmod

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    verifier, paypal, permits, escrow, artifact = _setup(PredicateType.D)
    _refuse_escrow(verifier)
    assert escrow.state == "REFUSED"
    captures_before = len(paypal.capture_calls)
    before = len(verifier.ledger)

    reasons = []
    for _ in range(10_000):
        result = verifier.verify_and_capture(
            "esc_1", Evidence(delivered_bytes=artifact)
        )
        assert not result.released
        assert result.capture is None
        reasons.append(result.reason)

    assert reasons[:n] == ["already_refused"] * n
    assert all(r == "rate_limited" for r in reasons[n:])
    growth = len(verifier.ledger) - before
    assert growth <= n + 1, f"log grew by {growth}, want <= {n + 1}"
    assert growth == n + 1
    assert len(_retry_denials(verifier.ledger)) == n
    rl = _rate_limited_receipts(verifier.ledger)
    assert len(rl) == 1
    assert rl[0].payload["count"] == 10_000 - n
    assert rl[0].payload["count"] == reasons.count("rate_limited")
    assert len(paypal.capture_calls) == captures_before == 0
    assert escrow.state == "REFUSED"
    ok, reason = verifier.ledger.verify_chain()
    assert ok, reason


def test_retry_rate_limit_flood_concurrent():
    """REA F7: 10_000 retries across 8 threads — same N+1 bound and exact count."""
    import threading

    import settlement.verifier as vmod

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    verifier, paypal, permits, escrow, artifact = _setup(PredicateType.D)
    _refuse_escrow(verifier)
    captures_before = len(paypal.capture_calls)
    before = len(verifier.ledger)

    n_threads = 8
    per_thread = 10_000 // n_threads
    barrier = threading.Barrier(n_threads)
    reasons: list[str] = []
    lock = threading.Lock()
    errors: list[BaseException] = []

    def worker():
        try:
            barrier.wait(timeout=10)
            local = []
            for _ in range(per_thread):
                result = verifier.verify_and_capture(
                    "esc_1", Evidence(delivered_bytes=artifact)
                )
                assert not result.released
                assert result.capture is None
                local.append(result.reason)
            with lock:
                reasons.extend(local)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert len(reasons) == 10_000
    assert reasons.count("already_refused") == n
    assert reasons.count("rate_limited") == 10_000 - n
    growth = len(verifier.ledger) - before
    assert growth <= n + 1
    assert growth == n + 1
    rl = _rate_limited_receipts(verifier.ledger)
    assert len(rl) == 1
    assert rl[0].payload["count"] == 10_000 - n
    assert len(paypal.capture_calls) == captures_before == 0
    assert escrow.state == "REFUSED"
    ok, reason = verifier.ledger.verify_chain()
    assert ok, reason


def test_retry_rate_limit_isolation_between_escrows():
    """REA F7: flooding escrow A does not rate-limit or slow escrow B."""
    import threading
    import time

    import settlement.verifier as vmod

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    verifier, paypal, permits, escrow_a, artifact = _setup(PredicateType.D)
    # Second escrow on the same permit.
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
    assert escrow_a.state == "REFUSED" and escrow_b.state == "REFUSED"

    before = len(verifier.ledger)
    # Flood A while B takes a handful of retries.
    b_reasons: list[str] = []
    errors: list[BaseException] = []

    def flood_a():
        try:
            for _ in range(10_000):
                r = verifier.verify_and_capture(
                    "esc_1", Evidence(delivered_bytes=artifact)
                )
                assert not r.released
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    def poke_b():
        try:
            time.sleep(0.01)
            for _ in range(5):
                r = verifier.verify_and_capture(
                    "esc_2", Evidence(delivered_bytes=artifact)
                )
                assert not r.released
                b_reasons.append(r.reason)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    t_a = threading.Thread(target=flood_a)
    t_b = threading.Thread(target=poke_b)
    t_a.start()
    t_b.start()
    t_a.join()
    t_b.join()
    assert errors == []
    assert b_reasons == ["already_refused"] * 5
    growth = len(verifier.ledger) - before
    # A's N+1 plus B's 5 individual denials.
    assert growth == (n + 1) + 5
    rl_a = [
        r
        for r in _rate_limited_receipts(verifier.ledger)
        if r.payload.get("escrow_id") == "esc_1"
    ]
    rl_b = [
        r
        for r in _rate_limited_receipts(verifier.ledger)
        if r.payload.get("escrow_id") == "esc_2"
    ]
    assert len(rl_a) == 1 and rl_a[0].payload["count"] == 10_000 - n
    assert rl_b == []
    ok, reason = verifier.ledger.verify_chain()
    assert ok, reason


def test_retry_refusal_index_benchmark():
    """REA F7: with an escrow-id refusal index, median retry with 100k receipts
    is at most 2x the median with 100 receipts (no full-log scan)."""
    import statistics
    import time

    def _median_retry_ns(pad: int) -> float:
        verifier, paypal, permits, escrow, artifact = _setup(PredicateType.D)
        _refuse_escrow(verifier)
        # Pad the ledger with unrelated receipts after the original refusal so
        # a scan-based lookup would pay O(pad) per retry.
        for i in range(pad):
            verifier.ledger.append(
                "BLOCKED",
                {"escrow_id": f"pad_{i}", "reason": "benchmark_pad"},
            )
        samples = []
        evidence = Evidence(delivered_bytes=artifact)
        # Warm once, then measure.
        verifier.verify_and_capture("esc_1", evidence)
        for _ in range(40):
            t0 = time.perf_counter_ns()
            result = verifier.verify_and_capture("esc_1", evidence)
            t1 = time.perf_counter_ns()
            assert not result.released
            assert result.reason in ("already_refused", "rate_limited")
            samples.append(t1 - t0)
        return statistics.median(samples)

    median_100 = _median_retry_ns(100)
    median_100k = _median_retry_ns(100_000)
    assert median_100 > 0
    assert median_100k <= 2.0 * median_100, (
        f"median@100k={median_100k} ns exceeds 2x median@100={median_100} ns"
    )


def test_only_verifier_calls_capture():
    import ast

    import settlement.verifier as v
    import settlement.paypal_client as pc

    tree = ast.parse(open(v.__file__).read())
    calls = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "capture"
    ]
    assert len(calls) == 1, "exactly one capture call site must exist (the verifier)"


# ---------------------------------------------------------------------------
# P1 settlement regression tests (outside-witness findings, 2026-10-02)
# ---------------------------------------------------------------------------


def test_p1_4_predicate_fail_void_timeout_cleanup_pending_then_retry():
    """P1-4: a void timeout on the predicate-fail path must NOT release the
    reservation silently. The escrow goes CLEANUP_PENDING with the
    reservation still held; retry_cleanup() finishes the job once the
    provider is reachable again."""
    verifier, paypal, permits, escrow, artifact = _setup(PredicateType.D)
    paypal.inject_void_timeout = True
    result = verifier.verify_and_capture(
        "esc_1", Evidence(delivered_bytes=b"tampered work product")
    )
    assert not result.released
    assert result.reason == "predicate:hash_mismatch"
    assert paypal.capture_calls == [], "capture must NEVER be called on N1"
    assert escrow.state == "CLEANUP_PENDING"
    # The hold may still be live: the reservation is NOT released yet.
    assert escrow.paypal_auth_id not in paypal.voids
    permit = permits.get(escrow.permit_id)
    assert permit.reserved_cents == 3000, "obligation retained while void unconfirmed"
    assert permit.captured_cents == 0
    # Provider recovers: retry_cleanup finishes the void + releases.
    paypal.inject_void_timeout = False
    assert verifier.retry_cleanup("esc_1") is True
    assert escrow.state == "VOIDED"
    assert escrow.paypal_auth_id in paypal.voids
    permit = permits.get(escrow.permit_id)
    assert permit.reserved_cents == 0, "reservation released after cleanup"
    assert permit.captured_cents == 0
    voided = [r for r in verifier.ledger.receipts() if r.event_type == "VOIDED"]
    assert len(voided) == 1


def test_p1_4b_broken_chain_attempts_void():
    """P1-4b: a broken ledger chain refuses capture but must not leave the
    money encumbered — the verifier attempts the void. Void succeeds →
    VOIDED + reservation released, capture never called."""
    verifier, paypal, permits, escrow, artifact = _setup(PredicateType.D)
    receipts = verifier.ledger.receipts()
    tampered = receipts[1]
    object.__setattr__(tampered, "payload", {**tampered.payload, "amount_cents": 1})
    verifier.ledger._receipts[1] = tampered
    result = verifier.verify_and_capture("esc_1", Evidence(delivered_bytes=artifact))
    assert not result.released
    assert result.reason == "broken_chain"
    assert paypal.capture_calls == []
    # The void WAS attempted (the P1-4b fix).
    assert escrow.paypal_auth_id in paypal.voids
    assert escrow.state == "VOIDED"
    permit = permits.get(escrow.permit_id)
    assert permit.reserved_cents == 0, "reservation released on broken-chain void"
    assert permit.captured_cents == 0
    voided = [r for r in verifier.ledger.receipts() if r.event_type == "VOIDED"]
    assert len(voided) == 1


def test_p1_4b_broken_chain_void_timeout_cleanup_pending():
    """P1-4b companion: if the broken-chain void also times out, the escrow
    goes CLEANUP_PENDING instead of pretending the hold is gone."""
    verifier, paypal, permits, escrow, artifact = _setup(PredicateType.D)
    receipts = verifier.ledger.receipts()
    tampered = receipts[1]
    object.__setattr__(tampered, "payload", {**tampered.payload, "amount_cents": 1})
    verifier.ledger._receipts[1] = tampered
    paypal.inject_void_timeout = True
    result = verifier.verify_and_capture("esc_1", Evidence(delivered_bytes=artifact))
    assert not result.released
    assert result.reason == "broken_chain"
    assert escrow.state == "CLEANUP_PENDING"
    permit = permits.get(escrow.permit_id)
    assert permit.reserved_cents == 3000
    pending = [
        r for r in verifier.ledger.receipts() if r.event_type == "CLEANUP_PENDING"
    ]
    assert len(pending) == 1


def test_p1_5_capture_pending_stays_unknown_obligation_retained():
    """P1-5: a PENDING capture is not a completed capture. The escrow goes
    UNKNOWN (never CAPTURED), the obligation is retained (reservation
    still held), and reconcile() is the only way forward."""
    verifier, paypal, permits, escrow, artifact = _setup(PredicateType.D)
    paypal.capture_status = "PENDING"
    result = verifier.verify_and_capture("esc_1", Evidence(delivered_bytes=artifact))
    assert not result.released
    assert result.reason == "capture_pending"
    assert escrow.state == "UNKNOWN"
    assert escrow.state != "CAPTURED"
    permit = permits.get(escrow.permit_id)
    assert permit.captured_cents == 0, "no captured accounting on PENDING"
    assert permit.reserved_cents == 3000, "obligation retained while pending"
    unknown = [r for r in verifier.ledger.receipts() if r.event_type == "UNKNOWN"]
    assert len(unknown) == 1
    assert unknown[0].payload["reason"] == "capture_pending"
    # The UNKNOWN escrow refuses further capture attempts outright.
    r2 = verifier.verify_and_capture("esc_1", Evidence(delivered_bytes=artifact))
    assert r2.reason == "unknown_reconcile_first"


def test_slow_capture_does_not_stall_other_escrow_ops():
    """Lock rework: a slow provider capture must not block void() on a
    different escrow, nor register(). Proves the verifier lock is
    released during provider I/O."""
    import threading
    import time

    from settlement.paypal_client import PayPalTimeout

    verifier, paypal, permits, escrow1, artifact = _setup(PredicateType.D)
    # Second escrow on the same permit.
    check = permits.check(escrow1.permit_id, 1000, "merchant_1")
    assert check.allowed
    auth2 = check.receipt.payload["auth_id"]
    pp_auth2 = paypal.authorize(1000, "merchant_1")
    escrow2 = Escrow(
        escrow_id="esc_2",
        permit_id=escrow1.permit_id,
        auth_id=auth2,
        paypal_auth_id=pp_auth2.auth_id,
        amount_cents=1000,
        merchant_id="merchant_1",
        predicate_type=PredicateType.D,
        artifact_hash=escrow1.artifact_hash,
    )
    verifier.register(escrow2)

    # Make capture slow.
    orig_capture = paypal.capture
    def slow_capture(*a, **k):
        time.sleep(2.0)
        return orig_capture(*a, **k)
    paypal.capture = slow_capture

    results = {}
    def do_capture():
        results["cap"] = verifier.verify_and_capture(
            "esc_1", Evidence(delivered_bytes=artifact)
        )
    t = threading.Thread(target=do_capture)
    start = time.monotonic()
    t.start()
    # Wait until esc_1 is in CAPTURING (lock released, I/O in flight).
    for _ in range(100):
        if escrow1.state == "CAPTURING":
            break
        time.sleep(0.02)
    assert escrow1.state == "CAPTURING"
    # void() on the OTHER escrow must not wait for the slow capture.
    assert verifier.void("esc_2") is True
    void_elapsed = time.monotonic() - start
    assert void_elapsed < 1.0, f"void stalled on slow capture: {void_elapsed:.2f}s"
    assert escrow2.state == "VOIDED"
    t.join()
    assert results["cap"].released
    assert escrow1.state == "CAPTURED"


def test_concurrent_capture_same_escrow_single_flight():
    """Two racing verify_and_capture calls: one drives, the other
    short-circuits with release_in_flight (no double capture)."""
    import threading
    import time

    verifier, paypal, permits, escrow, artifact = _setup(PredicateType.D)
    orig_capture = paypal.capture
    def slow_capture(*a, **k):
        time.sleep(1.0)
        return orig_capture(*a, **k)
    paypal.capture = slow_capture

    results = []
    def do_capture():
        results.append(
            verifier.verify_and_capture("esc_1", Evidence(delivered_bytes=artifact))
        )
    t1 = threading.Thread(target=do_capture)
    t2 = threading.Thread(target=do_capture)
    t1.start()
    # Ensure t1 is in CAPTURING before t2 starts.
    for _ in range(100):
        if escrow.state == "CAPTURING":
            break
        time.sleep(0.02)
    t2.start()
    t1.join()
    t2.join()
    assert len(paypal.capture_calls) == 1, "double capture!"
    reasons = sorted(r.reason for r in results)
    assert reasons == ["release_in_flight", "released"], reasons
