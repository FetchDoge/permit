"""Settlement tests: N1, N2, replay, idempotency, chain-break, void, happy path."""

import hashlib
import os
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
    RetryRateIntegrityError,
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
    sig = verifier.sign_acceptance("esc_1", escrow.artifact_hash, 3000)
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
    sig_for_esc1 = verifier.sign_acceptance("esc_1", escrow.artifact_hash, 3000)
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
    """Review F6: every refused retry on an already REFUSED/VOIDED escrow must
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
    """Review F6 concurrency: 25 serial + 25 parallel refused retries each write a
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


def _rate_limited_receipts(ledger, escrow_id: str | None = None):
    out = [
        r
        for r in ledger.receipts()
        if r.event_type == "REFUSED" and r.payload.get("reason") == "rate_limited"
    ]
    if escrow_id is not None:
        out = [r for r in out if r.payload.get("escrow_id") == escrow_id]
    return out


def _tally_count_sum(ledger, escrow_id: str) -> int:
    return sum(int(r.payload["count"]) for r in _rate_limited_receipts(ledger, escrow_id))


def _refuse_escrow(verifier, escrow_id: str = "esc_1", artifact=b"tampered"):
    result = verifier.verify_and_capture(
        escrow_id, Evidence(delivered_bytes=artifact)
    )
    assert not result.released
    return result


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


def test_retry_rate_limit_flood_serial():
    """REA F7: 10_000 serial retries — log grows by at most N+1; exact tally
    count; nothing captured; chain valid; prior hashes stable."""
    import settlement.verifier as vmod

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    verifier, paypal, permits, escrow, artifact = _setup(PredicateType.D)
    _refuse_escrow(verifier)
    assert escrow.state == "REFUSED"
    captures_before = len(paypal.capture_calls)
    hashes_before = [r.hash for r in verifier.ledger.receipts()]
    before = len(verifier.ledger)

    reasons = []
    for _ in range(10_000):
        result = verifier.verify_and_capture(
            "esc_1", Evidence(delivered_bytes=artifact)
        )
        assert not result.released
        assert result.capture is None
        reasons.append(result.reason)

    # Mid-window: only N individual denials on the log (counts in side store).
    assert len(verifier.ledger) - before == n
    verifier.flush_retry_rate_limits("esc_1")  # one combined tally
    over = 10_000 - n
    assert reasons[:n] == ["already_refused"] * n
    assert all(r == "rate_limited" for r in reasons[n:])
    growth = len(verifier.ledger) - before
    assert growth == n + 1
    assert len(_retry_denials(verifier.ledger)) == n
    rl = _rate_limited_receipts(verifier.ledger, "esc_1")
    assert len(rl) == 1
    assert rl[0].payload["count"] == over
    assert len(paypal.capture_calls) == captures_before == 0
    assert escrow.state == "REFUSED"
    after_hashes = [r.hash for r in verifier.ledger.receipts()]
    assert after_hashes[: len(hashes_before)] == hashes_before
    ok, reason = verifier.ledger.verify_chain()
    assert ok, reason


def test_retry_rate_limit_flood_concurrent():
    """REA F7: 10_000 retries across 8 threads — N+1 growth, exact count."""
    import threading

    import settlement.verifier as vmod

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    verifier, paypal, permits, escrow, artifact = _setup(PredicateType.D)
    _refuse_escrow(verifier)
    captures_before = len(paypal.capture_calls)
    hashes_before = [r.hash for r in verifier.ledger.receipts()]
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
    assert len(verifier.ledger) - before == n
    verifier.flush_retry_rate_limits("esc_1")
    over = 10_000 - n
    assert len(reasons) == 10_000
    assert reasons.count("already_refused") == n
    assert reasons.count("rate_limited") == over
    assert len(verifier.ledger) - before == n + 1
    assert _tally_count_sum(verifier.ledger, "esc_1") == over
    assert len(paypal.capture_calls) == captures_before == 0
    assert escrow.state == "REFUSED"
    after_hashes = [r.hash for r in verifier.ledger.receipts()]
    assert after_hashes[: len(hashes_before)] == hashes_before
    ok, reason = verifier.ledger.verify_chain()
    assert ok, reason


def test_retry_rate_limit_isolation_between_escrows():
    """REA F7: flooding A does not rate-limit B (functional isolation)."""
    import threading

    import settlement.verifier as vmod

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    verifier, paypal, permits, escrow_a, artifact = _setup(PredicateType.D)
    escrow_b = _second_escrow(verifier, paypal, permits, escrow_a)

    verifier.verify_and_capture("esc_1", Evidence(delivered_bytes=b"tampered"))
    verifier.verify_and_capture("esc_2", Evidence(delivered_bytes=b"tampered"))
    assert escrow_a.state == "REFUSED" and escrow_b.state == "REFUSED"

    evidence = Evidence(delivered_bytes=artifact)
    before = len(verifier.ledger)
    errors: list[BaseException] = []
    b_reasons: list[str] = []

    def flood_a():
        try:
            for _ in range(10_000):
                r = verifier.verify_and_capture("esc_1", evidence)
                assert not r.released
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    def poke_b():
        try:
            for _ in range(5):
                r = verifier.verify_and_capture("esc_2", evidence)
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
    verifier.flush_retry_rate_limits("esc_1")
    over = 10_000 - n
    growth = len(verifier.ledger) - before
    assert growth == (n + 1) + 5
    assert _tally_count_sum(verifier.ledger, "esc_1") == over
    assert _rate_limited_receipts(verifier.ledger, "esc_2") == []
    ok, reason = verifier.ledger.verify_chain()
    assert ok, reason


def test_retry_rate_limit_receipt_hashes_stable_across_flood():
    """REA F7: flooding never rewrites earlier receipt hashes."""
    verifier, paypal, permits, escrow, artifact = _setup(PredicateType.D)
    _refuse_escrow(verifier)
    for _ in range(5):
        verifier.verify_and_capture("esc_1", Evidence(delivered_bytes=artifact))
    prefix = [(r.seq, r.hash, r.prev_hash) for r in verifier.ledger.receipts()]
    for _ in range(500):
        verifier.verify_and_capture("esc_1", Evidence(delivered_bytes=artifact))
    verifier.flush_retry_rate_limits("esc_1")
    after = verifier.ledger.receipts()
    for seq, h, prev in prefix:
        assert after[seq].hash == h
        assert after[seq].prev_hash == prev
    ok, reason = verifier.ledger.verify_chain()
    assert ok, reason


def test_retry_rate_limit_crash_mid_window_sqlite():
    """REA F7: crash mid-window keeps over-limit count in Sqlite side table."""
    import tempfile

    import settlement.verifier as vmod
    from permit.sqlite_ledger import SqliteLedger

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        ledger = SqliteLedger(path)
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
        _refuse_escrow(verifier)
        evidence = Evidence(delivered_bytes=artifact)
        for _ in range(n):
            assert (
                verifier.verify_and_capture("esc_1", evidence).reason
                == "already_refused"
            )
        over = 250
        for _ in range(over):
            assert (
                verifier.verify_and_capture("esc_1", evidence).reason
                == "rate_limited"
            )
        # No tally on the hash chain yet (side table holds the count).
        assert _rate_limited_receipts(ledger, "esc_1") == []
        side = ledger.retry_rate_store.load_all()
        assert len(side) == 1
        assert side[0].rate_limited == over
        assert side[0].individual == n
        # Simulate crash.
        del verifier
        ledger2 = SqliteLedger(path)
        permits2 = PermitStore(ledger=ledger2)
        paypal2 = MockPayPalClient()
        clock = [side[0].window_start + 1.0]  # still inside W

        def now():
            return clock[0]

        verifier2 = ReleaseVerifier(paypal2, permits2, ledger=ledger2, clock=now)
        # Counters restored; still no loss.
        state = verifier2._retry_rate_windows.get("esc_1")
        assert state is not None
        assert state.rate_limited == over
        assert state.individual == n
        assert verifier2._original_refusal_id("esc_1") == _original_refusal_hash(
            ledger2, "esc_1"
        )
        verifier2.flush_retry_rate_limits("esc_1")
        assert _tally_count_sum(ledger2, "esc_1") == over
        assert len(_rate_limited_receipts(ledger2, "esc_1")) == 1


def test_retry_rate_limit_restart_keeps_counter_and_f6_link():
    """REA F7: restart rebuilds rate-limit counters and original_refusal_id."""
    import settlement.verifier as vmod

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    clock = [1_000_000.0]

    def now():
        return clock[0]

    verifier, paypal, permits, escrow, artifact = _setup(PredicateType.D)
    verifier = ReleaseVerifier(
        paypal, permits, ledger=verifier.ledger, clock=now
    )
    with verifier._lock:
        verifier._escrows[escrow.escrow_id] = escrow
    _refuse_escrow(verifier)
    original = verifier._original_refusal_id("esc_1")
    assert original is not None
    evidence = Evidence(delivered_bytes=artifact)
    for _ in range(n):
        assert verifier.verify_and_capture("esc_1", evidence).reason == "already_refused"
    for _ in range(37):
        assert verifier.verify_and_capture("esc_1", evidence).reason == "rate_limited"
    assert _rate_limited_receipts(verifier.ledger, "esc_1") == []
    ledger = verifier.ledger
    rate_store = verifier._rate_store

    # Restart: same ledger + same in-memory side store (simulates durable table).
    verifier2 = ReleaseVerifier(
        paypal,
        permits,
        ledger=ledger,
        clock=now,
        retry_rate_store=rate_store,
    )
    with verifier2._lock:
        verifier2._escrows[escrow.escrow_id] = escrow
    assert verifier2._original_refusal_id("esc_1") == original
    state = verifier2._retry_rate_windows.get("esc_1")
    assert state is not None
    assert state.individual == n
    assert state.rate_limited == 37
    r = verifier2.verify_and_capture("esc_1", evidence)
    assert r.reason == "rate_limited"
    open_row = verifier2._rate_store.get_open("esc_1")
    assert open_row is not None
    assert open_row.rate_limited == 38
    verifier2.flush_retry_rate_limits("esc_1")
    last = _rate_limited_receipts(ledger, "esc_1")[-1]
    assert last.payload["count"] == 38
    assert last.payload["original_refusal_id"] == original


def test_retry_rate_limit_crash_between_tally_append_and_done_mark():
    """Crash after tally append but before side-table done-mark: no duplicate."""
    import tempfile

    import settlement.verifier as vmod
    from permit.retry_rate_store import RetryRateRow
    from permit.sqlite_ledger import SqliteLedger

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    over = 50
    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        ledger = SqliteLedger(path)
        permits = PermitStore(ledger=ledger)
        paypal = MockPayPalClient()
        clock = [1_000_000.0]

        def now():
            return clock[0]

        verifier = ReleaseVerifier(paypal, permits, ledger=ledger, clock=now)
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
        _refuse_escrow(verifier)
        evidence = Evidence(delivered_bytes=artifact)
        before = len(ledger)
        for _ in range(n + over):
            verifier.verify_and_capture("esc_1", evidence)
        verifier.flush_retry_rate_limits("esc_1")
        assert len(_rate_limited_receipts(ledger, "esc_1")) == 1
        assert _tally_count_sum(ledger, "esc_1") == over
        assert len(ledger) - before == n + 1

        # Simulate crash after append, before done-mark: tally on chain,
        # side row still tally_flushed=0 (same count).
        side = ledger.retry_rate_store.load_all()[0]
        assert side.tally_flushed is True
        ledger.retry_rate_store.upsert(
            RetryRateRow(
                escrow_id=side.escrow_id,
                window_id=side.window_id,
                window_start=side.window_start,
                individual=side.individual,
                rate_limited=side.rate_limited,
                covered_reason=side.covered_reason,
                tally_flushed=False,
                rate_mac=side.rate_mac,
                prev_rate_mac=side.prev_rate_mac,
            )
        )
        del verifier
        ledger.close()

        ledger2 = SqliteLedger(path)
        permits2 = PermitStore(ledger=ledger2)
        paypal2 = MockPayPalClient()
        verifier2 = ReleaseVerifier(paypal2, permits2, ledger=ledger2, clock=now)
        # Rebuild must not append a second tally.
        assert len(_rate_limited_receipts(ledger2, "esc_1")) == 1
        assert _tally_count_sum(ledger2, "esc_1") == over
        assert len(ledger2) - before == n + 1
        side2 = [
            r
            for r in ledger2.retry_rate_store.load_all()
            if r.escrow_id == "esc_1"
        ][0]
        assert side2.tally_flushed is True
        assert side2.rate_limited == over
        ok, reason = ledger2.verify_chain()
        assert ok, reason
        ledger2.close()


def test_retry_rate_limit_two_writers_one_sqlite_file():
    """Two writers on one Sqlite file: exactly one tally, exact count, N+1."""
    import tempfile
    import threading

    import settlement.verifier as vmod
    from permit.sqlite_ledger import SqliteLedger

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    over = 50
    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        ledger = SqliteLedger(path)
        permits = PermitStore(ledger=ledger)
        paypal = MockPayPalClient()
        clock = [1_000_000.0]

        def now():
            return clock[0]

        verifier = ReleaseVerifier(paypal, permits, ledger=ledger, clock=now)
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
        _refuse_escrow(verifier)
        evidence = Evidence(delivered_bytes=artifact)
        before = len(ledger)
        for _ in range(n + over):
            assert verifier.verify_and_capture("esc_1", evidence).reason in (
                "already_refused",
                "rate_limited",
            )
        # Expire the window so rebuild materializes the tally.
        clock[0] += getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_W", 60.0) + 1.0
        side = ledger.retry_rate_store.load_all()[0]
        window_id = side.window_id
        assert side.tally_flushed is False
        assert side.rate_limited == over
        ledger.close()

        errors: list[BaseException] = []
        barrier = threading.Barrier(2)

        def writer():
            try:
                led = SqliteLedger(path)
                per = PermitStore(ledger=led)
                pp = MockPayPalClient()
                barrier.wait(timeout=10)
                # Both rebuild concurrently; expired unflushed window → tally.
                ReleaseVerifier(pp, per, ledger=led, clock=now)
                led.close()
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        t1 = threading.Thread(target=writer)
        t2 = threading.Thread(target=writer)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        assert errors == []

        final = SqliteLedger(path)
        rl = _rate_limited_receipts(final, "esc_1")
        assert len(rl) == 1
        assert rl[0].payload["window_id"] == window_id
        assert rl[0].payload["count"] == over
        assert _tally_count_sum(final, "esc_1") == over
        # N individual denials + 1 tally (+ prior grant/check/auth/refuse).
        assert len(final) - before == n + 1
        ok, reason = final.verify_chain()
        assert ok, reason
        final.close()


def test_retry_rate_limit_side_table_tamper_count_edited():
    """Edited side-table count vs chain tally → refuse to start."""
    import tempfile

    import settlement.verifier as vmod
    from permit.retry_rate_store import RetryRateRow
    from permit.sqlite_ledger import SqliteLedger

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        ledger = SqliteLedger(path)
        permits = PermitStore(ledger=ledger)
        paypal = MockPayPalClient()
        clock = [1_000_000.0]

        def now():
            return clock[0]

        verifier = ReleaseVerifier(paypal, permits, ledger=ledger, clock=now)
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
        _refuse_escrow(verifier)
        evidence = Evidence(delivered_bytes=artifact)
        for _ in range(n + 20):
            verifier.verify_and_capture("esc_1", evidence)
        verifier.flush_retry_rate_limits("esc_1")
        side = ledger.retry_rate_store.load_all()[0]
        tampered = side.rate_limited + 99
        from permit.retry_rate_store import HighWaterRecord, _atomic_write_hw_record, _hw_entry_path, _hw_lock_path
        import fcntl as _fcntl

        ledger.retry_rate_store.upsert(
            RetryRateRow(
                escrow_id=side.escrow_id,
                window_id=side.window_id,
                window_start=side.window_start,
                individual=side.individual,
                rate_limited=tampered,  # tamper
                covered_reason=side.covered_reason,
                tally_flushed=True,
            )
        )
        # Keep sidecar in sync so reopen reaches the chain tally mismatch check.
        hw_path = _hw_entry_path(side.escrow_id, side.window_id)
        lock_fd = os.open(_hw_lock_path(hw_path), os.O_RDWR)
        try:
            _fcntl.flock(lock_fd, _fcntl.LOCK_EX)
            _atomic_write_hw_record(
                hw_path,
                HighWaterRecord(
                    escrow_id=side.escrow_id,
                    window_id=side.window_id,
                    confirmed=tampered,
                    intent=None,
                ),
            )
        finally:
            _fcntl.flock(lock_fd, _fcntl.LOCK_UN)
            os.close(lock_fd)
        ledger.close()
        ledger2 = SqliteLedger(path)
        permits2 = PermitStore(ledger=ledger2)
        paypal2 = MockPayPalClient()
        with pytest.raises(RetryRateIntegrityError, match="count mismatch"):
            ReleaseVerifier(paypal2, permits2, ledger=ledger2, clock=now)
        ledger2.close()


def test_retry_rate_limit_side_table_tamper_done_flag_without_tally():
    """tally_flushed=1 with rate_limited>0 and no chain tally → refuse to start."""
    import tempfile

    from permit.retry_rate_store import (
        RetryRateRow,
        clear_high_water_creating_intent,
        create_high_water,
    )
    from permit.sqlite_ledger import SqliteLedger

    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        ledger = SqliteLedger(path)
        permits = PermitStore(ledger=ledger)
        paypal = MockPayPalClient()
        clock = [1_000_000.0]

        def now():
            return clock[0]

        verifier = ReleaseVerifier(paypal, permits, ledger=ledger, clock=now)
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
        _refuse_escrow(verifier)
        # Tamper: claim flushed with rate_limited>0 without ever writing a tally.
        create_high_water("esc_1", "rw_orphan", initial=7)
        clear_high_water_creating_intent("esc_1", "rw_orphan")
        ledger.retry_rate_store.upsert(
            RetryRateRow(
                escrow_id="esc_1",
                window_id="rw_orphan",
                window_start=clock[0],
                individual=0,
                rate_limited=7,
                covered_reason="already_refused",
                tally_flushed=True,
            )
        )
        ledger.close()
        ledger2 = SqliteLedger(path)
        permits2 = PermitStore(ledger=ledger2)
        paypal2 = MockPayPalClient()
        with pytest.raises(RetryRateIntegrityError, match="tally_flushed=1|no tally"):
            ReleaseVerifier(paypal2, permits2, ledger=ledger2, clock=now)
        ledger2.close()


def test_flushed_window_individual_only_restart_ok():
    """Close a window with only individual denials (rate_limited=0); restart OK."""
    import tempfile

    import settlement.verifier as vmod
    from permit.sqlite_ledger import SqliteLedger

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    w = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_W", 60)
    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        clock = [1_000_000.0]
        verifier, ledger, evidence = _sqlite_refused_setup(
            path, clock, n_denials=min(3, n), over=0
        )
        side = ledger.retry_rate_store.get_open("esc_1")
        assert side is not None
        assert side.rate_limited == 0
        assert side.individual >= 1
        # Expire the window so flush closes it with no rate_limited tally.
        clock[0] = side.window_start + w + 1
        verifier.flush_retry_rate_limits("esc_1")
        side2 = ledger.retry_rate_store.get_open("esc_1")
        assert side2 is None
        flushed = [
            r
            for r in ledger.retry_rate_store.load_all()
            if r.window_id == side.window_id
        ]
        assert len(flushed) == 1
        assert flushed[0].tally_flushed is True
        assert flushed[0].rate_limited == 0
        assert len(_rate_limited_receipts(ledger, "esc_1")) == 0
        ledger.close()

        # Restart must not refuse: no tally is required when rate_limited==0.
        ledger2 = SqliteLedger(path)
        permits2 = PermitStore(ledger=ledger2)
        paypal2 = MockPayPalClient()
        ReleaseVerifier(
            paypal2, permits2, ledger=ledger2, clock=lambda: clock[0]
        )
        ledger2.check_retry_rate_integrity(limit_n=n)
        ledger2.close()


def test_flushed_window_rate_limited_tally_deleted_refuses():
    """rate_limited>0 flushed window with tally deleted → refuse on restart."""
    import tempfile

    import settlement.verifier as vmod
    from permit.sqlite_ledger import SqliteLedger

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        clock = [1_000_000.0]
        verifier, ledger, evidence = _sqlite_refused_setup(
            path, clock, n_denials=n, over=5
        )
        side = ledger.retry_rate_store.get_open("esc_1")
        assert side is not None and side.rate_limited == 5
        verifier.flush_retry_rate_limits("esc_1")
        tallies = _rate_limited_receipts(ledger, "esc_1")
        assert len(tallies) == 1
        # Attacker with DB write: drop append-only, delete the tally tip, restore.
        tally_seq = tallies[0].seq
        tip = ledger._conn.execute("SELECT MAX(seq) FROM receipts").fetchone()[0]
        assert tally_seq == tip, "tally must be chain tip to delete without rehash"
        ledger._conn.execute("DROP TRIGGER IF EXISTS receipts_no_delete")
        ledger._conn.execute("DELETE FROM receipts WHERE seq = ?", (tally_seq,))
        side_rows = [
            r for r in ledger.retry_rate_store.load_all() if r.tally_flushed
        ]
        assert side_rows and side_rows[0].rate_limited > 0
        ledger.close()

        ledger2 = SqliteLedger(path)
        permits2 = PermitStore(ledger=ledger2)
        paypal2 = MockPayPalClient()
        with pytest.raises(
            RetryRateIntegrityError,
            match="no tally|tally_flushed=1|marked flushed",
        ):
            ReleaseVerifier(
                paypal2, permits2, ledger=ledger2, clock=lambda: clock[0]
            )
        ledger2.close()


def test_flushed_window_tally_deleted_rate_limited_lowered_without_key_refuses():
    """Delete tally + edit rate_limited→0 without key; HMAC counter still >0 → refuse."""
    import tempfile

    import settlement.verifier as vmod
    from permit.retry_rate_store import get_high_water
    from permit.sqlite_ledger import SqliteLedger

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        clock = [1_000_000.0]
        verifier, ledger, _ = _sqlite_refused_setup(
            path, clock, n_denials=n, over=5
        )
        side = ledger.retry_rate_store.get_open("esc_1")
        assert side is not None and side.rate_limited == 5
        wid = side.window_id
        verifier.flush_retry_rate_limits("esc_1")
        tallies = _rate_limited_receipts(ledger, "esc_1")
        assert len(tallies) == 1
        tally_seq = tallies[0].seq
        tip = ledger._conn.execute("SELECT MAX(seq) FROM receipts").fetchone()[0]
        assert tally_seq == tip
        ledger._conn.execute("DROP TRIGGER IF EXISTS receipts_no_delete")
        ledger._conn.execute("DELETE FROM receipts WHERE seq = ?", (tally_seq,))
        # Tamper editable row only (no MAC key / no sidecar rewrite).
        ledger._conn.execute(
            "DROP TRIGGER IF EXISTS retry_rate_rate_limited_monotonic"
        )
        ledger._conn.execute(
            "UPDATE retry_rate_windows SET rate_limited = 0"
            " WHERE escrow_id = ? AND window_id = ?",
            ("esc_1", wid),
        )
        assert get_high_water("esc_1", wid) == 5
        ledger.close()

        # Startup cross-check must refuse: HMAC counter still 5 despite
        # the editable rate_limited column being lowered to 0.
        with pytest.raises(
            RetryRateIntegrityError,
            match="confirmed|no tally|hw_confirmed|marked flushed|tally_flushed",
        ):
            SqliteLedger(path)


def test_stale_pending_hw_dead_writer_refused():
    """Pending counter from a dead writer with no DB row → refuse at startup."""
    import tempfile

    from permit.retry_rate_store import (
        HighWaterRecord,
        _atomic_write_hw_record,
        assert_high_water_files_for_rows,
        create_high_water,
        high_water_lock,
    )
    from permit.sqlite_ledger import SqliteLedger

    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        ledger = SqliteLedger(path)
        ledger.close()
        create_high_water("esc_dead", "rw_dead", initial=0)
        with high_water_lock("esc_dead", "rw_dead") as hwlock:
            rec = HighWaterRecord(
                escrow_id="esc_dead",
                window_id="rw_dead",
                confirmed=0,
                intent=-1,
                writer_pid=2**22 - 3,  # unused pid
                writer_start=1,
            )
            _atomic_write_hw_record(hwlock._path, rec)
        with pytest.raises(
            RetryRateIntegrityError,
            match="orphan|dead writer|stale|planted|pending",
        ):
            assert_high_water_files_for_rows(
                [],
                refresh_rows=lambda: [],
                row_exists=lambda e, w: False,
            )


def test_planted_pending_hw_deleted_row_refused():
    """Pending counter whose DB row was deleted → refuse at startup."""
    import tempfile

    from permit.retry_rate_store import (
        HighWaterRecord,
        RetryRateRow,
        _atomic_write_hw_record,
        create_high_water,
        high_water_lock,
    )
    from permit.sqlite_ledger import SqliteLedger

    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        ledger = SqliteLedger(path)
        create_high_water("esc_plant", "rw_plant", initial=0)
        ledger.retry_rate_store.upsert(
            RetryRateRow(
                escrow_id="esc_plant",
                window_id="rw_plant",
                window_start=1.0,
                individual=0,
                rate_limited=0,
                covered_reason="already_refused",
                tally_flushed=False,
            )
        )
        with high_water_lock("esc_plant", "rw_plant") as hwlock:
            rec = HighWaterRecord(
                escrow_id="esc_plant",
                window_id="rw_plant",
                confirmed=0,
                intent=1,
                writer_pid=2**22 - 5,
                writer_start=99,
            )
            _atomic_write_hw_record(hwlock._path, rec)
        # Delete the DB row; leave the planted pending sidecar.
        ledger._conn.execute(
            "DELETE FROM retry_rate_windows"
            " WHERE escrow_id = ? AND window_id = ?",
            ("esc_plant", "rw_plant"),
        )
        ledger.close()
        with pytest.raises(
            RetryRateIntegrityError,
            match="orphan|dead writer|stale|planted|pending",
        ):
            SqliteLedger(path)


def _c2_c3_live_decoy(ready_q, stop_path):
    """Spawn worker: stay alive so kill(pid) succeeds with a foreign PID."""
    import time

    ready_q.put(os.getpid())
    while not os.path.exists(stop_path):
        time.sleep(0.01)


def test_c2_planted_creating_live_pid_bogus_start_refused_at_startup():
    """C2: creating orphan naming a live same-user PID with a bogus start
    token must be refused at startup (not accepted on kill(pid) alone).

    Fails on 3c05aa9 (kill-only accept path); passes when pid+start required.
    """
    import multiprocessing as mp
    import tempfile

    from permit.retry_rate_store import (
        HighWaterRecord,
        RetryRateIntegrityError,
        _atomic_write_hw_record,
        create_high_water,
        high_water_lock,
    )
    from permit.sqlite_ledger import SqliteLedger

    ctx = mp.get_context("spawn")
    ready_q = ctx.Queue()
    with tempfile.TemporaryDirectory() as td:
        stop_path = td + "/stop"
        decoy = ctx.Process(target=_c2_c3_live_decoy, args=(ready_q, stop_path))
        decoy.start()
        decoy_pid = ready_q.get(timeout=10)
        assert decoy_pid != os.getpid()
        try:
            path = td + "/ledger.sqlite"
            os.environ["PERMIT_RETRY_RATE_MAC_HW_FILE"] = td + "/hw"
            ledger = SqliteLedger(path)
            ledger.close()
            create_high_water("esc_c2", "rw_c2", initial=0)
            with high_water_lock("esc_c2", "rw_c2") as hwlock:
                # Plant creating intent: decoy is live, start token is wrong.
                rec = HighWaterRecord(
                    escrow_id="esc_c2",
                    window_id="rw_c2",
                    confirmed=0,
                    intent=-1,
                    writer_pid=decoy_pid,
                    writer_start=1,  # bogus — does not match /proc starttime
                )
                _atomic_write_hw_record(hwlock._path, rec)
            with pytest.raises(
                RetryRateIntegrityError,
                match="orphan|dead writer|stale|planted|pending|creating",
            ):
                SqliteLedger(path)
        finally:
            open(stop_path, "w").write("1")
            decoy.join(timeout=10)


def test_c3_planted_creating_with_rolled_back_counter_refused_at_startup():
    """C3: planted creating + rolled-back counter must refuse at startup,
    not start clean and only fail on the first live update.

    Fails on 3c05aa9 (kill-only accept skips reconcile); passes when refused.
    """
    import multiprocessing as mp
    import tempfile

    from permit.retry_rate_store import (
        HighWaterRecord,
        RetryRateIntegrityError,
        RetryRateRow,
        _atomic_write_hw_record,
        create_high_water,
        get_high_water,
        high_water_lock,
    )
    from permit.sqlite_ledger import SqliteLedger

    ctx = mp.get_context("spawn")
    ready_q = ctx.Queue()
    with tempfile.TemporaryDirectory() as td:
        stop_path = td + "/stop"
        decoy = ctx.Process(target=_c2_c3_live_decoy, args=(ready_q, stop_path))
        decoy.start()
        decoy_pid = ready_q.get(timeout=10)
        assert decoy_pid != os.getpid()
        try:
            path = td + "/ledger.sqlite"
            os.environ["PERMIT_RETRY_RATE_MAC_HW_FILE"] = td + "/hw"
            ledger = SqliteLedger(path)
            create_high_water("esc_c3", "rw_c3", initial=0)
            # DB stays at rate_limited=5; counter file is rolled back to
            # creating@confirmed=0 naming a live foreign PID with a bogus
            # start token. On 3c05aa9 kill-only accepts and skips reconcile
            # → startup succeeds; head must refuse at startup.
            ledger.retry_rate_store.upsert(
                RetryRateRow(
                    escrow_id="esc_c3",
                    window_id="rw_c3",
                    window_start=1.0,
                    individual=0,
                    rate_limited=5,
                    covered_reason="already_refused",
                    tally_flushed=False,
                )
            )
            with high_water_lock("esc_c3", "rw_c3") as hwlock:
                hwlock.write_intent(1)
                hwlock.confirm(1)
            for n in range(2, 6):
                with high_water_lock("esc_c3", "rw_c3") as hwlock:
                    hwlock.write_intent(n)
                    hwlock.confirm(n)
            assert get_high_water("esc_c3", "rw_c3") == 5
            with high_water_lock("esc_c3", "rw_c3") as hwlock:
                rec = HighWaterRecord(
                    escrow_id="esc_c3",
                    window_id="rw_c3",
                    confirmed=0,  # rolled-back counter
                    intent=-1,
                    writer_pid=decoy_pid,
                    writer_start=1,  # bogus start token
                )
                _atomic_write_hw_record(hwlock._path, rec)
            ledger.close()
            with pytest.raises(
                RetryRateIntegrityError,
                match=(
                    "orphan|dead writer|stale|planted|pending|creating|"
                    "confirmed|high-water|rate_mac|mismatch|intent"
                ),
            ):
                SqliteLedger(path)
        finally:
            open(stop_path, "w").write("1")
            decoy.join(timeout=10)


def _a63e7ff_child_hold(ready_q, stop_path):
    """Spawn worker: publish pid+start, stay alive until stop file appears."""
    import time

    from permit import retry_rate_store as rrs

    ready_q.put(rrs._current_writer_identity())
    while not os.path.exists(stop_path):
        time.sleep(0.01)


def test_a63e7ff_live_foreign_creating_under_lock_not_planted():
    """Deterministic repro of the a63e7ff eight-process false refusal.

    On a63e7ff, reconcile() treated live foreign creating intent under the
    exclusive flock as planted. Inject the TOCTOU with a hook: first
    ``_writer_still_alive`` returns False (skip does not continue), then
    True inside reconcile — a63e7ff raises planted; head clears when
    confirmed==count.
    """
    import multiprocessing as mp
    import tempfile

    from permit import retry_rate_store as rrs
    from permit.retry_rate_store import (
        HighWaterRecord,
        RetryRateRow,
        _HW_CREATING_INTENT,
        _atomic_write_hw_record,
        create_high_water,
        high_water_lock,
    )
    from permit.sqlite_ledger import SqliteLedger

    ctx = mp.get_context("spawn")
    ready_q = ctx.Queue()
    with tempfile.TemporaryDirectory() as td:
        stop_path = td + "/stop"
        child = ctx.Process(
            target=_a63e7ff_child_hold, args=(ready_q, stop_path)
        )
        child.start()
        foreign_pid, foreign_start = ready_q.get(timeout=10)
        assert foreign_pid != os.getpid()

        calls = {"n": 0}
        real_alive = rrs._writer_still_alive

        def _flicker_alive(pid, start):
            # First probe (assert skip / accept): pretend dead → reconcile.
            # Later probes (inside reconcile): report the real live writer.
            calls["n"] += 1
            if calls["n"] == 1:
                return False
            return real_alive(pid, start)

        path = td + "/ledger.sqlite"
        os.environ["PERMIT_RETRY_RATE_MAC_HW_FILE"] = td + "/hw"
        rrs.clear_retry_rate_mac_key_cache()
        ledger = SqliteLedger(path)
        create_high_water("esc_a63", "rw_a63", initial=0)
        ledger.retry_rate_store.upsert(
            RetryRateRow(
                escrow_id="esc_a63",
                window_id="rw_a63",
                window_start=1.0,
                individual=1,
                rate_limited=0,
                covered_reason="already_refused",
                tally_flushed=False,
            )
        )
        with high_water_lock("esc_a63", "rw_a63") as hwlock:
            rec = HighWaterRecord(
                escrow_id="esc_a63",
                window_id="rw_a63",
                confirmed=0,
                intent=_HW_CREATING_INTENT,
                writer_pid=foreign_pid,
                writer_start=foreign_start,
            )
            _atomic_write_hw_record(hwlock._path, rec)
        ledger.close()

        rrs._writer_still_alive = _flicker_alive  # type: ignore[assignment]
        try:
            # Head: opens cleanly (reconcile clears creating). a63e7ff: planted.
            reopened = SqliteLedger(path)
            reopened.close()
        finally:
            rrs._writer_still_alive = real_alive  # type: ignore[assignment]
            open(stop_path, "w").write("1")
            child.join(timeout=10)
            assert child.exitcode == 0


def test_startup_flock_timeout_refuses_instead_of_hanging():
    """Startup exclusive flock wait is bounded; expiry refuses clearly."""
    import tempfile
    import threading

    from permit.retry_rate_store import (
        RetryRateIntegrityError,
        _ENV_FLOCK_TIMEOUT_S,
        create_high_water,
        high_water_lock,
    )
    from permit.sqlite_ledger import SqliteLedger

    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        os.environ["PERMIT_RETRY_RATE_MAC_HW_FILE"] = td + "/hw"
        ledger = SqliteLedger(path)
        create_high_water("esc_to", "rw_to", initial=0)
        ledger.close()

        held = threading.Event()
        release = threading.Event()

        def _holder():
            with high_water_lock("esc_to", "rw_to"):
                held.set()
                release.wait(timeout=60)

        th = threading.Thread(target=_holder, daemon=True)
        th.start()
        assert held.wait(timeout=5)
        prev = os.environ.get(_ENV_FLOCK_TIMEOUT_S)
        os.environ[_ENV_FLOCK_TIMEOUT_S] = "0.2"
        try:
            t0 = __import__("time").monotonic()
            with pytest.raises(
                RetryRateIntegrityError, match="flock wait exceeded"
            ):
                SqliteLedger(path)
            elapsed = __import__("time").monotonic() - t0
            assert elapsed < 5.0, f"timed out too slowly: {elapsed:.2f}s"
        finally:
            if prev is None:
                os.environ.pop(_ENV_FLOCK_TIMEOUT_S, None)
            else:
                os.environ[_ENV_FLOCK_TIMEOUT_S] = prev
            release.set()
            th.join(timeout=5)


def test_a1a_creating_live_pid_good_token_no_flock_row_deleted_refused():
    """A1a: live PID + matching start token + no flock + no DB row → orphan.

    Fails on 7bb7c02 (pid+start alone accepted creating); head requires flock.
    """
    import multiprocessing as mp
    import tempfile

    from permit import retry_rate_store as rrs
    from permit.retry_rate_store import (
        HighWaterRecord,
        RetryRateIntegrityError,
        _HW_CREATING_INTENT,
        _atomic_write_hw_record,
        create_high_water,
        high_water_lock,
    )
    from permit.sqlite_ledger import SqliteLedger

    ctx = mp.get_context("spawn")
    ready_q = ctx.Queue()
    with tempfile.TemporaryDirectory() as td:
        stop_path = td + "/stop"
        decoy = ctx.Process(
            target=_a63e7ff_child_hold, args=(ready_q, stop_path)
        )
        decoy.start()
        live_pid, live_start = ready_q.get(timeout=10)
        assert live_pid != os.getpid()
        try:
            path = td + "/ledger.sqlite"
            os.environ["PERMIT_RETRY_RATE_MAC_HW_FILE"] = td + "/hw"
            rrs.clear_retry_rate_mac_key_cache()
            ledger = SqliteLedger(path)
            ledger.close()
            create_high_water("esc_a1a", "rw_a1a", initial=0)
            with high_water_lock("esc_a1a", "rw_a1a") as hwlock:
                rec = HighWaterRecord(
                    escrow_id="esc_a1a",
                    window_id="rw_a1a",
                    confirmed=0,
                    intent=_HW_CREATING_INTENT,
                    writer_pid=live_pid,
                    writer_start=live_start,
                )
                _atomic_write_hw_record(hwlock._path, rec)
            # No DB row (row deleted / never inserted).
            with pytest.raises(
                RetryRateIntegrityError,
                match="orphan|dead writer|stale|planted|pending|creating",
            ):
                SqliteLedger(path)
        finally:
            open(stop_path, "w").write("1")
            decoy.join(timeout=10)


def test_a3a_creating_zombie_writer_good_token_refused():
    """A3a: zombie PID with matching start token is dead — refuse creating.

    Fails on 7bb7c02 (kill(0) succeeds on zombies); head treats Z as dead.
    """
    import tempfile

    from permit import retry_rate_store as rrs
    from permit.retry_rate_store import (
        HighWaterRecord,
        RetryRateIntegrityError,
        _HW_CREATING_INTENT,
        _atomic_write_hw_record,
        _process_start_token,
        create_high_water,
        high_water_lock,
    )
    from permit.sqlite_ledger import SqliteLedger

    # Fork a child that exits immediately; unreaped → zombie.
    zombie_pid = os.fork()
    if zombie_pid == 0:
        os._exit(0)
    # Wait until /proc shows state Z (or give up).
    z_start = None
    for _ in range(200):
        try:
            with open(f"/proc/{zombie_pid}/stat", "r", encoding="utf-8") as fh:
                buf = fh.read()
            rparen = buf.rfind(")")
            state = buf[rparen + 2 :].split()[0]
            if state == "Z":
                z_start = _process_start_token(zombie_pid)
                break
        except OSError:
            break
        __import__("time").sleep(0.01)
    try:
        assert z_start is not None, "failed to observe unreaped zombie"
        with tempfile.TemporaryDirectory() as td:
            path = td + "/ledger.sqlite"
            os.environ["PERMIT_RETRY_RATE_MAC_HW_FILE"] = td + "/hw"
            rrs.clear_retry_rate_mac_key_cache()
            ledger = SqliteLedger(path)
            ledger.close()
            create_high_water("esc_a3a", "rw_a3a", initial=0)
            with high_water_lock("esc_a3a", "rw_a3a") as hwlock:
                rec = HighWaterRecord(
                    escrow_id="esc_a3a",
                    window_id="rw_a3a",
                    confirmed=0,
                    intent=_HW_CREATING_INTENT,
                    writer_pid=zombie_pid,
                    writer_start=z_start,
                )
                _atomic_write_hw_record(hwlock._path, rec)
            with pytest.raises(
                RetryRateIntegrityError,
                match="orphan|dead writer|stale|planted|pending|creating",
            ):
                SqliteLedger(path)
    finally:
        try:
            os.waitpid(zombie_pid, 0)
        except ChildProcessError:
            pass


def test_c5_creating_live_good_token_no_flock_rolled_back_refused():
    """C5: live PID + good start + no flock + DB row with rolled-back counter.

    Fails on 7bb7c02 (accepts creating on pid+start, skips reconcile);
    head requires flock → reconcile → confirmed!=count refuses.
    """
    import multiprocessing as mp
    import tempfile

    from permit import retry_rate_store as rrs
    from permit.retry_rate_store import (
        HighWaterRecord,
        RetryRateIntegrityError,
        RetryRateRow,
        _HW_CREATING_INTENT,
        _atomic_write_hw_record,
        create_high_water,
        get_high_water,
        high_water_lock,
    )
    from permit.sqlite_ledger import SqliteLedger

    ctx = mp.get_context("spawn")
    ready_q = ctx.Queue()
    with tempfile.TemporaryDirectory() as td:
        stop_path = td + "/stop"
        decoy = ctx.Process(
            target=_a63e7ff_child_hold, args=(ready_q, stop_path)
        )
        decoy.start()
        live_pid, live_start = ready_q.get(timeout=10)
        assert live_pid != os.getpid()
        try:
            path = td + "/ledger.sqlite"
            os.environ["PERMIT_RETRY_RATE_MAC_HW_FILE"] = td + "/hw"
            rrs.clear_retry_rate_mac_key_cache()
            ledger = SqliteLedger(path)
            create_high_water("esc_c5", "rw_c5", initial=0)
            ledger.retry_rate_store.upsert(
                RetryRateRow(
                    escrow_id="esc_c5",
                    window_id="rw_c5",
                    window_start=1.0,
                    individual=0,
                    rate_limited=5,
                    covered_reason="already_refused",
                    tally_flushed=False,
                )
            )
            with high_water_lock("esc_c5", "rw_c5") as hwlock:
                hwlock.write_intent(1)
                hwlock.confirm(1)
            for n in range(2, 6):
                with high_water_lock("esc_c5", "rw_c5") as hwlock:
                    hwlock.write_intent(n)
                    hwlock.confirm(n)
            assert get_high_water("esc_c5", "rw_c5") == 5
            with high_water_lock("esc_c5", "rw_c5") as hwlock:
                rec = HighWaterRecord(
                    escrow_id="esc_c5",
                    window_id="rw_c5",
                    confirmed=0,
                    intent=_HW_CREATING_INTENT,
                    writer_pid=live_pid,
                    writer_start=live_start,
                )
                _atomic_write_hw_record(hwlock._path, rec)
            ledger.close()
            with pytest.raises(
                RetryRateIntegrityError,
                match=(
                    "orphan|dead writer|stale|planted|pending|creating|"
                    "confirmed|high-water|rate_mac|mismatch|intent"
                ),
            ):
                SqliteLedger(path)
        finally:
            open(stop_path, "w").write("1")
            decoy.join(timeout=10)


def test_a2b_creating_after_real_pid_reuse_refused():
    """A2b: recycled PID with the *new* process's start token, no flock.

    Deterministic: keep a live decoy, stub ``/proc/<pid>/stat`` so its
    starttime is a crafted post-reuse token, plant creating with that
    pid+token (no flock, no DB row). Fails on 7bb7c02 (accepts live
    pid+start without flock); head refuses.
    """
    import multiprocessing as mp
    import tempfile
    from io import StringIO

    from permit import retry_rate_store as rrs
    from permit.retry_rate_store import (
        HighWaterRecord,
        RetryRateIntegrityError,
        _HW_CREATING_INTENT,
        _atomic_write_hw_record,
        create_high_water,
        high_water_lock,
    )
    from permit.sqlite_ledger import SqliteLedger

    FAKE_START = 424242

    def _fake_stat_for(pid: int, start: int) -> str:
        # /proc/<pid>/stat: fields after ") " — state at [0], starttime at [19].
        tail = ["S"] + ["0"] * 18 + [str(start)] + ["0", "0"]
        return f"{pid} (decoy) " + " ".join(tail) + "\n"

    ctx = mp.get_context("spawn")
    ready_q = ctx.Queue()
    with tempfile.TemporaryDirectory() as td:
        stop_path = td + "/stop"
        decoy = ctx.Process(
            target=_a63e7ff_child_hold, args=(ready_q, stop_path)
        )
        decoy.start()
        live_pid, _real_start = ready_q.get(timeout=10)
        assert live_pid != os.getpid()
        real_open = open

        def _stub_open(path, *a, **k):
            if str(path) == f"/proc/{live_pid}/stat":
                return StringIO(_fake_stat_for(live_pid, FAKE_START))
            return real_open(path, *a, **k)

        try:
            path = td + "/ledger.sqlite"
            os.environ["PERMIT_RETRY_RATE_MAC_HW_FILE"] = td + "/hw"
            rrs.clear_retry_rate_mac_key_cache()
            ledger = SqliteLedger(path)
            ledger.close()
            create_high_water("esc_a2b", "rw_a2b", initial=0)
            # Install stub only for the refuse path so create_high_water
            # used the real /proc above.
            rrs_open = __import__("builtins").open
            __import__("builtins").open = _stub_open  # type: ignore[assignment]
            try:
                with high_water_lock("esc_a2b", "rw_a2b") as hwlock:
                    rec = HighWaterRecord(
                        escrow_id="esc_a2b",
                        window_id="rw_a2b",
                        confirmed=0,
                        intent=_HW_CREATING_INTENT,
                        writer_pid=live_pid,
                        writer_start=FAKE_START,
                    )
                    _atomic_write_hw_record(hwlock._path, rec)
                with pytest.raises(
                    RetryRateIntegrityError,
                    match="orphan|dead writer|stale|planted|pending|creating",
                ):
                    SqliteLedger(path)
            finally:
                __import__("builtins").open = rrs_open  # type: ignore[assignment]
        finally:
            open(stop_path, "w").write("1")
            decoy.join(timeout=10)


# C6 (documented pre-existing, not fixed here): between /proc/locks observation
# and acting on it there is an inherent TOCTOU; a writer can drop the flock
# after we sampled holds=True (or acquire after holds=False). Closing that
# race would need kernel help or a different protocol. Leave as known debt.


@pytest.mark.parametrize(
    "raw",
    ["1e12", "inf", "nan", "1e400", "", "-1"],
)
def test_flock_timeout_env_refuses_non_finite_negative_huge_blank(raw):
    """Refuse PERMIT_RETRY_RATE_FLOCK_TIMEOUT_S when blank/non-finite/≤0/>600."""
    import tempfile

    from permit import retry_rate_store as rrs
    from permit.retry_rate_store import (
        RetryRateIntegrityError,
        _ENV_FLOCK_TIMEOUT_S,
        flock_timeout_s,
    )
    from permit.sqlite_ledger import SqliteLedger

    prev = os.environ.get(_ENV_FLOCK_TIMEOUT_S)
    os.environ[_ENV_FLOCK_TIMEOUT_S] = raw
    try:
        with pytest.raises(RetryRateIntegrityError):
            flock_timeout_s()
        with tempfile.TemporaryDirectory() as td:
            os.environ["PERMIT_RETRY_RATE_MAC_HW_FILE"] = td + "/hw"
            rrs.clear_retry_rate_mac_key_cache()
            with pytest.raises(RetryRateIntegrityError):
                SqliteLedger(td + "/ledger.sqlite")
    finally:
        if prev is None:
            os.environ.pop(_ENV_FLOCK_TIMEOUT_S, None)
        else:
            os.environ[_ENV_FLOCK_TIMEOUT_S] = prev
    # Documented hard ceiling is 600s (10 minutes).
    assert getattr(rrs, "_MAX_FLOCK_TIMEOUT_S", 600.0) == 600.0


def test_flock_timeout_does_not_leak_open_fds():
    """N flock timeouts must leave the process open-fd count unchanged."""
    import tempfile
    import threading

    from permit.retry_rate_store import (
        RetryRateIntegrityError,
        _ENV_FLOCK_TIMEOUT_S,
        create_high_water,
        high_water_lock,
    )

    def _fd_count() -> int:
        return len(os.listdir(f"/proc/{os.getpid()}/fd"))

    with tempfile.TemporaryDirectory() as td:
        os.environ["PERMIT_RETRY_RATE_MAC_HW_FILE"] = td + "/hw"
        create_high_water("esc_fd", "rw_fd", initial=0)
        held = threading.Event()
        release = threading.Event()

        def _holder():
            with high_water_lock("esc_fd", "rw_fd"):
                held.set()
                release.wait(timeout=120)

        th = threading.Thread(target=_holder, daemon=True)
        th.start()
        assert held.wait(timeout=5)
        prev = os.environ.get(_ENV_FLOCK_TIMEOUT_S)
        os.environ[_ENV_FLOCK_TIMEOUT_S] = "0.05"
        try:
            before = _fd_count()
            for _ in range(8):
                with pytest.raises(
                    RetryRateIntegrityError, match="flock wait exceeded"
                ):
                    with high_water_lock("esc_fd", "rw_fd"):
                        pass
            after = _fd_count()
            assert after == before, (
                f"open-fd leak after flock timeouts: before={before} after={after}"
            )
        finally:
            if prev is None:
                os.environ.pop(_ENV_FLOCK_TIMEOUT_S, None)
            else:
                os.environ[_ENV_FLOCK_TIMEOUT_S] = prev
            release.set()
            th.join(timeout=5)


def test_retry_rate_limit_side_table_tamper_row_deleted():
    """Side row deleted while chain tally remains → refuse to start."""
    import tempfile

    import settlement.verifier as vmod
    from permit.sqlite_ledger import SqliteLedger

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        ledger = SqliteLedger(path)
        permits = PermitStore(ledger=ledger)
        paypal = MockPayPalClient()
        clock = [1_000_000.0]

        def now():
            return clock[0]

        verifier = ReleaseVerifier(paypal, permits, ledger=ledger, clock=now)
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
        _refuse_escrow(verifier)
        evidence = Evidence(delivered_bytes=artifact)
        for _ in range(n + 10):
            verifier.verify_and_capture("esc_1", evidence)
        verifier.flush_retry_rate_limits("esc_1")
        side = ledger.retry_rate_store.load_all()[0]
        from permit.retry_rate_store import _hw_entry_path

        hw_path = _hw_entry_path(side.escrow_id, side.window_id)
        ledger.retry_rate_store.delete(side.escrow_id, side.window_id)
        # Remove the sidecar too so reopen reaches the chain/side-row check
        # (orphan file alone would refuse at SqliteLedger.__init__).
        if os.path.exists(hw_path):
            os.remove(hw_path)
        ledger.close()
        ledger2 = SqliteLedger(path)
        permits2 = PermitStore(ledger=ledger2)
        paypal2 = MockPayPalClient()
        with pytest.raises(RetryRateIntegrityError, match="missing row"):
            ReleaseVerifier(paypal2, permits2, ledger=ledger2, clock=now)
        ledger2.close()


def test_retry_rate_limit_wall_clock_step_backwards():
    """Wall-clock stepping backwards must not reset the window or counters."""
    import settlement.verifier as vmod

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    wall = [1_000_000.0]

    def wall_clock():
        return wall[0]

    verifier, paypal, permits, escrow, artifact = _setup(PredicateType.D)
    verifier = ReleaseVerifier(
        paypal, permits, ledger=verifier.ledger, clock=wall_clock
    )
    with verifier._lock:
        verifier._escrows[escrow.escrow_id] = escrow
    _refuse_escrow(verifier)
    evidence = Evidence(delivered_bytes=artifact)
    for _ in range(n):
        assert verifier.verify_and_capture("esc_1", evidence).reason == "already_refused"
    for _ in range(10):
        assert verifier.verify_and_capture("esc_1", evidence).reason == "rate_limited"
    state = verifier._rate_store.get_open("esc_1")
    assert state is not None
    wid = state.window_id
    assert state.individual == n
    assert state.rate_limited == 10

    # Step wall clock backwards (NTP skew / manual set).
    wall[0] -= 10_000.0
    r = verifier.verify_and_capture("esc_1", evidence)
    assert r.reason == "rate_limited"
    state2 = verifier._rate_store.get_open("esc_1")
    assert state2 is not None
    assert state2.window_id == wid
    assert state2.individual == n
    assert state2.rate_limited == 11
    # Still no mid-window tally on the chain.
    assert _rate_limited_receipts(verifier.ledger, "esc_1") == []
    verifier.flush_retry_rate_limits("esc_1")
    assert len(_rate_limited_receipts(verifier.ledger, "esc_1")) == 1
    assert _tally_count_sum(verifier.ledger, "esc_1") == 11


def test_retry_rate_limit_side_table_tamper_zero_individual():
    """Zeroing side.individual while chain has denials → refuse."""
    import tempfile

    import settlement.verifier as vmod
    from permit.retry_rate_store import RetryRateRow
    from permit.sqlite_ledger import SqliteLedger

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        ledger = SqliteLedger(path)
        permits = PermitStore(ledger=ledger)
        paypal = MockPayPalClient()
        clock = [1_000_000.0]

        def now():
            return clock[0]

        verifier = ReleaseVerifier(paypal, permits, ledger=ledger, clock=now)
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
        _refuse_escrow(verifier)
        evidence = Evidence(delivered_bytes=artifact)
        for _ in range(n):
            assert verifier.verify_and_capture("esc_1", evidence).reason == "already_refused"
        side = ledger.retry_rate_store.get_open("esc_1")
        assert side is not None
        ledger.retry_rate_store.upsert(
            RetryRateRow(
                escrow_id=side.escrow_id,
                window_id=side.window_id,
                window_start=side.window_start,
                individual=0,  # zeroed
                rate_limited=side.rate_limited,
                covered_reason=side.covered_reason,
                tally_flushed=False,
            )
        )
        ledger.close()
        ledger2 = SqliteLedger(path)
        permits2 = PermitStore(ledger=ledger2)
        paypal2 = MockPayPalClient()
        with pytest.raises(RetryRateIntegrityError, match="individual mismatch"):
            ReleaseVerifier(paypal2, permits2, ledger=ledger2, clock=now)
        ledger2.close()


def test_retry_rate_limit_side_table_tamper_rate_limited_before_n():
    """Setting rate_limited=3 before individual reaches N → refuse."""
    import tempfile

    from permit.retry_rate_store import RetryRateRow, rate_limited_mac
    from permit.sqlite_ledger import SqliteLedger

    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        ledger = SqliteLedger(path)
        permits = PermitStore(ledger=ledger)
        paypal = MockPayPalClient()
        clock = [1_000_000.0]

        def now():
            return clock[0]

        verifier = ReleaseVerifier(paypal, permits, ledger=ledger, clock=now)
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
        _refuse_escrow(verifier)
        evidence = Evidence(delivered_bytes=artifact)
        for _ in range(5):
            assert verifier.verify_and_capture("esc_1", evidence).reason == "already_refused"
        side = ledger.retry_rate_store.get_open("esc_1")
        assert side is not None
        assert side.individual == 5
        anchor = verifier._latest_denial_hash("esc_1", side.window_id)
        assert anchor is not None
        # Forge a valid MAC + matching sidecar HW so the before-N check
        # (not MAC / high-water) is what fires.
        from permit.retry_rate_store import (
            HighWaterRecord,
            _atomic_write_hw_record,
            _hw_entry_path,
            _hw_lock_path,
        )
        import fcntl as _fcntl

        hw_path = _hw_entry_path(side.escrow_id, side.window_id)
        lock_fd = os.open(_hw_lock_path(hw_path), os.O_RDWR)
        try:
            _fcntl.flock(lock_fd, _fcntl.LOCK_EX)
            _atomic_write_hw_record(
                hw_path,
                HighWaterRecord(
                    escrow_id=side.escrow_id,
                    window_id=side.window_id,
                    confirmed=3,
                    intent=None,
                ),
            )
        finally:
            _fcntl.flock(lock_fd, _fcntl.LOCK_UN)
            os.close(lock_fd)
        ledger.retry_rate_store.upsert(
            RetryRateRow(
                escrow_id=side.escrow_id,
                window_id=side.window_id,
                window_start=side.window_start,
                individual=side.individual,
                rate_limited=3,  # tamper before N
                covered_reason=side.covered_reason,
                tally_flushed=False,
                rate_mac=rate_limited_mac(
                    anchor, side.escrow_id, side.window_id, 3,
                    prev_mac=side.rate_mac,
                    high_water=3,
                ),
                prev_rate_mac=side.rate_mac,
            )
        )
        ledger.close()
        ledger2 = SqliteLedger(path)
        permits2 = PermitStore(ledger=ledger2)
        paypal2 = MockPayPalClient()
        with pytest.raises(RetryRateIntegrityError, match="rate_limited set before"):
            ReleaseVerifier(paypal2, permits2, ledger=ledger2, clock=now)
        ledger2.close()


def test_retry_rate_limit_side_table_tamper_delete_open_row():
    """Deleting the open side row while chain has denials → refuse."""
    import tempfile

    from permit.sqlite_ledger import SqliteLedger

    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        ledger = SqliteLedger(path)
        permits = PermitStore(ledger=ledger)
        paypal = MockPayPalClient()
        clock = [1_000_000.0]

        def now():
            return clock[0]

        verifier = ReleaseVerifier(paypal, permits, ledger=ledger, clock=now)
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
        _refuse_escrow(verifier)
        evidence = Evidence(delivered_bytes=artifact)
        for _ in range(7):
            assert verifier.verify_and_capture("esc_1", evidence).reason == "already_refused"
        side = ledger.retry_rate_store.get_open("esc_1")
        assert side is not None
        from permit.retry_rate_store import _hw_entry_path

        hw_path = _hw_entry_path(side.escrow_id, side.window_id)
        ledger.retry_rate_store.delete(side.escrow_id, side.window_id)
        if os.path.exists(hw_path):
            os.remove(hw_path)
        ledger.close()
        ledger2 = SqliteLedger(path)
        permits2 = PermitStore(ledger=ledger2)
        paypal2 = MockPayPalClient()
        with pytest.raises(RetryRateIntegrityError, match="missing open row"):
            ReleaseVerifier(paypal2, permits2, ledger=ledger2, clock=now)
        ledger2.close()


def test_retry_rate_limit_frequent_restarts_still_close_window():
    """Restarts more often than every W must still close when start+W elapses."""
    import tempfile

    import settlement.verifier as vmod
    from permit.sqlite_ledger import SqliteLedger

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    w = 10.0
    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        clock = [1_000_000.0]

        def now():
            return clock[0]

        ledger = SqliteLedger(path)
        permits = PermitStore(ledger=ledger)
        paypal = MockPayPalClient()
        verifier = ReleaseVerifier(
            paypal, permits, ledger=ledger, clock=now, retry_rate_limit_w=w
        )
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
        _refuse_escrow(verifier)
        evidence = Evidence(delivered_bytes=artifact)
        over = 40
        for _ in range(n + over):
            verifier.verify_and_capture("esc_1", evidence)
        side0 = ledger.retry_rate_store.get_open("esc_1")
        assert side0 is not None
        start = side0.window_start
        wid = side0.window_id
        before = len(ledger)
        # Restart every 2s of clock while still inside W; window_start must
        # not reset (steps 1..4 → start+8 < W=10).
        for step in range(1, 5):
            clock[0] = start + step * 2.0
            ledger.close()
            ledger = SqliteLedger(path)
            permits = PermitStore(ledger=ledger)
            paypal = MockPayPalClient()
            verifier = ReleaseVerifier(
                paypal, permits, ledger=ledger, clock=now, retry_rate_limit_w=w
            )
            open_row = ledger.retry_rate_store.get_open("esc_1")
            assert open_row is not None
            assert open_row.window_id == wid
            assert open_row.window_start == start
            assert _rate_limited_receipts(ledger, "esc_1") == []
        # Cross W: next restart must close and tally.
        clock[0] = start + w + 0.5
        ledger.close()
        ledger = SqliteLedger(path)
        permits = PermitStore(ledger=ledger)
        paypal = MockPayPalClient()
        ReleaseVerifier(
            paypal, permits, ledger=ledger, clock=now, retry_rate_limit_w=w
        )
        assert len(_rate_limited_receipts(ledger, "esc_1")) == 1
        assert _tally_count_sum(ledger, "esc_1") == over
        assert len(ledger) - before == 1
        ledger.close()


def test_retry_rate_limit_restart_while_old_process_live():
    """Restart while the old writer is still alive: shared open window, exact tally."""
    import tempfile
    import threading

    import settlement.verifier as vmod
    from permit.sqlite_ledger import SqliteLedger

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        clock = [1_000_000.0]
        clock_lock = threading.Lock()

        def now():
            with clock_lock:
                return clock[0]

        ledger_a = SqliteLedger(path)
        permits_a = PermitStore(ledger=ledger_a)
        paypal_a = MockPayPalClient()
        verifier_a = ReleaseVerifier(paypal_a, permits_a, ledger=ledger_a, clock=now)
        permit, _ = permits_a.grant(
            agent_id="agent_1",
            cap_cents=5000,
            allowlist=["merchant_1"],
            expiry=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        check = permits_a.check(permit.permit_id, 3000, "merchant_1")
        auth_id = check.receipt.payload["auth_id"]
        pp_auth = paypal_a.authorize(3000, "merchant_1")
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
        verifier_a.register(escrow)
        _refuse_escrow(verifier_a)
        evidence = Evidence(delivered_bytes=artifact)
        for _ in range(40):
            assert (
                verifier_a.verify_and_capture("esc_1", evidence).reason
                == "already_refused"
            )
        # Old process still live; new process attaches to the same DB.
        ledger_b = SqliteLedger(path)
        permits_b = PermitStore(ledger=ledger_b)
        paypal_b = MockPayPalClient()
        verifier_b = ReleaseVerifier(paypal_b, permits_b, ledger=ledger_b, clock=now)
        with verifier_b._lock:
            verifier_b._escrows["esc_1"] = escrow
            verifier_b._terminal_reasons["esc_1"] = "already_refused"
        open_a = ledger_a.retry_rate_store.get_open("esc_1")
        open_b = ledger_b.retry_rate_store.get_open("esc_1")
        assert open_a is not None and open_b is not None
        assert open_a.window_id == open_b.window_id
        remaining = (n + 50) - 40
        for i in range(remaining):
            v = verifier_a if i % 2 == 0 else verifier_b
            r = v.verify_and_capture("esc_1", evidence)
            assert r.reason in ("already_refused", "rate_limited")
        verifier_a.flush_retry_rate_limits("esc_1")
        ledger_a.sync_receipts_from_db()
        ledger_b.sync_receipts_from_db()
        assert len(_rate_limited_receipts(ledger_a, "esc_1")) == 1
        assert _tally_count_sum(ledger_a, "esc_1") == 50
        # N denials + 1 tally on the shared chain (plus prior setup receipts).
        denials = [
            r
            for r in ledger_a.receipts()
            if r.event_type == "REFUSED"
            and r.payload.get("reason") == "already_refused"
            and r.payload.get("escrow_id") == "esc_1"
        ]
        assert len(denials) == n
        ledger_a.close()
        ledger_b.close()


def _mp_flood_worker(path, clock_value, n_iters, out_q, hw_path=None, mac_key=None):
    """Multiprocessing worker: flood retries on shared Sqlite ledger."""
    try:
        import sqlite3
        import time

        from permit.permit import PermitStore
        from permit.retry_rate_store import clear_retry_rate_mac_key_cache
        from permit.sqlite_ledger import SqliteLedger
        from settlement.paypal_client import MockPayPalClient
        from settlement.verifier import Evidence, ReleaseVerifier

        # Spawned workers: set key + HW path explicitly (don't rely on env
        # inheritance quirks across pytest/spawn).
        if mac_key:
            os.environ["PERMIT_RETRY_RATE_MAC_KEY"] = mac_key
        if hw_path:
            os.environ["PERMIT_RETRY_RATE_MAC_HW_FILE"] = hw_path
        clear_retry_rate_mac_key_cache()

        ledger = SqliteLedger(path)
        permits = PermitStore(ledger=ledger)
        paypal = MockPayPalClient()

        def now():
            return clock_value

        verifier = ReleaseVerifier(paypal, permits, ledger=ledger, clock=now)
        # Escrow was registered by the parent; mark terminal for lock-free path.
        verifier._terminal_reasons["esc_1"] = "already_refused"
        evidence = Evidence(delivered_bytes=b"delivered work product")
        for _ in range(n_iters):
            # busy_timeout handles most contention; a few short retries
            # cover residual lock races under -O / heavy CI load.
            for attempt in range(8):
                try:
                    r = verifier.verify_and_capture("esc_1", evidence)
                    break
                except sqlite3.OperationalError as exc:
                    if "locked" not in str(exc).lower() or attempt == 7:
                        raise
                    time.sleep(0.01 * (attempt + 1))
            assert not r.released
            assert r.reason in ("already_refused", "rate_limited")
        ledger.close()
        out_q.put(("ok", None))
    except BaseException as exc:  # noqa: BLE001
        out_q.put(("err", repr(exc)))


def test_retry_rate_limit_two_multiprocess_writers_one_sqlite_file():
    """Real multiprocessing flood on one DB: exactly N+1 and exact tally."""
    import multiprocessing as mp
    import tempfile

    import settlement.verifier as vmod
    from permit.sqlite_ledger import SqliteLedger

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    over = 80
    total = n + over
    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        clock_value = 1_000_000.0
        ledger = SqliteLedger(path)
        permits = PermitStore(ledger=ledger)
        paypal = MockPayPalClient()

        def now():
            return clock_value

        verifier = ReleaseVerifier(paypal, permits, ledger=ledger, clock=now)
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
        _refuse_escrow(verifier)
        before = len(ledger)
        ledger.close()

        ctx = mp.get_context("spawn")
        q = ctx.Queue()
        per = total // 2
        hw_path = os.environ.get("PERMIT_RETRY_RATE_MAC_HW_FILE")
        mac_key = os.environ.get("PERMIT_RETRY_RATE_MAC_KEY")
        p1 = ctx.Process(
            target=_mp_flood_worker,
            args=(path, clock_value, per, q, hw_path, mac_key),
        )
        p2 = ctx.Process(
            target=_mp_flood_worker,
            args=(path, clock_value, total - per, q, hw_path, mac_key),
        )
        p1.start()
        p2.start()
        p1.join(timeout=60)
        p2.join(timeout=60)
        assert p1.exitcode == 0 and p2.exitcode == 0
        results = [q.get(timeout=5), q.get(timeout=5)]
        assert all(status == "ok" for status, _ in results), results

        final = SqliteLedger(path)
        permits_f = PermitStore(ledger=final)
        paypal_f = MockPayPalClient()
        verifier_f = ReleaseVerifier(paypal_f, permits_f, ledger=final, clock=now)
        open_row = final.retry_rate_store.get_open("esc_1")
        assert open_row is not None
        assert open_row.individual == n
        assert open_row.rate_limited == over
        assert open_row.window_id  # single shared window
        verifier_f.flush_retry_rate_limits("esc_1")
        final.sync_receipts_from_db()
        assert len(_rate_limited_receipts(final, "esc_1")) == 1
        assert _tally_count_sum(final, "esc_1") == over
        assert len(final) - before == n + 1
        ok, reason = final.verify_chain()
        assert ok, reason
        final.close()


def _sqlite_refused_setup(td_path, clock, *, n_denials=0, over=0):
    """Shared helper: SqliteLedger escrow refused, optional denials/over."""
    import permit.retry_rate_store as rrs
    from permit.sqlite_ledger import SqliteLedger

    # Isolate the counter-file directory to this ledger so the bidirectional
    # DB↔file cross-check does not see orphans from other tests' windows.
    hw_base = td_path + ".hw"
    os.environ["PERMIT_RETRY_RATE_MAC_HW_FILE"] = hw_base
    rrs.clear_retry_rate_mac_key_cache()
    rrs.load_retry_rate_mac_key(refresh=True)

    ledger = SqliteLedger(td_path)
    # Stash for multiprocess workers (same process sees the env already).
    ledger._test_hw_base = hw_base  # type: ignore[attr-defined]

    def now():
        return clock[0]

    permits = PermitStore(ledger=ledger)
    paypal = MockPayPalClient()
    verifier = ReleaseVerifier(paypal, permits, ledger=ledger, clock=now)
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
    _refuse_escrow(verifier)
    evidence = Evidence(delivered_bytes=artifact)
    for _ in range(n_denials):
        assert verifier.verify_and_capture("esc_1", evidence).reason == "already_refused"
    for _ in range(over):
        assert verifier.verify_and_capture("esc_1", evidence).reason == "rate_limited"
    return verifier, ledger, evidence


def test_retry_rate_limit_live_tamper_individual_zero():
    """Live mid-window: individual=0 while chain has denials → next decision refuses."""
    import tempfile

    from permit.retry_rate_store import RetryRateRow

    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        clock = [1_000_000.0]
        verifier, ledger, evidence = _sqlite_refused_setup(path, clock, n_denials=10)
        before = len(ledger)
        side = ledger.retry_rate_store.get_open("esc_1")
        assert side is not None
        ledger.retry_rate_store.upsert(
            RetryRateRow(
                escrow_id=side.escrow_id,
                window_id=side.window_id,
                window_start=side.window_start,
                individual=0,
                rate_limited=side.rate_limited,
                covered_reason=side.covered_reason,
                tally_flushed=False,
                rate_mac=side.rate_mac,
                prev_rate_mac=side.prev_rate_mac,
            )
        )
        with pytest.raises(RetryRateIntegrityError, match="individual mismatch"):
            verifier.verify_and_capture("esc_1", evidence)
        assert len(ledger) == before
        assert _rate_limited_receipts(ledger, "esc_1") == []
        ledger.close()


def test_retry_rate_limit_live_tamper_individual_50():
    """Live mid-window: individual=50 vs chain=10 → next decision refuses."""
    import tempfile

    from permit.retry_rate_store import RetryRateRow

    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        clock = [1_000_000.0]
        verifier, ledger, evidence = _sqlite_refused_setup(path, clock, n_denials=10)
        before = len(ledger)
        side = ledger.retry_rate_store.get_open("esc_1")
        assert side is not None
        ledger.retry_rate_store.upsert(
            RetryRateRow(
                escrow_id=side.escrow_id,
                window_id=side.window_id,
                window_start=side.window_start,
                individual=50,
                rate_limited=side.rate_limited,
                covered_reason=side.covered_reason,
                tally_flushed=False,
                rate_mac=side.rate_mac,
                prev_rate_mac=side.prev_rate_mac,
            )
        )
        with pytest.raises(RetryRateIntegrityError, match="individual mismatch"):
            verifier.verify_and_capture("esc_1", evidence)
        assert len(ledger) == before
        ledger.close()


def test_retry_rate_limit_live_tamper_delete_row():
    """Live mid-window: delete side row → next decision refuses (not only at restart)."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        clock = [1_000_000.0]
        verifier, ledger, evidence = _sqlite_refused_setup(path, clock, n_denials=10)
        before = len(ledger)
        side = ledger.retry_rate_store.get_open("esc_1")
        assert side is not None
        ledger.retry_rate_store.delete(side.escrow_id, side.window_id)
        with pytest.raises(RetryRateIntegrityError, match="missing open row mid-window"):
            verifier.verify_and_capture("esc_1", evidence)
        assert len(ledger) == before
        assert _rate_limited_receipts(ledger, "esc_1") == []
        ledger.close()


def test_retry_rate_limit_live_tamper_rate_limited_zero():
    """Live mid-window: rate_limited=0 with stale MAC after over-limit → refuse."""
    import tempfile

    import settlement.verifier as vmod
    from permit.retry_rate_store import RetryRateRow

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        clock = [1_000_000.0]
        verifier, ledger, evidence = _sqlite_refused_setup(
            path, clock, n_denials=n, over=11
        )
        before = len(ledger)
        side = ledger.retry_rate_store.get_open("esc_1")
        assert side is not None
        assert side.rate_limited == 11
        # Zero the counter but leave the old MAC → detectable (raw SQL =
        # DB-only attacker; store upsert is monotonic).
        _raw_sql_rollback_side_row(
            ledger,
            RetryRateRow(
                escrow_id=side.escrow_id,
                window_id=side.window_id,
                window_start=side.window_start,
                individual=side.individual,
                rate_limited=0,
                covered_reason=side.covered_reason,
                tally_flushed=False,
                rate_mac=side.rate_mac,
                prev_rate_mac=side.prev_rate_mac,
            ),
        )
        with pytest.raises(
            RetryRateIntegrityError, match="high-water|rate_mac mismatch"
        ):
            verifier.verify_and_capture("esc_1", evidence)
        assert len(ledger) == before
        assert _tally_count_sum(ledger, "esc_1") == 0
        ledger.close()


def test_retry_rate_limit_live_tamper_rate_limited_three():
    """Live mid-window: rate_limited=3 with wrong MAC → refuse; no wrong tally."""
    import tempfile

    import settlement.verifier as vmod
    from permit.retry_rate_store import RetryRateRow

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        clock = [1_000_000.0]
        verifier, ledger, evidence = _sqlite_refused_setup(
            path, clock, n_denials=n, over=5
        )
        before = len(ledger)
        side = ledger.retry_rate_store.get_open("esc_1")
        assert side is not None
        _raw_sql_rollback_side_row(
            ledger,
            RetryRateRow(
                escrow_id=side.escrow_id,
                window_id=side.window_id,
                window_start=side.window_start,
                individual=side.individual,
                rate_limited=3,
                covered_reason=side.covered_reason,
                tally_flushed=False,
                rate_mac="0" * 64,  # not a valid MAC
                prev_rate_mac=side.prev_rate_mac,
            ),
        )
        with pytest.raises(
            RetryRateIntegrityError, match="high-water|rate_mac mismatch"
        ):
            verifier.verify_and_capture("esc_1", evidence)
        assert len(ledger) == before
        with pytest.raises(
            RetryRateIntegrityError, match="high-water|rate_mac mismatch"
        ):
            verifier.flush_retry_rate_limits("esc_1")
        # Restore honest row and flush for N+1 bound check path.
        ledger.retry_rate_store.upsert(side)
        verifier.flush_retry_rate_limits("esc_1")
        assert len(_rate_limited_receipts(ledger, "esc_1")) == 1
        assert _tally_count_sum(ledger, "esc_1") == 5
        assert len(ledger) - before == 1  # one tally; never > N+1 denials+tally
        ledger.close()


def test_retry_rate_limit_db_attacker_unkeyed_hash_refused():
    """DB-write attacker without the HMAC key: unkeyed SHA-256 must not verify."""
    import tempfile

    import settlement.verifier as vmod
    from permit.retry_rate_store import (
        RetryRateRow,
        unkeyed_rate_limited_digest,
    )

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        clock = [1_000_000.0]
        verifier, ledger, evidence = _sqlite_refused_setup(
            path, clock, n_denials=n, over=11
        )
        before = len(ledger)
        side = ledger.retry_rate_store.get_open("esc_1")
        assert side is not None
        assert side.rate_limited == 11
        latest = ledger.latest_denial_hash(side.escrow_id, side.window_id)
        assert latest is not None
        # Attacker can write the DB and recompute a plain hash, but not the HMAC.
        forged = unkeyed_rate_limited_digest(
            latest, side.escrow_id, side.window_id, 0
        )
        assert forged != side.rate_mac
        _raw_sql_rollback_side_row(
            ledger,
            RetryRateRow(
                escrow_id=side.escrow_id,
                window_id=side.window_id,
                window_start=side.window_start,
                individual=side.individual,
                rate_limited=0,  # wipe the over-limit counter
                covered_reason=side.covered_reason,
                tally_flushed=False,
                rate_mac=forged,  # unkeyed digest of the forged count
                prev_rate_mac=side.prev_rate_mac,
            ),
        )
        with pytest.raises(
            RetryRateIntegrityError, match="high-water|rate_mac mismatch"
        ):
            verifier.verify_and_capture("esc_1", evidence)
        assert len(ledger) == before
        assert _tally_count_sum(ledger, "esc_1") == 0
        ledger.close()


def _raw_sql_rollback_side_row(ledger, saved) -> None:
    """DB-only attacker: raw UPDATE that lowers rate_limited + restores old MAC.

    Drops the monotonic trigger (attacker has full DB write), tampers, then
    restores the trigger. Threat model: DB write, not the sidecar/key.
    """
    from permit.retry_rate_store import _DDL_RATE_LIMITED_MONOTONIC

    ledger._conn.execute(
        "DROP TRIGGER IF EXISTS retry_rate_rate_limited_monotonic"
    )
    try:
        ledger._conn.execute(
            "UPDATE retry_rate_windows SET"
            " rate_limited = ?, rate_mac = ?, prev_rate_mac = ?"
            " WHERE escrow_id = ? AND window_id = ?",
            (
                saved.rate_limited,
                saved.rate_mac,
                saved.prev_rate_mac,
                saved.escrow_id,
                saved.window_id,
            ),
        )
    finally:
        ledger._conn.execute(_DDL_RATE_LIMITED_MONOTONIC)


def test_retry_rate_limit_rollback_saved_pair_50_to_1():
    """Bar 2: roll DB back to a saved (count=1, mac) pair → sidecar detects."""
    import tempfile

    import settlement.verifier as vmod
    from permit.retry_rate_store import RetryRateRow

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        clock = [1_000_000.0]
        verifier, ledger, evidence = _sqlite_refused_setup(
            path, clock, n_denials=n, over=1
        )
        side1 = ledger.retry_rate_store.get_open("esc_1")
        assert side1 is not None and side1.rate_limited == 1
        saved = RetryRateRow(
            escrow_id=side1.escrow_id,
            window_id=side1.window_id,
            window_start=side1.window_start,
            individual=side1.individual,
            rate_limited=side1.rate_limited,
            covered_reason=side1.covered_reason,
            tally_flushed=False,
            rate_mac=side1.rate_mac,
            prev_rate_mac=side1.prev_rate_mac,
        )
        for _ in range(49):
            assert (
                verifier.verify_and_capture("esc_1", evidence).reason
                == "rate_limited"
            )
        side50 = ledger.retry_rate_store.get_open("esc_1")
        assert side50 is not None and side50.rate_limited == 50
        before = len(ledger)
        _raw_sql_rollback_side_row(ledger, saved)
        with pytest.raises(RetryRateIntegrityError, match="high-water"):
            verifier.verify_and_capture("esc_1", evidence)
        assert len(ledger) == before
        ledger.close()


def test_retry_rate_limit_rollback_saved_pair_50_to_older():
    """Bar 2: roll DB back to an older saved pair (count=10) → detected."""
    import tempfile

    import settlement.verifier as vmod
    from permit.retry_rate_store import RetryRateRow

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        clock = [1_000_000.0]
        verifier, ledger, evidence = _sqlite_refused_setup(
            path, clock, n_denials=n, over=10
        )
        side10 = ledger.retry_rate_store.get_open("esc_1")
        assert side10 is not None and side10.rate_limited == 10
        saved = RetryRateRow(
            escrow_id=side10.escrow_id,
            window_id=side10.window_id,
            window_start=side10.window_start,
            individual=side10.individual,
            rate_limited=side10.rate_limited,
            covered_reason=side10.covered_reason,
            tally_flushed=False,
            rate_mac=side10.rate_mac,
            prev_rate_mac=side10.prev_rate_mac,
        )
        for _ in range(40):
            assert (
                verifier.verify_and_capture("esc_1", evidence).reason
                == "rate_limited"
            )
        side50 = ledger.retry_rate_store.get_open("esc_1")
        assert side50 is not None and side50.rate_limited == 50
        before = len(ledger)
        _raw_sql_rollback_side_row(ledger, saved)
        with pytest.raises(RetryRateIntegrityError, match="high-water"):
            verifier.verify_and_capture("esc_1", evidence)
        assert len(ledger) == before
        ledger.close()


def _restore_suite_mac_key() -> None:
    import permit.retry_rate_store as rrs

    rrs.clear_retry_rate_mac_key_cache()
    os.environ.setdefault(
        "PERMIT_RETRY_RATE_MAC_KEY",
        "test-retry-rate-mac-key-NOT-FOR-PRODUCTION",
    )
    rrs.load_retry_rate_mac_key(refresh=True)


def test_retry_rate_mac_key_missing_fails():
    """No key configured → refuse (no demo fallback)."""
    import permit.retry_rate_store as rrs

    rrs.clear_retry_rate_mac_key_cache()
    old = {
        k: os.environ.pop(k, None)
        for k in (
            "PERMIT_RETRY_RATE_MAC_KEY",
            "PERMIT_RETRY_RATE_MAC_KEY_FILE",
        )
    }
    try:
        with pytest.raises(RetryRateIntegrityError, match="unset|refuse"):
            rrs.load_retry_rate_mac_key(refresh=True)
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        _restore_suite_mac_key()


def test_retry_rate_mac_key_empty_fails():
    """Empty PERMIT_RETRY_RATE_MAC_KEY → refuse."""
    import permit.retry_rate_store as rrs

    rrs.clear_retry_rate_mac_key_cache()
    old = os.environ.get("PERMIT_RETRY_RATE_MAC_KEY")
    old_file = os.environ.pop("PERMIT_RETRY_RATE_MAC_KEY_FILE", None)
    os.environ["PERMIT_RETRY_RATE_MAC_KEY"] = ""
    try:
        with pytest.raises(RetryRateIntegrityError, match="empty"):
            rrs.load_retry_rate_mac_key(refresh=True)
    finally:
        if old is None:
            os.environ.pop("PERMIT_RETRY_RATE_MAC_KEY", None)
        else:
            os.environ["PERMIT_RETRY_RATE_MAC_KEY"] = old
        if old_file is not None:
            os.environ["PERMIT_RETRY_RATE_MAC_KEY_FILE"] = old_file
        _restore_suite_mac_key()


def test_retry_rate_mac_key_short_fails():
    """Key shorter than 32 bytes → refuse."""
    import permit.retry_rate_store as rrs

    rrs.clear_retry_rate_mac_key_cache()
    old = os.environ.get("PERMIT_RETRY_RATE_MAC_KEY")
    old_file = os.environ.pop("PERMIT_RETRY_RATE_MAC_KEY_FILE", None)
    os.environ["PERMIT_RETRY_RATE_MAC_KEY"] = "x" * 31
    try:
        with pytest.raises(RetryRateIntegrityError, match="too short"):
            rrs.load_retry_rate_mac_key(refresh=True)
    finally:
        if old is None:
            os.environ.pop("PERMIT_RETRY_RATE_MAC_KEY", None)
        else:
            os.environ["PERMIT_RETRY_RATE_MAC_KEY"] = old
        if old_file is not None:
            os.environ["PERMIT_RETRY_RATE_MAC_KEY_FILE"] = old_file
        _restore_suite_mac_key()


def _mp_window_creator_worker(
    path, clock_value, escrow_ids, n_iters, out_q, hw_path, mac_key
):
    """Writer: create/advance rate windows on shared ledger (hits create+INSERT)."""
    try:
        import sqlite3
        import time

        from permit.permit import PermitStore
        from permit.retry_rate_store import clear_retry_rate_mac_key_cache
        from permit.sqlite_ledger import SqliteLedger
        from settlement.paypal_client import MockPayPalClient
        from settlement.verifier import Evidence, ReleaseVerifier

        os.environ["PERMIT_RETRY_RATE_MAC_KEY"] = mac_key
        os.environ["PERMIT_RETRY_RATE_MAC_HW_FILE"] = hw_path
        clear_retry_rate_mac_key_cache()

        ledger = SqliteLedger(path)
        permits = PermitStore(ledger=ledger)
        paypal = MockPayPalClient()
        verifier = ReleaseVerifier(
            paypal, permits, ledger=ledger, clock=lambda: clock_value
        )
        for eid in escrow_ids:
            verifier._terminal_reasons[eid] = "already_refused"
        evidence = Evidence(delivered_bytes=b"delivered work product")
        for i in range(n_iters):
            eid = escrow_ids[i % len(escrow_ids)]
            for attempt in range(8):
                try:
                    r = verifier.verify_and_capture(eid, evidence)
                    break
                except sqlite3.OperationalError as exc:
                    if "locked" not in str(exc).lower() or attempt == 7:
                        raise
                    time.sleep(0.01 * (attempt + 1))
            assert not r.released
            assert r.reason in ("already_refused", "rate_limited")
        ledger.close()
        out_q.put(("ok", None))
    except BaseException as exc:  # noqa: BLE001
        out_q.put(("err", repr(exc)))


def _mp_startup_opener_worker(
    path, n_opens, out_q, hw_path, mac_key, stop_flag_path
):
    """Starter: repeatedly open SqliteLedger (startup orphan cross-check)."""
    try:
        from permit.retry_rate_store import (
            RetryRateIntegrityError,
            clear_retry_rate_mac_key_cache,
        )
        from permit.sqlite_ledger import SqliteLedger

        os.environ["PERMIT_RETRY_RATE_MAC_KEY"] = mac_key
        os.environ["PERMIT_RETRY_RATE_MAC_HW_FILE"] = hw_path
        # Overlap instrumentation env is inherited from the parent process.
        clear_retry_rate_mac_key_cache()

        opens = 0
        while opens < n_opens and not os.path.exists(stop_flag_path):
            try:
                ledger = SqliteLedger(path)
                ledger.close()
                opens += 1
            except RetryRateIntegrityError as exc:
                out_q.put(("err", repr(exc)))
                return
        out_q.put(("ok", opens))
    except BaseException as exc:  # noqa: BLE001
        out_q.put(("err", repr(exc)))


def test_retry_rate_limit_eight_processes_no_false_integrity_error():
    """
    8 processes × 20 rounds: writers create new windows while others open
    SqliteLedger (startup orphan path). Each round prints false-refusals and
    startup/write overlaps; fail if total overlaps == 0 or refusals > 0.
    """
    import multiprocessing as mp
    import tempfile

    from permit.retry_rate_store import (
        RetryRateIntegrityError,
        _ENV_STARTUP_OVERLAP_FILE,
        _ENV_WRITE_ACTIVE_DIR,
    )
    from permit.sqlite_ledger import SqliteLedger

    n_writers = 4
    n_starters = 4
    per_writer = 80
    starter_opens = 40
    rounds = 20
    n_escrows = 4
    false_refusals = 0
    total_overlaps = 0

    def _one_round(round_idx: int) -> tuple[int, int]:
        import permit.retry_rate_store as rrs

        with tempfile.TemporaryDirectory() as td:
            path = td + f"/ledger_{round_idx}.sqlite"
            hw_base = path + ".hw"
            stop_flag = td + "/stop"
            write_active = td + "/writing"
            overlap_file = td + "/overlaps"
            os.makedirs(write_active, mode=0o700, exist_ok=True)
            os.environ["PERMIT_RETRY_RATE_MAC_HW_FILE"] = hw_base
            os.environ[_ENV_WRITE_ACTIVE_DIR] = write_active
            os.environ[_ENV_STARTUP_OVERLAP_FILE] = overlap_file
            rrs.clear_retry_rate_mac_key_cache()
            rrs.load_retry_rate_mac_key(refresh=True)
            clock_value = 3_000_000.0 + round_idx
            ledger = SqliteLedger(path)
            permits = PermitStore(ledger=ledger)
            paypal = MockPayPalClient()
            verifier = ReleaseVerifier(
                paypal, permits, ledger=ledger, clock=lambda: clock_value
            )
            permit, _ = permits.grant(
                agent_id="agent_1",
                cap_cents=50_000,
                allowlist=["merchant_1"],
                expiry=datetime.now(timezone.utc) + timedelta(hours=1),
            )
            artifact = b"delivered work product"
            digest = hashlib.sha256(artifact).hexdigest()
            escrow_ids = [f"esc_{i}" for i in range(n_escrows)]
            # Refuse each escrow but do NOT pre-create rate windows — writers
            # must create windows while starters open.
            for eid in escrow_ids:
                check = permits.check(permit.permit_id, 3000, "merchant_1")
                auth_id = check.receipt.payload["auth_id"]
                pp_auth = paypal.authorize(3000, "merchant_1")
                escrow = Escrow(
                    escrow_id=eid,
                    permit_id=permit.permit_id,
                    auth_id=auth_id,
                    paypal_auth_id=pp_auth.auth_id,
                    amount_cents=3000,
                    merchant_id="merchant_1",
                    predicate_type=PredicateType.D,
                    artifact_hash=digest,
                )
                verifier.register(escrow)
                verifier.verify_and_capture(
                    eid, Evidence(delivered_bytes=b"tampered")
                )
            ledger.close()

            ctx = mp.get_context("spawn")
            q = ctx.Queue()
            mac_key = os.environ["PERMIT_RETRY_RATE_MAC_KEY"]
            writers = [
                ctx.Process(
                    target=_mp_window_creator_worker,
                    args=(
                        path,
                        clock_value,
                        escrow_ids,
                        per_writer,
                        q,
                        hw_base,
                        mac_key,
                    ),
                )
                for _ in range(n_writers)
            ]
            starters = [
                ctx.Process(
                    target=_mp_startup_opener_worker,
                    args=(
                        path,
                        starter_opens,
                        q,
                        hw_base,
                        mac_key,
                        stop_flag,
                    ),
                )
                for _ in range(n_starters)
            ]
            # Propagate overlap instrumentation into spawn workers via env
            # (already set above; spawn inherits).
            for p in writers + starters:
                p.start()
            for p in writers:
                p.join(timeout=120)
                assert p.exitcode == 0
            open(stop_flag, "w").write("1")
            for p in starters:
                p.join(timeout=60)
                assert p.exitcode == 0
            results = [
                q.get(timeout=5) for _ in range(n_writers + n_starters)
            ]
            worker_false = sum(
                1
                for status, detail in results
                if status == "err"
                and "RetryRateIntegrityError" in str(detail)
            )
            assert all(
                status == "ok"
                or (
                    status == "err"
                    and "RetryRateIntegrityError" in str(detail)
                )
                for status, detail in results
            ), results

            overlaps = 0
            if os.path.exists(overlap_file):
                with open(overlap_file, "r", encoding="utf-8") as fh:
                    overlaps = sum(1 for line in fh if line.strip())

            try:
                final = SqliteLedger(path)
                final.check_retry_rate_integrity()
                final.close()
                refusals = worker_false
            except RetryRateIntegrityError:
                refusals = worker_false + 1

            print(
                f"eight_processes_round={round_idx} "
                f"false_refusals={refusals} overlaps={overlaps}"
            )
            return refusals, overlaps

    for i in range(rounds):
        r, o = _one_round(i)
        false_refusals += r
        total_overlaps += o

    print(
        f"eight_processes_false_refusal_count={false_refusals} "
        f"eight_processes_startup_write_overlaps={total_overlaps} "
        f"(rounds={rounds}, writers={n_writers}, starters={n_starters}, "
        f"per_writer={per_writer}, starter_opens={starter_opens})"
    )
    assert false_refusals == 0, (
        f"false RetryRateIntegrityError count {false_refusals} > 0"
    )
    assert total_overlaps > 0, (
        f"startup/write overlaps={total_overlaps}; test did not race the "
        "orphan path"
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


def test_hw_sidecar_missing_with_db_rows_refuses_start():
    """DB has rate rows + missing sidecar → refuse to open (never recreate from 0)."""
    import tempfile

    import settlement.verifier as vmod
    from permit.retry_rate_store import (
        RetryRateIntegrityError,
        _hw_entry_path,
        clear_retry_rate_mac_key_cache,
    )
    from permit.sqlite_ledger import SqliteLedger

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        clock = [1_000_000.0]
        verifier, ledger, evidence = _sqlite_refused_setup(
            path, clock, n_denials=n, over=1
        )
        side = ledger.retry_rate_store.get_open("esc_1")
        assert side is not None
        hw_path = _hw_entry_path(side.escrow_id, side.window_id)
        assert os.path.exists(hw_path)
        ledger.close()
        os.remove(hw_path)
        clear_retry_rate_mac_key_cache()
        with pytest.raises(RetryRateIntegrityError, match="missing|refuse to start"):
            SqliteLedger(path)


def test_hw_sidecar_truncated_corrupt_unreadable_fail_closed():
    """Truncated / corrupt sidecar → RetryRateIntegrityError (never restart from 0)."""
    import tempfile

    import settlement.verifier as vmod
    from permit.retry_rate_store import (
        RetryRateIntegrityError,
        _hw_entry_path,
        get_high_water,
    )

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        clock = [1_000_000.0]
        verifier, ledger, evidence = _sqlite_refused_setup(
            path, clock, n_denials=n, over=1
        )
        side = ledger.retry_rate_store.get_open("esc_1")
        assert side is not None
        hw_path = _hw_entry_path(side.escrow_id, side.window_id)

        with open(hw_path, "wb") as fh:
            fh.write(b"")
        os.chmod(hw_path, 0o600)
        with pytest.raises(RetryRateIntegrityError, match="truncated|empty|refuse"):
            get_high_water(side.escrow_id, side.window_id)

        with open(hw_path, "wb") as fh:
            fh.write(b"not-an-int\n")
        os.chmod(hw_path, 0o600)
        with pytest.raises(RetryRateIntegrityError, match="corrupt|refuse"):
            get_high_water(side.escrow_id, side.window_id)

        ledger.close()


def test_hw_sidecar_wrong_mode_refuses():
    """Startup / read: sidecar mode != 0600 → refuse."""
    import tempfile

    import settlement.verifier as vmod
    from permit.retry_rate_store import (
        RetryRateIntegrityError,
        _hw_entry_path,
        get_high_water,
    )

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        clock = [1_000_000.0]
        verifier, ledger, evidence = _sqlite_refused_setup(
            path, clock, n_denials=n, over=1
        )
        side = ledger.retry_rate_store.get_open("esc_1")
        assert side is not None
        hw_path = _hw_entry_path(side.escrow_id, side.window_id)
        os.chmod(hw_path, 0o644)
        with pytest.raises(RetryRateIntegrityError, match="0600|mode"):
            get_high_water(side.escrow_id, side.window_id)
        # Wrong owner (spoof euid) also refuses.
        import permit.retry_rate_store as rrs

        real_euid = os.geteuid()
        os.chmod(hw_path, 0o600)
        orig = os.geteuid
        os.geteuid = lambda: real_euid + 1  # type: ignore[assignment]
        try:
            with pytest.raises(RetryRateIntegrityError, match="owner|euid"):
                get_high_water(side.escrow_id, side.window_id)
        finally:
            os.geteuid = orig  # type: ignore[assignment]
        ledger.close()


def test_hw_crash_after_sql_before_confirm_no_lost_counts():
    """Crash between SQL COMMIT and intent confirm: recover via intent record."""
    import tempfile

    import settlement.verifier as vmod
    from permit.retry_rate_store import (
        _hw_entry_path,
        _read_hw_record,
        clear_hw_test_hooks,
        get_high_water,
        set_hw_test_hooks,
    )

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        clock = [1_000_000.0]
        verifier, ledger, evidence = _sqlite_refused_setup(
            path, clock, n_denials=n, over=5
        )
        side = ledger.retry_rate_store.get_open("esc_1")
        assert side is not None
        before = side.rate_limited
        assert get_high_water(side.escrow_id, side.window_id) == before

        set_hw_test_hooks(crash_after="after_sql_before_confirm")
        try:
            with pytest.raises(RetryRateIntegrityError, match="injected crash"):
                verifier.verify_and_capture("esc_1", evidence)
        finally:
            clear_hw_test_hooks()

        side2 = ledger.retry_rate_store.get_open("esc_1")
        assert side2 is not None
        assert side2.rate_limited == before + 1
        rec = _read_hw_record(_hw_entry_path(side2.escrow_id, side2.window_id))
        assert rec.confirmed == before and rec.intent == before + 1

        # Next honest step reconciles intent → confirm; no false refusal.
        assert (
            verifier.verify_and_capture("esc_1", evidence).reason == "rate_limited"
        )
        side3 = ledger.retry_rate_store.get_open("esc_1")
        assert side3 is not None
        assert side3.rate_limited == before + 2
        assert get_high_water(side3.escrow_id, side3.window_id) == before + 2
        ledger.close()


def test_hw_crash_after_intent_before_sql_no_false_refusal():
    """Crash after intent write before SQL: clear intent; no false refusal."""
    import tempfile

    import settlement.verifier as vmod
    from permit.retry_rate_store import (
        _hw_entry_path,
        _read_hw_record,
        clear_hw_test_hooks,
        get_high_water,
        set_hw_test_hooks,
    )

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        clock = [1_000_000.0]
        verifier, ledger, evidence = _sqlite_refused_setup(
            path, clock, n_denials=n, over=5
        )
        side = ledger.retry_rate_store.get_open("esc_1")
        assert side is not None
        before = side.rate_limited

        set_hw_test_hooks(crash_after="after_intent")
        try:
            with pytest.raises(RetryRateIntegrityError, match="injected crash"):
                verifier.verify_and_capture("esc_1", evidence)
        finally:
            clear_hw_test_hooks()

        side2 = ledger.retry_rate_store.get_open("esc_1")
        assert side2 is not None
        assert side2.rate_limited == before
        rec = _read_hw_record(_hw_entry_path(side2.escrow_id, side2.window_id))
        assert rec.confirmed == before and rec.intent == before + 1

        assert (
            verifier.verify_and_capture("esc_1", evidence).reason == "rate_limited"
        )
        side3 = ledger.retry_rate_store.get_open("esc_1")
        assert side3 is not None
        assert side3.rate_limited == before + 1
        assert get_high_water(side3.escrow_id, side3.window_id) == before + 1
        ledger.close()


def _mp_hw_concurrency_worker(path, clock_value, n_iters, out_q, hw_path, mac_key):
    """Two-process worker: flood over-limit increments on shared DB+sidecar."""
    try:
        import sqlite3

        from permit.permit import PermitStore
        from permit.retry_rate_store import clear_retry_rate_mac_key_cache
        from permit.sqlite_ledger import SqliteLedger
        from settlement.paypal_client import MockPayPalClient
        from settlement.verifier import Evidence, ReleaseVerifier

        os.environ["PERMIT_RETRY_RATE_MAC_KEY"] = mac_key
        os.environ["PERMIT_RETRY_RATE_MAC_HW_FILE"] = hw_path
        clear_retry_rate_mac_key_cache()

        ledger = SqliteLedger(path)
        permits = PermitStore(ledger=ledger)
        paypal = MockPayPalClient()

        def now():
            return clock_value

        verifier = ReleaseVerifier(paypal, permits, ledger=ledger, clock=now)
        verifier._terminal_reasons["esc_1"] = "already_refused"
        evidence = Evidence(delivered_bytes=b"delivered work product")
        ok = 0
        for _ in range(n_iters):
            for attempt in range(8):
                try:
                    r = verifier.verify_and_capture("esc_1", evidence)
                    assert r.reason == "rate_limited"
                    ok += 1
                    break
                except sqlite3.OperationalError as exc:
                    if "locked" not in str(exc).lower() or attempt == 7:
                        raise
                    import time

                    time.sleep(0.01 * (attempt + 1))
        ledger.close()
        out_q.put(("ok", ok))
    except BaseException as exc:  # noqa: BLE001
        out_q.put(("err", repr(exc)))


def test_hw_two_process_concurrency_atomic_updates():
    """Two processes: exclusive flock + atomic rename; final DB == HW == total."""
    import multiprocessing as mp
    import tempfile

    import settlement.verifier as vmod
    from permit.retry_rate_store import get_high_water

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    per = 40
    mac_key = os.environ["PERMIT_RETRY_RATE_MAC_KEY"]

    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        clock = [3_000_000.0]
        verifier, ledger, evidence = _sqlite_refused_setup(
            path, clock, n_denials=n, over=0
        )
        hw_path = os.environ["PERMIT_RETRY_RATE_MAC_HW_FILE"]
        side0 = ledger.retry_rate_store.get_open("esc_1")
        assert side0 is not None and side0.rate_limited == 0
        ledger.close()

        ctx = mp.get_context("spawn")
        q = ctx.Queue()
        procs = [
            ctx.Process(
                target=_mp_hw_concurrency_worker,
                args=(path, clock[0], per, q, hw_path, mac_key),
            )
            for _ in range(2)
        ]
        for p in procs:
            p.start()
        results = [q.get(timeout=120) for _ in procs]
        for p in procs:
            p.join(timeout=60)
            assert p.exitcode == 0, p.exitcode

        errs = [r for r in results if r[0] == "err"]
        assert not errs, errs
        total_ok = sum(r[1] for r in results if r[0] == "ok")
        assert total_ok == 2 * per

        from permit.sqlite_ledger import SqliteLedger

        final = SqliteLedger(path)
        side = final.retry_rate_store.get_open("esc_1")
        assert side is not None
        assert side.rate_limited == 2 * per
        assert get_high_water(side.escrow_id, side.window_id) == 2 * per
        final.close()


def test_no_demo_mac_key_constant_exists():
    """_DEMO_MAC_KEY and ALLOW_DEMO env path must be gone."""
    import permit.retry_rate_store as rrs

    assert not hasattr(rrs, "_DEMO_MAC_KEY")
    assert not hasattr(rrs, "_ENV_ALLOW_DEMO")
    src = open(rrs.__file__, encoding="utf-8").read()
    assert "_DEMO_MAC_KEY" not in src
    assert "PERMIT_RETRY_RATE_ALLOW_DEMO_MAC_KEY" not in src


def test_ledger_and_verifier_ctors_reject_bad_keys():
    """SqliteLedger and ReleaseVerifier constructors validate the MAC key."""
    import tempfile

    import permit.retry_rate_store as rrs
    from permit.permit import PermitStore
    from permit.sqlite_ledger import SqliteLedger
    from settlement.paypal_client import MockPayPalClient

    rrs.clear_retry_rate_mac_key_cache()
    old_key = os.environ.pop("PERMIT_RETRY_RATE_MAC_KEY", None)
    old_file = os.environ.pop("PERMIT_RETRY_RATE_MAC_KEY_FILE", None)
    try:
        with tempfile.TemporaryDirectory() as td:
            # Missing key
            with pytest.raises(RetryRateIntegrityError, match="unset|refuse"):
                SqliteLedger(td + "/missing.sqlite")
            with pytest.raises(RetryRateIntegrityError, match="unset|refuse"):
                ReleaseVerifier(MockPayPalClient(), PermitStore())

            # Empty key
            os.environ["PERMIT_RETRY_RATE_MAC_KEY"] = ""
            rrs.clear_retry_rate_mac_key_cache()
            with pytest.raises(RetryRateIntegrityError, match="empty"):
                SqliteLedger(td + "/empty.sqlite")
            with pytest.raises(RetryRateIntegrityError, match="empty"):
                ReleaseVerifier(MockPayPalClient(), PermitStore())

            # 31-byte key
            os.environ["PERMIT_RETRY_RATE_MAC_KEY"] = "x" * 31
            rrs.clear_retry_rate_mac_key_cache()
            with pytest.raises(RetryRateIntegrityError, match="too short"):
                SqliteLedger(td + "/short.sqlite")
            with pytest.raises(RetryRateIntegrityError, match="too short"):
                ReleaseVerifier(MockPayPalClient(), PermitStore())
    finally:
        if old_key is None:
            os.environ.pop("PERMIT_RETRY_RATE_MAC_KEY", None)
        else:
            os.environ["PERMIT_RETRY_RATE_MAC_KEY"] = old_key
        if old_file is not None:
            os.environ["PERMIT_RETRY_RATE_MAC_KEY_FILE"] = old_file
        _restore_suite_mac_key()


def test_rollback_50_to_49_exact_match_x30():
    """50→49 DB rollback vs confirmed=50 file must refuse; 30 repeats."""
    import tempfile

    import settlement.verifier as vmod
    from permit.retry_rate_store import RetryRateRow

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    for round_i in range(30):
        with tempfile.TemporaryDirectory() as td:
            path = td + f"/ledger_{round_i}.sqlite"
            clock = [1_000_000.0 + round_i]
            verifier, ledger, evidence = _sqlite_refused_setup(
                path, clock, n_denials=n, over=50
            )
            side = ledger.retry_rate_store.get_open("esc_1")
            assert side is not None and side.rate_limited == 50
            saved = RetryRateRow(
                escrow_id=side.escrow_id,
                window_id=side.window_id,
                window_start=side.window_start,
                individual=side.individual,
                rate_limited=49,
                covered_reason=side.covered_reason,
                tally_flushed=False,
                rate_mac=side.rate_mac,  # stale mac; HW equality fails first
                prev_rate_mac=side.prev_rate_mac,
            )
            # Forge a MAC for count=49 so HMAC alone isn't the only bar —
            # exact HW match must still catch the rollback.
            from permit.retry_rate_store import rate_limited_mac

            anchor = ledger.latest_denial_hash(side.escrow_id, side.window_id)
            saved.rate_mac = rate_limited_mac(
                anchor,
                side.escrow_id,
                side.window_id,
                49,
                prev_mac=side.prev_rate_mac,
                high_water=49,
            )
            before = len(ledger)
            _raw_sql_rollback_side_row(ledger, saved)
            with pytest.raises(
                RetryRateIntegrityError,
                match="sidecar != DB|exact match|rollback|confirmed != DB|process high-water",
            ):
                verifier.verify_and_capture("esc_1", evidence)
            assert len(ledger) == before
            ledger.close()


def test_live_joint_rollback_caught_by_process_hw():
    """Live joint rollback of DB+file (no key theft): process HW catches it."""
    import tempfile

    import settlement.verifier as vmod
    from permit.retry_rate_store import (
        HighWaterRecord,
        _atomic_write_hw_record,
        _hw_entry_path,
        _hw_lock_path,
        process_high_water,
        rate_limited_mac,
    )

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        clock = [1_000_000.0]
        verifier, ledger, evidence = _sqlite_refused_setup(
            path, clock, n_denials=n, over=20
        )
        side = ledger.retry_rate_store.get_open("esc_1")
        assert side is not None and side.rate_limited == 20
        assert process_high_water(side.escrow_id, side.window_id) == 20

        # Joint rollback: rewrite file + DB to 10 with valid file HMAC + rate_mac.
        target = 10
        hw_path = _hw_entry_path(side.escrow_id, side.window_id)
        lock_path = _hw_lock_path(hw_path)
        import fcntl as _fcntl

        lock_fd = os.open(lock_path, os.O_RDWR)
        try:
            _fcntl.flock(lock_fd, _fcntl.LOCK_EX)
            rec = HighWaterRecord(
                escrow_id=side.escrow_id,
                window_id=side.window_id,
                confirmed=target,
                intent=None,
            )
            _atomic_write_hw_record(hw_path, rec)
        finally:
            _fcntl.flock(lock_fd, _fcntl.LOCK_UN)
            os.close(lock_fd)

        anchor = ledger.latest_denial_hash(side.escrow_id, side.window_id)
        forged_mac = rate_limited_mac(
            anchor,
            side.escrow_id,
            side.window_id,
            target,
            prev_mac=side.prev_rate_mac,
            high_water=target,
        )
        from permit.retry_rate_store import RetryRateRow

        _raw_sql_rollback_side_row(
            ledger,
            RetryRateRow(
                escrow_id=side.escrow_id,
                window_id=side.window_id,
                window_start=side.window_start,
                individual=side.individual,
                rate_limited=target,
                covered_reason=side.covered_reason,
                tally_flushed=False,
                rate_mac=forged_mac,
                prev_rate_mac=side.prev_rate_mac,
            ),
        )
        with pytest.raises(
            RetryRateIntegrityError, match="process high-water|live joint rollback"
        ):
            verifier.verify_and_capture("esc_1", evidence)
        ledger.close()


class _FileAnchorStub:
    """Persists the latest rate_mac; check_startup refuses if missing after restart."""

    def __init__(self, path: str) -> None:
        self.path = path

    def __call__(self, rate_mac: str) -> None:
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(rate_mac)

    def check_startup(self, macs: set[str]) -> None:
        if not os.path.exists(self.path):
            return
        last = open(self.path, encoding="utf-8").read().strip()
        if last and last not in macs:
            raise RetryRateIntegrityError(
                f"anchor rate_mac {last!r} missing from DB after restart; "
                "refuse (joint on-disk rollback)"
            )


def test_restart_joint_rollback_caught_with_anchor_stub():
    """Restart after joint DB+file rollback: anchor stub catches it."""
    import tempfile

    import settlement.verifier as vmod
    from permit.retry_rate_store import (
        HighWaterRecord,
        _atomic_write_hw_record,
        _hw_entry_path,
        _hw_lock_path,
        clear_rate_mac_anchor,
        clear_retry_rate_mac_key_cache,
        rate_limited_mac,
        set_rate_mac_anchor,
    )
    from permit.sqlite_ledger import SqliteLedger

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        anchor_path = td + "/anchor.mac"
        clock = [1_000_000.0]
        stub = _FileAnchorStub(anchor_path)
        set_rate_mac_anchor(stub, url="https://example.invalid/anchor")
        try:
            verifier, ledger, evidence = _sqlite_refused_setup(
                path, clock, n_denials=n, over=15
            )
            side = ledger.retry_rate_store.get_open("esc_1")
            assert side is not None
            assert os.path.exists(anchor_path)
            anchored = open(anchor_path, encoding="utf-8").read().strip()
            assert anchored == side.rate_mac
            ledger.close()

            # Joint rollback on disk (no process HW): rewrite DB+file to 5.
            import fcntl as _fcntl
            import sqlite3

            from permit.retry_rate_store import _DDL_RATE_LIMITED_MONOTONIC

            target = 5
            conn = sqlite3.connect(path)
            conn.execute("DROP TRIGGER IF EXISTS retry_rate_rate_limited_monotonic")
            anchor_hash = None
            row = conn.execute(
                "SELECT escrow_id, window_id, window_start, individual,"
                " covered_reason, prev_rate_mac, rate_mac FROM retry_rate_windows"
                " WHERE tally_flushed = 0"
            ).fetchone()
            assert row is not None
            eid, wid = row[0], row[1]
            # Keep prev_mac; mint a valid mac for target under the key.
            # Need latest denial hash from receipts.
            den = conn.execute(
                "SELECT hash FROM receipts WHERE event_type='REFUSED'"
                " AND refusal_kind='already' AND escrow_id=? AND window_id=?"
                " ORDER BY seq DESC LIMIT 1",
                (eid, wid),
            ).fetchone()
            assert den is not None
            forged = rate_limited_mac(
                den[0], eid, wid, target, prev_mac=row[5] or "", high_water=target
            )
            conn.execute(
                "UPDATE retry_rate_windows SET rate_limited=?, rate_mac=?"
                " WHERE escrow_id=? AND window_id=?",
                (target, forged, eid, wid),
            )
            conn.commit()
            conn.execute(_DDL_RATE_LIMITED_MONOTONIC)
            conn.close()

            hw_path = _hw_entry_path(eid, wid)
            lock_path = _hw_lock_path(hw_path)
            lock_fd = os.open(lock_path, os.O_RDWR)
            try:
                _fcntl.flock(lock_fd, _fcntl.LOCK_EX)
                _atomic_write_hw_record(
                    hw_path,
                    HighWaterRecord(
                        escrow_id=eid, window_id=wid, confirmed=target, intent=None
                    ),
                )
            finally:
                _fcntl.flock(lock_fd, _fcntl.LOCK_UN)
                os.close(lock_fd)

            clear_retry_rate_mac_key_cache()
            with pytest.raises(
                RetryRateIntegrityError, match="anchor rate_mac|joint on-disk"
            ):
                SqliteLedger(path)
        finally:
            clear_rate_mac_anchor()
            clear_retry_rate_mac_key_cache()


def test_hw_symlink_counter_file_refused():
    """Planted symlink at the counter file path → refuse (seq 386)."""
    import tempfile

    import settlement.verifier as vmod
    from permit.retry_rate_store import _hw_entry_path, get_high_water

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        clock = [1_000_000.0]
        _verifier, ledger, _evidence = _sqlite_refused_setup(
            path, clock, n_denials=n, over=1
        )
        side = ledger.retry_rate_store.get_open("esc_1")
        assert side is not None
        hw_path = _hw_entry_path(side.escrow_id, side.window_id)
        real = hw_path + ".real"
        os.rename(hw_path, real)
        os.symlink(real, hw_path)
        with pytest.raises(RetryRateIntegrityError, match="symlink"):
            get_high_water(side.escrow_id, side.window_id)
        ledger.close()


def test_hw_symlink_lock_file_refused():
    """Planted symlink at the lock file path → refuse (seq 386)."""
    import tempfile

    import settlement.verifier as vmod
    from permit.retry_rate_store import _hw_entry_path, _hw_lock_path, get_high_water

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        clock = [1_000_000.0]
        _verifier, ledger, _evidence = _sqlite_refused_setup(
            path, clock, n_denials=n, over=1
        )
        side = ledger.retry_rate_store.get_open("esc_1")
        assert side is not None
        hw_path = _hw_entry_path(side.escrow_id, side.window_id)
        lock_path = _hw_lock_path(hw_path)
        assert os.path.exists(lock_path)
        real_lock = lock_path + ".real"
        os.rename(lock_path, real_lock)
        os.symlink(real_lock, lock_path)
        with pytest.raises(RetryRateIntegrityError, match="symlink"):
            get_high_water(side.escrow_id, side.window_id)
        ledger.close()


def test_hw_symlink_parent_directory_refused():
    """Planted symlink as the HW parent directory → refuse (seq 386)."""
    import tempfile

    import permit.retry_rate_store as rrs
    import settlement.verifier as vmod

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        clock = [1_000_000.0]
        _verifier, ledger, _evidence = _sqlite_refused_setup(
            path, clock, n_denials=n, over=1
        )
        decoy = td + "/decoy_hw"
        os.mkdir(decoy, 0o700)
        link = td + "/hw_link"
        os.symlink(decoy, link)
        old_hw = os.environ.get("PERMIT_RETRY_RATE_MAC_HW_FILE")
        os.environ["PERMIT_RETRY_RATE_MAC_HW_FILE"] = link
        rrs.clear_retry_rate_mac_key_cache()
        try:
            with pytest.raises(RetryRateIntegrityError, match="symlink"):
                rrs._hw_root_dir()
        finally:
            if old_hw is None:
                os.environ.pop("PERMIT_RETRY_RATE_MAC_HW_FILE", None)
            else:
                os.environ["PERMIT_RETRY_RATE_MAC_HW_FILE"] = old_hw
            rrs.clear_retry_rate_mac_key_cache()
            rrs.load_retry_rate_mac_key(refresh=True)
        ledger.close()


def test_hw_symlink_temp_file_refused(monkeypatch):
    """Planted symlink at the atomic-write temp path → refuse (seq 386)."""
    import tempfile

    import settlement.verifier as vmod
    from permit.retry_rate_store import (
        HighWaterRecord,
        _atomic_write_hw_record,
        _hw_entry_path,
        _hw_lock_path,
    )

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    fixed = "ab" * 16  # token_hex(16) → 32 hex chars
    monkeypatch.setattr(
        "permit.retry_rate_store.secrets.token_hex",
        lambda nbytes=16: fixed,
    )
    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        clock = [1_000_000.0]
        _verifier, ledger, _evidence = _sqlite_refused_setup(
            path, clock, n_denials=n, over=1
        )
        side = ledger.retry_rate_store.get_open("esc_1")
        assert side is not None
        hw_path = _hw_entry_path(side.escrow_id, side.window_id)
        parent = os.path.dirname(hw_path)
        tmp = os.path.join(parent, f".hwtmp.{fixed}.{os.getpid()}")
        decoy = td + "/decoy_payload"
        open(decoy, "wb").write(b"x")
        os.symlink(decoy, tmp)
        import fcntl as _fcntl

        lock_fd = os.open(_hw_lock_path(hw_path), os.O_RDWR)
        try:
            _fcntl.flock(lock_fd, _fcntl.LOCK_EX)
            with pytest.raises(RetryRateIntegrityError, match="symlink|temp file"):
                _atomic_write_hw_record(
                    hw_path,
                    HighWaterRecord(
                        escrow_id=side.escrow_id,
                        window_id=side.window_id,
                        confirmed=1,
                        intent=None,
                    ),
                )
        finally:
            _fcntl.flock(lock_fd, _fcntl.LOCK_UN)
            os.close(lock_fd)
        ledger.close()


def test_check_high_water_has_no_skew_tolerance():
    """grep-backed behaviour: count==hw-1 (50 vs 49) refuses, no +1 allowance."""
    import tempfile

    import settlement.verifier as vmod
    from permit.retry_rate_store import check_high_water

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        clock = [1_000_000.0]
        verifier, ledger, evidence = _sqlite_refused_setup(
            path, clock, n_denials=n, over=50
        )
        side = ledger.retry_rate_store.get_open("esc_1")
        assert side is not None
        with pytest.raises(
            RetryRateIntegrityError,
            match="exact match|!= DB|process high-water|rollback",
        ):
            check_high_water(side.escrow_id, side.window_id, 49)
        # Exact match still ok.
        assert check_high_water(side.escrow_id, side.window_id, 50) == 50
        ledger.close()


def test_lowered_counter_file_caught():
    """Attack: lower only the HMAC-tied counter file; DB stays high → refuse."""
    import fcntl as _fcntl
    import tempfile

    import settlement.verifier as vmod
    from permit.retry_rate_store import (
        HighWaterRecord,
        _atomic_write_hw_record,
        _hw_entry_path,
        _hw_lock_path,
    )

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        clock = [1_000_000.0]
        verifier, ledger, evidence = _sqlite_refused_setup(
            path, clock, n_denials=n, over=50
        )
        side = ledger.retry_rate_store.get_open("esc_1")
        assert side is not None and side.rate_limited == 50
        hw_path = _hw_entry_path(side.escrow_id, side.window_id)
        lock_fd = os.open(_hw_lock_path(hw_path), os.O_RDWR)
        try:
            _fcntl.flock(lock_fd, _fcntl.LOCK_EX)
            # Valid file HMAC for a lowered confirmed — key assumed stolen for
            # the file only; DB count remains 50 so exact match must refuse.
            _atomic_write_hw_record(
                hw_path,
                HighWaterRecord(
                    escrow_id=side.escrow_id,
                    window_id=side.window_id,
                    confirmed=40,
                    intent=None,
                ),
            )
        finally:
            _fcntl.flock(lock_fd, _fcntl.LOCK_UN)
            os.close(lock_fd)
        before = len(ledger)
        with pytest.raises(
            RetryRateIntegrityError,
            match="sidecar != DB|exact match|confirmed != DB|process high-water|rollback",
        ):
            verifier.verify_and_capture("esc_1", evidence)
        assert len(ledger) == before
        ledger.close()


def _sigkill_joint_rollback_worker(path, hw_base, mac_key, ready_q):
    """Child: open ledger (loads process HW), signal ready, sleep until SIGKILL."""
    import time

    from permit.retry_rate_store import clear_retry_rate_mac_key_cache
    from permit.sqlite_ledger import SqliteLedger

    os.environ["PERMIT_RETRY_RATE_MAC_KEY"] = mac_key
    os.environ["PERMIT_RETRY_RATE_MAC_HW_FILE"] = hw_base
    clear_retry_rate_mac_key_cache()
    ledger = SqliteLedger(path)
    ready_q.put(("ready", os.getpid()))
    # Hold the process (and in-process HW) until the parent SIGKILLs us.
    while True:
        time.sleep(60)


def _run_joint_rollback_with_sigkill_between_steps(
    *,
    use_anchor: bool,
) -> bool:
    """
    Build state, hold a live child, roll DB back, SIGKILL child, roll file back,
    then reopen. Returns True if the joint rollback was detected (refused).
    """
    import multiprocessing as mp
    import signal
    import tempfile

    import settlement.verifier as vmod
    from permit.retry_rate_store import (
        clear_rate_mac_anchor,
        clear_retry_rate_mac_key_cache,
        set_rate_mac_anchor,
    )
    from permit.sqlite_ledger import SqliteLedger

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    detected = False
    with tempfile.TemporaryDirectory() as td:
        path = td + "/ledger.sqlite"
        anchor_path = td + "/anchor.mac"
        clock = [1_000_000.0]
        if use_anchor:
            set_rate_mac_anchor(
                _FileAnchorStub(anchor_path),
                url="https://example.invalid/anchor",
            )
        try:
            _verifier, ledger, _evidence = _sqlite_refused_setup(
                path, clock, n_denials=n, over=20
            )
            side = ledger.retry_rate_store.get_open("esc_1")
            assert side is not None and side.rate_limited == 20
            hw_base = os.environ["PERMIT_RETRY_RATE_MAC_HW_FILE"]
            mac_key = os.environ["PERMIT_RETRY_RATE_MAC_KEY"]
            ledger.close()

            ctx = mp.get_context("spawn")
            ready_q = ctx.Queue()
            child = ctx.Process(
                target=_sigkill_joint_rollback_worker,
                args=(path, hw_base, mac_key, ready_q),
            )
            child.start()
            status, child_pid = ready_q.get(timeout=30)
            assert status == "ready" and child_pid == child.pid

            # Step 1 of joint rollback (DB only), then SIGKILL, then file.
            import fcntl as _fcntl
            import sqlite3

            from permit.retry_rate_store import (
                HighWaterRecord,
                _DDL_RATE_LIMITED_MONOTONIC,
                _atomic_write_hw_record,
                _hw_entry_path,
                _hw_lock_path,
                rate_limited_mac,
            )

            target = 8
            conn = sqlite3.connect(path)
            conn.execute("DROP TRIGGER IF EXISTS retry_rate_rate_limited_monotonic")
            row = conn.execute(
                "SELECT escrow_id, window_id, prev_rate_mac FROM retry_rate_windows"
                " WHERE tally_flushed = 0"
            ).fetchone()
            assert row is not None
            eid, wid, prev_mac = row[0], row[1], row[2] or ""
            den = conn.execute(
                "SELECT hash FROM receipts WHERE event_type='REFUSED'"
                " AND refusal_kind='already' AND escrow_id=? AND window_id=?"
                " ORDER BY seq DESC LIMIT 1",
                (eid, wid),
            ).fetchone()
            assert den is not None
            forged = rate_limited_mac(
                den[0], eid, wid, target, prev_mac=prev_mac, high_water=target
            )
            conn.execute(
                "UPDATE retry_rate_windows SET rate_limited=?, rate_mac=?"
                " WHERE escrow_id=? AND window_id=?",
                (target, forged, eid, wid),
            )
            conn.commit()
            conn.execute(_DDL_RATE_LIMITED_MONOTONIC)
            conn.close()

            # Between the two rollback steps: force-kill the honest process.
            os.kill(child.pid, signal.SIGKILL)
            child.join(timeout=10)
            assert child.exitcode is not None  # reaped after SIGKILL

            hw_path = _hw_entry_path(eid, wid)
            lock_fd = os.open(_hw_lock_path(hw_path), os.O_RDWR)
            try:
                _fcntl.flock(lock_fd, _fcntl.LOCK_EX)
                _atomic_write_hw_record(
                    hw_path,
                    HighWaterRecord(
                        escrow_id=eid, window_id=wid, confirmed=target, intent=None
                    ),
                )
            finally:
                _fcntl.flock(lock_fd, _fcntl.LOCK_UN)
                os.close(lock_fd)

            clear_retry_rate_mac_key_cache()
            try:
                SqliteLedger(path)
            except RetryRateIntegrityError:
                detected = True
        finally:
            clear_rate_mac_anchor()
            clear_retry_rate_mac_key_cache()
            _restore_suite_mac_key()
    return detected


def test_joint_rollback_sigkill_between_steps_with_anchor():
    """Joint DB+file rollback with SIGKILL between steps; anchor stub catches it."""
    assert _run_joint_rollback_with_sigkill_between_steps(use_anchor=True) is True


@pytest.mark.xfail(
    strict=True,
    reason=(
        "bar 2 decision pending with Marc: cross-restart joint DB+counter-file "
        "rollback with no external anchor is currently detected=False; this "
        "test asserts detection so it XFAILs until that bar lands"
    ),
)
def test_joint_rollback_sigkill_between_steps_no_anchor():
    """Joint DB+file rollback after SIGKILL, no anchor — desire detection."""
    # Currently detected=False without an anchor; xfail(strict) until Marc's
    # bar 2 decision makes this pass (then remove the marker).
    assert _run_joint_rollback_with_sigkill_between_steps(use_anchor=False) is True
