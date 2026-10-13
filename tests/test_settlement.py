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
    RetryRateIntegrityError,
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
        ledger.retry_rate_store.upsert(
            RetryRateRow(
                escrow_id=side.escrow_id,
                window_id=side.window_id,
                window_start=side.window_start,
                individual=side.individual,
                rate_limited=side.rate_limited + 99,  # tamper
                covered_reason=side.covered_reason,
                tally_flushed=True,
            )
        )
        ledger.close()
        ledger2 = SqliteLedger(path)
        permits2 = PermitStore(ledger=ledger2)
        paypal2 = MockPayPalClient()
        with pytest.raises(RetryRateIntegrityError, match="count mismatch"):
            ReleaseVerifier(paypal2, permits2, ledger=ledger2, clock=now)
        ledger2.close()


def test_retry_rate_limit_side_table_tamper_done_flag_without_tally():
    """tally_flushed=1 with no chain tally → refuse to start."""
    import tempfile

    from permit.retry_rate_store import RetryRateRow
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
        # Tamper: claim flushed without ever writing a tally.
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
        with pytest.raises(RetryRateIntegrityError, match="tally_flushed=1"):
            ReleaseVerifier(paypal2, permits2, ledger=ledger2, clock=now)
        ledger2.close()


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
        ledger.retry_rate_store.delete(side.escrow_id, side.window_id)
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
        # Forge a valid MAC so the before-N check (not MAC) is what fires.
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
                    anchor, side.escrow_id, side.window_id, 3
                ),
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
        ledger.retry_rate_store.delete(side.escrow_id, side.window_id)
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


def _mp_flood_worker(path, clock_value, n_iters, out_q):
    """Multiprocessing worker: flood retries on shared Sqlite ledger."""
    try:
        import sqlite3
        import time

        from permit.permit import PermitStore
        from permit.sqlite_ledger import SqliteLedger
        from settlement.paypal_client import MockPayPalClient
        from settlement.verifier import Evidence, ReleaseVerifier

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
        p1 = ctx.Process(
            target=_mp_flood_worker, args=(path, clock_value, per, q)
        )
        p2 = ctx.Process(
            target=_mp_flood_worker, args=(path, clock_value, total - per, q)
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
    from permit.sqlite_ledger import SqliteLedger

    ledger = SqliteLedger(td_path)

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
        # Zero the counter but leave the old MAC → detectable.
        ledger.retry_rate_store.upsert(
            RetryRateRow(
                escrow_id=side.escrow_id,
                window_id=side.window_id,
                window_start=side.window_start,
                individual=side.individual,
                rate_limited=0,
                covered_reason=side.covered_reason,
                tally_flushed=False,
                rate_mac=side.rate_mac,
            )
        )
        with pytest.raises(RetryRateIntegrityError, match="rate_mac mismatch"):
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
        ledger.retry_rate_store.upsert(
            RetryRateRow(
                escrow_id=side.escrow_id,
                window_id=side.window_id,
                window_start=side.window_start,
                individual=side.individual,
                rate_limited=3,
                covered_reason=side.covered_reason,
                tally_flushed=False,
                rate_mac="0" * 64,  # not a valid MAC
            )
        )
        with pytest.raises(RetryRateIntegrityError, match="rate_mac mismatch"):
            verifier.verify_and_capture("esc_1", evidence)
        assert len(ledger) == before
        with pytest.raises(RetryRateIntegrityError, match="rate_mac mismatch"):
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
        ledger.retry_rate_store.upsert(
            RetryRateRow(
                escrow_id=side.escrow_id,
                window_id=side.window_id,
                window_start=side.window_start,
                individual=side.individual,
                rate_limited=0,  # wipe the over-limit counter
                covered_reason=side.covered_reason,
                tally_flushed=False,
                rate_mac=forged,  # unkeyed digest of the forged count
            )
        )
        with pytest.raises(RetryRateIntegrityError, match="rate_mac mismatch"):
            verifier.verify_and_capture("esc_1", evidence)
        assert len(ledger) == before
        assert _tally_count_sum(ledger, "esc_1") == 0
        ledger.close()


def test_retry_rate_limit_eight_processes_no_false_integrity_error():
    """8×2000 retries × 20 rounds: print false-refusal count; fail if > 0."""
    import multiprocessing as mp
    import tempfile

    import settlement.verifier as vmod
    from permit.retry_rate_store import RetryRateIntegrityError
    from permit.sqlite_ledger import SqliteLedger

    n = getattr(vmod, "DEFAULT_RETRY_RATE_LIMIT_N", 100)
    per = 2000
    n_proc = 8
    rounds = 20
    false_refusals = 0

    def _one_round(round_idx: int) -> int:
        """Return 1 if this round saw a false RetryRateIntegrityError, else 0."""
        with tempfile.TemporaryDirectory() as td:
            path = td + f"/ledger_{round_idx}.sqlite"
            clock_value = 2_000_000.0 + round_idx
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
            procs = [
                ctx.Process(
                    target=_mp_flood_worker, args=(path, clock_value, per, q)
                )
                for _ in range(n_proc)
            ]
            for p in procs:
                p.start()
            for p in procs:
                p.join(timeout=120)
                assert p.exitcode == 0
            results = [q.get(timeout=5) for _ in range(n_proc)]
            # Worker-side integrity errors are false refusals under honest load.
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

            try:
                final = SqliteLedger(path)
                final.check_retry_rate_integrity(limit_n=n)
                permits_f = PermitStore(ledger=final)
                paypal_f = MockPayPalClient()
                verifier_f = ReleaseVerifier(
                    paypal_f, permits_f, ledger=final, clock=now
                )
                open_row = final.retry_rate_store.get_open("esc_1")
                assert open_row is not None
                assert open_row.individual == n
                total = n_proc * per
                assert open_row.rate_limited == total - n
                verifier_f.flush_retry_rate_limits("esc_1")
                final.sync_receipts_from_db()
                assert len(_rate_limited_receipts(final, "esc_1")) == 1
                assert _tally_count_sum(final, "esc_1") == total - n
                assert len(final) - before == n + 1
                final.close()
                return worker_false
            except RetryRateIntegrityError:
                return worker_false + 1

    for i in range(rounds):
        false_refusals += _one_round(i)

    print(
        f"eight_processes_false_refusal_count={false_refusals} "
        f"(rounds={rounds}, procs={n_proc}, per={per})"
    )
    assert false_refusals == 0, (
        f"false RetryRateIntegrityError count {false_refusals} > 0"
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
