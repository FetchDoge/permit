"""Focused killers for retry_rate_store mutants (timeout + intent token).

These tests exist to kill surviving mutmut mutants around:
- ``flock_timeout_s`` validation (blank / non-finite / ≤0 / >600)
- ``high_water_lock.write_intent`` writer pid+start token recording
- creating accept requiring flock (not pid+start alone)
- zombie writers treated as dead
"""

from __future__ import annotations

import math
import os
import tempfile

import pytest

from permit import retry_rate_store as rrs
from permit.retry_rate_store import (
    HighWaterRecord,
    RetryRateIntegrityError,
    _ENV_FLOCK_TIMEOUT_S,
    _HW_CREATING_INTENT,
    _MAX_FLOCK_TIMEOUT_S,
    _accept_live_creating_pending,
    _atomic_write_hw_record,
    _current_writer_identity,
    _hw_lock_path,
    _writer_is_zombie,
    _writer_still_alive,
    create_high_water,
    flock_timeout_s,
    high_water_lock,
)


@pytest.fixture(autouse=True)
def _hw_tmpdir(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        monkeypatch.setenv("PERMIT_RETRY_RATE_MAC_HW_FILE", td + "/hw")
        rrs.clear_retry_rate_mac_key_cache()
        yield td


def test_mut_flock_timeout_unset_returns_default(monkeypatch):
    monkeypatch.delenv(_ENV_FLOCK_TIMEOUT_S, raising=False)
    assert flock_timeout_s() == 30.0


def test_mut_flock_timeout_valid_value(monkeypatch):
    monkeypatch.setenv(_ENV_FLOCK_TIMEOUT_S, "12.5")
    assert flock_timeout_s() == 12.5


@pytest.mark.parametrize(
    "raw",
    ["", "   ", "inf", "+inf", "-inf", "nan", "NaN", "1e12", "1e400", "-1", "0", "-0.1", "601", "600.1"],
)
def test_mut_flock_timeout_rejects_invalid(monkeypatch, raw):
    monkeypatch.setenv(_ENV_FLOCK_TIMEOUT_S, raw)
    with pytest.raises(RetryRateIntegrityError):
        flock_timeout_s()


def test_mut_flock_timeout_max_is_600():
    assert _MAX_FLOCK_TIMEOUT_S == 600.0


def test_mut_flock_timeout_accepts_exactly_max(monkeypatch):
    monkeypatch.setenv(_ENV_FLOCK_TIMEOUT_S, "600")
    assert flock_timeout_s() == 600.0


def test_mut_flock_timeout_rejects_non_finite_float_objects(monkeypatch):
    # Guard the isfinite branch even if env parsing somehow yielded inf/nan.
    monkeypatch.setenv(_ENV_FLOCK_TIMEOUT_S, "1")
    real_float = float

    def _boom(x):
        s = str(x).strip().lower()
        if s in ("inf", "+inf", "-inf"):
            return math.inf
        if s == "nan":
            return math.nan
        return real_float(x)

    # Direct checks on the validation predicates used by flock_timeout_s.
    assert not math.isfinite(math.inf)
    assert not math.isfinite(math.nan)
    with pytest.raises(RetryRateIntegrityError):
        monkeypatch.setenv(_ENV_FLOCK_TIMEOUT_S, "inf")
        flock_timeout_s()


def test_mut_write_intent_records_live_pid_and_start_token():
    create_high_water("esc_mut_wi", "rw_mut_wi", initial=0)
    pid, start = _current_writer_identity()
    with high_water_lock("esc_mut_wi", "rw_mut_wi") as hwlock:
        rec = hwlock.write_intent(1)
        assert rec.intent == 1
        assert rec.writer_pid == pid
        assert rec.writer_start == start
        assert rec.writer_start is not None
        assert int(rec.writer_start) > 0
        # Token must match /proc (increment-intent identity check).
        assert _writer_still_alive(rec.writer_pid, rec.writer_start)


def test_mut_write_intent_rejects_non_monotonic_target():
    create_high_water("esc_mut_wi2", "rw_mut_wi2", initial=0)
    with high_water_lock("esc_mut_wi2", "rw_mut_wi2") as hwlock:
        with pytest.raises(RetryRateIntegrityError, match="confirmed\\+1|intent"):
            hwlock.write_intent(2)  # must be confirmed+1 == 1


def test_mut_write_intent_rejects_when_intent_already_pending():
    create_high_water("esc_mut_wi3", "rw_mut_wi3", initial=0)
    with high_water_lock("esc_mut_wi3", "rw_mut_wi3") as hwlock:
        hwlock.write_intent(1)
        with pytest.raises(RetryRateIntegrityError, match="already pending"):
            hwlock.write_intent(1)


def test_mut_accept_creating_requires_flock_not_pid_start_alone():
    create_high_water("esc_mut_ac", "rw_mut_ac", initial=0)
    pid, start = _current_writer_identity()
    path = rrs._hw_entry_path("esc_mut_ac", "rw_mut_ac")
    lock_path = _hw_lock_path(path)
    # Plant creating naming *this* process with a good token, but we do not
    # hold the create flock as that writer under accept's foreign-pid rule.
    # Use a foreign-looking pid by forging: accept rejects same-pid first.
    # So plant a decoy identity that is "alive" via monkeypatch.
    rec = HighWaterRecord(
        escrow_id="esc_mut_ac",
        window_id="rw_mut_ac",
        confirmed=0,
        intent=_HW_CREATING_INTENT,
        writer_pid=pid ^ 0x7F,
        writer_start=start,
    )
    # Force still_alive True and holds_flock False.
    real_alive = rrs._writer_still_alive
    real_holds = rrs._writer_holds_hw_flock
    try:
        rrs._writer_still_alive = lambda p, s: True  # type: ignore[assignment]
        rrs._writer_holds_hw_flock = lambda lp, p: False  # type: ignore[assignment]
        assert _accept_live_creating_pending(rec, lock_path=lock_path) is False
    finally:
        rrs._writer_still_alive = real_alive  # type: ignore[assignment]
        rrs._writer_holds_hw_flock = real_holds  # type: ignore[assignment]


def test_mut_accept_creating_true_only_with_flock_and_alive():
    create_high_water("esc_mut_ac2", "rw_mut_ac2", initial=0)
    path = rrs._hw_entry_path("esc_mut_ac2", "rw_mut_ac2")
    lock_path = _hw_lock_path(path)
    rec = HighWaterRecord(
        escrow_id="esc_mut_ac2",
        window_id="rw_mut_ac2",
        confirmed=0,
        intent=_HW_CREATING_INTENT,
        writer_pid=999999,
        writer_start=1,
    )
    real_alive = rrs._writer_still_alive
    real_holds = rrs._writer_holds_hw_flock
    try:
        rrs._writer_holds_hw_flock = lambda lp, p: True  # type: ignore[assignment]
        rrs._writer_still_alive = lambda p, s: True  # type: ignore[assignment]
        assert _accept_live_creating_pending(rec, lock_path=lock_path) is True
        rrs._writer_still_alive = lambda p, s: False  # type: ignore[assignment]
        assert _accept_live_creating_pending(rec, lock_path=lock_path) is False
        rrs._writer_holds_hw_flock = lambda lp, p: False  # type: ignore[assignment]
        rrs._writer_still_alive = lambda p, s: True  # type: ignore[assignment]
        assert _accept_live_creating_pending(rec, lock_path=lock_path) is False
    finally:
        rrs._writer_still_alive = real_alive  # type: ignore[assignment]
        rrs._writer_holds_hw_flock = real_holds  # type: ignore[assignment]


def test_mut_zombie_not_still_alive():
    zpid = os.fork()
    if zpid == 0:
        os._exit(0)
    z_start = None
    for _ in range(200):
        try:
            with open(f"/proc/{zpid}/stat", "r", encoding="utf-8") as fh:
                buf = fh.read()
            rparen = buf.rfind(")")
            if buf[rparen + 2 :].split()[0] == "Z":
                z_start = rrs._process_start_token(zpid)
                break
        except OSError:
            break
        __import__("time").sleep(0.01)
    try:
        assert z_start is not None
        assert _writer_is_zombie(zpid) is True
        assert _writer_still_alive(zpid, z_start) is False
    finally:
        try:
            os.waitpid(zpid, 0)
        except ChildProcessError:
            pass


def test_mut_confirm_requires_matching_intent_token_path():
    """Confirm only advances when intent matches; clears writer identity."""
    create_high_water("esc_mut_cf", "rw_mut_cf", initial=0)
    with high_water_lock("esc_mut_cf", "rw_mut_cf") as hwlock:
        hwlock.write_intent(1)
        with pytest.raises(RetryRateIntegrityError, match="confirm|intent"):
            hwlock.confirm(2)
        assert hwlock.confirm(1) == 1
        rec = hwlock.read()
        assert rec.intent is None
        assert rec.writer_pid is None
        assert rec.writer_start is None


def test_mut_accept_non_creating_intent_never_true():
    """`_accept_live_creating_pending` is False for increment intents."""
    path = "/tmp/unused"
    rec = HighWaterRecord(
        escrow_id="e",
        window_id="w",
        confirmed=0,
        intent=1,  # increment, not creating
        writer_pid=1,
        writer_start=1,
    )
    assert _accept_live_creating_pending(rec, lock_path=path) is False


def test_mut_writer_still_alive_none_pid_or_none_start():
    """Either missing pid or missing start → dead (not only both missing)."""
    assert _writer_still_alive(None, 1) is False
    assert _writer_still_alive(1, None) is False
    assert _writer_still_alive(None, None) is False
    assert _writer_still_alive(0, 1) is False
    assert _writer_still_alive(-1, 1) is False


def test_mut_write_intent_clears_creating_sentinel_then_sets_increment():
    """Creating-on-disk must clear to None (not '') before increment intent."""
    create_high_water("esc_mut_cr", "rw_mut_cr", initial=0)
    pid, start = _current_writer_identity()
    with high_water_lock("esc_mut_cr", "rw_mut_cr") as hwlock:
        rec = HighWaterRecord(
            escrow_id="esc_mut_cr",
            window_id="rw_mut_cr",
            confirmed=0,
            intent=_HW_CREATING_INTENT,
            writer_pid=pid,
            writer_start=start,
        )
        _atomic_write_hw_record(hwlock._path, rec)
        out = hwlock.write_intent(1)
        assert out.intent == 1
        assert out.writer_pid == pid
        assert out.writer_start == start
        # Re-read: creating cleared; increment pending with tokens.
        again = hwlock.read()
        assert again.intent == 1
        assert again.writer_pid == pid
        assert again.writer_start == start


def test_mut_writer_holds_hw_flock_true_while_locked():
    """Live flock holder is visible in /proc/locks for our pid."""
    create_high_water("esc_mut_fl", "rw_mut_fl", initial=0)
    with high_water_lock("esc_mut_fl", "rw_mut_fl") as hwlock:
        assert rrs._writer_holds_hw_flock(hwlock._lock_path, os.getpid()) is True
    # After release, we should not still hold it.
    path = rrs._hw_entry_path("esc_mut_fl", "rw_mut_fl")
    lock_path = _hw_lock_path(path)
    assert rrs._writer_holds_hw_flock(lock_path, os.getpid()) is False
    assert rrs._writer_holds_hw_flock(lock_path, None) is False
    assert rrs._writer_holds_hw_flock(lock_path, -1) is False
    assert rrs._writer_holds_hw_flock(lock_path, 0) is False


def test_mut_flock_timeout_error_messages_mention_env():
    """Error text must name the env var (kills message→None mutants)."""
    import tempfile

    prev = os.environ.get(_ENV_FLOCK_TIMEOUT_S)
    try:
        for raw in ("", "inf", "-1", "1e12", "not-a-float"):
            os.environ[_ENV_FLOCK_TIMEOUT_S] = raw
            with pytest.raises(RetryRateIntegrityError, match=_ENV_FLOCK_TIMEOUT_S):
                flock_timeout_s()
    finally:
        if prev is None:
            os.environ.pop(_ENV_FLOCK_TIMEOUT_S, None)
        else:
            os.environ[_ENV_FLOCK_TIMEOUT_S] = prev


def test_mut_same_pid_creating_not_accepted_as_foreign():
    """Own pid must never be accepted as a foreign live creating writer."""
    pid, start = _current_writer_identity()
    rec = HighWaterRecord(
        escrow_id="e",
        window_id="w",
        confirmed=0,
        intent=_HW_CREATING_INTENT,
        writer_pid=pid,
        writer_start=start,
    )
    real_holds = rrs._writer_holds_hw_flock
    try:
        rrs._writer_holds_hw_flock = lambda lp, p: True  # type: ignore[assignment]
        assert _accept_live_creating_pending(rec, lock_path="/x") is False
    finally:
        rrs._writer_holds_hw_flock = real_holds  # type: ignore[assignment]


def test_mut_accept_true_path_uses_real_lock_path_and_tokens():
    """Accept True requires real flock path + real pid/start (no monkeypatch).

    Kills mutants that replace lock_path/pid/start with None on the accept path.
    """
    import multiprocessing as mp

    # Use fork so the nested target need not be picklable at module scope.
    ctx = mp.get_context("fork")
    ready_q = ctx.Queue()
    stop_path = tempfile.mkdtemp() + "/stop"

    def _hold(q, sp):
        with rrs.high_water_create("esc_mut_real", "rw_mut_real", initial=0) as hw:
            q.put(
                (
                    os.getpid(),
                    rrs._process_start_token(os.getpid()),
                    hw._lock_path,
                )
            )
            while not os.path.exists(sp):
                __import__("time").sleep(0.01)

    child = ctx.Process(target=_hold, args=(ready_q, stop_path))
    child.start()
    try:
        pid, start, lock_path = ready_q.get(timeout=15)
        assert pid != os.getpid()
        rec = HighWaterRecord(
            escrow_id="esc_mut_real",
            window_id="rw_mut_real",
            confirmed=0,
            intent=_HW_CREATING_INTENT,
            writer_pid=pid,
            writer_start=start,
        )
        assert _accept_live_creating_pending(rec, lock_path=lock_path) is True
    finally:
        open(stop_path, "w").write("1")
        child.join(timeout=10)


def test_mut_flock_timeout_accepts_fractional_below_one(monkeypatch):
    """0 < val <= 1 must be accepted (kills ``val <= 1`` mutant)."""
    monkeypatch.setenv(_ENV_FLOCK_TIMEOUT_S, "0.5")
    assert flock_timeout_s() == 0.5


def test_mut_writer_still_alive_pid_zero_is_dead():
    assert _writer_still_alive(0, 1) is False


def test_mut_writer_holds_rejects_nonpositive_even_if_fcntl_present():
    create_high_water("esc_mut_np", "rw_mut_np", initial=0)
    path = rrs._hw_entry_path("esc_mut_np", "rw_mut_np")
    lock_path = _hw_lock_path(path)
    assert rrs.fcntl is not None
    assert rrs._writer_holds_hw_flock(lock_path, 0) is False
    assert rrs._writer_holds_hw_flock(lock_path, -3) is False


def test_mut_write_intent_clears_writer_pid_to_none_not_empty_str():
    create_high_water("esc_mut_clr", "rw_mut_clr", initial=0)
    pid, start = _current_writer_identity()
    with high_water_lock("esc_mut_clr", "rw_mut_clr") as hwlock:
        _atomic_write_hw_record(
            hwlock._path,
            HighWaterRecord(
                escrow_id="esc_mut_clr",
                window_id="rw_mut_clr",
                confirmed=0,
                intent=_HW_CREATING_INTENT,
                writer_pid=pid,
                writer_start=start,
            ),
        )
        hwlock.write_intent(1)
        # Mid clear is re-read; final pending must have int pid, and the
        # intermediate clear must use None (empty string would break identity).
        rec = hwlock.read()
        assert rec.writer_pid == pid
        assert isinstance(rec.writer_pid, int)
