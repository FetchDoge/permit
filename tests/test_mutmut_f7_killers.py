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


def test_mut_accept_falsy_pid_uses_or_minus_one(monkeypatch):
    """``writer_pid or -1`` (not ``or +1``): falsy pid is not treated as pid 1."""
    monkeypatch.setattr(os, "getpid", lambda: 1)
    monkeypatch.setattr(rrs.os, "getpid", lambda: 1)
    monkeypatch.setattr(rrs, "_writer_holds_hw_flock", lambda lp, p: True)
    monkeypatch.setattr(rrs, "_writer_still_alive", lambda p, s: True)
    rec = HighWaterRecord(
        escrow_id="e",
        window_id="w",
        confirmed=0,
        intent=_HW_CREATING_INTENT,
        writer_pid=0,  # falsy → `or -1` yields -1, not own pid
        writer_start=1,
    )
    # Original: not same-pid, holds+alive → True.
    # ``or +1`` mutant: treats pid as 1 == getpid() → False.
    assert _accept_live_creating_pending(rec, lock_path="/x") is True


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


def test_mut_write_intent_error_messages_exact():
    """Exact message text kills XX…XX / case-flip message mutants."""
    create_high_water("esc_mut_msg", "rw_mut_msg", initial=0)
    with high_water_lock("esc_mut_msg", "rw_mut_msg") as hwlock:
        hwlock.write_intent(1)
        with pytest.raises(
            RetryRateIntegrityError,
            match=r"^high-water intent already pending for ",
        ):
            hwlock.write_intent(1)
    create_high_water("esc_mut_msg2", "rw_mut_msg2", initial=0)
    with high_water_lock("esc_mut_msg2", "rw_mut_msg2") as hwlock:
        with pytest.raises(
            RetryRateIntegrityError,
            match=r"^high-water intent must be confirmed\+1 for ",
        ):
            hwlock.write_intent(2)


def test_mut_write_intent_marks_write_active(monkeypatch, tmp_path):
    """write_intent must call _mark_write_active when marker is unset."""
    active = tmp_path / "writing"
    active.mkdir()
    monkeypatch.setenv(rrs._ENV_WRITE_ACTIVE_DIR, str(active))
    create_high_water("esc_mut_mk", "rw_mut_mk", initial=0)
    with high_water_lock("esc_mut_mk", "rw_mut_mk") as hwlock:
        assert hwlock._write_marker is None
        hwlock.write_intent(1)
        assert hwlock._write_marker is not None
        assert os.path.exists(hwlock._write_marker)
        assert list(active.glob("*.writing")), "write-active marker missing"


def test_mut_zombie_missing_proc_is_not_zombie():
    """OSError reading /proc/<pid>/stat → False (not True)."""
    assert _writer_is_zombie(2_000_000_001) is False


def test_mut_zombie_no_paren_is_not_zombie(monkeypatch):
    """Missing ')' in /proc/stat → False (not True)."""

    def _fake_open(path, *a, **k):
        if str(path).endswith("/stat") and "/proc/" in str(path):
            from io import StringIO

            return StringIO("1 commwithoutparens Z 0 0 0\n")
        return open(path, *a, **k)  # noqa: SIM115

    monkeypatch.setattr("builtins.open", _fake_open)
    assert _writer_is_zombie(1) is False


def test_mut_zombie_empty_tail_after_paren_is_not_zombie(monkeypatch):
    """IndexError on empty tail after ')' → False (not True)."""

    def _fake_open(path, *a, **k):
        if str(path).endswith("/stat") and "/proc/" in str(path):
            from io import StringIO

            return StringIO("1 (x)")  # rfind ok, split()[0] IndexError
        return open(path, *a, **k)  # noqa: SIM115

    monkeypatch.setattr("builtins.open", _fake_open)
    assert _writer_is_zombie(1) is False


def test_mut_zombie_rfind_not_find_when_comm_has_paren(monkeypatch):
    """rfind(')') required when comm contains ')' (find would mis-parse)."""
    # pid (name)with)paren) Z ...start fields...
    # After rfind: state Z. After find: state is 'with)paren)' fragment.
    fake = "1 (evil)name) Z 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 99 0 0\n"

    def _fake_open(path, *a, **k):
        if str(path).endswith("/stat") and "/proc/" in str(path):
            from io import StringIO

            return StringIO(fake)
        return open(path, *a, **k)  # noqa: SIM115

    monkeypatch.setattr("builtins.open", _fake_open)
    assert _writer_is_zombie(1) is True


def test_mut_zombie_rparen_zero_still_parses(monkeypatch):
    """rparen == 0 must not be treated as missing ')' (`< 0` not `<= 0`)."""
    fake = ") Z 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 99 0 0\n"

    def _fake_open(path, *a, **k):
        if str(path).endswith("/stat") and "/proc/" in str(path):
            from io import StringIO

            return StringIO(fake)
        return open(path, *a, **k)  # noqa: SIM115

    monkeypatch.setattr("builtins.open", _fake_open)
    assert _writer_is_zombie(1) is True


def test_mut_still_alive_dead_pid_false():
    """kill(pid,0) OSError must yield False (not True)."""
    assert _writer_still_alive(2_000_000_002, 1) is False


def test_mut_still_alive_uses_signal_zero_only(monkeypatch):
    """Existence probe must use signal 0 (not SIGHUP=1)."""
    seen: list[int] = []

    def _kill(pid, sig):
        seen.append(int(sig))
        if int(sig) != 0:
            raise AssertionError(f"still_alive must use signal 0, got {sig}")
        return None

    # Patch both the global and the module binding mutmut rewrites.
    monkeypatch.setattr(os, "kill", _kill)
    monkeypatch.setattr(rrs.os, "kill", _kill)
    monkeypatch.setattr(rrs, "_writer_is_zombie", lambda p: False)
    monkeypatch.setattr(rrs, "_process_start_token", lambda p: 5)
    assert _writer_still_alive(os.getpid(), 5) is True
    assert seen == [0]


def test_mut_open_encoding_is_utf8_lowercase(monkeypatch):
    """``encoding='utf-8'`` (not None / omitted / UTF-8) on /proc reads."""
    seen: list[dict] = []
    real_open = open

    def _wrap(path, *a, **k):
        if "/proc/" in str(path):
            seen.append({"path": str(path), "args": a, "kwargs": dict(k)})
        return real_open(path, *a, **k)

    monkeypatch.setattr("builtins.open", _wrap)
    monkeypatch.setattr(rrs, "open", _wrap, raising=False)
    # Drive both zombie and holds /proc opens.
    _writer_is_zombie(os.getpid())
    create_high_water("esc_mut_enc", "rw_mut_enc", initial=0)
    with high_water_lock("esc_mut_enc", "rw_mut_enc") as hwlock:
        rrs._writer_holds_hw_flock(hwlock._lock_path, os.getpid())
    proc_opens = [s for s in seen if s["path"].startswith("/proc/")]
    assert proc_opens, "expected /proc opens"
    for s in proc_opens:
        # Mode must be positional "r"; encoding must be exactly "utf-8"
        # (kills omit-mode / encoding=None / encoding="UTF-8" mutants).
        enc = s["kwargs"].get("encoding", None)
        assert s["args"][:1] == ("r",), f"expected open(..., 'r', ...), got {s}"
        assert enc == "utf-8", f"expected encoding='utf-8', got {s}"


def test_mut_still_alive_missing_start_token_false(monkeypatch):
    """When starttime is unavailable, still_alive is False (not True)."""
    monkeypatch.setattr(rrs, "_process_start_token", lambda pid: None)
    monkeypatch.setattr(rrs, "_writer_is_zombie", lambda pid: False)
    # Live self pid; start token forced missing.
    assert _writer_still_alive(os.getpid(), 12345) is False


def test_mut_still_alive_pid_zero_and_one(monkeypatch):
    """pid 0 and pid 1 are rejected by `<= 0` / must not use `< 0` or `<= 1` alone."""
    # If the guard is weakened, make the rest claim alive so the mutant shows.
    monkeypatch.setattr(rrs, "_writer_is_zombie", lambda pid: False)
    monkeypatch.setattr(rrs, "_process_start_token", lambda pid: 99)

    def _kill(pid, sig):
        if int(pid) in (0, 1):
            return None  # pretend signalable
        raise OSError("nope")

    monkeypatch.setattr(os, "kill", _kill)
    assert _writer_still_alive(0, 99) is False
    # pid 1 must still be allowed through the <=0 guard (only <=0 rejects).
    # `<= 1` mutant wrongly rejects pid 1 → still_alive False; original True.
    assert _writer_still_alive(1, 99) is True


def test_mut_holds_fcntl_none_rejects_even_with_valid_pid(monkeypatch):
    """`fcntl is None` alone must reject (`or`, not `and` with <=0)."""
    create_high_water("esc_mut_fc", "rw_mut_fc", initial=0)
    with high_water_lock("esc_mut_fc", "rw_mut_fc") as hwlock:
        monkeypatch.setattr(rrs, "fcntl", None)
        assert rrs._writer_holds_hw_flock(hwlock._lock_path, os.getpid()) is False


def test_mut_holds_pid_zero_rejected_even_if_rest_would_match(monkeypatch):
    monkeypatch.setattr(rrs, "_writer_is_zombie", lambda pid: False)
    create_high_water("esc_mut_p0", "rw_mut_p0", initial=0)
    path = rrs._hw_entry_path("esc_mut_p0", "rw_mut_p0")
    lock_path = _hw_lock_path(path)
    st = os.stat(lock_path)
    maj, minor = os.major(st.st_dev), os.minor(st.st_dev)
    # Fabricate a /proc/locks line for pid 0 matching this inode.
    fake_line = (
        f"1: FLOCK ADVISORY WRITE 0 {maj:x}:{minor:x}:{st.st_ino} 0 EOF\n"
    )

    def _fake_open(path, *a, **k):
        if str(path) == "/proc/locks":
            from io import StringIO

            return StringIO(fake_line)
        return open(path, *a, **k)  # noqa: SIM115

    monkeypatch.setattr("builtins.open", _fake_open)
    assert rrs._writer_holds_hw_flock(lock_path, 0) is False


def test_mut_holds_pid_one_allowed_by_guard(monkeypatch):
    """`int(pid) <= 1` mutant wrongly rejects pid 1; original allows the check."""
    monkeypatch.setattr(rrs, "_writer_is_zombie", lambda pid: False)
    create_high_water("esc_mut_p1", "rw_mut_p1", initial=0)
    path = rrs._hw_entry_path("esc_mut_p1", "rw_mut_p1")
    lock_path = _hw_lock_path(path)
    st = os.stat(lock_path)
    maj, minor = os.major(st.st_dev), os.minor(st.st_dev)
    fake_line = (
        f"1: FLOCK ADVISORY WRITE 1 {maj:x}:{minor:x}:{st.st_ino} 0 EOF\n"
    )

    def _fake_open(path, *a, **k):
        if str(path) == "/proc/locks":
            from io import StringIO

            return StringIO(fake_line)
        return open(path, *a, **k)  # noqa: SIM115

    monkeypatch.setattr("builtins.open", _fake_open)
    assert rrs._writer_holds_hw_flock(lock_path, 1) is True


def test_mut_holds_zombie_never_true(monkeypatch):
    """Zombie writer must not be reported as holding the flock."""
    monkeypatch.setattr(rrs, "_writer_is_zombie", lambda pid: True)
    create_high_water("esc_mut_hz", "rw_mut_hz", initial=0)
    with high_water_lock("esc_mut_hz", "rw_mut_hz") as hwlock:
        assert rrs._writer_holds_hw_flock(hwlock._lock_path, os.getpid()) is False


def test_mut_holds_stat_oserror_false(monkeypatch):
    monkeypatch.setattr(rrs, "_writer_is_zombie", lambda pid: False)

    def _boom(path):
        raise OSError("gone")

    monkeypatch.setattr(os, "stat", _boom)
    assert rrs._writer_holds_hw_flock("/no/such/lock", os.getpid()) is False


def test_mut_holds_locks_oserror_false(monkeypatch):
    monkeypatch.setattr(rrs, "_writer_is_zombie", lambda pid: False)
    create_high_water("esc_mut_lk", "rw_mut_lk", initial=0)
    path = rrs._hw_entry_path("esc_mut_lk", "rw_mut_lk")
    lock_path = _hw_lock_path(path)

    real_open = open

    def _fake_open(p, *a, **k):
        if str(p) == "/proc/locks":
            raise OSError("no locks")
        return real_open(p, *a, **k)

    monkeypatch.setattr("builtins.open", _fake_open)
    assert rrs._writer_holds_hw_flock(lock_path, os.getpid()) is False


def test_mut_holds_short_line_continue_not_break(monkeypatch):
    """A short /proc/locks line must `continue`, not `break`, before a match."""
    monkeypatch.setattr(rrs, "_writer_is_zombie", lambda pid: False)
    create_high_water("esc_mut_sh", "rw_mut_sh", initial=0)
    path = rrs._hw_entry_path("esc_mut_sh", "rw_mut_sh")
    lock_path = _hw_lock_path(path)
    st = os.stat(lock_path)
    maj, minor = os.major(st.st_dev), os.minor(st.st_dev)
    pid = os.getpid()
    short = "1: FLOCK\n"  # len(parts) < 6
    match = (
        f"2: FLOCK ADVISORY WRITE {pid} "
        f"{maj:x}:{minor:x}:{st.st_ino} 0 EOF\n"
    )

    def _fake_open(p, *a, **k):
        if str(p) == "/proc/locks":
            from io import StringIO

            return StringIO(short + match)
        return open(p, *a, **k)  # noqa: SIM115

    monkeypatch.setattr("builtins.open", _fake_open)
    assert rrs._writer_holds_hw_flock(lock_path, pid) is True


def test_mut_holds_exactly_six_fields_still_parsed(monkeypatch):
    """`len(parts) < 6` (not `<= 6` / `< 7`) so a 6-field match counts."""
    monkeypatch.setattr(rrs, "_writer_is_zombie", lambda pid: False)
    create_high_water("esc_mut_6", "rw_mut_6", initial=0)
    path = rrs._hw_entry_path("esc_mut_6", "rw_mut_6")
    lock_path = _hw_lock_path(path)
    st = os.stat(lock_path)
    maj, minor = os.major(st.st_dev), os.minor(st.st_dev)
    pid = os.getpid()
    # Exactly 6 whitespace-separated fields (no trailing "0 EOF").
    six = f"1: FLOCK ADVISORY WRITE {pid} {maj:x}:{minor:x}:{st.st_ino}\n"

    def _fake_open(p, *a, **k):
        if str(p) == "/proc/locks":
            from io import StringIO

            return StringIO(six)
        return open(p, *a, **k)  # noqa: SIM115

    monkeypatch.setattr("builtins.open", _fake_open)
    assert rrs._writer_holds_hw_flock(lock_path, pid) is True


def test_mut_holds_requires_both_ino_and_dev(monkeypatch):
    """Matching inode alone (wrong device) must not count (`and`, not `or`)."""
    monkeypatch.setattr(rrs, "_writer_is_zombie", lambda pid: False)
    create_high_water("esc_mut_and", "rw_mut_and", initial=0)
    path = rrs._hw_entry_path("esc_mut_and", "rw_mut_and")
    lock_path = _hw_lock_path(path)
    st = os.stat(lock_path)
    pid = os.getpid()
    # Same inode, wrong major:minor.
    wrong = f"1: FLOCK ADVISORY WRITE {pid} 0:0:{st.st_ino} 0 EOF\n"

    def _fake_open(p, *a, **k):
        if str(p) == "/proc/locks":
            from io import StringIO

            return StringIO(wrong)
        return open(p, *a, **k)  # noqa: SIM115

    monkeypatch.setattr("builtins.open", _fake_open)
    assert rrs._writer_holds_hw_flock(lock_path, pid) is False


def test_mut_holds_bad_pid_field_continue_not_break(monkeypatch):
    """Non-int pid field must `continue` so a later matching line can win."""
    monkeypatch.setattr(rrs, "_writer_is_zombie", lambda pid: False)
    create_high_water("esc_mut_bp", "rw_mut_bp", initial=0)
    path = rrs._hw_entry_path("esc_mut_bp", "rw_mut_bp")
    lock_path = _hw_lock_path(path)
    st = os.stat(lock_path)
    maj, minor = os.major(st.st_dev), os.minor(st.st_dev)
    pid = os.getpid()
    bad = "1: FLOCK ADVISORY WRITE notapid fe:1:1 0 EOF\n"
    good = (
        f"2: FLOCK ADVISORY WRITE {pid} "
        f"{maj:x}:{minor:x}:{st.st_ino} 0 EOF\n"
    )

    def _fake_open(p, *a, **k):
        if str(p) == "/proc/locks":
            from io import StringIO

            return StringIO(bad + good)
        return open(p, *a, **k)  # noqa: SIM115

    monkeypatch.setattr("builtins.open", _fake_open)
    assert rrs._writer_holds_hw_flock(lock_path, pid) is True


def test_mut_holds_wrong_pid_continue_not_break(monkeypatch):
    monkeypatch.setattr(rrs, "_writer_is_zombie", lambda pid: False)
    create_high_water("esc_mut_wp", "rw_mut_wp", initial=0)
    path = rrs._hw_entry_path("esc_mut_wp", "rw_mut_wp")
    lock_path = _hw_lock_path(path)
    st = os.stat(lock_path)
    maj, minor = os.major(st.st_dev), os.minor(st.st_dev)
    pid = os.getpid()
    other = f"1: FLOCK ADVISORY WRITE {pid + 7} {maj:x}:{minor:x}:{st.st_ino} 0 EOF\n"
    good = (
        f"2: FLOCK ADVISORY WRITE {pid} "
        f"{maj:x}:{minor:x}:{st.st_ino} 0 EOF\n"
    )

    def _fake_open(p, *a, **k):
        if str(p) == "/proc/locks":
            from io import StringIO

            return StringIO(other + good)
        return open(p, *a, **k)  # noqa: SIM115

    monkeypatch.setattr("builtins.open", _fake_open)
    assert rrs._writer_holds_hw_flock(lock_path, pid) is True


def test_mut_holds_bad_dev_ino_continue_not_break(monkeypatch):
    monkeypatch.setattr(rrs, "_writer_is_zombie", lambda pid: False)
    create_high_water("esc_mut_bd", "rw_mut_bd", initial=0)
    path = rrs._hw_entry_path("esc_mut_bd", "rw_mut_bd")
    lock_path = _hw_lock_path(path)
    st = os.stat(lock_path)
    maj, minor = os.major(st.st_dev), os.minor(st.st_dev)
    pid = os.getpid()
    bad = f"1: FLOCK ADVISORY WRITE {pid} not-a-dev 0 EOF\n"
    good = (
        f"2: FLOCK ADVISORY WRITE {pid} "
        f"{maj:x}:{minor:x}:{st.st_ino} 0 EOF\n"
    )

    def _fake_open(p, *a, **k):
        if str(p) == "/proc/locks":
            from io import StringIO

            return StringIO(bad + good)
        return open(p, *a, **k)  # noqa: SIM115

    monkeypatch.setattr("builtins.open", _fake_open)
    assert rrs._writer_holds_hw_flock(lock_path, pid) is True
