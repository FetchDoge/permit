"""One killer per raise-removal survivor in retry_rate_store HW refusals.

Each test plants the exact on-disk (or in-memory) state that hits one
``raise RetryRateIntegrityError`` and asserts that specific message. Removing
the targeted raise must make the test fail (wrong success or different error).
"""

from __future__ import annotations

import json
import os
import tempfile

import pytest

from permit import retry_rate_store as rrs
from permit.retry_rate_store import (
    HighWaterRecord,
    RetryRateIntegrityError,
    _atomic_write_hw_record,
    _hw_entry_path,
    _hw_record_mac,
    _read_hw_record,
    assert_high_water_files_for_rows,
    check_high_water,
    create_high_water,
    get_high_water,
    high_water_create,
    high_water_lock,
    note_process_high_water,
    set_high_water,
)


@pytest.fixture(autouse=True)
def _hw_tmpdir(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        monkeypatch.setenv("PERMIT_RETRY_RATE_MAC_HW_FILE", td + "/hw")
        rrs.clear_retry_rate_mac_key_cache()
        yield td


def _path(escrow: str, window: str) -> str:
    return _hw_entry_path(escrow, window)


def _plant_raw(path: str, obj: dict) -> None:
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, mode=0o700, exist_ok=True)
    payload = (json.dumps(obj, separators=(",", ":"), sort_keys=True) + "\n").encode()
    flags = os.O_CREAT | os.O_WRONLY | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)


def _plant_record(
    escrow: str,
    window: str,
    *,
    confirmed: int = 0,
    intent: int | None = None,
    writer_pid: int | None = None,
    writer_start: int | None = None,
) -> str:
    create_high_water(escrow, window, initial=confirmed)
    path = _path(escrow, window)
    with high_water_lock(escrow, window) as hwlock:
        rec = HighWaterRecord(
            escrow_id=escrow,
            window_id=window,
            confirmed=confirmed,
            intent=intent,
            writer_pid=writer_pid,
            writer_start=writer_start,
        )
        _atomic_write_hw_record(hwlock._path, rec)
    return path


# ---------------------------------------------------------------------------
# Corrupt / truncated / tampered counter file (_parse_hw_record / meta)
# ---------------------------------------------------------------------------


def test_raise_truncated_empty_sidecar():
    path = _plant_record("e_trunc", "w_trunc", confirmed=1)
    with open(path, "wb") as fh:
        fh.write(b"")
    os.chmod(path, 0o600)
    with pytest.raises(
        RetryRateIntegrityError,
        match=r"^high-water sidecar truncated/empty at ",
    ):
        _read_hw_record(path)


def test_raise_corrupt_json_sidecar():
    path = _plant_record("e_cjson", "w_cjson", confirmed=1)
    with open(path, "wb") as fh:
        fh.write(b"{not-json\n")
    os.chmod(path, 0o600)
    with pytest.raises(
        RetryRateIntegrityError,
        match=r"^high-water sidecar corrupt at .*refuse \(never restart from 0\)",
    ):
        _read_hw_record(path)


def test_raise_corrupt_missing_fields_sidecar():
    path = _plant_record("e_cfields", "w_cfields", confirmed=1)
    _plant_raw(path, {"confirmed": 1, "mac": "x"})  # missing escrow/window
    with pytest.raises(
        RetryRateIntegrityError,
        match=r"^high-water sidecar corrupt at .*refuse$",
    ):
        _read_hw_record(path)


def test_raise_corrupt_negative_confirmed():
    path = _plant_record("e_neg", "w_neg", confirmed=1)
    _plant_raw(
        path,
        {
            "escrow_id": "e_neg",
            "window_id": "w_neg",
            "confirmed": -1,
            "intent": None,
            "writer_pid": None,
            "writer_start": None,
            "mac": "dead",
        },
    )
    with pytest.raises(
        RetryRateIntegrityError,
        match=r"^high-water sidecar corrupt at .* \(negative\); refuse$",
    ):
        _read_hw_record(path)


def test_raise_corrupt_negative_intent():
    path = _plant_record("e_negi", "w_negi", confirmed=0)
    _plant_raw(
        path,
        {
            "escrow_id": "e_negi",
            "window_id": "w_negi",
            "confirmed": 0,
            "intent": -99,
            "writer_pid": 1,
            "writer_start": 1,
            "mac": "dead",
        },
    )
    with pytest.raises(
        RetryRateIntegrityError,
        match=r"^high-water sidecar corrupt at .* \(negative intent\); refuse$",
    ):
        _read_hw_record(path)


def test_raise_pending_without_writer_identity():
    path = _plant_record("e_noid", "w_noid", confirmed=0)
    _plant_raw(
        path,
        {
            "escrow_id": "e_noid",
            "window_id": "w_noid",
            "confirmed": 0,
            "intent": 1,
            "writer_pid": None,
            "writer_start": None,
            "mac": "dead",
        },
    )
    with pytest.raises(
        RetryRateIntegrityError,
        match=r"^high-water sidecar pending without writer identity at ",
    ):
        _read_hw_record(path)


def test_raise_mac_mismatch_tampered_counter():
    path = _plant_record("e_mac", "w_mac", confirmed=3)
    rec = _read_hw_record(path)
    # Rewrite confirmed without updating MAC (tamper).
    _plant_raw(
        path,
        {
            "escrow_id": rec.escrow_id,
            "window_id": rec.window_id,
            "confirmed": 99,
            "intent": None,
            "writer_pid": None,
            "writer_start": None,
            "mac": rec.mac,
        },
    )
    with pytest.raises(
        RetryRateIntegrityError,
        match=r"^high-water sidecar MAC mismatch at ",
    ):
        _read_hw_record(path)


def test_raise_sidecar_missing_on_read():
    path = _path("e_miss", "w_miss")
    with pytest.raises(
        RetryRateIntegrityError,
        match=r"^high-water sidecar missing at .*refuse \(never restart from 0",
    ):
        _read_hw_record(path)


def test_raise_sidecar_unreadable_meta():
    # _refuse_if_symlink returns on FileNotFoundError; the subsequent lstat
    # then raises → "high-water sidecar unreadable at …".
    path = _path("e_unmeta", "w_unmeta")
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, mode=0o700, exist_ok=True)
    with pytest.raises(
        RetryRateIntegrityError,
        match=r"^high-water sidecar unreadable at ",
    ):
        rrs._assert_hw_file_meta(path)


def test_raise_sidecar_not_regular_file():
    path = _path("e_dir", "w_dir")
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, mode=0o700, exist_ok=True)
    os.makedirs(path, mode=0o700)  # directory where file should be
    with pytest.raises(
        RetryRateIntegrityError,
        match=r"^high-water sidecar .* is not a regular file; refuse$",
    ):
        rrs._assert_hw_file_meta(path)


def test_raise_sidecar_wrong_mode():
    path = _plant_record("e_mode", "w_mode", confirmed=1)
    os.chmod(path, 0o644)
    with pytest.raises(
        RetryRateIntegrityError,
        match=r"^high-water sidecar .* must be mode 0600 ",
    ):
        rrs._assert_hw_file_meta(path)


def test_raise_sidecar_wrong_owner(monkeypatch):
    path = _plant_record("e_own", "w_own", confirmed=1)
    real = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: real + 1)
    with pytest.raises(
        RetryRateIntegrityError,
        match=r"^high-water sidecar .* owner uid=",
    ):
        rrs._assert_hw_file_meta(path)


def test_raise_sidecar_unreadable_open(monkeypatch):
    path = _plant_record("e_unrd", "w_unrd", confirmed=1)
    real_open = os.open

    def _boom(p, *a, **k):
        if p == path:
            raise OSError("planted open fail")
        return real_open(p, *a, **k)

    monkeypatch.setattr(rrs, "_assert_hw_file_meta", lambda p: None)
    monkeypatch.setattr(os, "open", _boom)
    with pytest.raises(
        RetryRateIntegrityError,
        match=r"^high-water sidecar unreadable at ",
    ):
        _read_hw_record(path)


# ---------------------------------------------------------------------------
# Missing sidecar (get / set / lock / startup)
# ---------------------------------------------------------------------------


def test_raise_missing_for_get_high_water():
    with pytest.raises(
        RetryRateIntegrityError,
        match=r"^high-water sidecar missing for escrow_id=",
    ):
        get_high_water("e_gget", "w_gget")


def test_raise_missing_for_set_high_water():
    with pytest.raises(
        RetryRateIntegrityError,
        match=r"^high-water sidecar missing at .*refuse to set",
    ):
        set_high_water("e_sset", "w_sset", 1)


def test_raise_missing_under_high_water_lock():
    with pytest.raises(
        RetryRateIntegrityError,
        match=r"^high-water sidecar missing at .*never create under lock",
    ):
        with high_water_lock("e_lock", "w_lock"):
            pass


def test_raise_missing_at_startup_for_db_row():
    create_high_water("e_start", "w_start", initial=2)
    path = _path("e_start", "w_start")
    os.remove(path)
    with pytest.raises(
        RetryRateIntegrityError,
        match=r"^high-water sidecar missing at startup for ",
    ):
        assert_high_water_files_for_rows(
            [("e_start", "w_start", 2)],
            fresh_count=lambda e, w: 2,
            refresh_rows=lambda: [("e_start", "w_start", 2)],
        )


def test_raise_identity_mismatch_on_create():
    path = _plant_record("e_id1", "w_id1", confirmed=0)
    # Overwrite with a different escrow/window identity (valid MAC for that id).
    other = HighWaterRecord(
        escrow_id="e_other",
        window_id="w_other",
        confirmed=0,
        intent=None,
    )
    other.mac = _hw_record_mac(
        other.escrow_id, other.window_id, other.confirmed, other.intent
    )
    _atomic_write_hw_record(path, other)
    with pytest.raises(
        RetryRateIntegrityError,
        match=r"^high-water sidecar identity mismatch at ",
    ):
        with high_water_create("e_id1", "w_id1"):
            pass


# ---------------------------------------------------------------------------
# Orphan counter file
# ---------------------------------------------------------------------------


def test_raise_orphan_idle_no_db_row():
    _plant_record("e_orph", "w_orph", confirmed=0)
    with pytest.raises(
        RetryRateIntegrityError,
        match=r"^orphan high-water sidecar at .*DB↔file cross-check\)$",
    ):
        assert_high_water_files_for_rows(
            [],
            refresh_rows=lambda: [],
            row_exists=lambda e, w: False,
        )


def test_raise_orphan_pending_dead_writer_no_row():
    _plant_record(
        "e_orphd",
        "w_orphd",
        confirmed=0,
        intent=1,
        writer_pid=2**22 - 9,
        writer_start=1,
    )
    with pytest.raises(
        RetryRateIntegrityError,
        match=r"^orphan high-water sidecar at .*pending intent from dead writer",
    ):
        assert_high_water_files_for_rows(
            [],
            refresh_rows=lambda: [],
            row_exists=lambda e, w: False,
        )


def test_raise_orphan_corrupt_unmatched_digest():
    # Unmatched digest whose file fails parse → orphan raise (not raw parse).
    root = rrs._hw_root_dir()
    os.makedirs(root, mode=0o700, exist_ok=True)
    fpath = os.path.join(root, "deadbeefdeadbeefdeadbeefdeadbeef.hw")
    with open(fpath, "wb") as fh:
        fh.write(b"")
    os.chmod(fpath, 0o600)
    with pytest.raises(
        RetryRateIntegrityError,
        match=r"^orphan high-water sidecar at .*digest=deadbeef",
    ):
        assert_high_water_files_for_rows(
            [],
            refresh_rows=lambda: [],
            row_exists=lambda e, w: False,
        )


def test_raise_orphan_exists_but_db_count_none():
    """Row 'exists' via row_exists but fresh_count path leaves db_count None."""
    _plant_record("e_orphn", "w_orphn", confirmed=0)

    def _fresh(e, w):
        return None  # signals missing for fresh_count API

    # Use refresh_rows that claims the row mid-flight is gone, but first
    # pass says exists with no count — hit the db_count_for is None branch
    # by providing row_exists True without fresh_count/refresh giving a count.
    # assert path: exists True via row_exists, db_count_for stays None.
    with pytest.raises(
        RetryRateIntegrityError,
        match=r"^orphan high-water sidecar at .*DB↔file cross-check\)$",
    ):
        assert_high_water_files_for_rows(
            [],
            row_exists=lambda e, w: True,
            # no fresh_count / refresh_rows → db_count_for None when exists
        )


# ---------------------------------------------------------------------------
# Reconcile / check mismatches
# ---------------------------------------------------------------------------


def test_raise_reconcile_confirmed_ne_db_idle():
    _plant_record("e_rc1", "w_rc1", confirmed=2)
    with high_water_lock("e_rc1", "w_rc1") as hwlock:
        with pytest.raises(
            RetryRateIntegrityError,
            match=r"^high-water confirmed != DB count at reconcile for ",
        ):
            hwlock.reconcile(0)


def test_raise_reconcile_live_planted_increment_under_lock():
    pid, start = rrs._current_writer_identity()
    _plant_record(
        "e_rc2",
        "w_rc2",
        confirmed=0,
        intent=1,
        writer_pid=pid,
        writer_start=start,
    )
    # Foreign-looking live writer: same process but we hold the lock, so
    # reconcile treats non-matching recovery shapes as planted.
    with high_water_lock("e_rc2", "w_rc2") as hwlock:
        # intent=1, confirmed=0, db=5 → not a recoverable same-writer shape
        with pytest.raises(
            RetryRateIntegrityError,
            match=r"^high-water pending intent claims live writer under ",
        ):
            hwlock.reconcile(5)


def test_raise_reconcile_intent_db_disagree_dead_writer():
    _plant_record(
        "e_rc3",
        "w_rc3",
        confirmed=0,
        intent=5,
        writer_pid=2**22 - 11,
        writer_start=1,
    )
    with high_water_lock("e_rc3", "w_rc3") as hwlock:
        with pytest.raises(
            RetryRateIntegrityError,
            match=r"^high-water intent/DB disagree at reconcile for ",
        ):
            hwlock.reconcile(0)


def test_raise_reconcile_ne_db_after_intent_path(monkeypatch):
    # Foreign live creating with confirmed != db: leave pending, then
    # confirmed != count at the end of reconcile.
    _plant_record(
        "e_rc4",
        "w_rc4",
        confirmed=0,
        intent=rrs._HW_CREATING_INTENT,
        writer_pid=1,
        writer_start=rrs._process_start_token(1) or 1,
    )
    monkeypatch.setattr(rrs, "_writer_still_alive", lambda p, s: True)
    with high_water_lock("e_rc4", "w_rc4") as hwlock:
        with pytest.raises(
            RetryRateIntegrityError,
            match=r"^high-water != DB after intent reconcile for ",
        ):
            hwlock.reconcile(3)


def test_raise_check_pending_intent():
    pid, start = rrs._current_writer_identity()
    _plant_record(
        "e_ck1",
        "w_ck1",
        confirmed=0,
        intent=1,
        writer_pid=pid,
        writer_start=start,
    )
    with high_water_lock("e_ck1", "w_ck1") as hwlock:
        with pytest.raises(
            RetryRateIntegrityError,
            match=r"^high-water pending intent under check for ",
        ):
            hwlock.check(0)


def test_raise_check_process_hw_ahead_of_db():
    create_high_water("e_ck2", "w_ck2", initial=0)
    note_process_high_water("e_ck2", "w_ck2", 5)
    with high_water_lock("e_ck2", "w_ck2") as hwlock:
        with pytest.raises(
            RetryRateIntegrityError,
            match=r"^process high-water ahead of DB count for ",
        ):
            hwlock.check(0)


def test_raise_check_process_hw_ahead_of_file():
    create_high_water("e_ck3", "w_ck3", initial=0)
    note_process_high_water("e_ck3", "w_ck3", 3)
    # count >= proc so DB-ahead check passes; confirmed < proc → file-ahead.
    with high_water_lock("e_ck3", "w_ck3") as hwlock:
        with pytest.raises(
            RetryRateIntegrityError,
            match=r"^process high-water ahead of counter file for ",
        ):
            hwlock.check(5)


def test_raise_check_sidecar_ne_db():
    create_high_water("e_ck4", "w_ck4", initial=2)
    # Drop process high-water so the DB-ahead guard does not fire first.
    with rrs._hw_mem_guard:
        rrs._hw_mem.clear()
    with high_water_lock("e_ck4", "w_ck4") as hwlock:
        with pytest.raises(
            RetryRateIntegrityError,
            match=r"^retry rate high-water sidecar != DB count for ",
        ):
            hwlock.check(0)


def test_raise_check_high_water_pending_intent():
    pid, start = rrs._current_writer_identity()
    _plant_record(
        "e_chw1",
        "w_chw1",
        confirmed=0,
        intent=1,
        writer_pid=pid,
        writer_start=start,
    )
    with pytest.raises(
        RetryRateIntegrityError,
        match=r"^high-water sidecar has pending intent for ",
    ):
        check_high_water("e_chw1", "w_chw1", 0)


def test_raise_check_high_water_sidecar_ne_db():
    create_high_water("e_chw2", "w_chw2", initial=4)
    with rrs._hw_mem_guard:
        rrs._hw_mem.clear()
    with pytest.raises(
        RetryRateIntegrityError,
        match=r"^retry rate high-water sidecar != DB count for ",
    ):
        check_high_water("e_chw2", "w_chw2", 1)


def test_raise_check_high_water_process_ahead_of_db():
    create_high_water("e_chw3", "w_chw3", initial=0)
    note_process_high_water("e_chw3", "w_chw3", 7)
    with pytest.raises(
        RetryRateIntegrityError,
        match=r"^process high-water ahead of DB count for ",
    ):
        check_high_water("e_chw3", "w_chw3", 0)


def test_raise_get_high_water_process_ahead_of_file():
    create_high_water("e_ghw", "w_ghw", initial=0)
    note_process_high_water("e_ghw", "w_ghw", 4)
    # Lower the on-disk confirmed under the process high-water.
    with high_water_lock("e_ghw", "w_ghw") as hwlock:
        rec = HighWaterRecord(
            escrow_id="e_ghw",
            window_id="w_ghw",
            confirmed=0,
            intent=None,
        )
        _atomic_write_hw_record(hwlock._path, rec)
    # Clear in-process mem then re-note higher than file via direct mem poke
    # after a get that would sync — plant process ahead by noting then
    # rewriting file downward without going through get.
    rrs.clear_retry_rate_mac_key_cache()
    # Re-load key; mem cleared. Set process hw above file.
    note_process_high_water("e_ghw", "w_ghw", 9)
    with pytest.raises(
        RetryRateIntegrityError,
        match=r"^process high-water ahead of counter file for ",
    ):
        get_high_water("e_ghw", "w_ghw")


def test_raise_write_intent_already_pending():
    create_high_water("e_wi1", "w_wi1", initial=0)
    with high_water_lock("e_wi1", "w_wi1") as hwlock:
        hwlock.write_intent(1)
        with pytest.raises(
            RetryRateIntegrityError,
            match=r"^high-water intent already pending for ",
        ):
            hwlock.write_intent(1)


def test_raise_write_intent_must_be_confirmed_plus_one():
    create_high_water("e_wi2", "w_wi2", initial=0)
    with high_water_lock("e_wi2", "w_wi2") as hwlock:
        with pytest.raises(
            RetryRateIntegrityError,
            match=r"^high-water intent must be confirmed\+1 for ",
        ):
            hwlock.write_intent(3)


def test_raise_confirm_monotonic():
    create_high_water("e_cf1", "w_cf1", initial=5)
    with high_water_lock("e_cf1", "w_cf1") as hwlock:
        with pytest.raises(
            RetryRateIntegrityError,
            match=r"^high-water confirmed is monotonic; refuse lower value for ",
        ):
            hwlock.confirm(3)


def test_raise_confirm_without_pending_intent():
    create_high_water("e_cf2", "w_cf2", initial=0)
    with high_water_lock("e_cf2", "w_cf2") as hwlock:
        with pytest.raises(
            RetryRateIntegrityError,
            match=r"^high-water confirm without pending intent for ",
        ):
            hwlock.confirm(1)


def test_raise_confirm_ne_pending_intent():
    create_high_water("e_cf3", "w_cf3", initial=0)
    with high_water_lock("e_cf3", "w_cf3") as hwlock:
        hwlock.write_intent(1)
        with pytest.raises(
            RetryRateIntegrityError,
            match=r"^high-water confirm != pending intent for ",
        ):
            hwlock.confirm(2)


# ---------------------------------------------------------------------------
# Semantic survivor: increment live-skip must honor start token
# ---------------------------------------------------------------------------


def test_sem_increment_intent_live_skip_requires_matching_token():
    """Kill ``sem_increment_intent_live_skip_ignores_token``.

    Plant a foreign live pid with a *wrong* start token and a non-recoverable
    pending increment (intent/DB disagree). Correct code treats the writer as
    dead (token mismatch) and refuses at reconcile. A mutant that skips on
    pid-liveness alone would ``continue`` past reconcile and let startup pass.
    """
    import time

    child = os.fork()
    if child == 0:
        time.sleep(60)
        os._exit(0)
    try:
        real_start = rrs._process_start_token(child)
        assert real_start is not None
        assert child != os.getpid()
        _plant_record(
            "e_tok",
            "w_tok",
            confirmed=0,
            intent=5,  # not recoverable against db_count=0
            writer_pid=child,
            writer_start=1,  # mismatched token
        )
        with pytest.raises(
            RetryRateIntegrityError,
            match=r"^high-water intent/DB disagree at reconcile for ",
        ):
            assert_high_water_files_for_rows(
                [("e_tok", "w_tok", 0)],
                fresh_count=lambda e, w: 0,
                refresh_rows=lambda: [("e_tok", "w_tok", 0)],
            )
        # Pin the token check: wrong start → dead; matching start → alive.
        assert rrs._writer_still_alive(child, 1) is False
        assert rrs._writer_still_alive(child, real_start) is True
    finally:
        try:
            os.kill(child, 9)
        except OSError:
            pass
        try:
            os.waitpid(child, 0)
        except ChildProcessError:
            pass
