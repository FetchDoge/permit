"""REA round 5: silent-rebind refuse, fail-closed ephemeral, concurrent bind,
corrupt meta, harness K1 demo-key persist, one-time rebind.

These tests must FAIL on 6bed5ff (pre-r5 tip) and PASS on head.
"""

from __future__ import annotations

import json
import multiprocessing
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MIN = 32
SILENT = "refusing silent rebind"
REFUSE = "rotating the acceptance key on an existing database refuses startup"
CORRUPT = "corrupt durable meta.json"
REBIND_REFUSE = "old acceptance key does not match stored commitment"


def _env_no_key() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k != "PERMIT_ACCEPTANCE_KEY"}


def _append_one(ledger) -> None:
    ledger.append("TEST", {"n": 1})


# ---------------------------------------------------------------------------
# 1. Silent rebind: nonempty store without commitment refuses
# ---------------------------------------------------------------------------


def test_sqlite_nonempty_without_commitment_refuses_silent_rebind(tmp_path):
    from permit.sqlite_ledger import (
        ACCEPTANCE_KEY_COMMITMENT_META,
        SqliteLedger,
    )
    from settlement.verifier import ensure_acceptance_key_commitment

    db = tmp_path / "nonempty.db"
    lg = SqliteLedger(str(db))
    try:
        _append_one(lg)
        assert len(lg) > 0
        assert lg.get_meta(ACCEPTANCE_KEY_COMMITMENT_META) is None
        with pytest.raises(ValueError, match=SILENT):
            ensure_acceptance_key_commitment(lg, b"A" * MIN)
    finally:
        lg.close()


def test_durable_nonempty_missing_meta_refuses_silent_rebind(tmp_path):
    from permit.durability import DurableLedger
    from settlement.verifier import ensure_acceptance_key_commitment

    durable = tmp_path / "dur"
    lg = DurableLedger(durable_dir=durable)
    try:
        _append_one(lg)
        assert len(lg) > 0
        meta = durable / "meta.json"
        if meta.exists():
            meta.unlink()
        with pytest.raises(ValueError, match=SILENT):
            ensure_acceptance_key_commitment(lg, b"B" * MIN)
    finally:
        lg.close()


def test_durable_nonempty_meta_without_commitment_refuses(tmp_path):
    from permit.durability import DurableLedger
    from permit.sqlite_ledger import ACCEPTANCE_KEY_COMMITMENT_META
    from settlement.verifier import ensure_acceptance_key_commitment

    durable = tmp_path / "dur2"
    lg = DurableLedger(durable_dir=durable)
    try:
        _append_one(lg)
        lg.set_meta("other", "x")
        assert lg.get_meta(ACCEPTANCE_KEY_COMMITMENT_META) is None
        with pytest.raises(ValueError, match=SILENT):
            ensure_acceptance_key_commitment(lg, b"C" * MIN)
    finally:
        lg.close()


def test_sqlite_meta_row_deleted_nonempty_refuses(tmp_path):
    from permit.sqlite_ledger import (
        ACCEPTANCE_KEY_COMMITMENT_META,
        SqliteLedger,
    )
    from settlement.verifier import (
        acceptance_key_commitment,
        ensure_acceptance_key_commitment,
    )

    db = tmp_path / "del.db"
    lg = SqliteLedger(str(db))
    try:
        key = b"D" * MIN
        ensure_acceptance_key_commitment(lg, key)
        _append_one(lg)
        lg._conn.execute(
            "DELETE FROM meta WHERE key = ?",
            (ACCEPTANCE_KEY_COMMITMENT_META,),
        )
        assert lg.get_meta(ACCEPTANCE_KEY_COMMITMENT_META) is None
        with pytest.raises(ValueError, match=SILENT):
            ensure_acceptance_key_commitment(lg, key)
        # Wrong key also refuses (still silent-rebind path)
        with pytest.raises(ValueError, match=SILENT):
            ensure_acceptance_key_commitment(lg, b"E" * MIN)
    finally:
        lg.close()


def test_empty_store_may_first_bind(tmp_path):
    from permit.sqlite_ledger import (
        ACCEPTANCE_KEY_COMMITMENT_META,
        SqliteLedger,
    )
    from settlement.verifier import (
        acceptance_key_commitment,
        ensure_acceptance_key_commitment,
    )

    db = tmp_path / "empty.db"
    lg = SqliteLedger(str(db))
    try:
        assert len(lg) == 0
        key = b"F" * MIN
        ensure_acceptance_key_commitment(lg, key)
        assert lg.get_meta(ACCEPTANCE_KEY_COMMITMENT_META) == (
            acceptance_key_commitment(key)
        )
    finally:
        lg.close()


# ---------------------------------------------------------------------------
# 2. Fail-closed default: required unless ephemeral
# ---------------------------------------------------------------------------


def test_commitment_required_by_default_not_opt_in():
    from settlement.verifier import _bind_ledger_acceptance_key_commitment

    class _PlainNoFlag:
        """No ephemeral mark and no meta — must refuse (fail-closed)."""

    with pytest.raises(ValueError, match="refusing silent skip"):
        _bind_ledger_acceptance_key_commitment(_PlainNoFlag(), b"k" * MIN)


def test_in_memory_ledger_is_ephemeral():
    from permit.ledger import Ledger
    from settlement.verifier import _bind_ledger_acceptance_key_commitment

    mem = Ledger()
    assert mem.ephemeral_acceptance_key_commitment is True
    # Must not raise (skip commitment).
    _bind_ledger_acceptance_key_commitment(mem, b"k" * MIN)


def test_file_sqlite_cannot_turn_off_ephemeral(tmp_path):
    from permit.sqlite_ledger import SqliteLedger
    from settlement.verifier import _bind_ledger_acceptance_key_commitment

    db = tmp_path / "req.db"
    lg = SqliteLedger(str(db))
    try:
        assert lg.ephemeral_acceptance_key_commitment is False
        assert lg.requires_acceptance_key_commitment is True
        with pytest.raises(AttributeError):
            lg.ephemeral_acceptance_key_commitment = True  # type: ignore[misc]
        # Still required after failed assign attempt.
        assert lg.ephemeral_acceptance_key_commitment is False
        _bind_ledger_acceptance_key_commitment(lg, b"G" * MIN)
        assert lg.get_meta("acceptance_key_commitment_v1") is not None
    finally:
        lg.close()


def test_memory_sqlite_is_ephemeral():
    from permit.sqlite_ledger import SqliteLedger
    from settlement.verifier import _bind_ledger_acceptance_key_commitment

    lg = SqliteLedger(":memory:")
    try:
        assert lg.ephemeral_acceptance_key_commitment is True
        _bind_ledger_acceptance_key_commitment(lg, b"H" * MIN)
        assert lg.get_meta("acceptance_key_commitment_v1") is None
    finally:
        lg.close()


# ---------------------------------------------------------------------------
# 3. SQLite concurrent first boot (20 trials)
# ---------------------------------------------------------------------------


def _race_worker(db_path: str, key_hex: str, ready, go, q) -> None:
    import sqlite3
    import time

    from permit.sqlite_ledger import SqliteLedger
    from settlement.verifier import ensure_acceptance_key_commitment

    key = bytes.fromhex(key_hex)
    lg = None
    for attempt in range(50):
        try:
            lg = SqliteLedger(db_path)
            break
        except sqlite3.OperationalError:
            time.sleep(0.01)
    if lg is None:
        q.put(("boot_err", "could not open db"))
        ready.set()
        return
    ready.set()
    go.wait(timeout=10)
    try:
        ensure_acceptance_key_commitment(lg, key)
        q.put(("ok", key_hex))
    except ValueError as exc:
        q.put(("err", str(exc)))
    finally:
        lg.close()


def test_sqlite_concurrent_first_boot_20_trials(tmp_path):
    """Two processes, different keys: exactly one binds; the other mismatches."""
    ctx = multiprocessing.get_context("spawn")
    wins_a = wins_b = mismatches = 0
    for trial in range(20):
        db = tmp_path / f"race_{trial}.db"
        # Pre-create empty schema so both racers only contend on meta bind.
        from permit.sqlite_ledger import SqliteLedger

        SqliteLedger(str(db)).close()
        key_a = os.urandom(MIN)
        key_b = os.urandom(MIN)
        assert key_a != key_b
        q = ctx.Queue()
        ready1 = ctx.Event()
        ready2 = ctx.Event()
        go = ctx.Event()
        p1 = ctx.Process(
            target=_race_worker,
            args=(str(db), key_a.hex(), ready1, go, q),
        )
        p2 = ctx.Process(
            target=_race_worker,
            args=(str(db), key_b.hex(), ready2, go, q),
        )
        p1.start()
        p2.start()
        assert ready1.wait(timeout=10) and ready2.wait(timeout=10)
        go.set()
        p1.join(timeout=10)
        p2.join(timeout=10)
        assert p1.exitcode == 0 and p2.exitcode == 0, (
            f"trial {trial}: exitcodes {p1.exitcode}/{p2.exitcode}"
        )
        results = [q.get(timeout=2), q.get(timeout=2)]
        oks = [r for r in results if r[0] == "ok"]
        errs = [r for r in results if r[0] == "err"]
        assert len(oks) == 1, f"trial {trial}: {results}"
        assert len(errs) == 1, f"trial {trial}: {results}"
        assert "mismatch" in errs[0][1] or "refuses startup" in errs[0][1]
        if oks[0][1] == key_a.hex():
            wins_a += 1
        else:
            wins_b += 1
        mismatches += 1
    assert mismatches == 20
    assert wins_a + wins_b == 20


# ---------------------------------------------------------------------------
# 4. Corrupt meta.json refused (not empty) + mutant killer
# ---------------------------------------------------------------------------


def test_corrupt_meta_json_refused_not_empty(tmp_path):
    from permit.durability import DurableLedger

    durable = tmp_path / "badmeta"
    durable.mkdir()
    (durable / "meta.json").write_text("{not-json", encoding="utf-8")
    with pytest.raises(ValueError, match=CORRUPT):
        DurableLedger(durable_dir=durable)


def test_empty_meta_json_file_refused(tmp_path):
    from permit.durability import DurableLedger

    durable = tmp_path / "emptymeta"
    durable.mkdir()
    (durable / "meta.json").write_text("   \n", encoding="utf-8")
    with pytest.raises(ValueError, match=CORRUPT):
        DurableLedger(durable_dir=durable)


def test_mutant_corrupt_meta_treated_as_empty_is_killed(tmp_path, monkeypatch):
    """Surviving mutant: _read_meta returns {} on JSON error → killed here."""
    from permit.durability import DurableLedger

    durable = tmp_path / "mut"
    durable.mkdir()
    (durable / "meta.json").write_text("{broken", encoding="utf-8")

    real_read = DurableLedger._read_meta

    def mutant_read(self):
        if self._meta_path is None:
            return {}
        if not self._meta_path.exists():
            return {}
        try:
            text = self._meta_path.read_text(encoding="utf-8")
            if not text.strip():
                return {}
            raw = json.loads(text)
        except (json.JSONDecodeError, OSError, ValueError):
            return {}  # MUTANT: treat corrupt as empty
        if not isinstance(raw, dict):
            return {}
        return {str(k): str(v) for k, v in raw.items()}

    monkeypatch.setattr(DurableLedger, "_read_meta", mutant_read)
    # Under the mutant, construction succeeds (corrupt treated as empty).
    lg = DurableLedger(durable_dir=durable)
    lg.close()
    monkeypatch.setattr(DurableLedger, "_read_meta", real_read)
    # Real code must still refuse at open.
    with pytest.raises(ValueError, match=CORRUPT):
        DurableLedger(durable_dir=durable)


# ---------------------------------------------------------------------------
# 5. Harness K1 + --allow-demo-key, no env (r2 N-h)
# ---------------------------------------------------------------------------


def test_k1_allow_demo_key_survives_reopen_without_env(tmp_path, monkeypatch):
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    from harness.durability_harness import _run_kill_point

    work = tmp_path / "K1demo"
    res = _run_kill_point("K1", work, allow_demo_key=True)
    assert res["pass"], "\n".join(res.get("details", [])) + f"\nerror: {res.get('error')}"
    key_path = work / "acceptance_key"
    assert key_path.is_file(), "demo key must be persisted under harness state dir"
    mode = stat.S_IMODE(key_path.stat().st_mode)
    assert mode == 0o600, f"expected 0600, got {mode:04o}"
    assert len(key_path.read_bytes()) == MIN


def test_durability_harness_py_k1_allow_demo_key_no_env_exit_0(
    tmp_path, monkeypatch
):
    """Subprocess: durability_harness.py --kill-point K1 --allow-demo-key, no env.

    Runs the harness script through kill + reopen and asserts exit 0 so CI
    catches the r2 N-h bar without ci.yml changes (REA r5 fix 5).
    """
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    work = tmp_path / "cliK1"
    harness_py = ROOT / "harness" / "durability_harness.py"
    assert harness_py.is_file()
    proc = subprocess.run(
        [
            sys.executable,
            str(harness_py),
            "--kill-point",
            "K1",
            "--work-dir",
            str(work),
            "--allow-demo-key",
        ],
        cwd=ROOT,
        env=_env_no_key(),
        capture_output=True,
        text=True,
        timeout=30,
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    assert proc.returncode == 0, out
    assert "PASS" in out
    key_path = work / "K1" / "acceptance_key"
    assert key_path.is_file()
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600


# ---------------------------------------------------------------------------
# 6. One-time rebind (long OLD key → exact-32 NEW)
# ---------------------------------------------------------------------------


def test_rebind_succeeds_with_correct_old_key(tmp_path):
    from permit.sqlite_ledger import (
        ACCEPTANCE_KEY_COMMITMENT_META,
        SqliteLedger,
    )
    from settlement.verifier import (
        acceptance_key_commitment,
        ensure_acceptance_key_commitment,
        rebind_acceptance_key_commitment,
    )

    # Simulate 19b62ce binding with token_hex(32) → 64 UTF-8 bytes.
    old_key = os.urandom(32).hex().encode("utf-8")
    assert len(old_key) == 64
    new_key = os.urandom(MIN)
    db = tmp_path / "mig.db"
    lg = SqliteLedger(str(db))
    try:
        # Direct set_meta of old commitment (as 19b62ce would have stored).
        lg.set_meta(
            ACCEPTANCE_KEY_COMMITMENT_META,
            acceptance_key_commitment(old_key),
        )
        _append_one(lg)
        rebind_acceptance_key_commitment(lg, old_key, new_key)
        assert lg.get_meta(ACCEPTANCE_KEY_COMMITMENT_META) == (
            acceptance_key_commitment(new_key)
        )
        ensure_acceptance_key_commitment(lg, new_key)
    finally:
        lg.close()


def test_rebind_refused_with_wrong_old_key(tmp_path):
    from permit.sqlite_ledger import (
        ACCEPTANCE_KEY_COMMITMENT_META,
        SqliteLedger,
    )
    from settlement.verifier import (
        acceptance_key_commitment,
        rebind_acceptance_key_commitment,
    )

    old_key = os.urandom(32).hex().encode("utf-8")
    wrong = os.urandom(32).hex().encode("utf-8")
    new_key = os.urandom(MIN)
    db = tmp_path / "mig_bad.db"
    lg = SqliteLedger(str(db))
    try:
        lg.set_meta(
            ACCEPTANCE_KEY_COMMITMENT_META,
            acceptance_key_commitment(old_key),
        )
        with pytest.raises(ValueError, match=REBIND_REFUSE):
            rebind_acceptance_key_commitment(lg, wrong, new_key)
        # Commitment unchanged.
        assert lg.get_meta(ACCEPTANCE_KEY_COMMITMENT_META) == (
            acceptance_key_commitment(old_key)
        )
    finally:
        lg.close()


def test_rebind_cli_script(tmp_path):
    from permit.sqlite_ledger import (
        ACCEPTANCE_KEY_COMMITMENT_META,
        SqliteLedger,
    )
    from settlement.verifier import acceptance_key_commitment

    old_key = ("a" * 64).encode("utf-8")
    new_key = b"n" * MIN
    db = tmp_path / "cli.db"
    lg = SqliteLedger(str(db))
    lg.set_meta(
        ACCEPTANCE_KEY_COMMITMENT_META, acceptance_key_commitment(old_key)
    )
    lg.close()

    old_path = tmp_path / "old.key"
    new_path = tmp_path / "new.key"
    old_path.write_bytes(old_key)
    new_path.write_bytes(new_key)

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.rebind_acceptance_key",
            "--db",
            str(db),
            "--old-key-file",
            str(old_path),
            "--new-key-file",
            str(new_path),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "rebind ok" in proc.stdout

    lg2 = SqliteLedger(str(db))
    try:
        assert lg2.get_meta(ACCEPTANCE_KEY_COMMITMENT_META) == (
            acceptance_key_commitment(new_key)
        )
    finally:
        lg2.close()

    # Wrong old key via CLI.
    bad_old = tmp_path / "bad.key"
    bad_old.write_bytes(("b" * 64).encode("utf-8"))
    # Re-seed commitment to old again for the refuse path.
    lg3 = SqliteLedger(str(db))
    lg3.set_meta(
        ACCEPTANCE_KEY_COMMITMENT_META, acceptance_key_commitment(old_key)
    )
    lg3.close()
    proc2 = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.rebind_acceptance_key",
            "--db",
            str(db),
            "--old-key-file",
            str(bad_old),
            "--new-key-file",
            str(new_path),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert proc2.returncode != 0
    assert "rebind failed" in (proc2.stderr or "")
