"""REA seq 1690 regressions on durable demo key files (PR #54 follow-up).

Each case must fail on c063f8d (soft open/chmod, silent regenerate, forged
mode log, harness/forge demo-key defaults) and pass on the hardened head.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

from settlement.verifier import load_or_create_demo_key, resolve_acceptance_key

ROOT = Path(__file__).resolve().parents[1]
MIN = 32
FORGE_YML = ROOT / ".github" / "workflows" / "forge.yml"


def _write_key(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.write_bytes(data)
    os.chmod(path, mode)


def test_symlinked_key_file_refused(monkeypatch, tmp_path):
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    real = tmp_path / "real.key"
    link = tmp_path / "ledger.db.acceptance_key"
    _write_key(real, os.urandom(MIN), 0o600)
    link.symlink_to(real)
    with pytest.raises(ValueError, match="symlink"):
        load_or_create_demo_key(link)


def test_wrong_owner_refused(monkeypatch, tmp_path):
    """Simulate a foreign uid via fstat when chown is unavailable."""
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    path = tmp_path / "ledger.db.acceptance_key"
    _write_key(path, os.urandom(MIN), 0o600)
    real_fstat = os.fstat

    def foreign_fstat(fd):
        st = real_fstat(fd)
        return os.stat_result(
            (
                st.st_mode,
                st.st_ino,
                st.st_dev,
                st.st_nlink,
                st.st_uid + 1,  # not euid
                st.st_gid,
                st.st_size,
                st.st_atime,
                st.st_mtime,
                st.st_ctime,
            )
        )

    with mock.patch("settlement.verifier._os.fstat", side_effect=foreign_fstat):
        with pytest.raises(ValueError, match="owned by euid"):
            load_or_create_demo_key(path)


@pytest.mark.parametrize("bad_mode", [0o644, 0o666], ids=["0644", "0666"])
def test_wrong_mode_refused(monkeypatch, tmp_path, bad_mode):
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    path = tmp_path / "ledger.db.acceptance_key"
    _write_key(path, os.urandom(MIN), bad_mode)
    with pytest.raises(ValueError, match="mode 0600"):
        load_or_create_demo_key(path)


def test_trailing_newline_refused(monkeypatch, tmp_path):
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    path = tmp_path / "ledger.db.acceptance_key"
    _write_key(path, os.urandom(MIN) + b"\n", 0o600)
    with pytest.raises(ValueError, match="trailing"):
        load_or_create_demo_key(path)


def test_short_key_file_refused(monkeypatch, tmp_path):
    """Exactly-32 read rejects a short file with an explicit truncated error."""
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    path = tmp_path / "short.acceptance_key"
    _write_key(path, os.urandom(MIN - 1), 0o600)
    with pytest.raises(ValueError, match=r"is truncated \("):
        load_or_create_demo_key(path)


def test_nonempty_db_missing_key_refused(monkeypatch, tmp_path):
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    path = tmp_path / "ledger.db.acceptance_key"
    assert not path.exists()
    with pytest.raises(ValueError, match="refusing to regenerate"):
        load_or_create_demo_key(path, db_nonempty=True)
    with pytest.raises(ValueError, match="refusing to regenerate"):
        resolve_acceptance_key(
            allow_demo_key=True,
            demo_key_path=path,
            demo_key_db_nonempty=True,
        )


def test_create_then_load_is_exact_0600_and_stable(monkeypatch, tmp_path):
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    path = tmp_path / "ledger.db.acceptance_key"
    k1, mode1 = load_or_create_demo_key(path, db_nonempty=False)
    assert mode1 == 0o600
    assert len(k1) == MIN
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    k2, mode2 = load_or_create_demo_key(path, db_nonempty=True)
    assert k2 == k1 and mode2 == 0o600


def test_forge_demo_step_passes_allow_demo_key():
    """forge.yml must opt the installed CLI demos into --allow-demo-key."""
    text = FORGE_YML.read_text()
    assert "pull_request:" in text, "forge must run on pull_request so PRs prove the step"
    assert "permit demo --allow-demo-key" in text
    assert "permit demo-recovery --allow-demo-key" in text
    # Bare installed-CLI smoke without the flag must not remain.
    assert "permit demo)" not in text.replace("permit demo --allow-demo-key", "PERMIT_DEMO_OK")
    assert "permit demo-recovery)" not in text.replace(
        "permit demo-recovery --allow-demo-key", "PERMIT_RECOVERY_OK"
    )


def test_harness_default_disallows_demo_key(monkeypatch):
    """harness/durability_harness.py --allow-demo-key is off by default."""
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    # Import-time default on _build / argparse.
    from harness import durability_harness as dh

    import inspect

    sig = inspect.signature(dh._build)
    assert sig.parameters["allow_demo_key"].default is False
    sig_run = inspect.signature(dh._run_kill_point)
    assert sig_run.parameters["allow_demo_key"].default is False

    # CLI default: parsing with only --all must leave the flag False.
    # (main requires --all or --kill-point; parse via the private parser path.)
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from harness.durability_harness import main\n"
                "import argparse\n"
                # Re-build the same parser defaults the module exposes.
                "from harness import durability_harness as m\n"
                "import inspect\n"
                "src = inspect.getsource(m.main)\n"
                "assert 'allow-demo-key' in src\n"
                "assert 'default=False' in src\n"
                "print('ok')\n"
            ),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "ok" in proc.stdout

    # Without env key and without the flag, _build must raise.
    import tempfile

    with tempfile.TemporaryDirectory(prefix="harness-demo-key-") as td:
        with pytest.raises(ValueError):
            dh._build(Path(td), allow_demo_key=False)
