"""Installed-style CLI behavior, including a subprocess network tripwire."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from permit import cli


ROOT = Path(__file__).resolve().parents[1]


def _guarded_cli(tmp_path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    guard = tmp_path / "network_guard"
    guard.mkdir()
    (guard / "sitecustomize.py").write_text(
        "import socket\n"
        "def forbidden(*args, **kwargs):\n"
        "    raise AssertionError('network access attempted by offline CLI')\n"
        "socket.socket = forbidden\n",
        encoding="utf-8",
    )
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["PYTHONPATH"] = os.pathsep.join((str(guard), str(ROOT)))
    before = {path.name for path in tmp_path.iterdir()}
    result = subprocess.run(
        [sys.executable, "-m", "permit", *args],
        cwd=tmp_path,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
        check=False,
    )
    after = {path.name for path in tmp_path.iterdir()}
    assert after == before, "CLI created a file outside its package"
    return result


def test_demo_is_offline_and_shows_required_invariants(tmp_path):
    result = _guarded_cli(tmp_path, "demo")
    assert result.returncode == 0, result.stderr
    assert "CAP BLOCK:" in result.stdout
    assert "E-STOP:" in result.stdout
    assert "LEDGER VERIFIED:" in result.stdout
    assert "no network, credentials, or real money" in result.stdout


def test_recovery_demo_is_offline_and_does_not_duplicate_capture(tmp_path):
    result = _guarded_cli(tmp_path, "demo-recovery")
    assert result.returncode == 0, result.stderr
    assert "UNKNOWN:" in result.stdout
    assert "CAPTURED:" in result.stdout
    assert "NO DUPLICATE MOCK CAPTURE:" in result.stdout
    assert "LEDGER VERIFIED:" in result.stdout


@pytest.mark.parametrize(
    "args",
    [(), ("invalid-command",), ("--sandbox",), ("demo", "--sandbox")],
)
def test_misuse_is_rejected(tmp_path, args):
    result = _guarded_cli(tmp_path, *args)
    assert result.returncode == 2
    assert "usage:" in result.stderr


def test_help_lists_only_offline_demo_commands(tmp_path):
    result = _guarded_cli(tmp_path, "--help")
    assert result.returncode == 0
    assert "demo-recovery" in result.stdout
    assert "--sandbox" not in result.stdout


def test_invariant_failure_returns_nonzero(monkeypatch, capsys):
    def fail():
        raise cli.DemoInvariantError("boom")

    monkeypatch.setattr(cli, "run_demo", fail)
    assert cli.main(["demo"]) == 1
    assert "DEMO FAILED: boom" in capsys.readouterr().out


def test_cli_imports_no_network_capable_programs():
    check = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            "import socket, sys\n"
            "def forbidden(*args, **kwargs):\n"
            "    raise AssertionError('network access attempted while importing CLI')\n"
            "socket.socket = forbidden\n"
            f"sys.path.insert(0, {str(ROOT)!r})\n"
            "import permit.cli\n"
            "imported = set(sys.modules)\n"
            "forbidden_modules = [\n"
            "    name for name in imported\n"
            "    if name == 'settlement.sandbox_client'\n"
            "    or name == 'agent' or name.startswith('agent.')\n"
            "    or name == 'dashboard' or name.startswith('dashboard.')\n"
            "]\n"
            "if forbidden_modules:\n"
            "    raise AssertionError('network-capable imports: ' + ', '.join(sorted(forbidden_modules)))\n",
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
        check=False,
    )
    assert check.returncode == 0, check.stderr


def test_pyproject_declares_explicit_packages_and_entry_point():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'requires-python = ">=3.10"' in text
    assert 'permit = "permit.cli:main"' in text
    assert "dependencies = []" in text
    # Package discovery covers permit + settlement (and related trees).
    assert "permit*" in text and "settlement*" in text
