"""Issue #53: acceptance-key handling after #44.

REA's after-the-fact check of main 9809cc7 (#44) failed two bars. The
pass bar, written before this fix:

1. The verifier and ledger constructors reject a whitespace-only key,
   including one of 32 bytes or more, with a test.
2. The demo key is an explicit opt-in flag, off by default. server.py
   in mock mode (including --db), demo.py, demos/*, python -m permit
   and trace.py exit with a non-zero code when no valid key is set and
   the flag is absent, with a test for each entry point.
3. A key set through env but invalid (empty, 31 bytes, or whitespace)
   raises an error even when the demo flag is on.
4. In --db mode with the demo flag, the key does not change silently
   across a restart: it persists in a 0600 sidecar file.
5. The stale ledger.py docstring is fixed and the sign_acceptance API
   change is noted in the README (checked by inspection, not here).
6. Every test in this file fails on 9809cc7 and passes on the fix.
"""

import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

from permit.ledger import Ledger
from permit.permit import PermitStore
from settlement.paypal_client import MockPayPalClient
from settlement.verifier import ReleaseVerifier, sign_acceptance

ROOT = Path(__file__).resolve().parents[1]
GOOD_KEY = b"k" * 32


def _verifier(**kwargs):
    ledger = Ledger()
    permits = PermitStore(ledger=ledger)
    return ReleaseVerifier(
        MockPayPalClient(), permits, ledger=ledger, **kwargs
    )


# --- bar 1: whitespace-only keys are rejected everywhere -------------------

@pytest.mark.parametrize(
    "bad_key",
    [b" " * 32, b" " * 64, " " * 40, "\t\n " * 12, b"\x0b\x0c" * 20],
)
def test_whitespace_only_explicit_key_rejected(monkeypatch, bad_key):
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    with pytest.raises(ValueError):
        _verifier(acceptance_key=bad_key)


def test_whitespace_only_env_key_rejected(monkeypatch):
    monkeypatch.setenv("PERMIT_ACCEPTANCE_KEY", " " * 32)
    with pytest.raises(ValueError):
        _verifier()


def test_whitespace_only_key_rejected_by_durable_verifier(monkeypatch):
    from permit.durability import DurablePermitStore, DurableReleaseVerifier

    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    ledger = Ledger()
    permits = DurablePermitStore(ledger=ledger)
    with pytest.raises(ValueError):
        DurableReleaseVerifier(
            MockPayPalClient(), permits, ledger=ledger,
            acceptance_key=b" " * 32,
        )


def test_sign_acceptance_rejects_whitespace_key():
    with pytest.raises(ValueError):
        sign_acceptance("esc", "hash", 100, b" " * 32)
    assert len(sign_acceptance("esc", "hash", 100, GOOD_KEY)) == 64


# --- bar 3: a configured-but-invalid key is fatal even with the demo flag --

@pytest.mark.parametrize("bad_env", ["", "x" * 31, " " * 32])
def test_invalid_env_key_raises_even_with_demo_flag(monkeypatch, bad_env):
    monkeypatch.setenv("PERMIT_ACCEPTANCE_KEY", bad_env)
    with pytest.raises(ValueError):
        _verifier(allow_demo_key=True)


def test_invalid_explicit_key_raises_even_with_demo_flag(monkeypatch):
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    with pytest.raises(ValueError):
        _verifier(acceptance_key=b"x" * 31, allow_demo_key=True)
    with pytest.raises(ValueError):
        _verifier(acceptance_key=b"", allow_demo_key=True)



# --- bar 4 (unit): the persisted demo key file ------------------------------

def test_demo_key_file_persists_with_0600(tmp_path):
    from settlement.verifier import load_or_create_demo_key_file

    path = tmp_path / "ledger.db.demo-key"
    key1 = load_or_create_demo_key_file(path)
    assert len(key1) >= 32
    assert (os.stat(path).st_mode & 0o777) == 0o600
    first_bytes = path.read_bytes()
    key2 = load_or_create_demo_key_file(path)
    assert key2 == key1
    assert path.read_bytes() == first_bytes


def test_demo_key_file_rejects_garbage(tmp_path):
    from settlement.verifier import load_or_create_demo_key_file

    path = tmp_path / "bad.demo-key"
    path.write_text("not-a-hex-key\n")
    with pytest.raises(ValueError):
        load_or_create_demo_key_file(path)


# --- bar 2: every entry point exits non-zero without key or flag -----------

def _clean_env(extra=None):
    env = {k: v for k, v in os.environ.items() if k != "PERMIT_ACCEPTANCE_KEY"}
    env["PYTHONPATH"] = str(ROOT)
    if extra:
        env.update(extra)
    return env


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _run(argv, timeout=90, extra_env=None):
    return subprocess.run(
        [sys.executable, *argv], cwd=ROOT, env=_clean_env(extra_env),
        capture_output=True, text=True, timeout=timeout,
    )


ENTRYPOINTS_NO_FLAG = [
    ["demo.py"],
    ["demos/demo_admission.py"],
    ["demos/demo_approval.py", "--fast"],
    ["demos/demo_delegation.py", "--fast"],
    ["demos/demo_six_beat.py", "--fast"],
    ["demos/demo_sla_escrow.py", "--fast"],
    ["-m", "permit", "demo"],
    ["trace.py"],
]


@pytest.mark.parametrize("argv", ENTRYPOINTS_NO_FLAG)
def test_entrypoint_exits_nonzero_without_key_or_flag(argv):
    proc = _run(argv)
    assert proc.returncode != 0, f"{argv} exited 0 without a key or --demo-key"
    combined = proc.stdout + proc.stderr
    assert "demo-key" in combined or "PERMIT_ACCEPTANCE_KEY" in combined, (
        f"{argv} failed for the wrong reason:\n{combined[-800:]}"
    )


def test_server_exits_nonzero_without_key_or_flag():
    proc = _run(["server.py", "--port", str(_free_port())], timeout=30)
    assert proc.returncode != 0
    assert "demo-key" in proc.stdout + proc.stderr


def test_server_invalid_env_key_fatal_even_with_demo_flag():
    proc = _run(
        ["server.py", "--port", str(_free_port()), "--demo-key"],
        timeout=30, extra_env={"PERMIT_ACCEPTANCE_KEY": "x" * 31},
    )
    assert proc.returncode != 0
    assert "under 32 bytes" in proc.stdout + proc.stderr


# --- bar 2/4 (positive): the flag opts in, and --db persists the key -------

@pytest.mark.parametrize(
    "argv",
    [
        ["demo.py", "--demo-key"],
        ["demos/demo_sla_escrow.py", "--fast", "--demo-key"],
        ["-m", "permit", "demo", "--demo-key"],
    ],
)
def test_entrypoint_runs_with_demo_key_flag(argv):
    proc = _run(argv, timeout=120)
    assert proc.returncode == 0, (proc.stdout + proc.stderr)[-800:]


def _wait_for_server(proc, port, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise AssertionError(
                f"server exited {proc.returncode}: {proc.stdout.read()[-500:]}"
            )
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/api/ledger", timeout=2
            ):
                return
        except Exception:
            time.sleep(0.1)
    raise AssertionError("server did not start listening")


def _start_server(argv, extra_env=None):
    proc = subprocess.Popen(
        [sys.executable, *argv], cwd=ROOT, env=_clean_env(extra_env),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    return proc


def test_server_starts_with_demo_key_flag():
    port = _free_port()
    proc = _start_server(["server.py", "--port", str(port), "--demo-key"])
    try:
        _wait_for_server(proc, port)
        assert proc.poll() is None
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def test_server_db_demo_key_persists_across_restart(tmp_path):
    db = tmp_path / "ledger.db"
    sidecar = Path(str(db) + ".demo-key")
    seen = []
    for _ in range(2):
        port = _free_port()
        proc = _start_server(
            ["server.py", "--port", str(port), "--db", str(db), "--demo-key"]
        )
        try:
            _wait_for_server(proc, port)
        finally:
            proc.terminate()
            proc.wait(timeout=10)
        assert sidecar.exists()
        assert (os.stat(sidecar).st_mode & 0o777) == 0o600
        seen.append(sidecar.read_bytes())
    assert seen[0] == seen[1], "demo key changed silently across a restart"
