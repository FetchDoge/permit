"""REA seq 1854: with --db --allow-demo-key, PERMIT_ACCEPTANCE_KEY must win.

Regression from 2a1bbfe: the server pre-loaded the durable file and passed
those bytes as an explicit acceptance_key, so a set env key was ignored.
These cases must fail on c7b1ac7 and pass on head.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from permit.sqlite_ledger import (
    ACCEPTANCE_KEY_COMMITMENT_META,
    SqliteLedger,
)
from settlement.verifier import acceptance_key_commitment

ROOT = Path(__file__).resolve().parents[1]
MIN = 32


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _env(**extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k != "PERMIT_ACCEPTANCE_KEY"}
    env.update(extra)
    return env


def _run_server(db: Path, env: dict[str, str], *, timeout: float = 8.0):
    port = _free_port()
    proc = subprocess.Popen(
        [
            sys.executable,
            "server.py",
            "--port",
            str(port),
            "--db",
            str(db),
            "--allow-demo-key",
        ],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    deadline = time.time() + timeout
    listened = False
    try:
        while time.time() < deadline:
            rc = proc.poll()
            if rc is not None:
                out = proc.stdout.read() if proc.stdout else ""
                return subprocess.CompletedProcess(proc.args, rc, out or "", "")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    listened = True
                    break
            except OSError:
                time.sleep(0.05)
        out = ""
        proc.terminate()
        try:
            out, _ = proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate(timeout=3)
        return subprocess.CompletedProcess(
            proc.args, 0 if listened else (proc.returncode or 1), out or "", ""
        )
    finally:
        if proc.poll() is None:
            proc.kill()


def _seed_db_and_file(tmp_path: Path, file_key: bytes) -> tuple[Path, Path]:
    db = tmp_path / "ledger.db"
    key_path = Path(f"{db}.acceptance_key")
    SqliteLedger(str(db)).close()
    key_path.write_bytes(file_key)
    os.chmod(key_path, 0o600)
    return db, key_path


def test_db_allow_demo_env_valid_uses_exact_env_key(tmp_path):
    """Env set and valid: that exact key is used (not the file key)."""
    file_key = b"F" * MIN
    env_key = b"E" * MIN
    assert file_key != env_key
    db, key_path = _seed_db_and_file(tmp_path, file_key)
    before = key_path.read_bytes()

    proc = _run_server(db, _env(PERMIT_ACCEPTANCE_KEY=env_key.decode()))
    out = proc.stdout or ""
    assert proc.returncode == 0, out
    assert "acceptance key error" not in out

    # File must be untouched; commitment must bind the env key.
    assert key_path.read_bytes() == before
    lg = SqliteLedger(str(db))
    try:
        stored = lg.get_meta(ACCEPTANCE_KEY_COMMITMENT_META)
        assert stored == acceptance_key_commitment(env_key)
        assert stored != acceptance_key_commitment(file_key)
    finally:
        lg.close()


def test_db_allow_demo_env_empty_refuses(tmp_path):
    db, _ = _seed_db_and_file(tmp_path, b"F" * MIN)
    proc = _run_server(db, _env(PERMIT_ACCEPTANCE_KEY=""))
    out = proc.stdout or ""
    assert proc.returncode != 0
    assert "acceptance key error:" in out
    assert "Traceback" not in out


def test_db_allow_demo_env_31_bytes_refuses(tmp_path):
    db, _ = _seed_db_and_file(tmp_path, b"F" * MIN)
    proc = _run_server(db, _env(PERMIT_ACCEPTANCE_KEY="x" * 31))
    out = proc.stdout or ""
    assert proc.returncode != 0
    assert "acceptance key error:" in out
    assert "under 32" in out or "31" in out
    assert "Traceback" not in out


def test_db_allow_demo_env_whitespace_refuses(tmp_path):
    db, _ = _seed_db_and_file(tmp_path, b"F" * MIN)
    proc = _run_server(db, _env(PERMIT_ACCEPTANCE_KEY=" " * 32))
    out = proc.stdout or ""
    assert proc.returncode != 0
    assert "acceptance key error:" in out
    assert "whitespace" in out
    assert "Traceback" not in out


def test_db_allow_demo_env_unset_uses_file_key(tmp_path):
    """Env unset: the durable file key is used."""
    file_key = b"Z" * MIN
    db, key_path = _seed_db_and_file(tmp_path, file_key)

    proc = _run_server(db, _env())
    out = proc.stdout or ""
    assert proc.returncode == 0, out
    assert key_path.read_bytes() == file_key

    lg = SqliteLedger(str(db))
    try:
        assert lg.get_meta(ACCEPTANCE_KEY_COMMITMENT_META) == (
            acceptance_key_commitment(file_key)
        )
    finally:
        lg.close()
