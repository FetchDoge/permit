"""REA seq 1801 (N-b) regressions on PR #54 @ 70b0fc6.

- chmod-000 / foreign-owner opens must become clean ValueError (not
  PermissionError traceback).
- A FIFO at the key path must fail fast (O_NONBLOCK), not hang.
- server.py must open the durable key file exactly once at startup.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

import server as server_mod
from settlement.verifier import load_or_create_demo_key

ROOT = Path(__file__).resolve().parents[1]
MIN = 32


def _write_key(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.write_bytes(data)
    os.chmod(path, mode)


def test_chmod_000_key_file_is_clean_valueerror(monkeypatch, tmp_path):
    """Own-user mode-000 file: EACCES → ValueError (never skip; fail if root)."""
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    assert os.geteuid() != 0, (
        "chmod-000 key test must run as non-root (root bypasses mode bits); "
        "do not skip — fix the environment"
    )
    path = tmp_path / "locked.acceptance_key"
    _write_key(path, os.urandom(MIN), 0o000)
    assert path.stat().st_uid == os.geteuid()
    try:
        with pytest.raises(ValueError, match="cannot be opened"):
            load_or_create_demo_key(path)
    finally:
        os.chmod(path, 0o600)


def test_chmod_000_server_exits_clean_no_traceback(monkeypatch, tmp_path):
    """Own-user mode-000 key: server exits 1 with clean acceptance key error."""
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    assert os.geteuid() != 0, (
        "chmod-000 server test must run as non-root; do not skip — fix the environment"
    )
    db = tmp_path / "ledger.db"
    key = Path(f"{db}.acceptance_key")
    _write_key(key, os.urandom(MIN), 0o000)
    assert key.stat().st_uid == os.geteuid()
    env = {k: v for k, v in os.environ.items() if k != "PERMIT_ACCEPTANCE_KEY"}
    from permit.sqlite_ledger import SqliteLedger

    SqliteLedger(str(db)).close()
    try:
        proc = subprocess.run(
            [
                sys.executable,
                "server.py",
                "--port",
                "0",
                "--db",
                str(db),
                "--allow-demo-key",
            ],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=8,
        )
    finally:
        os.chmod(key, 0o600)
    out = (proc.stdout or "") + (proc.stderr or "")
    assert proc.returncode == 1, out
    assert "acceptance key error:" in out
    assert "Traceback" not in out
    assert "PermissionError" not in out


def _sudo_n(*args: str) -> subprocess.CompletedProcess[str]:
    """Run ``sudo -n …``. Fail (never skip) if passwordless sudo is unavailable."""
    return subprocess.run(
        ["sudo", "-n", *args],
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_foreign_owner_real_chown_clean_valueerror(tmp_path, monkeypatch):
    """Real foreign-owned 0600 key via ``sudo -n chown nobody`` (never skip).

    Creates a 0600 key, then ``sudo -n chown nobody``. GitHub Ubuntu runners
    have passwordless sudo; if ``sudo -n`` fails, this test FAILS (does not
    skip). Non-root open then hits EACCES; that must map to a clean
    ValueError / ``acceptance key error`` (exit 1, no traceback). Cleanup
    uses sudo too.
    """
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    assert os.geteuid() != 0, (
        "foreign-owner test must run as non-root so open hits EACCES; "
        "do not skip — fix the environment"
    )
    path = tmp_path / "foreign.acceptance_key"
    _write_key(path, os.urandom(MIN), 0o600)

    chown = _sudo_n("chown", "nobody", str(path))
    assert chown.returncode == 0, (
        "sudo -n chown nobody failed — passwordless sudo is required "
        f"(never skip). stderr={chown.stderr!r} stdout={chown.stdout!r}"
    )
    try:
        st = os.stat(path)
        assert st.st_uid != os.geteuid(), "chown nobody did not change ownership"
        assert (st.st_mode & 0o777) == 0o600

        with pytest.raises(ValueError, match="cannot be opened"):
            load_or_create_demo_key(path)

        # Also exercise the server entry point: clean exit 1, no traceback.
        db = tmp_path / "foreign.db"
        from permit.sqlite_ledger import SqliteLedger

        SqliteLedger(str(db)).close()
        server_key = Path(f"{db}.acceptance_key")
        _write_key(server_key, os.urandom(MIN), 0o600)
        chown2 = _sudo_n("chown", "nobody", str(server_key))
        assert chown2.returncode == 0, chown2.stderr
        env = {k: v for k, v in os.environ.items() if k != "PERMIT_ACCEPTANCE_KEY"}
        try:
            proc = subprocess.run(
                [
                    sys.executable,
                    "server.py",
                    "--port",
                    "0",
                    "--db",
                    str(db),
                    "--allow-demo-key",
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=8,
            )
        finally:
            fix2 = _sudo_n(
                "chown", f"{os.geteuid()}:{os.getegid()}", str(server_key)
            )
            assert fix2.returncode == 0, fix2.stderr
            os.chmod(server_key, 0o600)
        out = (proc.stdout or "") + (proc.stderr or "")
        assert proc.returncode == 1, out
        assert "acceptance key error:" in out
        assert "Traceback" not in out
        assert "PermissionError" not in out
    finally:
        fix = _sudo_n("chown", f"{os.geteuid()}:{os.getegid()}", str(path))
        assert fix.returncode == 0, (
            f"sudo cleanup chown failed: stderr={fix.stderr!r}"
        )
        os.chmod(path, 0o600)


def test_fifo_at_key_path_fails_fast(monkeypatch, tmp_path):
    """A FIFO at the key path must fail fast (O_NONBLOCK), not hang open()."""
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    path = tmp_path / "fifo.acceptance_key"
    os.mkfifo(path, 0o600)
    # Run in a child process so a blocking open on 70b0fc6 is killed by timeout
    # rather than wedging the pytest worker thread.
    env = {k: v for k, v in os.environ.items() if k != "PERMIT_ACCEPTANCE_KEY"}
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "from settlement.verifier import load_or_create_demo_key\n"
                    f"load_or_create_demo_key({str(path)!r})\n"
                ),
            ],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"load_or_create_demo_key hung on FIFO: {exc}")
    assert time.monotonic() - t0 < 3.0
    out = (proc.stdout or "") + (proc.stderr or "")
    assert proc.returncode != 0, out
    assert "regular file" in out


def test_fifo_server_exits_fast_nonzero(monkeypatch, tmp_path):
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    db = tmp_path / "fifo.db"
    key = Path(f"{db}.acceptance_key")
    from permit.sqlite_ledger import SqliteLedger

    SqliteLedger(str(db)).close()
    os.mkfifo(key, 0o600)
    env = {k: v for k, v in os.environ.items() if k != "PERMIT_ACCEPTANCE_KEY"}
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            [
                sys.executable,
                "server.py",
                "--port",
                "0",
                "--db",
                str(db),
                "--allow-demo-key",
            ],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"server hung on FIFO key path: {exc}")
    assert time.monotonic() - t0 < 3.0
    out = (proc.stdout or "") + (proc.stderr or "")
    assert proc.returncode != 0
    assert "acceptance key error:" in out
    assert "Traceback" not in out


def test_server_opens_demo_key_file_exactly_once(monkeypatch, tmp_path):
    """The durable key must be loaded once; a second load can diverge (seq 1801)."""
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    db = tmp_path / "once.db"
    key_path = Path(f"{db}.acceptance_key")
    from permit.sqlite_ledger import SqliteLedger
    import settlement.verifier as verifier_mod
    from permit.ledger import Ledger
    from permit.permit import PermitStore

    SqliteLedger(str(db)).close()

    opens: list[str] = []
    real_load = verifier_mod.load_or_create_demo_key

    def counting_load(path, *, db_nonempty=False):
        opens.append(str(path))
        return real_load(path, db_nonempty=db_nonempty)

    # Patch both the server import and the verifier module name resolve uses.
    monkeypatch.setattr(verifier_mod, "load_or_create_demo_key", counting_load)
    monkeypatch.setattr(server_mod, "load_or_create_demo_key", counting_load)

    class _FakeServer:
        def __init__(self, *a, **k):
            pass

        def serve_forever(self):
            raise KeyboardInterrupt

    monkeypatch.setattr(server_mod, "ThreadingHTTPServer", _FakeServer)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "server.py",
            "--port",
            "8765",
            "--db",
            str(db),
            "--allow-demo-key",
        ],
    )
    # Reset module globals that main() mutates.
    server_mod.ledger = Ledger()
    server_mod.permits = PermitStore(ledger=server_mod.ledger)
    try:
        server_mod.main()
    except SystemExit as exc:
        pytest.fail(f"server exited early: {exc}")
    assert opens == [str(key_path)], f"expected one load, got {opens!r}"
    assert key_path.exists()
