"""#53: every real entry point fails closed without a valid acceptance key.

Each entry point is run as a subprocess with (a) no key, (b) a 31-byte key,
and (c) a whitespace-only key. All three must exit non-zero when the demo
flag is absent. These cases must fail on main@9809cc7 (demo key was on by
default / whitespace accepted) and pass on the #53 fix.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SIX_BEAT_FIXTURE = ROOT / "demos" / "fixtures" / "demo_transcript.jsonl"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _clean_env(**extra: str) -> dict[str, str]:
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in (
            "PERMIT_ACCEPTANCE_KEY",
            "PERMIT_AGENT_CLI",
            "PERMIT_GROK_CLI",
        )
    }
    env.update(extra)
    return env


def _run(args: list[str], *, env: dict[str, str], timeout: float = 25.0):
    """Run an entry point. For server.py, treat a successful listen as exit 0

    (fail-open) and a quick non-zero exit as the expected fail-closed path.
    This avoids hanging the suite on 9809cc7 where mock mode swapped in a
    demo key and served forever.
    """
    import time

    is_server = any(a == "server.py" or a.endswith("/server.py") for a in args)
    if not is_server:
        return subprocess.run(
            [sys.executable, *args],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    # Extract --port value for a listen probe.
    port = None
    for i, a in enumerate(args):
        if a == "--port" and i + 1 < len(args):
            port = int(args[i + 1])
            break
    proc = subprocess.Popen(
        [sys.executable, *args],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    deadline = time.time() + min(timeout, 8.0)
    listened = False
    try:
        while time.time() < deadline:
            rc = proc.poll()
            if rc is not None:
                out = proc.stdout.read() if proc.stdout else ""
                return subprocess.CompletedProcess(
                    proc.args, rc, out or "", ""
                )
            if port is not None:
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        listened = True
                        break
                except OSError:
                    pass
            time.sleep(0.05)
        out = ""
        proc.terminate()
        try:
            out, _ = proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate(timeout=3)
        # Listening means the process accepted a bad/missing key and started.
        return subprocess.CompletedProcess(
            proc.args, 0 if listened else (proc.returncode or 1), out or "", ""
        )
    except Exception:
        proc.kill()
        raise


# (id, argv builder) — builders may need a free port / tmp path.
def _entry_points(tmp_path: Path):
    port = _free_port()
    db_path = tmp_path / "ep.db"
    return [
        ("demo.py", ["demo.py"]),
        ("demos/demo_admission.py", ["demos/demo_admission.py"]),
        ("demos/demo_approval.py", ["demos/demo_approval.py", "--fast", "--port", str(port)]),
        (
            "demos/demo_delegation.py",
            ["demos/demo_delegation.py", "--fast", "--port", str(_free_port())],
        ),
        (
            "demos/demo_six_beat.py",
            [
                "demos/demo_six_beat.py",
                "--fast",
                "--replay",
                str(SIX_BEAT_FIXTURE),
                "--port",
                str(_free_port()),
            ],
        ),
        ("demos/demo_sla_escrow.py", ["demos/demo_sla_escrow.py", "--fast"]),
        ("python -m permit", ["-m", "permit", "demo"]),
        ("trace.py", ["trace.py"]),
        ("server.py", ["server.py", "--port", str(_free_port())]),
        (
            "server.py --db",
            ["server.py", "--port", str(_free_port()), "--db", str(db_path)],
        ),
    ]


KEY_CASES = [
    ("no_key", {}),
    ("short_31", {"PERMIT_ACCEPTANCE_KEY": "x" * 31}),
    ("whitespace_only", {"PERMIT_ACCEPTANCE_KEY": " " * 32}),
]


@pytest.mark.parametrize("case_name,key_env", KEY_CASES, ids=[c[0] for c in KEY_CASES])
def test_each_entry_point_rejects_bad_or_missing_key(tmp_path, case_name, key_env):
    env = _clean_env(**key_env)
    failures: list[str] = []
    for name, argv in _entry_points(tmp_path):
        proc = _run(argv, env=env, timeout=30.0)
        if proc.returncode == 0:
            failures.append(
                f"{name} ({case_name}) exited 0; stdout={proc.stdout!r} "
                f"stderr={proc.stderr!r}"
            )
    assert not failures, "\n".join(failures)


def test_server_db_demo_key_persists_across_restart(tmp_path):
    """#53 bar 4: --db --allow-demo-key writes a 0600 key that survives restart."""
    import time

    db = tmp_path / "durable.db"
    key_file = Path(f"{db}.acceptance_key")
    env = _clean_env()

    def _boot(port: int) -> subprocess.Popen:
        return subprocess.Popen(
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

    def _wait_listen(srv: subprocess.Popen, port: int, timeout: float = 8.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if srv.poll() is not None:
                out, _ = srv.communicate(timeout=2)
                raise AssertionError(
                    f"server exited {srv.returncode} before listen: {out}"
                )
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.05)
        raise AssertionError("server did not listen in time")

    port = _free_port()
    srv = _boot(port)
    try:
        _wait_listen(srv, port)
        assert key_file.exists()
        assert (key_file.stat().st_mode & 0o777) == 0o600
        first = key_file.read_bytes()
    finally:
        srv.terminate()
        try:
            srv.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            srv.kill()

    port2 = _free_port()
    srv2 = _boot(port2)
    try:
        _wait_listen(srv2, port2)
        assert key_file.read_bytes() == first
    finally:
        srv2.terminate()
        try:
            srv2.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            srv2.kill()
