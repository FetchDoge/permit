"""The camera paths must exit 0: mock demo and trace.

demo_six_beat.py is exercised manually (it drives the real LLM agent);
demo.py and trace.py are deterministic and run here.
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_mock_demo_exits_clean():
    proc = _run(["demo.py"])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "VERIFIED" in proc.stdout
    assert "delegate a $15 sub-permit" in proc.stdout
    assert "revoke parent cascades" in proc.stdout
    assert "parent remaining $50.00 (unspent carve released)" in proc.stdout
    assert "post-cascade release: released=False" in proc.stdout


def test_trace_exits_clean():
    proc = _run(["trace.py"])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "TRACE COMPLETE" in proc.stdout
    assert "DELEGATED" in proc.stdout
    assert "REVOKED_CASCADE" in proc.stdout
    assert "CARVE_RELEASED" in proc.stdout
