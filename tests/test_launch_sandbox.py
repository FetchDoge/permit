"""launch_sandbox.py is a shipped entry point: pin what it actually does.

The launcher at the repo root maps .env.sandbox names (PAYPAL_SANDBOX_*)
to the PERMIT_PAYPAL_* names server.py expects. Until now it was
mentioned in no doc and covered by no test, and two of its behaviors
are easy to trip over: it overrides PERMIT_PAYPAL_MERCHANT_ID with a
hardcoded sandbox merchant, and a missing .env.sandbox crashes with a
FileNotFoundError traceback instead of a message. These tests run the
launcher as a subprocess against a temp PERMIT_ROOT holding a fake
server.py, so no network, no credentials, and no real server start.
"""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "launch_sandbox.py"
HARDCODED_MERCHANT = "GVBH7M3B2KVPW"

FAKE_SERVER = (
    "import os, sys\n"
    "print('FAKE SERVER argv=' + ' '.join(sys.argv[1:]))\n"
    "print('FAKE id=' + os.environ.get('PERMIT_PAYPAL_CLIENT_ID', ''))\n"
    "print('FAKE secret=' + os.environ.get('PERMIT_PAYPAL_CLIENT_SECRET', ''))\n"
    "print('FAKE merchant=' + os.environ.get('PERMIT_PAYPAL_MERCHANT_ID', ''))\n"
)

_DROP = (
    "PAYPAL_SANDBOX_CLIENT_ID",
    "PAYPAL_SANDBOX_SECRET",
    "PERMIT_PAYPAL_CLIENT_ID",
    "PERMIT_PAYPAL_CLIENT_SECRET",
    "PERMIT_PAYPAL_MERCHANT_ID",
)


def _run_launcher(tmp_path: Path, extra_env: dict | None = None):
    env = {k: v for k, v in os.environ.items() if k not in _DROP}
    env["PERMIT_ROOT"] = str(tmp_path)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [sys.executable, str(LAUNCHER)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )


def test_missing_env_file_crashes_with_traceback(tmp_path):
    # No .env.sandbox under PERMIT_ROOT: the unguarded open() raises
    # FileNotFoundError. Pinned as-is so the runbook can state it
    # accurately; a friendlier failure is a deliberate future change.
    proc = _run_launcher(tmp_path)
    assert proc.returncode != 0
    assert "FileNotFoundError" in proc.stderr
    assert ".env.sandbox" in proc.stderr


def test_empty_credentials_exit_1_before_launch(tmp_path):
    (tmp_path / ".env.sandbox").write_text("# no credentials here\n")
    (tmp_path / "server.py").write_text("print('SHOULD_NOT_RUN')\n")
    proc = _run_launcher(tmp_path)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "missing credentials" in proc.stdout
    assert "SHOULD_NOT_RUN" not in proc.stdout


def test_mapping_and_merchant_override(tmp_path):
    (tmp_path / ".env.sandbox").write_text(
        "PAYPAL_SANDBOX_CLIENT_ID=file-id\n"
        "PAYPAL_SANDBOX_SECRET=file-secret\n"
    )
    (tmp_path / "server.py").write_text(FAKE_SERVER)
    proc = _run_launcher(
        tmp_path,
        extra_env={
            "PERMIT_PAYPAL_CLIENT_ID": "preset-id",
            "PERMIT_PAYPAL_MERCHANT_ID": "OTHER-MERCHANT",
        },
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "permit: sandbox rail armed" in proc.stdout
    # File values replace any preset PERMIT_PAYPAL_* names.
    assert "FAKE id=file-id" in proc.stdout
    assert "FAKE secret=file-secret" in proc.stdout
    # The merchant is always the hardcoded sandbox merchant.
    assert f"FAKE merchant={HARDCODED_MERCHANT}" in proc.stdout
    assert "OTHER-MERCHANT" not in proc.stdout
    assert "--sandbox" in proc.stdout
    assert "8741" in proc.stdout


def test_runbook_documents_the_launcher():
    text = (ROOT / "docs" / "sandbox-runbook.md").read_text(encoding="utf-8")
    for needle in (
        "launch_sandbox.py",
        "PAYPAL_SANDBOX_CLIENT_ID",
        "PAYPAL_SANDBOX_SECRET",
        HARDCODED_MERCHANT,
        "missing credentials",
        "FileNotFoundError",
    ):
        assert needle in text, needle
