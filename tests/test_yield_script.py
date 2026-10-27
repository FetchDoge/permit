"""scripts/yield.py: counts not percentages, receipt proof required, stderr shown, mock-only."""
import importlib.util
import os
import types

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "permit_yield", os.path.join(os.path.dirname(__file__), "..", "scripts", "yield.py"))
yld = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(yld)

PYTEST_OK = "....\n410 passed, 3 skipped in 19.50s\n"
DEMO_OK = "...\n== ledger chain: VERIFIED (16 receipts)\n"
REPLAY_OK = "ledger chain: VERIFIED (26 receipts)\n"


def _runner(results):
    it = iter(results)
    calls = []

    def run(cmd, **kw):
        calls.append((cmd, kw))
        rc, out, err = next(it)
        return types.SimpleNamespace(returncode=rc, stdout=out, stderr=err)
    return run, calls


def test_counts_not_percentage(capsys):
    run, _ = _runner([(0, PYTEST_OK, ""), (0, DEMO_OK, ""), (0, REPLAY_OK, "")])
    assert yld.main(["-n", "1"], runner=run) == 0
    out = capsys.readouterr().out
    assert "pytest: 1 passed, 0 failed of 1 runs | 410 passed, 3 skipped, 0 failed" in out
    assert "replay: 1 passed, 0 failed of 1 runs" in out
    assert "%" not in out


def test_exit_zero_without_receipt_line_fails(capsys):
    run, _ = _runner([(0, "ledger chain: VERIFIED (15 receipts)\n", "")])
    assert yld.main(["-n", "1", "-t", "demo"], runner=run) == 1
    assert "demo: 0 passed, 1 failed" in capsys.readouterr().out


def test_pytest_failure_counted_even_with_exit_zero():
    run, _ = _runner([(0, "1 failed, 409 passed, 3 skipped in 2.0s\n", "")])
    ok, detail = yld.run_target("pytest", yld.TARGETS["pytest"][0], None, run)
    assert not ok and "1 failed" in detail


def test_nonzero_exit_prints_stderr(capsys):
    run, _ = _runner([(1, "", "Traceback: boom\n")])
    assert yld.main(["-n", "1", "-t", "replay"], runner=run) == 1
    assert "Traceback: boom" in capsys.readouterr().err


def test_replay_target_has_no_fast_flag():
    cmd, expect = yld.TARGETS["replay"]
    assert "--fast" not in cmd and expect.endswith("VERIFIED (26 receipts)")


def test_strips_paypal_credentials(monkeypatch):
    monkeypatch.setenv("PERMIT_PAYPAL_CLIENT_ID", "x")
    monkeypatch.setenv("PAYPAL_SANDBOX_SECRET", "y")
    run, calls = _runner([(0, DEMO_OK, "")])
    yld.main(["-n", "1", "-t", "demo"], runner=run)
    assert not any(k.startswith(("PERMIT_PAYPAL_", "PAYPAL_SANDBOX_"))
                   for k in calls[0][1]["env"])


def test_refuses_sandbox_commands():
    run, calls = _runner([])
    for cmd in (["python", "launch_sandbox.py"], ["python", "scripts/sandbox_smoke.py"]):
        with pytest.raises(ValueError):
            yld.run_target("x", cmd, "x", run)
    assert calls == []
