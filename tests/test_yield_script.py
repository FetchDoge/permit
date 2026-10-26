"""scripts/yield.py: pass-rate counting, mock-only environment, sandbox refusal."""
import importlib.util
import os
import types

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "permit_yield", os.path.join(os.path.dirname(__file__), "..", "scripts", "yield.py"))
yld = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(yld)


def _fake_runner(results):
    it = iter(results)
    calls = []

    def run(cmd, **kw):
        calls.append((cmd, kw))
        return types.SimpleNamespace(returncode=next(it))
    return run, calls


def test_yield_reports_pass_rate_per_target(capsys):
    run, calls = _fake_runner([0, 1, 0, 0])  # demo: 1/2, pytest: 2/2
    rc = yld.main(["-n", "2"], runner=run)
    out = capsys.readouterr().out
    assert "demo.py: 1/2 passed (50%)" in out
    assert "pytest: 2/2 passed (100%)" in out
    assert rc == 1
    assert len(calls) == 4


def test_yield_all_pass_exits_zero():
    run, _ = _fake_runner([0] * 6)
    assert yld.main(["-n", "3"], runner=run) == 0


def test_yield_strips_paypal_credentials(monkeypatch):
    monkeypatch.setenv("PERMIT_PAYPAL_CLIENT_ID", "x")
    monkeypatch.setenv("PAYPAL_SANDBOX_SECRET", "y")
    run, calls = _fake_runner([0, 0])
    yld.main(["-n", "1"], runner=run)
    for _, kw in calls:
        assert not any(k.startswith(("PERMIT_PAYPAL_", "PAYPAL_SANDBOX_"))
                       for k in kw["env"])


def test_yield_refuses_sandbox_commands():
    run, calls = _fake_runner([0])
    with pytest.raises(ValueError):
        yld.run_target(["python", "launch_sandbox.py"], runner=run)
    with pytest.raises(ValueError):
        yld.run_target(["python", "scripts/sandbox_smoke.py"], runner=run)
    assert calls == []
