"""scripts/sandbox_smoke.py is the one-command live rail proof: pin it.

The smoke script is the first thing an operator runs against the real
PayPal sandbox (OAuth, a $1.00 AUTHORIZE-intent order, an order read,
and, only when the order is already payer-approved, authorize plus an
immediate void). Until now it was mentioned in no doc and covered by
no test, and its load-bearing promises are easy to break silently:

- exit 2 with instructions when credentials are absent, and no client
  is constructed (so no network is touched);
- exit 1 when the rail itself fails (OAuth, create, read, authorize,
  void), naming the step that failed;
- an unapproved order is a pass (exit 0) that stops before authorize;
- it NEVER captures: an approved order is authorized and voided only.

These tests load the script as a module and swap in a fake sandbox
client, so no network and no credentials are involved. One subprocess
test pins the real __main__ exit-code wiring for the no-credentials
path.
"""

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "sandbox_smoke.py"

_spec = importlib.util.spec_from_file_location("sandbox_smoke", SCRIPT)
smoke = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(smoke)

from settlement.sandbox_client import ApprovalTimeout, NeedsPayerApproval  # noqa: E402

_DROP = (
    "PERMIT_PAYPAL_CLIENT_ID",
    "PERMIT_PAYPAL_CLIENT_SECRET",
    "PERMIT_PAYPAL_MERCHANT_ID",
)


class FakeClient:
    """Records every call; capture() exists only to prove it is unused."""

    def __init__(self, status="CREATED", oauth_error=None,
                 authorize_error=None, wait_error=None):
        self.status = status
        self.oauth_error = oauth_error
        self.authorize_error = authorize_error
        self.wait_error = wait_error
        self.calls = []

    def _ensure_token(self):
        self.calls.append(("oauth",))
        if self.oauth_error is not None:
            raise self.oauth_error

    def create_order(self, amount_cents, idempotency_key=None):
        self.calls.append(("create_order", amount_cents))
        return "ORDER-1", "https://approve.example/ORDER-1"

    def order_status(self, order_id):
        self.calls.append(("order_status", order_id))
        return self.status

    def wait_for_approval(self, order_id, timeout_s=0):
        self.calls.append(("wait_for_approval", order_id, timeout_s))
        if self.wait_error is not None:
            raise self.wait_error
        return "APPROVED"

    def authorize_order(self, order_id, amount_cents, merchant_id):
        self.calls.append(("authorize_order", order_id, amount_cents, merchant_id))
        if self.authorize_error is not None:
            raise self.authorize_error
        return SimpleNamespace(auth_id="AUTH-1", status="CREATED")

    def void(self, auth_id):
        self.calls.append(("void", auth_id))
        return SimpleNamespace(status="VOIDED")

    def capture(self, *args, **kwargs):  # pragma: no cover - must never run
        self.calls.append(("capture",))
        raise AssertionError("sandbox_smoke must never capture")


def _rig(monkeypatch, fake, wait_s=0.0, merchant=None):
    constructed = []

    def factory(*args, **kwargs):
        constructed.append((args, kwargs))
        return fake

    monkeypatch.setattr(smoke, "SandboxPayPalClient", factory)
    monkeypatch.setattr(smoke, "APPROVAL_WAIT_S", wait_s)
    monkeypatch.setenv("PERMIT_PAYPAL_CLIENT_ID", "cid")
    monkeypatch.setenv("PERMIT_PAYPAL_CLIENT_SECRET", "secret")
    if merchant is None:
        monkeypatch.delenv("PERMIT_PAYPAL_MERCHANT_ID", raising=False)
    else:
        monkeypatch.setenv("PERMIT_PAYPAL_MERCHANT_ID", merchant)
    return constructed


def _names(fake):
    return [c[0] for c in fake.calls]


def test_missing_credentials_exit_2_and_no_client_constructed(monkeypatch, capsys):
    constructed = []

    def factory(*args, **kwargs):  # pragma: no cover - must never run
        constructed.append((args, kwargs))
        raise AssertionError("client constructed without credentials")

    monkeypatch.setattr(smoke, "SandboxPayPalClient", factory)
    for name in _DROP:
        monkeypatch.delenv(name, raising=False)
    assert smoke.main() == 2
    out = capsys.readouterr().out
    assert "SMOKE SKIP (exit 2)" in out
    assert "PERMIT_PAYPAL_CLIENT_ID" in out
    assert "PERMIT_PAYPAL_CLIENT_SECRET" in out
    assert constructed == []


def test_missing_credentials_subprocess_exit_2():
    env = {k: v for k, v in os.environ.items() if k not in _DROP}
    proc = subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=ROOT, capture_output=True, text=True, timeout=60, env=env,
    )
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "SMOKE SKIP (exit 2)" in proc.stdout


def test_oauth_failure_exit_1_before_order(monkeypatch, capsys):
    fake = FakeClient(oauth_error=RuntimeError("bad credentials"))
    _rig(monkeypatch, fake)
    assert smoke.main() == 1
    out = capsys.readouterr().out
    assert "SMOKE FAIL: oauth token fetch failed" in out
    assert _names(fake) == ["oauth"]


def test_unapproved_order_passes_without_authorize(monkeypatch, capsys):
    fake = FakeClient(status="CREATED")
    _rig(monkeypatch, fake, wait_s=0.0)
    assert smoke.main() == 0
    out = capsys.readouterr().out
    assert "SMOKE 2/4: order created: ORDER-1" in out
    assert "SMOKE 4/4: rail live through order creation and order reads." in out
    assert "https://approve.example/ORDER-1" in out
    assert _names(fake) == ["oauth", "create_order", "order_status"]


def test_approval_wait_timeout_passes_without_authorize(monkeypatch, capsys):
    fake = FakeClient(
        status="CREATED",
        wait_error=ApprovalTimeout("ORDER-1", 5.0, "CREATED"),
    )
    _rig(monkeypatch, fake, wait_s=5.0)
    assert smoke.main() == 0
    out = capsys.readouterr().out
    assert "approval not received" in out
    assert "authorize_order" not in _names(fake)
    assert "capture" not in _names(fake)


def test_approved_order_authorizes_then_voids_never_captures(monkeypatch, capsys):
    fake = FakeClient(status="APPROVED")
    _rig(monkeypatch, fake, merchant="MERCH-1")
    assert smoke.main() == 0
    out = capsys.readouterr().out
    assert ("authorize_order", "ORDER-1", 100, "MERCH-1") in fake.calls
    assert ("void", "AUTH-1") in fake.calls
    assert "capture" not in _names(fake)
    assert "no capture performed, no money moved" in out
    assert "SANDBOX RAIL LIVE" in out


def test_authorize_still_needs_approval_exit_1_no_void(monkeypatch, capsys):
    fake = FakeClient(
        status="APPROVED",
        authorize_error=NeedsPayerApproval("ORDER-1", "https://approve.example/ORDER-1"),
    )
    _rig(monkeypatch, fake)
    assert smoke.main() == 1
    out = capsys.readouterr().out
    assert "SMOKE FAIL: order still needs approval" in out
    assert "void" not in _names(fake)
    assert "capture" not in _names(fake)


def test_runbook_and_checklist_document_the_smoke():
    runbook = (ROOT / "docs" / "sandbox-runbook.md").read_text(encoding="utf-8")
    for needle in (
        "scripts/sandbox_smoke.py",
        "tests/test_sandbox_smoke.py",
        "PERMIT_SMOKE_WAIT_S",
        "never captures",
        "exit 2",
    ):
        assert needle in runbook, needle
    checklist = (ROOT / "docs" / "submission-checklist.md").read_text(encoding="utf-8")
    assert "scripts/sandbox_smoke.py" in checklist
