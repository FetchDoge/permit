"""Issue #35: the release verifier must fail closed on its acceptance key.

Before this fix, settlement/verifier.py fell back to a hardcoded
DEMO_ACCEPTANCE_KEY when PERMIT_ACCEPTANCE_KEY was unset, so anyone who
read the repo could forge Type A acceptances in a default deployment.

Pass bar (from the issue):
- No fallback key in library code; the constant is gone.
- Missing, empty, or short (under 32 byte) key raises at construction.
- Demo use opts in only through an explicit flag, off by default, with
  the key generated per run.
"""

import hashlib
from datetime import datetime, timedelta, timezone

import pytest

import settlement.verifier as verifier_module
from permit.ledger import Ledger
from permit.permit import PermitStore
from settlement.paypal_client import MockPayPalClient
from settlement.verifier import (
    Escrow,
    Evidence,
    PredicateType,
    ReleaseVerifier,
    sign_acceptance,
)

GOOD_KEY = b"k" * 32


def _rig(**kwargs):
    ledger = Ledger()
    permits = PermitStore(ledger=ledger)
    paypal = MockPayPalClient()
    verifier = ReleaseVerifier(paypal, permits, ledger=ledger, **kwargs)
    return verifier, paypal, permits


def test_no_fallback_key_constant():
    assert not hasattr(verifier_module, "DEMO_ACCEPTANCE_KEY")
    assert not hasattr(verifier_module, "ACCEPTANCE_KEY")


def test_missing_key_raises(monkeypatch):
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    with pytest.raises(ValueError):
        _rig()


def test_empty_key_raises(monkeypatch):
    monkeypatch.setenv("PERMIT_ACCEPTANCE_KEY", "")
    with pytest.raises(ValueError):
        _rig()
    with pytest.raises(ValueError):
        _rig(acceptance_key=b"")


def test_short_key_raises(monkeypatch):
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    with pytest.raises(ValueError):
        _rig(acceptance_key=b"x" * 31)
    monkeypatch.setenv("PERMIT_ACCEPTANCE_KEY", "x" * 31)
    with pytest.raises(ValueError):
        _rig()


def test_env_key_and_explicit_key_construct(monkeypatch):
    monkeypatch.setenv("PERMIT_ACCEPTANCE_KEY", "e" * 32)
    _rig()
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY")
    _rig(acceptance_key=GOOD_KEY)
    _rig(acceptance_key="s" * 40)  # str keys are encoded


def test_demo_opt_in_generates_per_instance_key(monkeypatch):
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    v1, _, _ = _rig(allow_demo_key=True)
    v2, _, _ = _rig(allow_demo_key=True)
    sig1 = v1.sign_acceptance("esc", "hash", 100)
    sig2 = v2.sign_acceptance("esc", "hash", 100)
    assert sig1 != sig2  # per-run keys: a signature for one run fits no other


def test_sign_acceptance_requires_a_real_key():
    with pytest.raises(ValueError):
        sign_acceptance("esc", "hash", 100, b"short")
    sig = sign_acceptance("esc", "hash", 100, GOOD_KEY)
    assert len(sig) == 64


def test_type_a_release_uses_configured_key(monkeypatch):
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    verifier, paypal, permits = _rig(acceptance_key=GOOD_KEY)
    permit, _ = permits.grant(
        agent_id="agent_1",
        cap_cents=5000,
        allowlist=["merchant_1"],
        expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    check = permits.check(permit.permit_id, 3000, "merchant_1", agent_id=permit.agent_id)
    assert check.allowed
    pp_auth = paypal.authorize(3000, "merchant_1")
    artifact_hash = hashlib.sha256(b"work").hexdigest()
    verifier.register(
        Escrow(
            escrow_id="esc_1",
            permit_id=permit.permit_id,
            auth_id=check.receipt.payload["auth_id"],
            paypal_auth_id=pp_auth.auth_id,
            amount_cents=3000,
            merchant_id="merchant_1",
            predicate_type=PredicateType.A,
            artifact_hash=artifact_hash,
        )
    )
    # A signature under any other key (for example the old demo key) fails.
    forged = sign_acceptance("esc_1", artifact_hash, 3000, b"demo-key" + b"0" * 24)
    refused = verifier.verify_and_capture(
        "esc_1", Evidence(acceptance_signature=forged)
    )
    assert not refused.released
    assert len(paypal.capture_calls) == 0
