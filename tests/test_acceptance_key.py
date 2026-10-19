"""Issue #35/#53: the release verifier must fail closed on its acceptance key.

Before #35, settlement/verifier.py fell back to a hardcoded
DEMO_ACCEPTANCE_KEY when PERMIT_ACCEPTANCE_KEY was unset, so anyone who
read the repo could forge Type A acceptances in a default deployment.

#53 (REA check of #44) adds: reject whitespace-only keys; never paper over
an invalid configured key with the demo flag; persist demo keys in --db
mode.
"""

import hashlib
import stat
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
    resolve_acceptance_key,
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


def test_whitespace_only_key_raises(monkeypatch):
    """#53 bar 1: verifier rejects whitespace-only keys, including >= 32 bytes."""
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    for bad in (b" " * 32, b"\t\n" * 16, " " * 40, b" \t " * 20):
        with pytest.raises(ValueError, match="whitespace-only"):
            _rig(acceptance_key=bad)
    monkeypatch.setenv("PERMIT_ACCEPTANCE_KEY", " " * 32)
    with pytest.raises(ValueError, match="whitespace-only"):
        _rig()
    with pytest.raises(ValueError, match="whitespace-only"):
        sign_acceptance("esc", "hash", 100, b" " * 32)


def test_invalid_configured_key_raises_even_with_demo_flag(monkeypatch):
    """#53 bar 3: a set-but-invalid env/arg key raises even with allow_demo_key."""
    monkeypatch.setenv("PERMIT_ACCEPTANCE_KEY", "x" * 31)
    with pytest.raises(ValueError):
        _rig(allow_demo_key=True)
    monkeypatch.setenv("PERMIT_ACCEPTANCE_KEY", " " * 32)
    with pytest.raises(ValueError, match="whitespace-only"):
        _rig(allow_demo_key=True)
    monkeypatch.setenv("PERMIT_ACCEPTANCE_KEY", "")
    with pytest.raises(ValueError):
        _rig(allow_demo_key=True)
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    with pytest.raises(ValueError):
        _rig(acceptance_key=b"x" * 31, allow_demo_key=True)


def test_env_key_and_explicit_key_construct(monkeypatch):
    monkeypatch.setenv("PERMIT_ACCEPTANCE_KEY", "e" * 32)
    _rig()
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY")
    _rig(acceptance_key=GOOD_KEY)
    _rig(acceptance_key="s" * 32)  # str keys are encoded; must be exactly 32


def test_long_key_33_and_64_refused(monkeypatch):
    """Keys must be exactly 32 bytes after decoding (same as the key file)."""
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    for bad in (b"x" * 33, b"y" * 64, "z" * 33, "w" * 64):
        with pytest.raises(ValueError, match="exactly 32 bytes"):
            _rig(acceptance_key=bad)
    monkeypatch.setenv("PERMIT_ACCEPTANCE_KEY", "e" * 33)
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        _rig()
    monkeypatch.setenv("PERMIT_ACCEPTANCE_KEY", "e" * 64)
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        _rig()
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        sign_acceptance("esc", "hash", 100, b"L" * 33)
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        sign_acceptance("esc", "hash", 100, b"L" * 64)


def test_demo_opt_in_generates_per_instance_key(monkeypatch):
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    v1, _, _ = _rig(allow_demo_key=True)
    v2, _, _ = _rig(allow_demo_key=True)
    sig1 = v1.sign_acceptance("esc", "hash", 100)
    sig2 = v2.sign_acceptance("esc", "hash", 100)
    assert sig1 != sig2  # per-run keys: a signature for one run fits no other


def test_demo_key_path_persists_across_resolve(monkeypatch, tmp_path):
    """#53 bar 4: durable demo key is stable across resolve calls (0600 file)."""
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    path = tmp_path / "ledger.db.acceptance_key"
    # demo_key_path is the #53 API; must be accepted (fails on 9809cc7).
    k1 = resolve_acceptance_key(allow_demo_key=True, demo_key_path=path)
    assert path.exists()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    k2 = resolve_acceptance_key(allow_demo_key=True, demo_key_path=path)
    assert k1 == k2
    from settlement.verifier import load_or_create_demo_key

    k3, mode = load_or_create_demo_key(path)
    assert k3 == k1
    assert mode == 0o600


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
    check = permits.check(permit.permit_id, 3000, "merchant_1")
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


def test_ledger_module_docstring_no_longer_claims_hardcoded_demo_keys():
    """#53 bar 5: ledger.py:13 must not claim demo keys are hardcoded."""
    import permit.ledger as ledger_mod

    doc = ledger_mod.__doc__ or ""
    assert "Demo keys are hardcoded" not in doc
    assert "fail" in doc.lower() or "configured" in doc.lower()
