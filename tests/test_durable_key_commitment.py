"""REA seq 1888: DurableLedger / harness must enforce acceptance-key commitment.

On 19b62ce, DurableLedger lacked get_meta/set_meta so ReleaseVerifier
silently skipped the check. Reopening with key B must refuse.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from harness.durability_harness import _build, _close_ledger
from permit.durability import DurableLedger
from permit.ledger import Ledger
from permit.sqlite_ledger import SqliteLedger
from settlement.verifier import ReleaseVerifier, acceptance_key_commitment

REFUSE = "rotating the acceptance key on an existing database refuses startup"
MIN = 32


def test_durable_ledger_harness_key_rotation_refuses(tmp_path, monkeypatch):
    """Build with key A via harness path; reopen with key B → refusal.

    Imports stay compatible with 19b62ce so collection succeeds and the
    assertion fails there (silent skip / no meta).
    """
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    durable = tmp_path / "dur"
    key_a = b"A" * MIN
    key_b = b"B" * MIN
    assert key_a != key_b

    monkeypatch.setenv("PERMIT_ACCEPTANCE_KEY", key_a.decode())
    ledger, permits, paypal, verifier, flow = _build(
        durable, allow_demo_key=False
    )
    assert verifier._acceptance_key == key_a
    # On head, commitment is stored; on 19b62ce get_meta is absent → AttributeError
    # (fails the test). Prefer an explicit mismatch on reopen either way.
    get_meta = getattr(ledger, "get_meta", None)
    if callable(get_meta):
        from permit.sqlite_ledger import ACCEPTANCE_KEY_COMMITMENT_META

        assert get_meta(ACCEPTANCE_KEY_COMMITMENT_META) == (
            acceptance_key_commitment(key_a)
        )
    else:
        pytest.fail(
            "DurableLedger missing get_meta — commitment was silently skipped"
        )
    _close_ledger(ledger)

    monkeypatch.setenv("PERMIT_ACCEPTANCE_KEY", key_b.decode())
    with pytest.raises(ValueError, match=REFUSE):
        _build(durable, allow_demo_key=False)


def test_durable_ledger_direct_mismatch(tmp_path, monkeypatch):
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    from permit.permit import PermitStore
    from settlement.paypal_client import MockPayPalClient

    durable = tmp_path / "dur2"
    key_a = b"C" * MIN
    key_b = b"D" * MIN
    lg = DurableLedger(durable_dir=durable)
    assert getattr(lg, "requires_acceptance_key_commitment", False) is True
    assert hasattr(lg, "get_meta") and hasattr(lg, "set_meta")
    paypal = MockPayPalClient()
    permits = PermitStore(ledger=Ledger())
    ReleaseVerifier(paypal, permits, ledger=lg, acceptance_key=key_a)
    lg.close()

    lg2 = DurableLedger(durable_dir=durable)
    with pytest.raises(ValueError, match=REFUSE):
        ReleaseVerifier(
            paypal, permits, ledger=lg2, acceptance_key=key_b
        )
    lg2.close()


def test_no_ledger_type_silently_skips_commitment():
    """Every durable ledger type either enforces or raises — never skips."""
    from settlement.verifier import _bind_ledger_acceptance_key_commitment

    # In-memory Ledger: no commitment required.
    mem = Ledger()
    assert not getattr(mem, "requires_acceptance_key_commitment", False)

    # Sqlite file-backed + DurableLedger: meta API present.
    assert hasattr(DurableLedger, "get_meta")
    assert hasattr(DurableLedger, "set_meta")
    assert hasattr(SqliteLedger, "get_meta")
    assert hasattr(SqliteLedger, "set_meta")

    # A durable ledger that opts in but lacks meta must raise (no silent skip).
    class _BrokenDurable:
        requires_acceptance_key_commitment = True

    with pytest.raises(ValueError, match="refusing silent skip"):
        _bind_ledger_acceptance_key_commitment(_BrokenDurable(), b"k" * MIN)
