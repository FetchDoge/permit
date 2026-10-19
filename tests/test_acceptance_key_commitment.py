"""REA seq 1801 N-b / 1854: durable HMAC commitment for the acceptance key.

Stored in the SQLite meta table on first use; a same-length corrupted key
must refuse to start. Lives in its own commit lineage so it can be dropped.

Enforced at every --db / SqliteLedger entry point (not only server.py):
  1. settlement/verifier.py ReleaseVerifier.__init__ (SqliteLedger duck-type)
  2. server.py main --db (explicit SystemExit wrapper)

Rotating the key on an existing database refuses startup (no rebind).
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MIN = 32

REFUSE_ROTATION = (
    "rotating the acceptance key on an existing database refuses startup"
)


def _env_no_key() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k != "PERMIT_ACCEPTANCE_KEY"}


def test_commitment_stored_on_first_use(tmp_path):
    from permit.sqlite_ledger import (
        ACCEPTANCE_KEY_COMMITMENT_META,
        SqliteLedger,
    )
    from settlement.verifier import (
        acceptance_key_commitment,
        ensure_acceptance_key_commitment,
    )

    db = tmp_path / "commit.db"
    lg = SqliteLedger(str(db))
    try:
        key = os.urandom(MIN)
        assert lg.get_meta(ACCEPTANCE_KEY_COMMITMENT_META) is None
        ensure_acceptance_key_commitment(lg, key)
        stored = lg.get_meta(ACCEPTANCE_KEY_COMMITMENT_META)
        assert stored == acceptance_key_commitment(key)
        ensure_acceptance_key_commitment(lg, key)
        assert lg.get_meta(ACCEPTANCE_KEY_COMMITMENT_META) == stored
    finally:
        lg.close()


def test_commitment_mismatch_raises_valueerror(tmp_path):
    from permit.sqlite_ledger import SqliteLedger
    from settlement.verifier import ensure_acceptance_key_commitment

    db = tmp_path / "mismatch.db"
    lg = SqliteLedger(str(db))
    try:
        key_a = os.urandom(MIN)
        key_b = os.urandom(MIN)
        assert key_a != key_b
        ensure_acceptance_key_commitment(lg, key_a)
        with pytest.raises(ValueError, match=REFUSE_ROTATION):
            ensure_acceptance_key_commitment(lg, key_b)
    finally:
        lg.close()


def test_entry_release_verifier_sqlite_mismatch(tmp_path, monkeypatch):
    """Entry point 1: ReleaseVerifier + SqliteLedger refuses rotation."""
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    from permit.ledger import Ledger
    from permit.permit import PermitStore
    from permit.sqlite_ledger import (
        ACCEPTANCE_KEY_COMMITMENT_META,
        SqliteLedger,
    )
    from settlement.paypal_client import MockPayPalClient
    from settlement.verifier import (
        ReleaseVerifier,
        acceptance_key_commitment,
    )

    db = tmp_path / "rv.db"
    lg = SqliteLedger(str(db))
    good = os.urandom(MIN)
    bad = os.urandom(MIN)
    assert good != bad
    lg.set_meta(ACCEPTANCE_KEY_COMMITMENT_META, acceptance_key_commitment(good))
    paypal = MockPayPalClient()
    # PermitStore needs a ledger; use in-memory for permits, sqlite for verifier.
    permits = PermitStore(ledger=Ledger())
    with pytest.raises(ValueError, match=REFUSE_ROTATION):
        ReleaseVerifier(
            paypal, permits, ledger=lg, acceptance_key=bad
        )
    lg.close()


def test_entry_server_db_mismatch(tmp_path, monkeypatch):
    """Entry point 2: server.py --db refuses rotation with documented message."""
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    from permit.sqlite_ledger import (
        ACCEPTANCE_KEY_COMMITMENT_META,
        SqliteLedger,
    )
    from settlement.verifier import acceptance_key_commitment

    db = tmp_path / "corrupt.db"
    key_path = Path(f"{db}.acceptance_key")
    SqliteLedger(str(db)).close()

    good = os.urandom(MIN)
    key_path.write_bytes(good)
    os.chmod(key_path, 0o600)
    lg = SqliteLedger(str(db))
    lg.set_meta(ACCEPTANCE_KEY_COMMITMENT_META, acceptance_key_commitment(good))
    lg.close()

    bad = os.urandom(MIN)
    assert bad != good and len(bad) == MIN
    key_path.write_bytes(bad)
    os.chmod(key_path, 0o600)

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
        env=_env_no_key(),
        capture_output=True,
        text=True,
        timeout=8,
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    assert proc.returncode != 0
    assert "acceptance key error:" in out
    assert "commitment mismatch" in out
    assert REFUSE_ROTATION in out
    assert "Traceback" not in out


# Keep the historical name as an alias so older reports still find it.
def test_same_length_corrupted_key_refuses_startup(tmp_path, monkeypatch):
    test_entry_server_db_mismatch(tmp_path, monkeypatch)
