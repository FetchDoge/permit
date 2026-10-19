"""REA seq 1801 N-b: durable HMAC commitment for the acceptance key.

Stored in the SQLite meta table on first use; a same-length corrupted key
must refuse to start. Lives in its own commit so it can be dropped.

Imports of new symbols are deferred inside tests so this module still
collects on 70b0fc6, where the cases fail by assertion (or AttributeError).
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MIN = 32


def _env_no_key() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k != "PERMIT_ACCEPTANCE_KEY"}


def test_commitment_stored_on_first_use(tmp_path):
    from permit.sqlite_ledger import (
        ACCEPTANCE_KEY_COMMITMENT_META,
        SqliteLedger,
    )
    import server as server_mod
    from settlement.verifier import acceptance_key_commitment

    db = tmp_path / "commit.db"
    lg = SqliteLedger(str(db))
    try:
        key = os.urandom(MIN)
        assert lg.get_meta(ACCEPTANCE_KEY_COMMITMENT_META) is None
        server_mod._ensure_acceptance_key_commitment(lg, key)
        stored = lg.get_meta(ACCEPTANCE_KEY_COMMITMENT_META)
        assert stored == acceptance_key_commitment(key)
        server_mod._ensure_acceptance_key_commitment(lg, key)
        assert lg.get_meta(ACCEPTANCE_KEY_COMMITMENT_META) == stored
    finally:
        lg.close()


def test_commitment_mismatch_raises_valueerror(tmp_path):
    from permit.sqlite_ledger import SqliteLedger
    import server as server_mod

    db = tmp_path / "mismatch.db"
    lg = SqliteLedger(str(db))
    try:
        key_a = os.urandom(MIN)
        key_b = os.urandom(MIN)
        assert key_a != key_b
        server_mod._ensure_acceptance_key_commitment(lg, key_a)
        with pytest.raises(ValueError, match="commitment mismatch"):
            server_mod._ensure_acceptance_key_commitment(lg, key_b)
    finally:
        lg.close()


def test_same_length_corrupted_key_refuses_startup(tmp_path, monkeypatch):
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
    # On 70b0fc6 set_meta / ACCEPTANCE_KEY_COMMITMENT_META are absent —
    # AttributeError fails the test. On head, seed the commitment then corrupt.
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
    assert "Traceback" not in out
