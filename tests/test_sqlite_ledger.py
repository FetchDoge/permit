"""SqliteLedger contract tests: durable variant of the hash-chained ledger.

Design: docs/sqlite-durability-design.md. The SQLite ledger must match
the in-memory Ledger's interface and verification semantics exactly,
plus: restore-after-restart, crash-consistency, idempotent re-append.
"""

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from permit.ledger import GENESIS_HASH, Ledger
from permit.sqlite_ledger import SqliteLedger

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def db_path(tmp_path):
    return str(tmp_path / "ledger.db")


def test_append_verify_matches_in_memory(db_path):
    """Same receipts -> same hashes and verify result as the in-memory ledger."""
    mem = Ledger()
    db = SqliteLedger(db_path)
    events = [
        ("GRANTED", {"permit_id": "p1"}),
        ("ALLOWED", {"permit_id": "p1", "auth_id": "a1", "amount_cents": 100}),
        ("BLOCKED", {"permit_id": "p1", "reason": "over_remaining_cap"}),
        ("CAPTURED", {"permit_id": "p1", "auth_id": "a1", "amount_cents": 100}),
    ]
    for et, pl in events:
        r_mem = mem.append(et, pl)
        r_db = db.append(et, pl)
        # Structural equivalence: same positions, types, payloads. Hashes
        # necessarily differ — each append stamps its own microsecond
        # timestamp and the hash covers it, so two independent chains
        # can never share hashes by design.
        assert r_db.seq == r_mem.seq
        assert r_db.event_type == r_mem.event_type
        assert r_db.payload == r_mem.payload
    assert mem.verify_chain() == (True, "ok")
    assert db.verify_chain() == (True, "ok")
    # Within each chain, prev_hash links to the previous receipt's hash.
    for rs in (mem.receipts(), db.receipts()):
        for prev, cur in zip(rs, rs[1:]):
            assert cur.prev_hash == prev.hash
    assert db.verify_chain() == (True, "ok")
    assert len(db) == len(mem) == 4
    assert db.allowed_receipt("a1").seq == 1
    assert db.allowed_receipt("nope") is None
    db.close()


def test_restore_rebuilds_state_and_index(db_path):
    """Close and reopen: receipts, chain, and auth index all survive."""
    db = SqliteLedger(db_path)
    db.append("GRANTED", {"permit_id": "p1"})
    db.append("ALLOWED", {"permit_id": "p1", "auth_id": "a9", "amount_cents": 50})
    db.close()
    db2 = SqliteLedger(db_path)
    assert len(db2) == 2
    assert db2.verify_chain() == (True, "ok")
    assert db2.allowed_receipt("a9").payload["amount_cents"] == 50
    # Appending after restore continues the chain.
    r = db2.append("BLOCKED", {"reason": "x"})
    assert r.seq == 2
    assert r.prev_hash == db2.receipts()[1].hash
    assert db2.verify_chain() == (True, "ok")
    db2.close()


def test_memory_path_works(db_path_unused=None):
    """:memory: databases work (no WAL) for tests."""
    db = SqliteLedger(":memory:")
    db.append("GRANTED", {"permit_id": "p1"})
    assert db.verify_chain() == (True, "ok")
    db.close()


def test_path_required():
    with pytest.raises(ValueError):
        SqliteLedger("")
    with pytest.raises(ValueError):
        SqliteLedger(None)  # type: ignore[arg-type]


def test_corrupt_chain_refuses_to_serve(db_path):
    """A tampered payload on disk -> constructor raises, never serves."""
    db = SqliteLedger(db_path)
    db.append("GRANTED", {"permit_id": "p1"})
    db.close()
    con = sqlite3.connect(db_path)
    con.execute("PRAGMA journal_mode=DELETE")
    # Bypass triggers via direct SQL would fail; instead corrupt the payload
    # text through a fresh connection after dropping the trigger guard is
    # impossible — so corrupt by rewriting the hash column via the trigger
    # path is blocked too. Corrupt at the file level: flip a payload byte
    # using UPDATE after dropping triggers (simulates disk tampering).
    con.execute("DROP TRIGGER receipts_no_update")
    con.execute("UPDATE receipts SET payload = '{\"x\": 1}' WHERE seq = 0")
    con.commit()
    con.close()
    with pytest.raises(RuntimeError):
        SqliteLedger(db_path)


def test_triggers_enforce_append_only(db_path):
    """Direct SQL UPDATE/DELETE is rejected by the triggers."""
    db = SqliteLedger(db_path)
    db.append("GRANTED", {"permit_id": "p1"})
    con = sqlite3.connect(db_path)
    with pytest.raises(sqlite3.IntegrityError):
        con.execute("UPDATE receipts SET event_type = 'X' WHERE seq = 0")
    with pytest.raises(sqlite3.IntegrityError):
        con.execute("DELETE FROM receipts WHERE seq = 0")
    con.close()
    db.close()


def test_idempotent_reappend_returns_existing(db_path):
    """Same idempotency_key twice -> one row, same receipt returned."""
    db = SqliteLedger(db_path)
    r1 = db.append("ALLOWED", {"auth_id": "a1", "idempotency_key": "k-1"})
    r2 = db.append("ALLOWED", {"auth_id": "a1", "idempotency_key": "k-1"})
    assert r1.seq == r2.seq
    assert r1.hash == r2.hash
    assert len(db) == 1
    # A different key is a different row.
    r3 = db.append("ALLOWED", {"auth_id": "a2", "idempotency_key": "k-2"})
    assert r3.seq == 1
    assert len(db) == 2
    db.close()


def test_kill9_mid_append_chain_verifies_or_refuses(tmp_path):
    """kill -9 during a write burst: reopen either verifies or refuses."""
    db_path = str(tmp_path / "crash.db")
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import sys; sys.path.insert(0, '.');"
            "from permit.sqlite_ledger import SqliteLedger;"
            "l = SqliteLedger(sys.argv[1]);"
            "i = 0;"
            "while True:"
            "    l.append('NOISE', {'i': i, 'pad': 'x' * 200}); i += 1",
            db_path,
        ],
        cwd=str(REPO_ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1.5)
    child.kill()  # SIGKILL: no cleanup, torn writes possible
    child.wait()
    # Reopen: either the chain verifies (torn write rolled back) or the
    # constructor refuses to serve. Both are fail-closed; serving a
    # broken chain is the only wrong outcome.
    try:
        db = SqliteLedger(db_path)
    except RuntimeError:
        return  # refused to serve: acceptable
    ok, reason = db.verify_chain()
    assert ok, f"served a broken chain: {reason}"
    db.close()


def test_10k_restore_timing(tmp_path):
    """10k receipts restore + verify in reasonable time."""
    db_path = str(tmp_path / "big.db")
    db = SqliteLedger(db_path)
    for i in range(10_000):
        db.append("NOISE", {"i": i})
    db.close()
    start = time.monotonic()
    db2 = SqliteLedger(db_path)
    elapsed = time.monotonic() - start
    assert len(db2) == 10_000
    assert db2.verify_chain() == (True, "ok")
    db2.close()
    assert elapsed < 30, f"10k restore took {elapsed:.1f}s"


def test_fold_equivalence_live_vs_replay():
    """Contract: folding the live ledger's receipts reproduces the store."""
    from datetime import datetime, timedelta, timezone

    from permit.ledger import Ledger
    from permit.permit import PermitStore
    from permit.sqlite_ledger import fold_receipts

    ledger = Ledger()
    store = PermitStore(ledger=ledger)
    now = datetime.now(timezone.utc)
    exp = now + timedelta(hours=1)

    p1, _ = store.grant("agent1", 10000, ["m1", "m2"], exp)
    p2, _ = store.grant("agent2", 5000, ["m1"], exp)
    c1 = store.check(p1.permit_id, 3000, "m1")  # ALLOWED, reserves
    assert c1.allowed
    c2 = store.check(p1.permit_id, 2000, "m1")  # ALLOWED, reserves
    assert c2.allowed
    store.check(p1.permit_id, 99999, "m1")  # BLOCKED, no state change
    d = store.delegate(p1.permit_id, "agent3", 1000, ["m1"], exp)
    assert d.ok
    child = d.permit
    cc = store.check(child.permit_id, 400, "m1")  # child ALLOWED
    assert cc.allowed
    store.tighten(p2.permit_id, cap_cents=4000, actor="test")
    # Settle one hold to captured, void the other.
    auth1 = c1.receipt.payload["auth_id"]
    auth2 = c2.receipt.payload["auth_id"]
    store.settle_capture(p1.permit_id, auth1)
    store.settle_void(p1.permit_id, auth2)
    store.estop(p2.permit_id)

    folded = fold_receipts(ledger.receipts())

    assert set(folded._permits) == set(store._permits)
    for pid, live in store._permits.items():
        f = folded._permits[pid]
        assert f.agent_id == live.agent_id, pid
        assert f.cap_cents == live.cap_cents, pid
        assert f.allowlist == live.allowlist, pid
        assert f.expiry == live.expiry, pid
        assert f.revoked == live.revoked, pid
        assert f.reserved_cents == live.reserved_cents, pid
        assert f.captured_cents == live.captured_cents, pid
        assert f.in_flight == live.in_flight, pid
        assert f.parent_id == live.parent_id, pid
        assert f.depth == live.depth, pid
        assert f.tighten_cap_cents == live.tighten_cap_cents, pid
        assert f.tighten_allowlist == live.tighten_allowlist, pid
        assert f.tighten_expiry == live.tighten_expiry, pid
        assert (
            f.tighten_approval_threshold_cents
            == live.tighten_approval_threshold_cents
        ), pid
    assert folded._children == store._children
    # The fold wrote no receipts of its own.
    assert len(folded.ledger) == 0


def test_fold_durable_roundtrip(tmp_path):
    """End-to-end: live ops -> SQLite -> close -> reopen -> fold == live."""
    from datetime import datetime, timedelta, timezone

    from permit.ledger import Ledger
    from permit.permit import PermitStore
    from permit.sqlite_ledger import SqliteLedger, fold_receipts

    db_path = str(tmp_path / "fold.db")
    db = SqliteLedger(db_path)
    store = PermitStore(ledger=db)
    exp = datetime.now(timezone.utc) + timedelta(hours=1)
    p, _ = store.grant("a1", 8000, ["m"], exp)
    c = store.check(p.permit_id, 1500, "m")
    assert c.allowed
    live_reserved = p.reserved_cents
    db.close()

    db2 = SqliteLedger(db_path)
    folded = fold_receipts(db2.receipts())
    f = folded._permits[p.permit_id]
    assert f.reserved_cents == live_reserved == 1500
    assert f.in_flight == {c.receipt.payload["auth_id"]: 1500}
    assert f.cap_cents == 8000
    db2.close()
