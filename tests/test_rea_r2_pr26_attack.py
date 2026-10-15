"""Review R2 attack suite vs Permit PR #26 durability (file-backed).

Ports the axes from the R2 review onto permit/durability.py.
Each test that previously ACCEPTed a bypass must now REJECT (fail closed)
or retain the reservation (axis E).
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from permit.durability import (
    DurableLedger,
    DurablePermitStore,
    _fsync_dir,
    _permits_mac,
)


def _future():
    return datetime.now(timezone.utc) + timedelta(hours=1)


def _grant_check(tmp_path: Path, amount: int = 3000, cap: int = 5000):
    ledger = DurableLedger(durable_dir=tmp_path)
    permits = DurablePermitStore(ledger=ledger, durable_dir=tmp_path)
    permit, _ = permits.grant(
        agent_id="a1",
        cap_cents=cap,
        allowlist=["merchant_1"],
        expiry=_future(),
    )
    result = permits.check(permit.permit_id, amount, "merchant_1")
    assert result.allowed
    return ledger, permits, permit


# ---------------------------------------------------------------------------
# C — exclusive writer lock
# ---------------------------------------------------------------------------


def test_R2_C_double_writer_no_lock(tmp_path: Path):
    """A second DurableLedger on the same dir must fail closed."""
    first = DurableLedger(durable_dir=tmp_path)
    first.append("GRANTED", {"permit_id": "prm_x", "agent_id": "a"})
    with pytest.raises(RuntimeError, match="writer lock"):
        DurableLedger(durable_dir=tmp_path)
    # While first holds the lock, sequences stay unique.
    first.append("ALLOWED", {"permit_id": "prm_x", "amount_cents": 1, "auth_id": "a1"})
    seqs = [r.seq for r in first.receipts()]
    assert seqs == list(range(len(seqs)))
    assert first.verify_chain()[0]
    first.close()


def test_R2_C_unlink_ledger_while_open(tmp_path: Path):
    """Renaming ledger.jsonl under a live writer must fail closed on next append."""
    ledger = DurableLedger(durable_dir=tmp_path)
    ledger.append("GRANTED", {"permit_id": "prm_x", "agent_id": "a"})
    renamed = tmp_path / "ledger.jsonl.orphaned"
    os.rename(tmp_path / "ledger.jsonl", renamed)
    with pytest.raises(RuntimeError, match="ledger (path disappeared|inode diverged)"):
        ledger.append(
            "ALLOWED", {"permit_id": "prm_x", "amount_cents": 1, "auth_id": "a1"}
        )
    ledger.close()


# ---------------------------------------------------------------------------
# A — unsigned / rewound permits.json
# ---------------------------------------------------------------------------


def test_R2_A_forged_permits_json(tmp_path: Path):
    """Rewinding reserved_cents in permits.json must not reopen the cap."""
    ledger, permits, permit = _grant_check(tmp_path, amount=3000, cap=5000)
    pid = permit.permit_id
    assert permits.get(pid).reserved_cents == 3000
    tip = ledger.tip()
    ledger.close()

    # Attacker rewinds counters but keeps / forges a binding + mac.
    forged_body = {
        pid: {
            "permit_id": pid,
            "agent_id": "a1",
            "cap_cents": 5000,
            "allowlist": ["merchant_1"],
            "expiry": _future().isoformat(),
            "revoked": False,
            "reserved_cents": 0,
            "captured_cents": 0,
            "in_flight": {},
        }
    }
    envelope = {
        "permits": forged_body,
        "ledger_head": tip,
        "mac": _permits_mac(forged_body, tip),
    }
    (tmp_path / "permits.json").write_text(
        json.dumps(envelope, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    ledger2 = DurableLedger(durable_dir=tmp_path)
    permits2 = DurablePermitStore(ledger=ledger2, durable_dir=tmp_path)
    p2 = permits2.get(pid)
    assert p2 is not None
    # Ledger fold restores the reservation — cap is not reopened.
    assert p2.reserved_cents == 3000
    denied = permits2.check(pid, 3000, "merchant_1")
    assert not denied.allowed
    assert denied.reason == "over_remaining_cap"
    ledger2.close()


def test_R2_A_permits_mac_tamper_fails_closed(tmp_path: Path):
    """Tampering with permits.json without a matching HMAC fails closed."""
    ledger, permits, permit = _grant_check(tmp_path)
    ledger.close()
    raw = json.loads((tmp_path / "permits.json").read_text(encoding="utf-8"))
    # Corrupt mac only.
    raw["mac"] = "0" * 64
    (tmp_path / "permits.json").write_text(
        json.dumps(raw, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    ledger2 = DurableLedger(durable_dir=tmp_path)
    with pytest.raises(ValueError, match="HMAC"):
        DurablePermitStore(ledger=ledger2, durable_dir=tmp_path)
    ledger2.close()


# ---------------------------------------------------------------------------
# B — wipe → genesis (note only; not counted as FAIL)
# ---------------------------------------------------------------------------


def test_R2_B_wipe_regenesis(tmp_path: Path):
    ledger, permits, _ = _grant_check(tmp_path)
    ledger.close()
    for name in ("ledger.jsonl", "ledger.head", "permits.json", "writer.lock"):
        p = tmp_path / name
        if p.exists():
            p.unlink()
    ledger2 = DurableLedger(durable_dir=tmp_path)
    assert len(ledger2) == 0
    permits2 = DurablePermitStore(ledger=ledger2, durable_dir=tmp_path)
    assert list(permits2._permits) == []
    ledger2.close()


# ---------------------------------------------------------------------------
# D — truncate / edit / torn tail
# ---------------------------------------------------------------------------


def test_R2_D_truncate_and_edit_ledger(tmp_path: Path):
    ledger, permits, permit = _grant_check(tmp_path)
    pid = permit.permit_id
    # Extra line so truncate has something to drop beyond GRANTED+ALLOWED.
    ledger.append("BLOCKED", {"permit_id": pid, "reason": "probe"})
    n = len(ledger)
    assert n >= 3
    path = tmp_path / "ledger.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    assert len(lines) == n
    ledger.close()

    # Truncate last complete line; ledger.head still commits the old length.
    path.write_text("".join(lines[:-1]), encoding="utf-8")
    with pytest.raises(ValueError, match="truncated"):
        DurableLedger(durable_dir=tmp_path)

    # Restore full ledger for the edit check; refresh head to match.
    path.write_text("".join(lines), encoding="utf-8")
    # Edit a middle payload while leaving a stale hash → reject.
    edited = []
    for i, line in enumerate(lines):
        d = json.loads(line)
        if i == 1:
            d["payload"] = dict(d["payload"])
            d["payload"]["amount_cents"] = 999999
            # leave d["hash"] stale
        edited.append(json.dumps(d, sort_keys=True, separators=(",", ":")) + "\n")
    path.write_text("".join(edited), encoding="utf-8")
    with pytest.raises(ValueError, match="hash mismatch"):
        DurableLedger(durable_dir=tmp_path)


def test_R2_D_torn_tail(tmp_path: Path):
    ledger, permits, _ = _grant_check(tmp_path)
    path = tmp_path / "ledger.jsonl"
    text = path.read_text(encoding="utf-8")
    ledger.close()
    # Tear the final JSON line.
    path.write_text(text.rstrip("\n")[:-8], encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        DurableLedger(durable_dir=tmp_path)


# ---------------------------------------------------------------------------
# E — ledger ahead of permits (crash between ALLOWED and permits persist)
# ---------------------------------------------------------------------------


def test_R2_E_ledger_ahead_of_permits(tmp_path: Path):
    """SIGKILL after ALLOWED ledger line but before permits.json must retain reservation."""
    ledger = DurableLedger(durable_dir=tmp_path)
    permits = DurablePermitStore(ledger=ledger, durable_dir=tmp_path)
    permit, _ = permits.grant(
        agent_id="a1", cap_cents=5000, allowlist=["merchant_1"], expiry=_future()
    )
    pid = permit.permit_id

    def boom():
        raise KeyboardInterrupt("simulated SIGKILL after ledger, before permits")

    permits._persist = boom  # type: ignore[method-assign]
    with pytest.raises(KeyboardInterrupt):
        permits.check(pid, 3000, "merchant_1")

    # Ledger durable; permits.json still at post-grant binding.
    assert any(r.event_type == "ALLOWED" for r in ledger.receipts())
    ledger.close()

    ledger2 = DurableLedger(durable_dir=tmp_path)
    permits2 = DurablePermitStore(ledger=ledger2, durable_dir=tmp_path)
    p2 = permits2.get(pid)
    assert p2 is not None
    assert p2.reserved_cents == 3000, "reservation must be rebuilt from ledger"
    denied = permits2.check(pid, 3000, "merchant_1")
    assert not denied.allowed
    assert denied.reason == "over_remaining_cap"
    ledger2.close()


# ---------------------------------------------------------------------------
# Skips / P2
# ---------------------------------------------------------------------------


def test_R2_SKIP_signed_replay_and_markers():
    pytest.skip("No ReplayStore / MarkerDir API to port from Go durable/")


def test_R2_P2_fsync_dir_swallows(tmp_path: Path, caplog):
    """_fsync_dir must log and raise on OSError (no longer swallow)."""
    with patch("permit.durability.os.open", side_effect=OSError("boom")):
        with caplog.at_level(logging.ERROR):
            with pytest.raises(OSError, match="boom"):
                _fsync_dir(tmp_path)
    assert any("fsync" in r.message.lower() for r in caplog.records)
