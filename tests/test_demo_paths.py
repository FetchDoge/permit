"""The camera paths must exit 0: mock demo, trace, six-beat replay.

demo.py and trace.py are deterministic and run here. demo_six_beat.py
drives the real LLM agent live, but its replay path is deterministic
and IS covered here against the committed fixture transcript
(demos/fixtures/demo_transcript.jsonl) — the absence of that coverage
is what let a 0-byte transcript pass as "ready" before the 2026-10-14
diagnosis (job-board ROI-02).

The other offline judge demos are pinned here too: demo_admission.py
(the M4 acceptance beats) and demo_sla_escrow.py. The e-stop demo has
its own pin in test_estop_race.py. The LLM demos (demo_approval.py,
demo_delegation.py) are not pinned: they need PERMIT_AGENT_CLI and are
not offline paths.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SIX_BEAT_FIXTURE = ROOT / "demos" / "fixtures" / "demo_transcript.jsonl"


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_mock_demo_exits_clean():
    proc = _run(["demo.py"])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "VERIFIED" in proc.stdout
    assert "delegate a $15 sub-permit" in proc.stdout
    assert "revoke parent cascades" in proc.stdout
    assert "parent remaining $50.00 (unspent carve released)" in proc.stdout
    assert "post-cascade release: released=False" in proc.stdout


def test_admission_demo_exits_clean():
    # M4 acceptance beats as a judge runs them: (a) a runaway loop is
    # refused at budget exhaustion with zero rail calls for the refused
    # attempts, (b) parallel overspend cannot exceed the cap.
    proc = _run(["demos/demo_admission.py"])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "try 4: BLOCKED  over_remaining_cap" in proc.stdout
    assert "PayPal authorize calls: 3 for 3 admitted spends, 0 for 3 refusals" in proc.stdout
    assert "admitted: 3 spends, $45.00 total (cap $50.00)" in proc.stdout
    assert "refused:  13 at admission, 0 phantom PayPal calls" in proc.stdout
    assert proc.stdout.count("VERIFIED") == 2  # one chain line per beat


def test_sla_escrow_demo_exits_clean():
    proc = _run(["demos/demo_sla_escrow.py"])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "predicate:invalid_acceptance_signature" in proc.stdout
    assert "PayPal captures: 1 (beat 3 only)" in proc.stdout
    assert "Demo complete: every dollar is accounted for." in proc.stdout


def test_trace_exits_clean():
    proc = _run(["trace.py"])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "TRACE COMPLETE" in proc.stdout
    assert "DELEGATED" in proc.stdout
    assert "REVOKED_CASCADE" in proc.stdout
    assert "CARVE_RELEASED" in proc.stdout


def test_six_beat_replay_exits_clean():
    # The headline judge path, fully offline, on the shipped fixture.
    proc = _run(["demos/demo_six_beat.py", "--fast",
                 "--replay", str(SIX_BEAT_FIXTURE), "--port", "8499"])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "VERIFIED" in proc.stdout
    assert "REVOKED_CASCADE" in proc.stdout          # Beat 4 happened
    assert "post-cascade deliver: released=False" in proc.stdout
    assert "predicate:hash_mismatch" in proc.stdout  # Beat 5
    assert "outcome=captured" in proc.stdout         # Beat 6


def test_six_beat_replay_empty_transcript_fails_fast(tmp_path):
    empty = tmp_path / "empty.jsonl"
    empty.write_text("")
    proc = _run(["demos/demo_six_beat.py", "--fast",
                 "--replay", str(empty), "--port", "8499"])
    assert proc.returncode != 0
    assert "missing or empty" in (proc.stdout + proc.stderr)
    assert "StopIteration" not in (proc.stdout + proc.stderr)


def test_six_beat_replay_missing_beat4_is_named(tmp_path):
    # Fixture with the Beat-4 section removed must fail naming Beat 4,
    # not crash with StopIteration at the escrow lookup.
    kept, skipping = [], False
    for line in SIX_BEAT_FIXTURE.read_text().splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        if record.get("type") == "beat":
            skipping = record.get("n") == 4
        if not skipping:
            kept.append(line)
    partial = tmp_path / "no_beat4.jsonl"
    partial.write_text("\n".join(kept) + "\n")
    proc = _run(["demos/demo_six_beat.py", "--fast",
                 "--replay", str(partial), "--port", "8499"])
    assert proc.returncode != 0
    assert "beat 4" in (proc.stdout + proc.stderr)
    assert "StopIteration" not in (proc.stdout + proc.stderr)


def test_failed_live_run_preserves_transcript(tmp_path):
    # A live run that fails preflight (no PERMIT_AGENT_CLI) must not
    # truncate the existing recording — the 2026-10-14 self-destruction
    # mechanism this suite now guards.
    work = tmp_path / "repo"
    shutil.copytree(
        ROOT, work,
        ignore=shutil.ignore_patterns(
            ".git", "__pycache__", "demo_transcript.jsonl",
            "demo_transcript.replay.jsonl"))
    seeded = work / "demo_transcript.jsonl"
    seeded.write_bytes(SIX_BEAT_FIXTURE.read_bytes())
    env = {k: v for k, v in os.environ.items() if k not in ("PERMIT_AGENT_CLI", "PERMIT_GROK_CLI")}
    proc = subprocess.run(
        [sys.executable, "demos/demo_six_beat.py", "--fast", "--port", "8499"],
        cwd=work, capture_output=True, text=True, timeout=120, env=env)
    assert proc.returncode != 0
    assert seeded.read_bytes() == SIX_BEAT_FIXTURE.read_bytes()
