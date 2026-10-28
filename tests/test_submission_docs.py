"""Submission docs must exist and must not overclaim.

The submission checklist listed the threat model and the lifecycle
docs as "still to write" through M3. These tests pin that both docs
now exist, that the checklist points at them instead of the old
to-write wording, and that the threat model keeps its honest
boundaries in writing: the coalition gap, the PR #55 gap, and the
localhost boundary. If a future edit quietly drops one of those
boundaries, this test fails before a judge finds it.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"


def _read(name: str) -> str:
    return (DOCS / name).read_text(encoding="utf-8")


def test_threat_model_exists_with_boundaries():
    text = _read("threat-model.md")
    for needle in (
        "## Assets",
        "## Actors",
        "## Trust boundaries",
        "## Not mitigated, and not claimed",
        "Coalition and identity attacks",
        "PR #55",
        "localhost",
    ):
        assert needle in text, needle


def test_lifecycle_exists_with_core_states():
    text = _read("lifecycle.md")
    for needle in (
        "GRANTED",
        "TIGHTEN",
        "DELEGATED",
        "BLOCKED",
        "AUTHORIZED",
        "CAPTURED",
        "VOIDED",
        "UNKNOWN",
        "REVOKED_CASCADE",
    ):
        assert needle in text, needle


def test_checklist_no_longer_lists_docs_as_to_write():
    text = _read("submission-checklist.md")
    assert "still to write" not in text
    assert "docs/threat-model.md" in text
    assert "docs/lifecycle.md" in text


def test_demo_video_script_exists_with_honesty_lines():
    # The M5 recording script must keep the checklist's honesty rules
    # in the spoken text itself: the camera run is the mock rail, it
    # does not call PayPal, the six beats have not run as one live
    # sandbox session, and VERIFIED is internal chain integrity only.
    text = _read("demo-video-script.md")
    for needle in (
        "python3 demos/demo_six_beat.py --fast --replay demos/fixtures/demo_transcript.jsonl",
        "mock rail",
        "It does not\ncall PayPal",
        "over_remaining_cap",
        "VERIFIED, twenty-six receipts",
        "not a PayPal signature",
        "docs/submission-checklist.md",
    ):
        assert needle in text, needle
    checklist = _read("submission-checklist.md")
    assert "docs/demo-video-script.md" in checklist


def test_submission_docs_have_no_em_dashes():
    # Standing copy rule for user-facing text: no em dashes.
    for name in ("threat-model.md", "lifecycle.md", "demo-video-script.md"):
        assert "\u2014" not in _read(name), name
