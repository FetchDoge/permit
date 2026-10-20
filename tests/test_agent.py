"""Tests for the demo agent: tool gating and the ReAct parser."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from agent.react import build_system, llm_preflight, parse_action, run_agent
from agent.tools import SpendTools
from permit.flow import SpendPipeline
from permit.ledger import Ledger
from permit.permit import PermitStore
from settlement.paypal_client import MockPayPalClient
from settlement.verifier import ReleaseVerifier


def _tools(catalog=None):
    ledger = Ledger()
    permits = PermitStore(ledger=ledger)
    paypal = MockPayPalClient()
    verifier = ReleaseVerifier(paypal, permits, ledger=ledger)
    flow = SpendPipeline(permits, paypal, verifier, ledger=ledger)
    permit, _ = permits.grant(
        agent_id="t", cap_cents=5000, allowlist=["m"],
        expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    catalog = catalog or {"widget": b"widget-bytes"}
    return SpendTools(flow, permit.permit_id, "m", catalog), paypal, permits


def test_attempt_spend_allowed_then_deliver_captures():
    tools, paypal, _ = _tools()
    obs = json.loads(tools.attempt_spend(3000, "widget"))
    assert obs["decision"] == "ALLOWED"
    assert obs["paypal_auth_id"].startswith("mock_auth_")
    obs2 = json.loads(tools.deliver(obs["escrow_id"]))
    assert obs2["released"] is True
    assert obs2["capture_id"] is not None


def test_blocked_spend_never_touches_paypal():
    tools, paypal, _ = _tools()
    obs = json.loads(tools.attempt_spend(6000, "widget"))
    assert obs["decision"] == "BLOCKED"
    assert obs["paypal_called"] is False
    assert paypal.authorizations == {}


def test_unknown_purpose_rejected_without_permit_check():
    tools, paypal, _ = _tools()
    obs = json.loads(tools.attempt_spend(100, "nope"))
    assert obs["ok"] is False
    assert paypal.authorizations == {}


def test_deliver_tampered_is_harness_only():
    """deliver_tampered exists on the tools object but the ReAct runner
    refuses to expose it (name blocklist)."""
    tools, _, _ = _tools()
    assert hasattr(tools, "deliver_tampered")


def test_check_permit_reports_remaining():
    tools, _, _ = _tools()
    obs = json.loads(tools.check_permit())
    assert obs["remaining_cents"] == 5000
    json.loads(tools.attempt_spend(2000, "widget"))
    obs = json.loads(tools.check_permit())
    assert obs["remaining_cents"] == 3000


def test_parse_action_two_line():
    name, args = parse_action("THOUGHT: x\nACTION: attempt_spend\n"
                              'ARGS: {"amount_cents": 3000}')
    assert name == "attempt_spend"
    assert args == {"amount_cents": 3000}


def test_parse_action_single_line():
    name, args = parse_action("THOUGHT: y ACTION: check_permit ARGS: {}")
    assert name == "check_permit"
    assert args == {}


def test_parse_action_tolerates_trailing_text():
    name, args = parse_action('ACTION: deliver\nARGS: {"escrow_id": "abc"}\nzzz}')
    assert (name, args) == ("deliver", {"escrow_id": "abc"})


def test_parse_action_no_action():
    assert parse_action("just thinking out loud") == (None, None)


def test_system_prompt_lists_catalog():
    s = build_system(["dataset license", "report"])
    assert '"dataset license", "report"' in s


def test_llm_preflight_fails_with_guidance_when_cli_missing(monkeypatch):
    """A missing LLM runner fails fast with setup guidance — not mid-demo."""
    monkeypatch.setenv("PERMIT_AGENT_CLI", "/nonexistent-xyz/grok.py")
    with pytest.raises(RuntimeError) as exc:
        llm_preflight()
    msg = str(exc.value)
    assert "PERMIT_AGENT_CLI" in msg
    assert "--replay" in msg


def test_llm_preflight_passes_for_existing_cli(monkeypatch):
    monkeypatch.setenv("PERMIT_AGENT_CLI", __file__)  # any real file
    llm_preflight()  # must not raise


def test_llm_preflight_accepts_deprecated_alias(monkeypatch):
    """PERMIT_GROK_CLI still works as a fallback when PERMIT_AGENT_CLI is unset."""
    monkeypatch.delenv("PERMIT_AGENT_CLI", raising=False)
    monkeypatch.setenv("PERMIT_GROK_CLI", __file__)
    llm_preflight()  # must not raise


def test_new_env_var_takes_precedence_over_alias(monkeypatch):
    """PERMIT_AGENT_CLI wins over the deprecated PERMIT_GROK_CLI."""
    monkeypatch.setenv("PERMIT_AGENT_CLI", "/nonexistent-xyz/runner.py")
    monkeypatch.setenv("PERMIT_GROK_CLI", __file__)
    with pytest.raises(RuntimeError) as exc:
        llm_preflight()
    assert "/nonexistent-xyz/runner.py" in str(exc.value)


def _replay_transcript(path, lines):
    with open(path, "w") as f:
        for obj in lines:
            f.write(json.dumps(obj) + "\n")


def test_replay_never_touches_llm_backend(monkeypatch, tmp_path):
    """Replay mode is fully offline: it must not preflight the LLM runner."""
    monkeypatch.setenv("PERMIT_AGENT_CLI", "/nonexistent-xyz/grok.py")
    replay = tmp_path / "rec.jsonl"
    _replay_transcript(replay, [
        {"type": "beat", "n": 7, "task": "noop"},
        {"type": "answer", "text": "done offline"},
    ])
    tools, _, _ = _tools()
    final = run_agent(tools, "noop", str(tmp_path / "out.jsonl"),
                      replay=str(replay), beat=7)
    assert final == "done offline"


def test_replay_reexecutes_actions_with_id_remap(tmp_path):
    """
    Replay re-executes the recorded actions against the live tools: the
    recorded escrow_id is remapped to the fresh one, the deliver really
    captures, and the fresh ids land in the written transcript.
    """
    tools, paypal, _ = _tools()
    replay = tmp_path / "rec.jsonl"
    _replay_transcript(replay, [
        {"type": "beat", "n": 7, "task": "buy a widget"},
        {"type": "llm", "text": "THOUGHT: buy it"},
        {"type": "action", "tool": "attempt_spend",
         "args": {"amount_cents": 3000, "purpose": "widget"}},
        {"type": "observation", "text": json.dumps({
            "ok": True, "decision": "ALLOWED",
            "escrow_id": "esc_RECORDED1",
            "paypal_auth_id": "mock_auth_RECORDED",
            "amount_cents": 3000})},
        {"type": "llm", "text": "THOUGHT: deliver it"},
        {"type": "action", "tool": "deliver",
         "args": {"escrow_id": "esc_RECORDED1"}},
        {"type": "observation", "text": json.dumps({
            "ok": True, "released": True, "reason": "delivered",
            "capture_id": "cap_RECORDED"})},
        {"type": "answer", "text": "bought the widget"},
        {"type": "beat", "n": 8, "task": "next"},
    ])
    out = tmp_path / "out.jsonl"
    final = run_agent(tools, "buy a widget", str(out),
                      replay=str(replay), beat=7)
    assert final == "bought the widget"
    # The replay really moved money on the mock rail.
    assert len(paypal.capture_calls) == 1
    # The recorded escrow_id was remapped to a fresh one in the log.
    logged = [json.loads(l) for l in open(out)]
    deliver = next(o for o in logged
                   if o.get("type") == "action" and o["tool"] == "deliver")
    assert deliver["args"]["escrow_id"] != "esc_RECORDED1"
    assert deliver["args"]["escrow_id"].startswith("esc_")
    fresh_obs = next(o for o in logged
                     if o.get("type") == "observation"
                     and "released" in o["text"])
    assert json.loads(fresh_obs["text"])["released"] is True


def test_llm_preflight_fails_with_guidance_when_cli_unset(monkeypatch):
    """No built-in default path: an unset PERMIT_AGENT_CLI fails fast with guidance."""
    monkeypatch.delenv("PERMIT_AGENT_CLI", raising=False)
    monkeypatch.delenv("PERMIT_GROK_CLI", raising=False)
    with pytest.raises(RuntimeError) as exc:
        llm_preflight()
    msg = str(exc.value)
    assert "PERMIT_AGENT_CLI" in msg
    assert "--replay" in msg

# -- M3: the agent loop cannot escape its permit --------------------------------
# test_gate proves the gate at the pipeline boundary. These three tests prove
# the same refusals hold at the agent-loop boundary: run_agent's replay path
# is the exact code path the --replay honest demo runs, so a rogue recorded
# turn is the strongest adversary the real demo can face.


def _rogue_transcript(path, actions):
    """A replay transcript whose recorded turns attempt `actions`
    (list of (tool, args, recorded_observation_json)). The actions are
    re-executed against the live tools, so the fresh observations are real."""
    with open(path, "w") as f:
        f.write(json.dumps({"type": "beat", "n": 7, "task": "rogue"}) + "\n")
        for i, (tool, args, obs) in enumerate(actions):
            f.write(json.dumps({"type": "llm",
                                "text": f"THOUGHT: rogue turn {i}"}) + "\n")
            f.write(json.dumps({"type": "action", "tool": tool,
                                "args": args}) + "\n")
            f.write(json.dumps({"type": "observation", "text": obs}) + "\n")
        f.write(json.dumps({"type": "answer", "text": "loop complete"}) + "\n")
        f.write(json.dumps({"type": "beat", "n": 8, "task": "next"}) + "\n")


def _fresh_observations(out_path):
    logged = [json.loads(l) for l in open(out_path)]
    return [json.loads(o["text"]) for o in logged
            if o.get("type") == "observation"]


def test_rogue_agent_over_cap_blocked_rail_silent(tmp_path):
    """A rogue agent turn that tries to spend past its cap is refused by the
    gate before the rail. The allowed spend that precedes it proves the rail
    spy is not vacuous."""
    tools, paypal, _ = _tools()
    rec_ok = json.dumps({"ok": True, "decision": "ALLOWED",
                         "escrow_id": "esc_REC",
                         "paypal_auth_id": "mock_auth_REC",
                         "amount_cents": 3000})
    rec_block = json.dumps({"ok": False, "decision": "BLOCKED",
                            "reason": "over_remaining_cap",
                            "paypal_called": False})
    replay = tmp_path / "rec.jsonl"
    _rogue_transcript(replay, [
        ("attempt_spend", {"amount_cents": 3000, "purpose": "widget"}, rec_ok),
        ("attempt_spend", {"amount_cents": 3000, "purpose": "widget"}, rec_block),
    ])
    out = tmp_path / "out.jsonl"
    final = run_agent(tools, "rogue", str(out), replay=str(replay), beat=7)
    assert final == "loop complete"

    obs = _fresh_observations(out)
    assert len(obs) == 2
    assert obs[0]["decision"] == "ALLOWED"
    assert obs[1]["decision"] == "BLOCKED"
    assert obs[1]["reason"] == "over_remaining_cap"

    # Rail spy: exactly one authorization (the allowed spend); the rogue
    # attempt never reached the rail.
    assert len(paypal.authorize_calls) == 1, paypal.authorize_calls
    assert len(paypal.authorizations) == 1
    assert paypal.capture_calls == [] and paypal.captures == {}
    assert paypal.voids == {}

    # A BLOCKED receipt with the exact reason sits on the chain, intact.
    blocked = [r for r in tools.flow.ledger.receipts()
               if r.event_type == "BLOCKED"
               and r.payload.get("reason") == "over_remaining_cap"]
    assert blocked, "no BLOCKED receipt for the rogue over-cap attempt"
    ok, msg = tools.flow.ledger.verify_chain()
    assert ok, msg


def test_rogue_agent_tamper_tool_refused_at_loop_boundary(tmp_path):
    """The name blocklist holds at the agent-loop boundary: a recorded turn
    that names the harness-only deliver_tampered gets an unknown-tool error,
    the tool is never executed, and the rail is untouched."""
    tools, paypal, _ = _tools()
    replay = tmp_path / "rec.jsonl"
    _rogue_transcript(replay, [
        ("deliver_tampered", {"escrow_id": "esc_X", "payload": "x"},
         json.dumps({"ok": False, "error": "unknown tool 'deliver_tampered'"})),
    ])
    out = tmp_path / "out.jsonl"
    run_agent(tools, "rogue", str(out), replay=str(replay), beat=7)

    obs = _fresh_observations(out)
    assert len(obs) == 1
    assert obs[0]["ok"] is False
    assert "unknown tool" in obs[0]["error"]

    assert paypal.authorize_calls == [] and paypal.authorizations == {}
    assert paypal.capture_calls == [] and paypal.captures == {}
    assert paypal.voids == {}


def test_agent_merchant_binding_holds_at_loop_boundary(tmp_path):
    """The permit's merchant allowlist binds at the agent-loop boundary:
    tools bound to a merchant outside the allowlist get BLOCKED with
    merchant_not_allowed before the rail."""
    tools, paypal, _ = _tools()
    from agent.tools import SpendTools
    outsider = SpendTools(tools.flow, tools.permit_id,
                          "rogue_merchant", tools.catalog)
    rec_block = json.dumps({"ok": False, "decision": "BLOCKED",
                            "reason": "merchant_not_allowed",
                            "paypal_called": False})
    replay = tmp_path / "rec.jsonl"
    _rogue_transcript(replay, [
        ("attempt_spend", {"amount_cents": 100, "purpose": "widget"}, rec_block),
    ])
    out = tmp_path / "out.jsonl"
    run_agent(outsider, "rogue", str(out), replay=str(replay), beat=7)

    obs = _fresh_observations(out)
    assert len(obs) == 1
    assert obs[0]["decision"] == "BLOCKED"
    assert obs[0]["reason"] == "merchant_not_allowed"

    assert paypal.authorize_calls == [] and paypal.authorizations == {}
    blocked = [r for r in tools.flow.ledger.receipts()
               if r.event_type == "BLOCKED"
               and r.payload.get("reason") == "merchant_not_allowed"]
    assert blocked, "no BLOCKED receipt for the out-of-allowlist merchant"
    ok, msg = tools.flow.ledger.verify_chain()
    assert ok, msg


def test_agent_tighten_permit_narrows_cap_and_records_receipt():
    """An agent can voluntarily narrow its own permit cap; writes a TIGHTEN
    receipt and subsequent spends above the tightened cap are BLOCKED."""
    tools, paypal, permits = _tools()
    p_init = permits.get(tools.permit_id)
    assert p_init.cap_cents == 5000

    res = json.loads(tools.tighten_permit(cap_cents=2000))
    assert res["ok"] is True
    assert res["tightened"] is True
    assert res["effective_cap_cents"] == 2000
    assert res["remaining_cents"] == 2000

    assert permits.get(tools.permit_id).remaining_cents() == 2000

    tighten_receipts = [
        r for r in tools.flow.ledger.receipts()
        if r.event_type == "TIGHTEN"
    ]
    assert len(tighten_receipts) == 1
    assert tighten_receipts[0].payload["actor"] == "agent:t"
    assert tighten_receipts[0].payload["changes"]["cap_cents"] == {
        "from": 5000,
        "to": 2000,
    }
    ok, msg = tools.flow.ledger.verify_chain()
    assert ok, msg

    obs = json.loads(tools.attempt_spend(2500, "widget"))
    assert obs["decision"] == "BLOCKED"
    assert obs["reason"] == "tightened_cap_exceeded"
    assert obs["paypal_called"] is False


def test_agent_tighten_permit_rejects_widening_attempt():
    """Tighten is strictly narrowing: attempting to increase cap or leave
    all fields empty fails closed without mutating the permit."""
    tools, paypal, permits = _tools()
    res_empty = json.loads(tools.tighten_permit())
    assert res_empty["ok"] is False
    assert "tighten requires at least one of" in res_empty["error"]

    res_widen = json.loads(tools.tighten_permit(cap_cents=10000))
    assert res_widen["ok"] is False
    assert permits.get(tools.permit_id).remaining_cents() == 5000


def test_agent_tighten_permit_narrows_allowlist():
    """Agent can voluntarily drop merchants from its allowlist."""
    ledger = Ledger()
    permits = PermitStore(ledger=ledger)
    paypal = MockPayPalClient()
    verifier = ReleaseVerifier(paypal, permits, ledger=ledger)
    flow = SpendPipeline(permits, paypal, verifier, ledger=ledger)
    permit, _ = permits.grant(
        agent_id="t", cap_cents=5000, allowlist=["m1", "m2"],
        expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    tools = SpendTools(flow, permit.permit_id, "m2", {"widget": b"widget-bytes"})

    res = json.loads(tools.tighten_permit(remove_merchants=["m2"]))
    assert res["ok"] is True
    assert res["effective_allowlist"] == ["m1"]

    obs = json.loads(tools.attempt_spend(1000, "widget"))
    assert obs["decision"] == "BLOCKED"
    assert obs["reason"] == "merchant_not_allowed"

