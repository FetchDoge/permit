"""
ReAct runner: a real LLM (Grok) driving the spend tools in a loop.

The LLM reasons in THOUGHT lines, acts with ACTION + ARGS lines, reads
OBSERVATION lines, and finishes with ANSWER. The runner executes only
the tools in SpendTools; anything else the model emits is ignored.

Transcript: every turn is appended to a JSONL transcript (llm text,
parsed action, observation) so the video can show the agent's real
reasoning trace. --replay <transcript> re-runs a saved transcript
without calling the LLM (offline fallback for recording day): the
recorded reasoning is replayed verbatim and the recorded actions are
re-executed against the live tools, so the receipts stay real.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

# Path to the LLM runner CLI, set via the PERMIT_GROK_CLI environment
# variable. There is no built-in default, so the repo carries no local paths.
# Resolved at call time by _grok_cli(); this constant mirrors the value seen
# at import time ("" when unset).
GROK_CLI = os.environ.get("PERMIT_GROK_CLI", "")

SYSTEM_TEMPLATE = """You are a shopping agent with a spending permit. You can spend ONLY \
through your tools - you have no other way to move money.

Tools (one call per turn):
- attempt_spend: try to spend. Args: {"amount_cents": int, "purpose": str}
  Valid purpose values (use exactly): {purposes}
- deliver: the merchant delivers the purchased item for escrow release. \
Args: {"escrow_id": str}
- check_permit: see your permit's remaining budget. \
Args: {}
- delegate_subpermit: carve a sub-permit out of your remaining cap for \
another agent. Args: {"cap_cents": int, "agent_id": str, \
"expiry_minutes": int}. The child inherits your merchant allowlist and \
cannot outlive or outspend your permit.
- check_approval: poll a principal-approval request. \
Args: {"approval_id": str}
- complete_approved_spend: execute a principal-approved spend. \
Args: {"approval_id": str}

Rules:
- Amounts are in cents (3000 = $30.00).
- If a spend is BLOCKED, do NOT retry it or split it into smaller spends \
to dodge the cap. Report the refusal.
- If a spend is PENDING (above your permit's approval threshold), use \
check_approval to poll; once approved, call complete_approved_spend, \
then deliver as usual. A denied approval is final: report it.
- After an ALLOWED spend, call deliver with the escrow_id to complete \
the purchase, then report the capture id - unless the task says not to.
- Delegation never increases total spending power: the carved cap is \
reserved on your permit until the child spends or is revoked.
- Keep reasoning short.

Respond in exactly this format each turn:
THOUGHT: <one or two sentences>
ACTION: <tool_name>
ARGS: <JSON object>
or, when done:
THOUGHT: <one or two sentences>
ANSWER: <what happened, in plain language>
"""

ACTION_RE = re.compile(r"ACTION:\s*(\w+)")
ARGS_RE = re.compile(r"ARGS:\s*")
ANSWER_RE = re.compile(r"^ANSWER:\s*(.*)$", re.M | re.S)


def build_system(purposes: list[str]) -> str:
    return SYSTEM_TEMPLATE.replace(
        "{purposes}", ", ".join(f'"{p}"' for p in purposes))


def parse_action(text: str):
    """
    Parse ACTION/ARGS from a turn. Handles both layouts the model uses:
      ACTION: name
      ARGS: {...}
    and the single-line form:
      ACTION: name ARGS: {...}
    Returns (name, args_dict) or (name, None) / (None, None).
    """
    m_action = ACTION_RE.search(text)
    if not m_action:
        return None, None
    rest = text[m_action.end():]
    m_args = ARGS_RE.search(rest)
    if not m_args:
        return None, None
    blob = rest[m_args.end():].strip()
    # Shortest prefix that parses as JSON (tolerates trailing text).
    for i, ch in enumerate(blob):
        if ch == "}":
            try:
                return m_action.group(1), json.loads(blob[: i + 1])
            except json.JSONDecodeError:
                continue
    return m_action.group(1), None


def _grok_cli() -> str:
    """Resolve the Grok runner path from PERMIT_GROK_CLI at call time.

    Raises RuntimeError with setup guidance when the variable is unset.
    """
    cli = os.environ.get("PERMIT_GROK_CLI", "").strip()
    if not cli:
        raise RuntimeError(
            "agent LLM backend not configured: PERMIT_GROK_CLI is not set. "
            "Set PERMIT_GROK_CLI to the path of your Grok runner script, or run "
            "the demo with --replay <transcript> (fully offline)."
        )
    return cli


def llm_preflight() -> None:
    """
    Fail fast when the agent's LLM backend is unavailable.

    The demo agent reasons through a real LLM unless --replay is used.
    A missing runner must surface here — with setup guidance — not as a
    mid-demo subprocess failure after beats have already run.
    """
    cli = _grok_cli()
    if not os.path.isfile(cli):
        raise RuntimeError(
            f"agent LLM backend unavailable: {cli!r} is not a file. "
            "Set PERMIT_GROK_CLI to the Grok runner, or run the demo with "
            "--replay <transcript> (fully offline)."
        )


def _execute_tool(tools, name: str, args: dict) -> str:
    """Run one tool call. Tool errors become observations, not crashes."""
    fn = getattr(tools, name, None)
    if fn is None or name.startswith("_") or name == "deliver_tampered":
        return json.dumps({"ok": False, "error": f"unknown tool {name!r}"})
    try:
        return fn(**args)
    except Exception as e:  # tool errors are observations, not crashes
        return json.dumps({"ok": False, "error": str(e)})


def _remap_ids(value, id_map: dict[str, str]):
    """
    Rewrite recorded ids to this run's fresh ids (exact string match).

    Replay re-executes the recorded actions, but ids are minted fresh each
    run — so a recorded deliver(escrow_id=<old>) must follow the fresh
    escrow_id the re-executed attempt_spend just returned.
    """
    if isinstance(value, dict):
        return {k: _remap_ids(v, id_map) for k, v in value.items()}
    if isinstance(value, list):
        return [_remap_ids(v, id_map) for v in value]
    if isinstance(value, str) and value in id_map:
        return id_map[value]
    return value


def _learn_ids(recorded_text: str, fresh_text: str,
               id_map: dict[str, str]) -> None:
    """
    Map recorded ids -> fresh ids by comparing the recorded observation
    with the fresh one. Any string field whose key names an id
    (endswith "_id" / "_ids") is paired; lists pair positionally.
    """
    try:
        rec = json.loads(recorded_text)
        fresh = json.loads(fresh_text)
    except (json.JSONDecodeError, TypeError):
        return
    if not isinstance(rec, dict) or not isinstance(fresh, dict):
        return
    for key, rec_val in rec.items():
        if key not in fresh:
            continue
        if not (key.endswith("_id") or key.endswith("_ids")):
            continue
        fresh_val = fresh[key]
        if isinstance(rec_val, str) and isinstance(fresh_val, str):
            if rec_val != fresh_val:
                id_map[rec_val] = fresh_val
        elif isinstance(rec_val, list) and isinstance(fresh_val, list):
            for r, f in zip(rec_val, fresh_val):
                if isinstance(r, str) and isinstance(f, str) and r != f:
                    id_map[r] = f


def llm_turn(system: str, history: str) -> str:
    """One Grok call. Returns the raw text (receipt stripped)."""
    proc = subprocess.run(
        [sys.executable, _grok_cli(), "chat", history,
         "--system", system, "--temperature", "0.3",
         "--max-tokens", "400"],
        capture_output=True, text=True, timeout=180,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"grok cli failed: {proc.stderr[-500:]}")
    # stdout is the answer; the [input=...] receipt goes to stderr.
    return proc.stdout.strip()


def run_agent(tools, task: str, transcript_path: str,
              max_turns: int = 8, replay: str | None = None,
              beat: int = 0) -> str:
    """
    Drive the agent on `task`. Returns the final ANSWER.
    Every turn is appended to transcript_path as JSONL, sectioned by beat.
    With replay=<path>, replays that transcript's turns for this beat
    without calling the LLM (offline fallback for recording day): the
    recorded reasoning text is replayed verbatim and the recorded ACTIONS
    are re-executed against the live tools, so the receipts stay real.
    """
    if replay is None:
        # The agent reasons through a real LLM: verify the runner exists
        # before any beat runs, with setup guidance on failure.
        llm_preflight()

    transcript = open(transcript_path, "a")
    history = f"TASK: {task}\n"
    log = lambda obj: (transcript.write(json.dumps(obj) + "\n"),
                       transcript.flush())
    system = build_system(list(tools.catalog.keys()))

    if replay:
        # Offline fallback: this beat's recorded turns, no LLM call.
        # Recorded actions are RE-EXECUTED (deterministic on the mock
        # rail); the fresh observations replace the recorded ones, and
        # recorded ids are remapped to the fresh ids so chained calls
        # (deliver after attempt_spend) follow the new ids.
        section, in_beat = [], False
        for line in open(replay):
            obj = json.loads(line)
            if obj.get("type") == "beat":
                in_beat = obj.get("n") == beat
                continue
            if in_beat:
                section.append(obj)
        final = ""
        id_map: dict[str, str] = {}
        i = 0
        while i < len(section):
            obj = section[i]
            otype = obj.get("type")
            if otype == "action":
                if i + 1 >= len(section) or section[i + 1].get("type") != "observation":
                    raise ValueError(
                        f"replay transcript corrupt at beat {beat}: "
                        "action without a following observation"
                    )
                rec_obs = section[i + 1]
                name = obj["tool"]
                args = _remap_ids(obj.get("args") or {}, id_map)
                obs_text = _execute_tool(tools, name, args)
                log({"type": "action", "tool": name, "args": args})
                log({"type": "observation", "text": obs_text})
                _learn_ids(rec_obs.get("text", ""), obs_text, id_map)
                i += 2
                continue
            if otype == "observation":
                # Stray recorded observation (its action was re-executed
                # above): skip it, the fresh one stands.
                i += 1
                continue
            log(obj)
            if otype == "answer":
                final = obj["text"]
            i += 1
        transcript.close()
        return final

    log({"type": "beat", "n": beat, "task": task})

    final = ""
    for _ in range(max_turns):
        text = llm_turn(system, history)
        log({"type": "llm", "text": text})
        history += f"\n{text}\n"

        m_answer = ANSWER_RE.search(text)
        if m_answer:
            final = m_answer.group(1).strip()
            log({"type": "answer", "text": final})
            break

        name, args = parse_action(text)
        if not name or args is None:
            obs = json.dumps({"ok": False,
                              "error": "no ACTION/ARGS parsed; use the format"})
            history += f"OBSERVATION: {obs}\n"
            log({"type": "observation", "text": obs})
            continue

        log({"type": "action", "tool": name, "args": args})
        obs = _execute_tool(tools, name, args)
        history += f"OBSERVATION: {obs}\n"
        log({"type": "observation", "text": obs})

    transcript.close()
    return final


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--task", required=True)
    ap.add_argument("--transcript", required=True)
    ap.add_argument("--replay", default=None)
    ap.add_argument("--permit-id", required=True)
    ap.add_argument("--merchant", required=True)
    args = ap.parse_args()
    print("react.py is a library; wire it in demo_six_beat.py")


if __name__ == "__main__":
    main()
