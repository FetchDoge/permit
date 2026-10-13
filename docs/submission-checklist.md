# Submission checklist

Maps this repo to the [PayPal AI Hackathon](https://paypalaihackathon.devpost.com/) deliverables. Deadline: Nov 12, 2026, 12:00 pm Pacific. Status is the state of this tree, not a filled-in Devpost form.

Every artifact below has to tell the same arc, in this order: **the problem → the gate → the live proof → what's next.** A page that starts a second story does not belong in the submission.

The live proof the judge must see, in one command, is: grant → allowed capture → blocked overspend (no PayPal call) → **delegated sub-permit + revoke cascade** → refused tamper → UNKNOWN then reconcile. That cascade is the differentiator.

## Functional demo

**Status: ready.** A judge can run it from a fresh checkout. Python 3.10 or newer. No pip install, no API key, no `.env`, no network. Measured on this tree: `python3 demos/demo_six_beat.py --fast` reaches `VERIFIED` in about half a minute (the LLM agent calls dominate); the receipt chain is deterministic. The cascade is included.

| What the judge does | Where it lives | What it shows |
| --- | --- | --- |
| `python3 demos/demo_six_beat.py --hold`, then open the printed URL | `demos/demo_six_beat.py`, `dashboard/index.html`, `dashboard/server.py` | The six beats on the mock rail, including a $15 carved sub-permit and a parent revoke cascade. The page stays up until Ctrl+C. |
| `python3 demo.py` | `demo.py` | Allow, block, delegate, cascade, chain verified. Exits. |
| `python3 trace.py` | `trace.py`, `server.py` | The same gate over HTTP, including `POST /api/permits/<id>/delegate` and `POST /api/permits/<id>/revoke-cascade`. Starts its own server on port 8741. Do not leave `server.py` running on that port. |
| Read the boundary | `docs/sandbox-runbook.md` | What the gate stops, and the sandbox procedure. Threat model and lifecycle docs are still to write. |

This demo does **not** call PayPal. Saying that it does is off-arc.

## Delegation semantics (the part the cascade proves)

A sub-permit is **carved** from the parent's remaining cap: the carve is reserved on the parent at delegation, so sibling sub-permits cannot oversubscribe the parent. Captures roll up the chain (reserved → captured per ancestor). Revoking a parent cascades to every descendant (`REVOKED_CASCADE` receipts); in-flight holds across the subtree are voided; unspent carves are released post-order (`CARVE_RELEASED`), idempotently. `POST /api/permits/<id>/revoke-cascade` names the revoked descendants in `cascaded_to`.

## Demo video

**Status: not submitted.** No public video URL is in this repo.

Devpost asks for a demonstration video linked from the submission. Host it on YouTube, Vimeo, or Youku, and keep it public. Cut it under three minutes. Judges watch the opening, then the product moving.

Storyboard, same arc:

| When | Say and show |
| --- | --- |
| 0:00 | The problem. An agent with a wallet can overspend, pay the wrong merchant, or ignore a stop. A budget in a prompt is not a control. |
| 0:20 | The gate. Cap, allowlist, expiry, not revoked. A sub-permit is carved from the parent's remaining cap — siblings can't overspend it. Hold with `AUTHORIZE`. Capture once, only if the hash matches. The cap returns only when the void is confirmed. |
| 0:45 | Live proof, on screen. `python3 demos/demo_six_beat.py --hold`. $30 captures. $60 is blocked and PayPal is not called. A $15 sub-permit is carved. Revoke on the parent cascades: child revoked, hold voided, carve released. Tampered bytes are refused. A dropped capture stays `UNKNOWN`, then reconcile records the one capture. |
| 2:20 | What's next, in one sentence. These beats on PayPal's sandbox are the written procedure, not this recording. This recording is the mock rail. |
| 2:35 | `VERIFIED` means the receipt list in this process is internally intact. It is not a PayPal signature and it is not durable. |

The recording has to say the camera run is the mock. It must not say the six beats already ran on the live sandbox.

## Text description

**Status: not submitted.** The README is the source. Paste from it. Do not write a second pitch on the form.

## Public code repository

**Status: the tree is the submission. Publishing is not done here.**

| Artifact | Status |
| --- | --- |
| `LICENSE` (MIT) | In the repo. |
| README cold-start | In the repo. One command, stdlib only, reaches the running dashboard. |
| This checkout's git remote | None. The public GitHub URL is a Devpost field still to fill. Do not treat a local branch as the published remote. |

## Project requirements, checked against the rules

| Requirement | Where it is met | Status |
| --- | --- | --- |
| PayPal developer platform, sandbox | `settlement/sandbox_client.py`, `python3 server.py --sandbox`, `docs/sandbox-runbook.md` | Partial. The six beats have not been run as one sandbox session. |
| AI in the product, not beside it | The spender in the demo beats is the agent. It has no PayPal credentials. The gate is the only way it spends. | Met. |
| Working prototype a judge can run | `python3 demos/demo_six_beat.py --hold` | Met on the mock rail. Includes carved sub-permits and the revoke cascade. |
| Documentation a judge can grade | README, sandbox runbook, this checklist | Partial. Threat model and lifecycle docs still to write. |
| English | All of the above | Met. |
| New or significantly updated during Oct 1–Nov 12 | Initial commit Oct 2, 2026 | Met in this history. Say so on the form. |

## Explicitly not a deliverable

| Item | Why it is gone or unused |
| --- | --- |
| Internal review notes (`CHATGPT-CRITIQUE-ACTIONS.md`) | Process log. Removed from the tree. |
| One-off sandbox spike (`spike.py`, `spike-report.md`) | Printed `VERIFIED` for API probes. That word is the ledger's word. The Oct 2 facts live in `docs/sandbox-runbook.md`, labeled as API observations. Removed from the tree. |
| `--live` with no `PERMIT_GROK_CLI` | Stops immediately and prints the offline command. |
