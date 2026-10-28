# Demo video recording script

The word-for-word script for the submission video (M5). It follows the
storyboard in `docs/submission-checklist.md` and nothing else: one arc,
the problem, the gate, the live proof, what is next. Every number spoken
below was read off a real run of the commands shown, verified again on
2026-10-28 against main. If a rerun prints different numbers, fix this
script before recording, not after.

Target length: 2 minutes 30 seconds to 2 minutes 50 seconds edited.
Devpost asks for under three minutes. If the cut runs long, trim pauses
between beats first, never the honesty lines.

## Before recording

- Fresh checkout of main. Run `python3 -m pytest -q` once off camera;
  the suite must be green before the camera run means anything.
- Run each on-screen command once off camera so the terminal history
  holds no surprises, then clear the terminal.
- Terminal large enough that receipt lines do not wrap. The replay
  prints a dashboard URL at the end and leaves it live; know that the
  last segment opens it.
- Record the terminal and the narration in one take if possible. The
  replay is deterministic, so a retake shows the identical run.

## The script

### 0:00 The problem (narration over a plain title card)

Say: "An AI agent with a wallet can overspend, pay the wrong merchant,
or ignore a stop, and a budget written in a prompt is not a control.
Permit is a gate between the agent and PayPal. The agent never holds
PayPal credentials. Every spend it attempts is checked against a permit
a human granted, and every decision is written to a receipt ledger."

### 0:20 The gate (show `permit/permit.py` or the README diagram)

Say: "A permit carries four limits: a cap, a merchant allowlist, an
expiry, and revocation. A spend is admitted only if all four pass, and
admission is atomic: the cap is reserved in the same step, so parallel
attempts cannot overspend it. A sub-permit is carved out of the parent
permit's remaining cap, so sibling sub-permits cannot oversubscribe
the parent. Keep this in mind; the live run proves each part."

### 0:45 Live proof (terminal, one command)

Run on camera:

```bash
python3 demos/demo_six_beat.py --fast --replay demos/fixtures/demo_transcript.jsonl
```

Say while it runs: "This run is a replay on the mock rail. It does not
call PayPal. Beat one: a human grants a fifty dollar permit, one
merchant, one hour. Beat two: the agent buys the thirty dollar dataset
license. It captures, and twenty dollars remain. Beat three: the agent
tries the sixty dollar premium tier. Blocked, reason
over_remaining_cap, and look at the counter: PayPal authorize calls did
not change. The blocked spend never reached the rail. Beat four: a
fifteen dollar sub-permit is carved from the parent, the child holds
ten dollars, and then the human revokes the parent. The revocation
cascades: the child is revoked, the ten dollar hold is voided, the
carve is released, and the parent is whole again. Beat five: the
merchant submits evidence that does not match the precommitment. It is
refused, hash mismatch, the hold is voided, and no capture happens.
Beat six:
a capture times out and stays UNKNOWN, neither captured nor failed,
until reconcile checks the provider and records exactly one capture.
The final line reads: ledger chain VERIFIED, twenty-six receipts."

Then open the dashboard URL the replay printed and say: "The same
receipts, as an audit view. Every allowed, blocked, and revoked
decision is on the record."

### 2:20 What is next (narration over the dashboard or title card)

Say: "What is next: these same beats on the PayPal sandbox, following
the written procedure in the sandbox runbook. The agent loop has
already run on the live sandbox wire: an over-cap attempt was blocked
before any wire call, and an allowed spend created a real order and
stopped at PayPal's buyer approval, which needs the account holder's
sign-in. This recording is not that run, and it does not claim to be."

### 2:35 What VERIFIED means (narration, closing card)

Say: "One word to close. VERIFIED means the receipt list in this
process is internally intact: every hash matches the receipt before
it. It is not a PayPal signature, and it is not durable storage.
Permit is the gate, the ledger is the proof, and both are in the repo
for any judge to run."

## Honesty rules for the recording

- Say "mock rail" out loud in the live proof segment. The checklist
  requires it and this script puts it in the first sentence.
- Never say the six beats ran on the live sandbox. They have not, as
  one session. The checklist states this and so does the 2:20 segment.
- Never say the demo calls PayPal. It does not.
- Do not speak a test count. The graded count lives in the README
  evidence line, and a spoken count can only go stale.
- If a beat prints something this script does not describe, stop the
  take. The script is wrong or the build is; either way, fix it off
  camera.

## After recording

- Watch the full cut once, start to finish, and confirm the mock rail
  disclosure is audible and the VERIFIED segment is uncut.
- Uploading to YouTube is the account holder's step, on his account.
  When the public URL exists, it goes in the checklist's Demo video
  section and on the Devpost form; until then the status there stays
  "not submitted".
