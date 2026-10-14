# Replay fixture — provenance

`demo_transcript.jsonl` is the recorded agent transcript the six-beat
demo replays offline:

```bash
python3 demos/demo_six_beat.py --fast --replay demos/fixtures/demo_transcript.jsonl
```

**Provenance, stated plainly:** the recording was made on 2026-10-04
against a sibling checkout (permit-converge), not against this tree.
It was adopted as the committed fixture on 2026-10-14 only after a
control run proved it replays deterministically on this branch's
HEAD (`d79be84`): all six beats, `ledger chain: VERIFIED`
(26 receipts), exit 0. Recorded ids are remapped at replay time, so
the fixture does not need regenerating when id generation changes —
only when tool names/args or the beat tasks change.

Re-recording against this HEAD with a live agent is the cleaner
long-term state; it requires `PERMIT_GROK_CLI`, which the recording
environment must provide. Until then this file — replay-verified,
not re-recorded — is the judge path, and it is labelled as such
everywhere it is cited.
