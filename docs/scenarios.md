# Scenario catalog

Diverse, runnable uses of the Permit engine. Each scenario is pure
orchestration — no new authority clauses. Scenarios prove the engine's
diversity; the engine proves the scenarios' soundness.

## sla_escrow — agent-to-agent SLA settlement (this repo)

A client hires a worker agent for a deliverable. The client delegates a
fenced sub-permit; the worker's pay goes on hold in escrow; the client's
acceptance signature is the only key that releases it.

Exercises: delegation carve-outs, the grant fence (over-delegation
refused with `over_parent_remaining`), predicate-gated settlement
(`acceptance_signature`), forged-evidence refusal, capture roll-up
through the tree, cascade revocation with post-order carve release.

Run: `python3 demos/demo_sla_escrow.py [--fast]` (mock rail, offline).
Tests: `tests/test_sla_escrow.py` (5 tests).

## Built-in scenarios (existing demos)

- `demos/demo_six_beat.py` — the core authority story: grant, allow, block,
  e-stop with void semantics, tampered-predicate refusal, capture
  reconciliation.
- `demos/demo_delegation.py` — the delegation story: carve, spend with
  roll-up, over-cap refused at both levels, cascade reclaim.

## Future scenarios (from the 2026-10-04 brainstorm, not built)

Ranked by the crew for a later night; each needs its honesty check
before it ships:

- **Royalty waterfall** — N children, one acceptance claim, N captures.
  Needs: partial-capture support on the rail (or N holds).
- **Mutual-aid cascade** — incident-scoped tree, spend one child,
  revoke the parent, dashboard shows the cascade. (Mostly covered by
  `demos/demo_delegation.py`; the incident predicate is the new piece.)
- **Fiduciary drawdown** — needs a payee-not-spender check the four
  clauses do not have. Do not imply it.
- **Humanitarian disbursement** — needs ledger claim-uniqueness
  (dedupe). Unknown whether the ledger rejects duplicate claim ids.
- **Demand-response payout** — payee inversion (the merchant is paid for
  an event). Same predicate machine as SLA; the story needs a meter or
  registry, which is theater without one.
