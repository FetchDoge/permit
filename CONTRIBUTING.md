# Contributing to Permit

Permit is the payment authority layer for AI agents: agents spend on permits,
never raw account access. Contributions are welcome — here's how to make one
that gets merged.

## The one rule

**Authority only narrows.** Every change must preserve or strengthen the
guarantee that no code path can widen what an agent is allowed to spend.
If your change touches `permit/` or `settlement/`, say in the PR description
exactly why it cannot widen authority. Tighten-only is the model: caps,
allowlists, expiries, and approval thresholds can be narrowed live, never
widened.

## Setup

```bash
python3 -m pytest tests/ -q   # the whole suite; must stay green
```

No credentials needed: the mock PayPal rail is the default. The sandbox rail
(`--sandbox`) needs `PERMIT_PAYPAL_CLIENT_ID` / `PERMIT_PAYPAL_CLIENT_SECRET`
and an interactive payer approval — see `docs/sandbox-runbook.md`.

## What good PRs look like

- **One behavior per PR.** Small, reversible, tested.
- **Tests are the spec.** New behavior ships with tests in `tests/`;
  adversarial tests (the refusal paths, the race paths) are valued more
  than happy-path tests.
- **Receipts for everything.** State changes write to the hash-chained
  ledger (`permit/ledger.py`). If your change moves money or authority and
  doesn't write a receipt, it's incomplete.
- **No mocks on the money path.** The mock rail exists for credential-free
  runs; production-shaped code must work against the sandbox client too.

## Good first issues

Issues labeled `good first issue` are scoped, documented, and don't require
PayPal credentials. Start there. If you're unsure, open an issue first and
we'll scope it together.

## Architecture map

- `permit/permit.py` — the authority core: grants, the 4-clause check,
  delegation carve-outs, tighten-only narrowing, principal approvals.
- `permit/flow.py` — the spend pipeline: check → reserve → PayPal authorize
  → escrow → predicate-gated capture.
- `settlement/` — PayPal rails (mock + sandbox) and the release verifier.
- `dashboard/` — the principal's console: permits, approvals, e-stop.
- `docs/` + the wiki — runbooks, the submission checklist, the evidence map.

Read `README.md` first, then the wiki's Architecture page. The demo scripts
(`demo_*.py`) are the fastest way to see the whole machine move.
