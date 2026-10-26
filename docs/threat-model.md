# Permit: threat model

Status: current for the tree on main at f9f8c9c5 (2026-10-23), plus the
M4 e-stop demo merged in PR #61. Every mitigation below names the code
that implements it and the test that proves it. Anything not proven in
this tree is listed under "Not mitigated" rather than implied.

## What Permit is, in one paragraph

Permit is an authority layer between an AI agent and PayPal. The agent
never holds PayPal credentials. It asks the gate to spend; the gate
checks a permit (cap, merchant allowlist, expiry, not revoked, through
a tighten-only min-gate) before any PayPal call exists, reserves the
cap atomically, and writes a hash-chained receipt for every decision,
allowed or blocked. Settlement then runs through an escrow whose
release requires delivery evidence verified against a predicate, with
idempotent capture and reconcile for the timeout case.

## Assets

- The principal's money: the permit cap is the maximum loss the gate
  will authorize, per permit and, through carve accounting, per tree.
- PayPal credentials: held only by the service (`SandboxPayPalClient`
  in `settlement/sandbox_client.py`, configured from the environment).
  The agent process never receives them.
- The acceptance key: signs delivery acceptance in
  `settlement/verifier.py` (`sign_acceptance`). Whoever holds it can
  approve a release, so it is treated as a secret, not a config value.
- The ledger: the receipt chain is the audit evidence. Its value is
  that tampering after the fact is detectable, not that it is secret.

## Actors

- Principal: grants, tightens, delegates, revokes, and e-stops. The
  only actor who can widen nothing: even the principal cannot widen a
  permit after issuance, because `tighten()` only narrows (see
  `PermitStore.tighten` in `permit/permit.py`).
- Agent: untrusted spender. It may be prompt-injected, loop, or be
  given a wrong cart. The design assumption is that the agent will
  eventually ask for something it should not get.
- Merchant: identified by the provider-reported `payee.merchant_id`
  on the PayPal order, never by a name the agent supplies.
- Auditor or judge: read-only. Sees the audit rollup
  (`permit/audit.py`) and the raw receipts.

## Trust boundaries

1. Agent to gate: every spend, delegate, and release request crosses
   this boundary and is re-evaluated against the permit's effective
   (post-tighten, lineage-aware) authority at that moment.
2. Gate to PayPal: no PayPal call is made until the authority check
   passes and the cap is reserved. Blocked attempts are proven
   rail-silent by a strict spy in `tests/test_gate.py`.
3. PayPal back to gate: provider responses are not trusted at face
   value. The sandbox client refuses to authorize an order whose
   payee merchant or amount differs from the permit's binding
   (`MerchantMismatch` in `settlement/sandbox_client.py`), and
   recovers an already-authorized order by reading it back instead of
   failing or double-authorizing.
4. Evidence to escrow release: capture happens only when the
   verifier's predicate passes for the registered escrow, and the
   capture key is derived from the permit and claim so a retry after
   a timeout cannot double-charge.

## Threats and mitigations (all proven in this tree)

| Threat | Mitigation | Proof |
| --- | --- | --- |
| Agent overspends the cap, once or in a loop | Remaining-cap check counts reserved plus captured; blocked attempts allocate nothing and never reach the rail | `tests/test_gate.py`, `tests/test_admission.py` (runaway loop refused at budget exhaustion before any order exists) |
| Parallel overspend races past the cap | Cap reservation is atomic under the permit lock; concurrent attempts admit at most the cap and fail closed | `tests/test_admission.py` (8 threads, $50 cap, exactly $40 admitted) |
| Agent pays the wrong merchant, or a merchant is swapped after authorization | Allowlist check at the gate, plus provider payee binding re-checked in the sandbox client at authorize time | `tests/test_gate.py` (`merchant_not_allowed`), `tests/test_sandbox_client.py` |
| Expired or revoked permit is used | Revoked and expiry clauses are evaluated on every attempt, including through ancestors (`_lineage_block_reason`) | `tests/test_gate.py` (`revoked`, `expired`, `ancestor_revoked`, `ancestor_expired`) |
| A revoked parent leaves live children behind | Revocation cascades to every descendant, voids in-flight holds across the subtree, and releases unspent carves idempotently | `tests/test_estop_race.py`, six-beat demo cascade beat |
| E-stop arrives too late, mid-spend | E-stop wins at three timings: before the spend (blocked, zero rail calls), inside authorize (hold voided, reservation released, no escrow), and after authorize (escrow voided, late delivery refused) | `tests/test_estop_race.py`, `demos/demo_estop.py` |
| Authority is widened after issuance | `tighten()` and `delegate()` only narrow: cap, allowlist, and expiry can only shrink, for the permit and its descendants | `tests/test_tighten.py`, `tests/test_delegation.py` (`allowlist_escalation`, `expiry_beyond_parent`, `over_parent_remaining`) |
| Delegated children oversubscribe the parent together | A delegation carves from the parent's remaining cap and reserves it on the parent at delegation time, so siblings cannot oversubscribe | `tests/test_delegation.py`, `demo.py` cascade beat |
| Capture is retried after a timeout and double-charges | Capture is idempotent (`PayPal-Request-Id` derived from permit plus claim); a timed-out capture goes UNKNOWN, never optimistically captured or failed, and `reconcile()` converges it from PayPal's own state | `tests/test_reconcile.py`, sandbox runbook step 6 |
| Payer approval is faked or replayed | Approvals bind to the exact order and are consumed atomically; on the live wire PayPal itself refuses authorize with ORDER_NOT_APPROVED until the buyer approves, and the pipeline holds the reservation and surfaces that state instead of proceeding | `tests/test_agent_sandbox_live.py`, `tests/test_approval.py`; also the Apart collusion experiments (approval laundering failed against this build, 2026-10-23) |
| A second identity or a coalition splits a cap | NOT stopped by design today; see "Not mitigated" | Apart collusion experiments, 2026-10-23: cap-splitting and identity rotation succeeded against the sandbox |
| Ledger is edited after the fact to hide a spend | Every receipt commits to the previous receipt's hash; `verify_chain()` recomputes each hash and the linkage, and the audit rollup is derived from receipts only | `permit/ledger.py`, `tests/test_audit.py`; tamper refusal is a six-beat demo beat |
| Blocked attempts are invisible | Every blocked attempt writes exactly one BLOCKED receipt carrying the exact reason, counted by reason in the audit summary | `tests/test_gate.py`, `permit/audit.py` |

## Not mitigated, and not claimed

- Coalition and identity attacks: two agents with separate permits,
  or one agent rotating to a fresh permit, can together exceed a
  single permit's cap. Permit has no cross-permit aggregate
  accounting and no identity binding. This was demonstrated, not
  hypothesized, in the 2026-10-23 collusion experiments. Closing it
  needs an aggregate budget per principal, which is future work.
- Completed captures cannot be voided. An e-stop after capture needs
  a refund, which is outside this prototype's scope (stated in
  `docs/sandbox-runbook.md`, step 7).
- The ledger proves internal consistency, not external truth.
  `VERIFIED` means the receipt chain in this process is intact. It is
  not a PayPal signature. Durability across a crash depends on using
  the SQLite ledger (`permit/sqlite_ledger.py`); the in-memory ledger
  is a demo and test tool.
- The HTTP service is a localhost prototype. It has no principal
  authentication of its own; anyone who can reach the port can act as
  the principal. Do not expose it beyond localhost without adding
  authentication first.
- The acceptance-key fail-closed hardening for issue #53 is in open
  PR #55 and is not on main yet. On main, entry points that are given
  no key can still fall back to a demo key where the demo flag allows
  it. That is why #53 is open, and this document does not claim it
  closed.
- The agent's reasoning is out of scope. Permit does not judge
  whether a permitted purchase is wise, only whether it is
  authorized. A permitted merchant selling the wrong item at a
  permitted price passes the gate; intent binding is future work.

## How to check this document

Run the suite (`python3 -m pytest -q`). Every row above names its
test file. If a named test is missing or failing, the row is wrong
and the document, not the test, should be fixed first.
