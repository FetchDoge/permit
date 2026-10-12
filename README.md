# Permit

**Permit puts enforceable spending authority between AI agents and PayPal. Every decision, allowed or blocked, writes a hash-chained receipt.**

[![ci](https://github.com/marsojuji-cmyk/permit/actions/workflows/ci.yml/badge.svg)](https://github.com/marsojuji-cmyk/permit/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE) [![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)

No spend without a permit. No timeout without a receipt.

AI agents are getting wallets. The missing piece is the authority layer: what an agent may spend, on whose terms, and with what record. Permit answers that with a scoped permit (a budget, approved merchants, an expiry, revocation) and an e-stop. The agent never holds raw account access or credentials.

Built for the [PayPal AI Hackathon](https://paypalaihackathon.devpost.com/) (Nov 12, 2026).

## What it guarantees

**The authority check, stated exactly.** Attempt `a` against permit `P` is authorized iff

```
amount(a) <= remaining(P)
  AND merchant(a) IN allowlist(P)
  AND now < expiry(P)
  AND NOT revoked(P)
```

where `remaining(P) = cap(P) − reserved(P) − captured(P)`. Four clauses, no discretion.

- **Positive amounts only.** The authority boundary accepts positive integers. Anything else is blocked and receipted.
- **Blocked attempts never reach PayPal.** The check runs before any provider call.
- **Expiry is checked twice:** once at check time and again at release time.
- **Capture is single-flight and idempotent.** The key `{permit_id}:{auth_id}:capture` goes out as `PayPal-Request-Id`, so a retried capture after a timeout cannot double-charge.
- **Delegation only subdivides.** A sub-permit cannot exceed the parent's remaining cap, add merchants beyond the parent's allowlist, or outlive the parent's expiry. The carved cap is reserved on the parent, so delegated budget cannot be double-spent. Captures roll up through every ancestor.
- **Approval thresholds only tighten.** You can set or lower them on a live permit, but never raise them. Approved spends are single-use.
- **Every decision writes a receipt** to a SHA-256 hash-chained claim ledger. `verify_chain()` runs before every capture (`settlement/verifier.py`).

## Quickstart

```bash
python -m pip install pytest
python -m pytest -q        # full suite: mock rail, no credentials, no network
python demo.py             # end-to-end mock demo, ends with the ledger chain check
```

More demos (in `demos/`; `trace.py` is the canonical evidence path —
it asserts the real gate and doubles as the run's evidence log):

```bash
python demos/demo_sla_escrow.py        # offline: agent-to-agent SLA escrow, acceptance-signed capture, forged signature refused
python server.py                 # the service at http://127.0.0.1:8741
python trace.py                  # with server.py running: allow, block, delegate, cascade revoke, chain check
python demos/demo_six_beat.py          # LLM agent: grant → capture → over-cap block → delegate + cascade → tampered evidence → timeout/reconcile
python demos/demo_delegation.py --fast # LLM agents: buyer and researcher, five beats, live dashboard
python demos/demo_approval.py --fast   # LLM agent: auto-allow, approve, deny, fail-closed
python demos/demo_admission.py         # offline: runaway loop refused at budget exhaustion, concurrent overspend cannot exceed cap
```

The three LLM demos call the runner set by `PERMIT_GROK_CLI`. There is no default: if it is unset, the demo exits 1 with a `RuntimeError` that names the fix. `demos/demo_six_beat.py` also takes `--replay <transcript>`, which replays the recorded reasoning and re-executes every recorded action against the live tools, fully offline. A live run records `demo_transcript.jsonl`. The file is gitignored, so a fresh clone has no transcript until you record one.

## How it fails

Permit fails closed. When state is uncertain, money does not move.

| Condition | Behavior |
|---|---|
| Release after expiry | Hold voided, reservation freed, no capture |
| Revocation or expiry while authorization is in flight | The operation is tracked before the external call. The hold is voided and the spend dies. Capture admission rechecks both immediately before money moves |
| E-stop | Revokes the permit and voids every in-flight authorization it can reach |
| Parent revoked | **Cascades:** every descendant is revoked, holds voided, unspent carves released up the chain |
| Approved spend whose budget moved | `complete_approved_spend()` re-runs the full check against the stored request and refuses it. Denied approvals never complete. Pending approvals expire (15 min default) |
| Capture call times out | The escrow goes **UNKNOWN**, never guessed. `reconcile()` re-queries PayPal and converges: CAPTURED if money moved, VOIDED (reservation freed) otherwise |
| Void fails | The escrow waits in **CLEANUP_PENDING** with the reservation held until `retry_cleanup()` confirms the void |
| Provider merchant, currency, or amount mismatch | The sandbox client binds `payee.merchant_id`, CAD, and amount to the operation and refuses a mismatch (`PERMIT_PAYPAL_MERCHANT_ID`) |
| Tampered delivery evidence | Release refused, hold voided |

**What it does not defend (production boundaries):**
- All authoritative state lives in memory. A restart loses permits, escrows, revocations, and the ledger.
- The HTTP service has no caller authentication (localhost demo boundary).
- The ledger is a hash chain, not a signature. It detects edits and reordering, but it cannot detect removal of final entries without an external checkpoint.
- It is a single-merchant sandbox prototype, not a claim about all agent payments.
- E-stop voids uncaptured authorizations. A completed capture needs a refund path, which is out of scope.

## The spend pipeline

```
check → reserve cap → PayPal AUTHORIZE hold → escrow registered
      → evidence in → predicate evaluated → idempotent capture
```

**Sandbox approval flow.** Each PayPal order needs interactive payer approval:

1. `POST /api/permits/<id>/spend`: the authority check reserves the cap, then the pipeline creates the order and tries to authorize. Before payer approval the service answers **202** with `{status: approval_required, operation_id, order_id, approval_url}`. The reservation, operation, and order stay held server-side.
2. The payer approves at `approval_url`. Permit confirms approval by polling the order's API state, never the checkout page.
3. `POST /api/operations/<operation_id>/resume` authorizes the **same** order (never a second one) and registers the escrow.
4. `POST /api/escrows/<id>/release` with delivery evidence: predicate check, then capture.
5. `POST /api/escrows/<id>/reconcile` or `/retry-cleanup`: the recovery paths above.

**Service verbs (JSON):** issue (`POST /api/permits`), delegate (`POST /api/permits/<id>/delegate`), tighten (`POST /api/permits/<id>/tighten`: narrows cap, merchants, expiry, or approval threshold, never widens), check (read-only: no reservation, no receipt), spend, resume, release, reconcile, retry cleanup, e-stop, revoke a subtree (`POST /api/permits/<id>/revoke-cascade`), and read the ledger (`GET /api/ledger`). Mock mode is the default. `--sandbox` arms the real PayPal sandbox rail (needs `PERMIT_PAYPAL_CLIENT_ID` / `PERMIT_PAYPAL_CLIENT_SECRET`).

**Actors:** the **payer** approves, the **merchant** delivers, the **Permit operator** issues permits and holds the e-stop, and the **credential owner** holds the PayPal secret. The agent never holds credentials.

**Lineage:** [Interlock](https://github.com/marsojuji-cmyk/interlock) is the conceptual origin of the leased-authority model. This repo's ledger is standalone.

## Evidence

- **212 tests pass:** `python -m pytest -q`, run 2026-10-12 on the M3 agent-loop branch (209 on main at 3632636 + 3 new). CI runs the same suite plus `python demo.py` on every push.
- **Mock end-to-end demo:** `python demo.py` ends with `ledger chain: VERIFIED (15 receipts)` (run 2026-10-07 at `dc0f3a5`).
- **Mock rail vs sandbox, kept separate:**
  - `demos/demo_six_beat.py` runs on the mock rail, with no PayPal network or credentials. Its agent still needs `PERMIT_GROK_CLI` or a recorded transcript.
  - The Oct 2 sandbox spike made real REST calls (OAuth, order, authorize, capture, void) against PayPal sandbox and verified merchant identity. Its report left the tree in `3f88feb`. Read it with `git show 3f88feb^:spike-report.md`.
  - `docs/sandbox-runbook.md` is the scripted procedure for an integrated six-beat sandbox run. That run is not yet recorded.

## Status

The project builds in the open toward the Nov 12, 2026 hackathon deadline.
- **Implemented and tested:** permit core, 4-clause authority gate, spend pipeline, release verifier with UNKNOWN → reconcile, PayPal sandbox client with merchant binding and idempotent capture, e-stop with in-flight handling, delegation with cascade revoke, principal approvals, the agent spender, and the six-beat mock demo.
- **Remaining:** the integrated sandbox run, the video (by Nov 8), and the Devpost package (by Nov 10).

## License

MIT. See [LICENSE](LICENSE).
