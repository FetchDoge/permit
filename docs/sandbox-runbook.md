# Permit — sandbox runbook: integrated beat run on the real rail

Status: documented procedure. The automated, camera-ready beats (demos/demo_six_beat.py)
run in **mock mode** (mock PayPal rail: no PayPal network, no PayPal
credentials). The agent's reasoning is live (Grok CLI) unless
`--replay demo_transcript.jsonl` is used — that is the fully offline,
deterministic camera path. This document is
the scripted procedure for the integrated SANDBOX run: every beat executed against
PayPal's sandbox REST API with the same SpendPipeline and ReleaseVerifier the mock
beats use. Nothing about the authority logic changes between rails — only the
PayPalClient implementation.

## Prerequisites

- `PERMIT_PAYPAL_CLIENT_ID` / `PERMIT_PAYPAL_CLIENT_SECRET` in the environment
  (sandbox app "Permit Hackathon"; the secret is pasted transiently, never committed).
- `PERMIT_PAYPAL_MERCHANT_ID` — the sandbox merchant account the permit allowlist is
  bound to (spike-verified: the payee merchant_id on sandbox orders). The
  SandboxPayPalClient refuses to authorize any order whose provider-reported
  payee.merchant_id differs from this value (fail closed).
- A browser for the payer-approval step (sandbox buyer account
  sb-pynfz53124146@personal.example.com). Approval is confirmed by polling the
  order's API state — never by what the checkout page shows (2026-10-02 lesson:
  the page can stall visually while the order is already APPROVED server-side).
- The permit service: `python3 server.py --sandbox --port 8741`.

## The approval flow (what the service does)

1. `POST /api/permits` → grant a permit (cap, allowlist, expiry). Receipt GRANTED.
2. `POST /api/permits/<id>/spend` → authority check reserves the cap, then the
   pipeline creates the PayPal order and tries to authorize it. Because the payer
   hasn't approved yet, the service answers **202**:
   `{"status":"approval_required","operation_id","order_id","approval_url"}`.
   The reservation STAYS HELD — the operation, order, and reservation are retained
   server-side under the operation id. No second spend may be issued for the same
   purchase (that would double-reserve the cap).
3. Payer opens `approval_url` and approves in the browser.
4. `POST /api/operations/<operation_id>/resume` → the service re-polls the order
   to APPROVED, authorizes the SAME order (never a second one), and registers the
   escrow. Answers 200 with the escrow id.
5. `POST /api/escrows/<id>/release` with the delivery evidence → predicate check →
   idempotent capture (`PayPal-Request-Id` derived from the permit + claim id, so a
   retried capture after a timeout cannot double-charge).
6. If a capture call times out, the escrow goes UNKNOWN — never optimistically
   marked captured or failed. `reconcile()` re-queries PayPal by the authorization
   id and converges the ledger: CAPTURED (money moved — recorded as truth) or
   VOIDED (hold released, reservation freed, fail closed).
7. `POST /api/permits/<id>/estop` → revokes the permit and voids every in-flight
   authorization, including authorizations that completed while the e-stop was in
   flight. Completed captures are NOT voidable — they need a refund, which is
   outside this prototype's scope (stated boundary, not a silent gap).

## Integrated sandbox beat script

Run against the live service (`--sandbox`). Record the ledger (`GET /api/ledger`)
at the end — the receipt chain is the evidence.

- **Beat 1 — setup.** Grant a $50 permit: allowlist = [configured merchant],
  expiry 1 hour. Confirm `remaining_cents == 5000`.
- **Beat 2 — real purchase.** Spend $30 via the approval flow (steps 2–5 above).
  Deliver the real bytes, release, capture. Record the PayPal capture id from the
  CAPTURED receipt. Confirm the capture appears in the sandbox dashboard.
- **Beat 3 — blocked attempt.** Spend $60 (over remaining). Confirm BLOCKED,
  and confirm zero new PayPal authorizations (the rail is never touched).
- **Beat 4 — e-stop mid-hold.** New permit; spend $10 (approval flow through
  resume); before release, e-stop the permit. Confirm: permit revoked, the
  authorization voided (PayPal-confirmed, not just locally marked), release
  refused afterwards.
- **Beat 5 — tampered evidence.** Spend $15; submit wrong bytes; confirm REFUSED,
  no capture, hold voided, reservation released.
- **Beat 6 — dropped response.** Spend $25; on the capture call, simulate the
  timeout (or observe a real one). Confirm the escrow is UNKNOWN — the service
  does NOT claim success or failure. Run reconcile; confirm convergence to the
  PayPal truth (CAPTURED with the same capture id if the money moved, else VOIDED
  with the reservation freed) and exactly one capture on the rail.

## What this run does NOT prove (boundaries, stated plainly)

- All authoritative state is in memory: a restart loses permits, escrows,
  revocations, and the ledger. The hash chain detects tampering of retained
  entries but not deletion of the tail without an external checkpoint.
- The HTTP service has no caller authentication (localhost demo boundary).
- Single-merchant sandbox prototype: the merchant binding is configured, not
  discovered. This is a prototype of *a* payment authority layer, not a claim
  about all agent payments.
- Actors in the loop: the payer (approves), the merchant (delivers), the Permit
  operator (issues permits, holds the e-stop), the credential owner (holds the
  PayPal secret). The agent never holds credentials.
