# Permit — Integrated PayPal Sandbox Run Plan

## Objective

Produce one reproducible end-to-end demonstration proving that Permit’s authority gate, AI proposal flow, PayPal sandbox rail, evidence ledger, and emergency controls operate together.

## Golden Move 37

Run the smallest complete loop:

1. Grant a USD 50, 24-hour Permit.
2. AI proposes an eligible purchase.
3. Permit authorizes the proposal.
4. PayPal sandbox captures the payment.
5. Permit writes a hash-chained receipt.
6. A USD 75 attempt is blocked.
7. The Permit is revoked and a further attempt is blocked.

## Preconditions

- [ ] PayPal developer sandbox account available
- [ ] PayPal sandbox client ID and secret stored only in local environment variables
- [ ] Permit server starts successfully
- [ ] Dashboard starts successfully
- [ ] Existing test suite passes
- [ ] Mock rail remains available as a fallback

## Execution Steps

1. Start Permit in sandbox mode.
2. Create a Permit with principal, agent identity, approved scope, USD 50 cap, USD currency, 24-hour expiry, purchase operation, and evidence requirement enabled.
3. Submit a natural-language purchase intent to the agent.
4. Confirm the agent returns a structured proposal, not a direct payment instruction.
5. Confirm the four-clause gate passes: amount within remaining cap, merchant allowed, not expired, and not revoked.
6. Execute the approved PayPal sandbox capture using an idempotency key.
7. Confirm the capture result is recorded.
8. Confirm a hash-chained receipt is appended.
9. Submit a USD 75 proposal.
10. Confirm Permit blocks it before any PayPal call.
11. Revoke the Permit.
12. Submit another eligible proposal.
13. Confirm Permit blocks it and records the revocation denial.

## Required Artifacts

- [ ] Screenshot: active Permit details
- [ ] Screenshot: AI proposal
- [ ] Screenshot: authorization decision
- [ ] Screenshot: PayPal sandbox capture result
- [ ] Screenshot: receipt-ledger event
- [ ] Screenshot: over-cap block
- [ ] Screenshot: revoked-Permit block
- [ ] Screen recording: complete authorized flow
- [ ] Screen recording: block and revoke flow
- [ ] Saved receipt reference or sanitized demo output

## Pass Criteria

- [ ] No payment occurs without an active, unexpired, in-scope Permit
- [ ] The over-cap attempt never reaches PayPal
- [ ] The revoked-Permit attempt never reaches PayPal
- [ ] The same proposal cannot create duplicate captures
- [ ] The receipt chain verifies successfully
- [ ] Every authorization, block, capture, and revocation is visible in the evidence trail

## Fallback

If PayPal sandbox integration blocks progress, use the mock rail to preserve the policy, ledger, UI, and control demonstration. Clearly label the environment as `mock-rail` rather than `paypal-sandbox`.

## Honest Boundaries

This run demonstrates prototype capability in PayPal’s sandbox. It does not by itself establish production readiness for durability, role-based access, refund handling, ledger checkpointing, or full compliance.
