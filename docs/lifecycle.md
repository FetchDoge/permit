# Permit: lifecycle

Status: current for the tree on main at f9f8c9c5 (2026-10-23), plus
the M4 e-stop demo merged in PR #61. States below are the states the
code actually uses, in `permit/permit.py`, `permit/flow.py`, and
`settlement/verifier.py`. Receipt names are the event types written
to the ledger.

## A permit's life

1. Granted. `PermitStore.grant()` issues a permit with a cap in
   cents, a merchant allowlist, and an expiry. Receipt: GRANTED.
   Nothing about a granted permit can later be widened.
2. Optionally tightened. `tighten()` narrows the cap, the allowlist,
   or the expiry, for the permit and, by cascade, its descendants.
   Each descendant keeps the narrower of its own authority and the
   new bound. Receipt: TIGHTEN, carrying old to new values.
3. Optionally delegated. `delegate()` carves a sub-permit from the
   parent's remaining cap. The carve is reserved on the parent at
   delegation time. A delegation that would exceed the parent's
   remaining cap, escalate the allowlist, outlive the parent, or go
   too deep is refused with a reason and no sub-permit is created.
   Receipt on success: DELEGATED.
4. Used. Every spend attempt is evaluated, then allowed or blocked
   (next section). A permit is usable until it expires or is revoked;
   there is no separate active flag.
5. Expired. Once the effective expiry (the narrower of grant and
   tighten) passes, every attempt is blocked with reason `expired`
   or `tightened_expiry_passed`. Expiry is evaluated per attempt,
   not swept in the background.
6. Revoked or e-stopped. `estop()` revokes the permit and,
   in its cascade form, every descendant. In-flight holds across
   the subtree are voided and unspent carves are released.
   Receipts: E-STOP for the target permit, REVOKED_CASCADE for each
   descendant, plus VOIDED and CARVE_RELEASED where they apply.
   Revocation is
   final: a revoked permit has no un-revoke path, and attempts
   against it or any descendant are blocked with `revoked` or
   `ancestor_revoked`.
7. Settled accounting. Captures roll up the chain: reserved becomes
   captured on the permit and each ancestor. Voids release the
   reservation only when the provider confirms the void; an
   unconfirmed void stays pending cleanup rather than freeing cap
   on a guess (`retry_cleanup` is the retry path).

## A spend's life

1. Attempt. The agent asks to spend an amount at a merchant. An
   amount that is not a positive integer number of cents is blocked
   with reason `invalid_amount` before any permit lookup.
2. Evaluation. The four clauses are checked through the
   tighten-only min-gate (`_evaluate`): not revoked, not expired,
   merchant in the effective allowlist, amount within the remaining
   cap (cap minus reserved minus captured). Then the lineage is
   checked, so a revoked or expired ancestor blocks the attempt
   even when the permit itself looks clean.
3. Blocked. Exactly one BLOCKED receipt with the exact reason, zero
   PayPal calls, no reservation, no order. The attempt is over;
   retrying it is a new attempt and is evaluated fresh.
4. Allowed, cap reserved. Receipt: ALLOWED. The amount moves from
   free cap to reserved on this permit. From here, no other attempt
   can spend the same cents.
5. Approval, when required. Two distinct gates can pause a spend:
   - Principal approval above the permit's approval threshold:
     receipts APPROVAL_REQUESTED and APPROVAL_PENDING, decided by
     APPROVAL_DECIDED. An approval binds to the exact spend and is
     consumed atomically when used; a denied or expired approval
     ends the spend with the reservation released.
   - Payer approval on the PayPal rail: the order is created, the
     provider refuses authorize until the buyer approves, and the
     pipeline raises the approval-required state with the
     reservation held. Resuming authorizes the same order; a second
     order is never created for the same purchase.
6. Authorized. The provider authorization is registered as an
   escrow awaiting delivery evidence. Receipt: AUTHORIZED.
7. Released and captured. Delivery evidence is checked against the
   escrow's predicate. On a pass, capture runs idempotently and
   the receipts record CAPTURED once at the permit scope and once
   at the escrow scope (the audit rollup counts only the
   permit-scoped one, so money is never double-counted).
8. Voided instead. If the escrow is voided before capture, or an
   e-stop voids it, the hold is voided with the provider and the
   reservation is released once the void is confirmed.
   Receipt: VOIDED.
9. UNKNOWN and reconcile. If a capture call times out, the escrow
   goes UNKNOWN: not captured, not failed. `reconcile()` asks the
   provider for the truth and converges the ledger to CAPTURED
   (money moved) or VOIDED (hold released, reservation freed).

## An e-stop's race, in order

The e-stop is designed to win at whichever point it lands:

- Before the spend: the spend is blocked, reason `revoked`, zero
  rail calls.
- Inside authorize: the spend reports `revoked_during_auth`, the
  hold is voided, the reservation is released, and no escrow is
  created, so capture is unreachable.
- After authorize: the in-flight escrow is voided and a late
  delivery presented afterwards is refused.
- After capture: the e-stop cannot void a completed capture. That
  money needs a refund, outside this prototype's scope.

Proof: `tests/test_estop_race.py` covers all three winnable timings
as one claim, and `demos/demo_estop.py` shows the same beats.

## The ledger's life

Receipts are appended in order, each committing to the previous
receipt's hash, starting from a genesis hash of 64 zeros. The chain
is verified by recomputation (`verify_chain()`), not by trusting a
stored verdict. The in-memory ledger lives and dies with the
process. The SQLite ledger (`permit/sqlite_ledger.py`, used with
`server.py --db`) persists receipts and re-verifies the chain on
open. The audit summary (`permit/audit.py`) is a read-only rollup
derived from receipts at read time; it stores nothing of its own.

## What ends what

| Event | Ends | Receipt |
| --- | --- | --- |
| Expiry passes | Future attempts on that permit | (blocked attempts carry the reason) |
| Tighten | The wider bound it replaces | TIGHTEN |
| Revoke or e-stop | The permit, its descendants' usability, and in-flight holds | REVOKED_CASCADE, VOIDED |
| Capture | The escrow, as completed spend | CAPTURED |
| Confirmed void | The escrow, with cap freed | VOIDED |
| Reconcile | An UNKNOWN escrow, in either direction | CAPTURED or VOIDED |
| Approval denied or expired | That spend attempt | APPROVAL_DECIDED |
