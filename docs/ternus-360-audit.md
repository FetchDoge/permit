# Permit 360-degree engineering audit — through the Ternus lens

**Date:** 2026-10-10. **Auditor:** Ektar. **Scope:** `permit/` (authority core),
`settlement/` (money path), `server.py` (HTTP surface), `agent/`, `dashboard/`.
**Method:** full read of the money path, lock-order analysis, API review.
Tests: 184 passed, 0 failed (2026-10-09).

## The lens

John Ternus became Apple CEO on September 1, 2026 after running Hardware
Engineering through the Intel-to-Apple-Silicon transition. The reported
shape of his engineering leadership: **own the whole stack** (silicon to
software, no seams), **function over form** (the pivot away from Ive-era
form-first), **a thousand no's** (surface area is the enemy), **tolerances
and fit-and-finish** (precision is the product), **platform thinking**
(build the substrate others stand on), and **security by architecture**.
The board's words: "relentless focus on creating great products."

Applied to Permit — a payment authority layer, where the product IS the
guarantee — the audit asks one question per element: *would this survive
being the silicon?*

## What Ternus would praise (keep)

- **The isolation boundary.** `permit/permit.py` never imports any PayPal
  client, enforced by an import test. Authority and settlement are
  separate dies on the same package. This is the single best architectural
  decision in the codebase.
- **Fail-closed as a reflex.** Every indeterminate state (timeout, broken
  chain, dead permit) resolves to refusal, never to optimism. The
  UNKNOWN/reconcile design is exactly right.
- **Receipted everything.** The hash-chained ledger is the product's
  memory. Ternus would call this the fit-and-finish.
- **Lock discipline is documented, not just present.** Lock-order notes
  at every nesting site (`delegate`, `_lineage_block_reason`,
  `release_carve`). Rare in any codebase.
- **Honest scoping.** The demo acceptance key is labeled NOT-FOR-PRODUCTION
  in the code. No fake production-readiness.

## Findings, ordered by ROI (points per effort)

### 1. `assert` used for control flow on trust boundaries — permit/permit.py:889,892,912,915,934,968,1003; settlement/sandbox_client.py:182,195,264,311,360

`settle_capture`, `settle_void`, `estop`, and `revoke_subtree` use `assert`
for unknown-permit / unknown-auth_id handling; `server.py` catches
`AssertionError` and maps it to 404. Python's `-O` flag strips all
asserts. Under `-O`, an e-stop for an unknown permit raises
`AttributeError` instead of returning 404, and `settle_*` proceed on
`None`. A security boundary that changes behavior under an interpreter
flag is not a boundary.

*Ternus principle: tolerances.* The guarantee must hold under every
build flag, not just the debug one.
*Fix:* replace each with an explicit exception (`UnknownPermit`,
`UnknownAuth`), map to 404/400 in the server. ~30 minutes, fully
test-covered already. **Do this first.**

### 2. `verify_chain()` is O(n^2) — permit/ledger.py:verify_chain

`if r.seq != receipts.index(r)` calls `list.index()` — O(n) — once per
receipt. The docstring says the settlement verifier calls this **before
every capture**. Every capture on a ledger with n receipts costs O(n^2).
At hackathon scale this is invisible; at hyperscale (a long-lived
authority ledger) it is the first thing that breaks.

*Ternus principle: fit-and-finish.* The slow path nobody profiles is
where quality dies.
*Fix:* iterate with `enumerate` and compare to `r.seq`. One line.
Add a perf regression test (10k receipts verifies in <1s). ~20 minutes.

### 3. The verifier holds its lock across network I/O — settlement/verifier.py:verify_and_capture

The entire capture path — admission recheck, chain verification,
`paypal.capture()`, `paypal.void()` — runs under `self._lock`. One slow
PayPal call stalls every other escrow operation on the verifier. The
authority plane should never block on the provider plane.

*Ternus principle: own the whole stack.* Apple designs so the slow
outside world never stalls the inside. The seam between "decide" and
"call the provider" must be explicit.
*Fix:* transition escrow state under the lock (AUTHORIZED -> CAPTURING),
release the lock for provider I/O, re-acquire to commit the outcome.
Medium effort; the state machine already exists (UNKNOWN/CLEANUP_PENDING
prove the team thinks this way). Worth doing before any load claims.

### 4. Everything is in-memory — permits, ledger, escrows, PENDING_OPS

A process restart erases the entire receipt chain, every permit, every
escrow, every pending operation. For a *payment authority layer* this is
the number-one hyperscale blocker: the guarantee "no spend without a
permit, no timeout without a receipt" does not survive a deploy.

*Ternus principle: own the whole stack, end to end.* Apple would not
ship a wallet that forgets.
*Fix:* SQLite-backed ledger (append-only table; the hash chain maps
1:1 to rows) plus permit snapshot/restore on startup. Stdlib ships
sqlite3 — no dependency change. This is the biggest single engineering
investment on this list and the one that most changes what Permit can
claim. Schedule it as its own milestone.

### 5. PENDING_OPS has no TTL — server.py

The payer-approval path (`ApprovalRequired`) holds a **real cap
reservation** with no expiry and no sweep. If the payer abandons the
browser flow, the reservation is held forever and the dict grows
without bound. The principal-approval path has `ttl_minutes=15`; the
payer path has nothing. Asymmetric by accident, not design.

*Ternus principle: function over form.* The happy path demos; the
abandoned path is the product.
*Fix:* TTL on pending operations (15 min, matching the principal path)
with a sweep that voids the hold and releases the reservation, receipted
as `OPERATION_EXPIRED`. Small, high-value.

### 6. No authentication on the HTTP API — server.py

Localhost-bound (correct), but any local process can issue permits,
spend, and e-stop. For a payment authority layer the threat model
should name this explicitly.

*Ternus principle: security by architecture.*
*Fix:* bearer token (env-provided) on all mutating routes; document the
localhost-only posture as the current threat model. ~1 hour.

### 7. Demo sprawl — six demo scripts + trace.py

`demo.py`, `demo_admission.py`, `demo_approval.py`, `demo_delegation.py`,
`demo_six_beat.py`, `demo_sla_escrow.py`, plus `trace.py`. Seven entry
points demonstrating overlapping beats. `trace.py` is the strongest
(it asserts against the real gate and doubles as evidence).

*Ternus principle: a thousand no's.* Every demo is surface area that
rots. One canonical path; the rest become beats inside it or get cut.
*Fix:* make `trace.py` the single runnable evidence path, fold unique
beats in, archive the rest. Mostly deletion — the cheapest kind of
quality.

### 8. `_find_check_receipt` is an O(n) scan — permit/flow.py

Linear scan of all receipts per `resume_operation`. Index ALLOWED
receipts by `auth_id` (dict maintained on append). Five minutes.

### 9. Dashboard reaches into privates — dashboard/server.py:state()

Reads `permits._permits` directly. Expose a read-only snapshot method
on `PermitStore` instead. Encapsulation is a tolerance.

### 10. No structured logging

`log_message` is silenced; the service prints. At hyperscale, the
receipt chain is the audit log but operators need the operational log:
JSON lines, levels, request ids. Small, unglamorous, load-bearing.

### 11. No packaging

No `pyproject.toml`; runs from a checkout. For the hackathon judges
and for agents that will embed Permit, ship a pip-installable package
with a version. Platform thinking: make the substrate easy to stand on.

### 12. Key management is honestly scoped out — and must be scoped back in

`DEMO_ACCEPTANCE_KEY` is hardcoded and labeled. The honesty is right;
the roadmap must exist: env-provided keys now, KMS/HSM story for
production. A payment authority layer cannot hyperscale on a demo key,
however well labeled.

### 13. `release_carve` parent underflow — permit/permit.py:release_carve

`parent.reserved_cents -= unspent` asserts `unspent >= 0` but never
checks `parent.reserved_cents >= unspent`. Add the guard (fail closed,
receipted). Ten minutes.

### 14. Unbounded request bodies — server.py:_read_json

`Content-Length` is trusted without a cap. Localhost-only mitigates;
cap at 1MB anyway. Five minutes.

## What was checked and cleared

- Lock ordering across `delegate` / `revoke_subtree` / spend path: no
  inversion found (ledger never calls back into the store).
- `check()`'s double evaluation (probe + under-lock re-check) is
  intentional and documented; the lock's view wins. Correct.
- `revoke_subtree` vs `delegate` race is documented with the caller's
  serialization contract. Honest.
- Idempotency keys are stable across retries (`permit:auth:capture`).
  Correct.
- Time is tz-aware everywhere; `tighten` rejects naive datetimes.
- Amount discipline (positive ints, bool excluded) is enforced at
  every boundary.

## The hyperscale roadmap (Ternus order)

1. **Correctness first** (1, 13, 14) — an afternoon. The guarantee must
   be exact before anything else.
2. **Performance honesty** (2, 8, 3) — the O(n^2) and the lock-across-
   network fixes before any load or scale claim.
3. **Durability** (4) — the milestone-sized one. SQLite ledger +
   restore. This is what turns Permit from a demo into infrastructure.
4. **Operability** (5, 6, 10) — TTLs, auth, logs. The abandoned paths
   and the threat model.
5. **Subtraction** (7) — one demo path.
6. **Platform** (11, 12, 9) — packaging, keys, clean read APIs.

*Function over form, then fit-and-finish, then the platform. In that
order, no exceptions — not even for the demo video.*
