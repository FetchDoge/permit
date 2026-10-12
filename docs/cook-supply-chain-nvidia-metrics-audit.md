# Cook Supply-Chain / NVIDIA-Metrics Audit

**Date:** 2026-10-10
**Lens:** Tim Cook's operations doctrine, applied to Permit as if it were a
supply chain. Scoreboard: NVIDIA-style corporate metrics, adapted.
**Status:** findings + executable improvements. Sourced baselines below;
every figure carries its source. Figures labeled `derived` are arithmetic,
not company-reported.

---

## 1. The lens

Cook's operating questions, stripped of mythology:

1. **Where is the single point of failure, and what is the plan for the
   day it fails?** Apple names single-source risk in its 10-K and manages
   it with money: $33.2B of vendor non-trade receivables (Apple buys
   components directly and consigns them to assemblers), $56.2B of
   manufacturing purchase obligations covering ~150 days of forecast.
2. **What is your inventory, and why is it not smaller?** Cook: inventory
   is "fundamentally evil," depreciates 1–2% per week, "manage it like
   you're in the dairy business." Apple runs ~10.7 days of supply
   (`derived` from FY2025 10-K: $5.7B inventory vs $221B cost of sales).
3. **Who owns the bottleneck?** Supply management sits in every
   significant Apple meeting; Cook personally runs the operational
   reviews.
4. **How do you know your supplier is telling the truth?** 893
   third-party supplier assessments in 2024; violations "occur from time
   to time" (Apple's own 10-K wording).
5. **What happens during a shortage?** Q4 FY2021: ~$6B of supply
   constraints; the 10-K warns semiconductor shortages "could occur in
   the future."

NVIDIA is the scoreboard: a company that reports its concentration
honestly (Data Center ~90% of revenue) and is judged on margins,
inventory discipline, and R&D intensity. FY2026 10-K (filed Feb 25,
2026): revenue $215.9B (+65%), gross margin 71.1%, operating margin
60.4%, R&D $18.5B (+43%), inventories $21.4B (more than doubled year
over year). Q2 FY27: revenue $96.2B (+106%), gross margin 75.0%,
operating margin 66.2%.

The uncomfortable NVIDIA datum for this audit: inventories grew **112%**
YoY in FY2026 while revenue grew 65%. Inventory growing faster than
throughput is exactly the trend Cook's doctrine flags.

---

## 2. Findings — supply-chain resilience

### F1. Single-source settlement: 100% PayPal, no second rail

**Cook principle:** single-sourcing a custom component is acceptable;
single-sourcing it *without a plan* is not. Apple dual-sources where
possible (five NAND suppliers, 2005) and pre-funds capacity where it
cannot.

**Permit reality:** PayPal is the sole settlement rail. There is a
provider seam (`MockPayPalClient` / `SandboxPayPalClient`), but it is a
mode switch, not a supplier switch. If the PayPal API is down, slow, or
returns ambiguous outcomes, every escrow operation degrades to
fail-closed UNKNOWN — correct, but there is no degraded mode, no
second rail, no queued-and-forwarded settlement.

**Executable:**
- Define the provider interface as a *supplier* contract (methods:
  authorize, capture, void, query-truth), with the explicit requirement
  that a second implementation can be added without touching
  `ReleaseVerifier`.
- Instrument provider failure rate, latency distribution, and timeout
  rate per method (the JSON logging landed 2026-10-10 makes this
  feasible; it is not yet emitted for provider calls).
- Set an SLO: ambiguous-outcome (UNKNOWN) rate per 1,000 captures.

### F2. Inventory: unsettled exposure is the stock on the shelves

**Cook principle:** ~10.7 days of supply; every unit of inventory is
depreciation risk.

**Permit reality:** the "inventory" is money in ambiguous states:
AUTHORIZED-but-uncaptured holds, UNKNOWN escrows (capture may or may
not have applied), CLEANUP_PENDING (void unconfirmed), and
payer-approval operations awaiting a human. The 15-minute TTL on
`PENDING_OPS` (landed 2026-10-10) is exactly Cook-style inventory
reduction: freshness date enforced, expired stock reaped.

**Executable:**
- Track **in-flight exposure**: sum of `reserved_cents` across permits
  plus amounts in UNKNOWN/CLEANUP_PENDING escrows. Report it as a
  single number on the dashboard (read APIs exist: `permits_snapshot`,
  `escrows_snapshot`).
- Track **UNKNOWN aging**: time from UNKNOWN-state entry to
  `reconcile()` resolution. Cook would ask for the distribution, not
  the average. SLO: 95% reconciled within N minutes (N set by operator).
- `reconcile()` is operator-initiated today. Add a cadence: automatic
  reconcile sweep for UNKNOWN escrows older than the SLO, reusing the
  existing 60-second sweeper pattern.

### F3. Bottleneck ownership: the verifier lock is fixed; the next two are external

**Cook principle:** the bottleneck has a named owner and a review
cadence.

**Permit reality:** the internal bottleneck (verifier lock held across
PayPal I/O) was reworked 2026-10-10 into three phases: decide under
lock, I/O with lock released, commit under lock. The remaining
bottlenecks are external: (a) PayPal API latency, (b) human
payer-approval latency.

**Executable:**
- Emit per-phase timing for verify_and_capture (decide_ms,
  provider_io_ms, commit_ms) in the JSON log. The bottleneck you cannot
  see is the one you cannot own.
- Payer-approval latency: histogram of approval-to-decision time; the
  15-minute TTL bounds the tail, but the median tells you whether the
  human is the bottleneck.

### F4. Supplier truth: reconcile is the audit program; it needs a cadence

**Cook principle:** 893 supplier assessments; trust but verify, on a
schedule.

**Permit reality:** `reconcile()` queries provider truth for UNKNOWN
escrows — the equivalent of a supplier audit. But it runs only when an
operator invokes it. A supplier audit program that runs "whenever
someone remembers" is not a program.

**Executable:**
- Automatic reconcile sweep on a cadence (suggest 5 minutes for UNKNOWN
  escrows; CLEANUP_PENDING via existing `retry_cleanup`).
- Metric: **provider-truth divergence rate** — fraction of reconciles
  where provider truth differed from local state. Non-zero is expected
  ("violations occur from time to time"); trending up is the signal.

### F5. Capacity reservation: none exists

**Cook principle:** $56.2B of purchase obligations; $1.25B prepaid to
lock NAND supply through 2010.

**Permit reality:** no capacity planning against the PayPal API (rate
limits, quotas). The per-permit concurrent cap (M4, #20) is capacity
control on the *demand* side; nothing guards the *supply* side.

**Executable:**
- Track PayPal API call rate vs known quota; alert at 70%.
- Document the degraded behavior at quota exhaustion (today: fail
  closed with timeout semantics — verify this is actually what happens
  rather than an unhandled exception; add a test).

---

## 3. NVIDIA-style metrics, adapted for Permit

Every NVIDIA figure below is company-reported (FY2026 10-K filed Feb
25, 2026, or the cited earnings release). Every Permit figure is an
*adaptation* — same discipline, different domain. Do not mix the two
columns.

| # | NVIDIA (reported) | Permit adaptation | How to measure |
|---|---|---|---|
| M1 | Data Center ~90% of revenue (concentration disclosed) | **Provider concentration: 100% PayPal** | Count of settlement rails in production. Target: 2. |
| M2 | Gross margin 71.1% (FY26) → 75.0% (Q2 FY27) | **Authorization efficiency:** % of permitted volume settling cleanly (CAPTURED) vs blocked/refused/voided | Receipt-chain fold over a window: CAPTURED / (ALLOWED) |
| M3 | Operating margin 60.4% → 66.2% | **Cost per permitted transaction:** compute + provider fees per settled dollar | JSON log timings + fee schedule; report per 1,000 transactions |
| M4 | R&D $18.5B, +43% YoY | **Reliability investment ratio:** engineering effort on correctness/durability vs features | Qualitative per milestone; the SQLite + lock-rework batch is the current data point |
| M5 | Inventories $21.4B, +112% YoY vs revenue +65% | **Exposure growth vs throughput growth:** is in-flight exposure growing faster than settled volume? | F2 exposure metric, trended weekly |
| M6 | Cash + marketables $62.6B → $99.4B | **Reserve headroom:** unreserved permit capacity vs total caps | `permits_snapshot`: sum(cap − reserved − captured) / sum(cap) |
| M7 | Q3 FY27 guide: $108B ±2% (guidance as discipline) | **SLOs published per metric** (F1–F5): UNKNOWN rate, reconcile latency, exposure ceiling | Dashboard; review cadence Friday 9am (existing milestone review) |

The single most Cook-like number in the table is **M5**: if exposure
grows faster than throughput, the operation is accumulating risk while
calling it growth. NVIDIA gets asked about exactly this on every
earnings call.

---

## 4. Priority order (Cook-style: what gets fixed first)

1. **F2 exposure metric + dashboard number** — you cannot manage what
   you do not count. Half a day; uses existing snapshot APIs.
2. **F4 reconcile cadence** — the audit program must run on a schedule.
   Reuses the sweeper pattern; small.
3. **F1 provider instrumentation** (latency/failure/timeout per method)
   — prerequisite to every other supply-chain claim.
4. **F5 quota guard** — one test + one alert; cheap insurance.
5. **M1 second rail** — the strategic item. Interface definition first
   (no code against PayPal until the contract exists); implementation
   after the hackathon.

---

## Sources

- Apple Inc. Form 10-K, FY ended Sep 27, 2025 (SEC EDGAR, read live
  2026-10-11)
- NVIDIA FY2026 10-K (filed Feb 25, 2026); Q1 FY27 and Q2 FY27 earnings
  releases (NVIDIA newsroom / investor.nvidia.com, read live 2026-10-11)
- Fortune profile of Tim Cook (2008), via secondary quotation;
  supplychaindigital.com; EE Times on Lashinsky's *Inside Apple*
- Apple Q4 FY2021 earnings call transcript (Motley Fool)
- Full research notes: `~/workspace/research_notes/cook-supply-chain-nvidia-metrics-20261011-0248/`

*Inventory turns (~10.7 days Apple, ~92 days NVIDIA FY26) are derived
arithmetic, not company-reported. TSMC share, "two suppliers per
component," and the Cook quotations are press/secondary, flagged as
such in the research notes.*
