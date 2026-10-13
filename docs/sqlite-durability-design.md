# SQLite durability design

**Source:** Grok architect draft (2026-10-10, $0.0565), grounded against
`permit/ledger.py` by Ektar. **Status:** design accepted; implementation
is the heavy build (builder crew).

## Problem

Everything is in-memory: permits, ledger, escrows, pending ops. A process
restart erases the receipt chain and all authority state. For a payment
authority layer, durability is the precondition for every hyperscale
claim.

## Schema (stdlib `sqlite3` only)

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA foreign_keys = ON;

CREATE TABLE receipts (
  seq        INTEGER PRIMARY KEY,   -- app-assigned, not AUTOINCREMENT
  prev_hash  TEXT    NOT NULL,
  event_type TEXT    NOT NULL,
  payload    TEXT    NOT NULL,      -- exact canonical JSON text that was hashed
  timestamp  TEXT    NOT NULL,      -- exact ISO string that was hashed
  hash       TEXT    NOT NULL UNIQUE
);
CREATE TRIGGER receipts_no_update BEFORE UPDATE ON receipts
BEGIN SELECT RAISE(ABORT, 'receipts append-only'); END;
CREATE TRIGGER receipts_no_delete BEFORE DELETE ON receipts
BEGIN SELECT RAISE(ABORT, 'receipts append-only'); END;
-- seq continuity + prev_hash link enforced at write time (genesis exempt)
CREATE TRIGGER receipts_link BEFORE INSERT ON receipts WHEN NEW.seq <> 0
BEGIN
  SELECT RAISE(ABORT, 'seq gap or prev_hash mismatch')
  WHERE NEW.prev_hash IS NOT (SELECT hash FROM receipts WHERE seq = NEW.seq - 1);
END;
```

SQLite core has no sha256 — hashing stays in the existing Python
canonicalizer (`ledger._canonical`).

## Ledger API mapping

Same public signatures as `Ledger`. Constructor takes a path
(`":memory:"` for tests — no zero-arg default). `append()`: take the
lock → `BEGIN IMMEDIATE` → re-read tip from DB → build the receipt with
the existing canonicalizer → single INSERT of all six columns including
the hash → `commit()` → only then accepted. `receipts()` serves from a
restore-loaded cache; `verify_chain()` contract unchanged
(`tuple[bool, str]`); `__len__` = `len(cache)`. Autocommit mode with
explicit transactions; one writer connection.

## Restore / verify sequence (startup)

1. Open, apply `synchronous=FULL`, confirm WAL.
2. `PRAGMA integrity_check` — anything but `ok` (incl. SQLITE_CORRUPT):
   raise, don't serve, don't write.
3. SELECT all rows ordered by seq.
4. `verify_chain()` over the rows — mismatch: raise, don't serve,
   don't delete/truncate.
5. Fold the verified rows into a fresh `PermitStore` (pure fold: no
   network, no clock, no new receipts).
6. Only then bind the serve path.

Torn writes: SQLite atomic commit means no half-rows; the single INSERT
prevents app-level tears. `journal_mode=OFF` / `synchronous=OFF` are
forbidden.

## Decided tradeoffs

1. **Exactly-once append across a crash:** `idempotency_key` inside the
   hashed payload + partial unique index over
   `json_extract(payload,'$.idempotency_key')`. On conflict, return the
   existing row and write nothing.
2. **PermitStore rebuild vs snapshot:** rebuild by folding the verified
   chain on every start. No persisted permit/escrow/pending-op tables.
   The incremental apply and the full replay MUST be the same code path
   (test: replay-from-empty comparison). If restore ever gets slow, the
   reversal is a checkpoint written as a chained receipt, folding forward
   from it — still one authority. External effects are excluded from the
   fold; replay must never resend.
3. **Fail closed vs truncate-and-serve:** refuse to serve on any
   failure. Recovery is an operator procedure, not an automatic one.

## Grounded facts (Ektar, from `permit/ledger.py`)

- Genesis: `seq=0`, `prev_hash="0"*64` (`GENESIS_HASH`).
- `Receipt.hash` = sha256 over canonical JSON
  (`sort_keys=True, separators=(",",":")`) of
  `{seq, prev_hash, event_type, payload, timestamp}`.
- `verify_chain()` returns `tuple[bool, str]`, never raises on a broken
  chain.
- The `_allowed_by_auth` index (auth_id → ALLOWED receipt) must be
  rebuilt from the restored rows.
- `Ledger.__len__` is used in boolean context in `permit.py`/`flow.py`
  (`ledger if ledger is not None`) — preserve the explicit-None-check
  pattern; do not rely on truthiness.

## Implementation contract (for the builder)

- New module `permit/sqlite_ledger.py`: `SqliteLedger` implementing the
  `Ledger` interface (append/receipts/verify_chain/__len__/allowed_receipt).
- `permit/ledger.py` keeps the in-memory `Ledger` (tests, demos).
- `server.py --db PATH` wires `SqliteLedger`; default stays in-memory
  (no behavior change unless the flag is passed).
- Tests: crash-consistency (kill -9 mid-append → chain verifies or
  refuses to serve), idempotent re-append, restore-fold equivalence
  (folded store == live store on permits/reserved/captured), 10k-receipt
  restore timing.
- Full suite green, including under `python -O`.
