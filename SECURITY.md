# Security Policy

## What this repository is

`permit` is a payment-authority scheme in which agents spend against permits rather than holding raw account access.

## Reporting a vulnerability

**Preferred: GitHub private vulnerability reporting.** Open the **Security** tab on this repository and
choose **Report a vulnerability**. That channel is private between you and the maintainer, requires no
email, and nothing is posted publicly. Private reporting is enabled on this repository.

If you cannot use that channel, open a **minimal public issue** stating only that you have a security
report and how to reach you. Please do **not** include exploit details, proof-of-concept code, or
affected-version specifics in a public issue.

## Scope

**In scope:** Any path where a permit can be replayed, reused beyond its scope, escalated to a descendant capability, or revoked-then-honoured; and any way a permit's recorded use can diverge from its actual use.

**Out of scope / stated plainly:** The scheme is a design and reference implementation. It has not been reviewed by a payment network or a financial auditor.

## What to expect

| Stage | Commitment |
|---|---|
| Acknowledgement of your report | within 7 days |
| Initial assessment and severity call | within 14 days |
| Fix, or an agreed public disclosure | coordinated with you |

You will be credited in the fix or advisory unless you ask to remain anonymous.

## What this policy does NOT offer

There is **no bug bounty**, and no monetary reward is offered or implied. This is an independent
research project maintained by one person. What it can offer is a fast, honest response and public
credit.

## Acceptance key + durable ledgers

- `PERMIT_ACCEPTANCE_KEY`, when set, is always used (including with `--db --allow-demo-key`).
  The value is taken as UTF-8 encoded bytes (nothing is decoded). Empty,
  whitespace-only, and wrong-length values (not exactly 32 bytes) refuse startup;
  the demo flag never papers over a bad configured key. The durable key file uses
  the same exact-32-byte rule.
- Every durable ledger binds an HMAC commitment of the acceptance key on first use
  (`ensure_acceptance_key_commitment` via `ReleaseVerifier`):
  - `SqliteLedger` (server `--db`)
  - `DurableLedger` (file-backed under `durable_dir`, including
    `harness/durability_harness.py`)
  Commitment is **required** unless the ledger is explicitly ephemeral (in-memory
  `Ledger`, `:memory:` SqliteLedger, or DurableLedger without `durable_dir`).
  File-backed SqliteLedger cannot opt out. Ledgers that need the commitment but
  lack `get_meta` / `set_meta` refuse startup (no silent skip).
  Only an **empty** store may bind a key for the first time; a nonempty store
  without a commitment refuses startup (no silent rebind). Concurrent first-boot
  binds atomically (`INSERT OR IGNORE`, then re-read and compare). Corrupt
  `meta.json` is refused (never treated as empty).
  **Rotating the acceptance key on an existing durable store refuses startup.**

### Upgrading from a pre-exact-32 key (e.g. commit `19b62ce`)

Databases bound with a key longer than 32 bytes (for example 64 hex characters from
`secrets.token_hex(32)`) are locked out after the exact-32 upgrade. Run the one-time
rebind with the OLD key and a new exact-32-byte key:

```bash
# OLD may be any non-empty length (e.g. 64 hex chars from token_hex(32)).
# NEW must be exactly 32 UTF-8 bytes (e.g. token_hex(16)).
printf '%s' "$OLD_LONG_KEY" > /tmp/old.key
python -c 'import secrets; open("/tmp/new.key","w").write(secrets.token_hex(16))'

python -m scripts.rebind_acceptance_key --db /path/to/ledger.db \
  --old-key-file /tmp/old.key --new-key-file /tmp/new.key

export PERMIT_ACCEPTANCE_KEY="$(cat /tmp/new.key)"
python server.py --db /path/to/ledger.db
```

The command checks the OLD key against the stored HMAC commitment and rebinds
atomically. A wrong OLD key is refused; the commitment is left unchanged.

## Related

- Our agent-systems threat posture and the method behind these reviews: see the `adversarial-seat`
  repository for the review method, and `hermes-refuse` for the fail-closed execution posture.
