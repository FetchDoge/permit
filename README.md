# Permit

Permit is an in-memory prototype of a payment-authority layer for agents. A permit
sets a spending cap, merchant allowlist, and expiry; attempts are recorded in a
local hash-chained receipt ledger. This repository demonstrates the design with a
mock payment provider. It is not a production payment system.

## Install and run the offline CLI

Python 3.9 or newer is required. Build a local wheel, then install it into a
virtual environment without using an editable checkout:

```bash
python -m venv .venv-build
.venv-build/bin/python -m pip install build
.venv-build/bin/python -m build --wheel

python -m venv .venv-demo
.venv-demo/bin/python -m pip install dist/permit_authority_demo-0.1.0-py3-none-any.whl
.venv-demo/bin/permit --help
.venv-demo/bin/permit demo
.venv-demo/bin/permit demo-recovery
```

The same commands are available as `python -m permit demo` and
`python -m permit demo-recovery`.

Both installed demos are credential-free, headless, and use only in-memory mock
objects. They do not open sockets, start a server or dashboard, call an LLM or
payment API, write transcripts, or move real money.

- `permit demo` verifies a mock capture, an over-cap block that never reaches the
  mock provider, an e-stop that voids an in-flight mock authorization, and the
  receipt chain.
- `permit demo-recovery` deliberately drops a mock capture response, shows the
  escrow as `UNKNOWN`, reconciles it to `CAPTURED` from mock provider state, and
  verifies that no second mock capture was attempted.

The commands exit nonzero on invalid arguments or if a demonstrated invariant
does not hold. There is deliberately no installed `--sandbox` switch.

## Authority check

An attempt is eligible only when all four conditions hold:

```text
amount <= remaining cap
merchant is allowlisted
current time is before expiry
permit is not revoked
```

An allowed attempt reserves cap. A verified release moves the in-memory
reservation to captured state; a confirmed void releases it. Blocked attempts are
receipted without calling the configured provider object.

## Source-only programs

The root `demo.py` remains the original mock pipeline demonstration. It is not the
installed entry point.

`demo_six_beat.py`, `server.py`, `trace.py`, the dashboard, and the agent modules
are source-tree experiments and are intentionally excluded from the wheel. In
particular, the six-beat program can call an external LLM, starts a local dashboard
server, and writes a transcript; replay also requires an external transcript.
Those programs must not be described as network-free merely because their payment
rail is mocked.

The repository also contains a PayPal sandbox adapter and runbook. That integration
is unverified for this milestone and is not exercised by the installed CLI or its
tests. Do not supply credentials to the offline demos.

## Tested prototype behavior

The mock test suite exercises the four-clause authority gate, in-process cap
reservation, ledger verification, evidence predicates, e-stop handling, and
dropped-response reconciliation. Capture requests use a stable idempotency key in
one running process, and the mock provider records whether a duplicate request was
made. These tests establish simulated behavior only; they do not prove behavior of
a live payment provider.

Cleanup has an important unresolved boundary: if voiding an
authorized-but-unregistered provider hold fails, current flow paths can release the
permit's cap reservation before provider cleanup is confirmed. Operators therefore
must not interpret a released cap or an e-stop report as proof that every external
hold was cleaned up. Broader cleanup and convergence guarantees are not made.

## Explicit limitations

- All permits, reservations, escrows, provider mock state, and receipts live only
  in process memory. A restart loses them; there is no restart recovery.
- There is no caller authentication or hosted authorization boundary.
- There is no multi-process coordination or safety guarantee.
- There is no production safety or security guarantee and no live-rail validation.
- Captured payments are not refunded; refunds are out of scope.
- Provider cleanup may remain uncertain after a void failure, as described above.
- `UNKNOWN -> CAPTURED` in the recovery demo is same-process reconciliation against
  mock state, not durable crash recovery.

Durable storage, crash-safe recovery, concurrency across processes, and a complete
persistent payment state machine are deferred work.

## Development

```bash
python -m pytest -q
```

Tests use mocks and must not contact payment or LLM services. See
[CONTRIBUTING.md](CONTRIBUTING.md) for contribution notes and
[docs/sandbox-runbook.md](docs/sandbox-runbook.md) for the separate, unverified
sandbox procedure.

## License

MIT. See [LICENSE](LICENSE).
