# Understanding the test suite

The suite is 389 tests (1 skipped, 390 collected). The count is the factory output. The interesting part is turning one concrete failure into a repeatable, receipted gate.

## Hardest failure case: capture timeout (UNKNOWN)

The physical limit is simple: after a capture call times out, you do not know whether money moved. Guessing is the wrong architecture. Timeouts are UNKNOWN, never guessed. Reconcile against provider truth. A completed capture cannot be voided here.

This was the hardest to make repeatable because the test has to inject the timeout at the exact point (before or after the provider applied the change), keep the reservation held, write an UNKNOWN receipt, make zero further PayPal calls until reconcile, then converge correctly without double-capture or silent release.

### Walkthrough of one rejected request and its receipt

Setup (from `tests/test_reconcile.py`):
- Permit granted: cap 5000 cents, merchant_1, 1 hour expiry.
- Check allows 3000 cents. Auth id reserved.
- PayPal mock authorizes the hold.
- Escrow registered with delivery artifact hash.

Request:
```python
paypal.inject_capture_timeout = "before_apply"
result = verifier.verify_and_capture("esc_1", Evidence(delivered_bytes=artifact))
```

What happens:
- Capture times out before the provider applied anything.
- `result.released` is False, reason `unknown_after_timeout`.
- Escrow state becomes UNKNOWN.
- Reservation stays at 3000 cents. Captured stays 0.
- `paypal.capture_calls` is empty (request never reached the provider).
- A receipt is written:
  - event_type: UNKNOWN
  - payload reason: capture_timeout

Then reconcile:
```python
rec = verifier.reconcile("esc_1")
```
- Provider truth is still AUTHORIZED with no capture.
- Fail closed: void the hold, free the reservation, escrow VOIDED.
- No capture ever happened. Chain verifies.

The other half (timeout after_apply) records the CAPTURED outcome without a second capture call. Both paths are in the suite. Blocked attempts never reach PayPal. Every money or authority state change writes a receipt to the hash-chained ledger.

That is one test. The rest of the suite is the same pattern for every other refusal path (invalid amount, merchant not allowed, over remaining cap, revoked, expired, ancestor revoked, unconfirmed void that holds the cap until VOIDED is confirmed, cascade, tighten-only, etc.).

Run `python -m pytest -q` to see the full factory.
