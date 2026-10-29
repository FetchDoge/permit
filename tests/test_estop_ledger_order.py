"""
Regression: an e-stop that arrives while a capture is in flight must not be receipted
between the provider capture and its CAPTURED receipt.

#22 promised that an E-STOP receipt lands either before the release-time recheck
(capture refused) or after CAPTURED (permit.py estop_cascade docstring). The #24 lock
rework moved the CAPTURED commit out of settlement_gate, which reopened the window:
the ledger could read AUTHORIZED, E-STOP, CAPTURED. No money moves after the stop,
but the receipt order no longer proves it.

The interleaving is forced deterministically, with no sleeps:
  1. The release thread enters the gate and calls the provider capture.
  2. Inside the capture, an e-stop thread is started, and we wait until it is
     blocked on settlement_gate. So the e-stop arrived after the capture was sent.
  3. Before the capture commit (settle_capture) runs, the release thread waits for one of two things:
     (a) the E-STOP receipt was written (only possible if the gate was released
         before the commit, which is the bug), or
     (b) the release thread still owns the gate while the e-stop is blocked on it
         (the fixed behaviour).
Event waits carry a timeout only as a deadlock guard.
"""
import hashlib
import threading
from datetime import datetime, timedelta, timezone

from permit.flow import SpendPipeline
from permit.ledger import Ledger
from permit.permit import PermitStore
from settlement.paypal_client import MockPayPalClient
from settlement.verifier import Evidence, PredicateType, ReleaseVerifier

GUARD_S = 10


class ObservedGate:
    """RLock wrapper that reports ownership and when a would-be acquirer blocks."""

    def __init__(self):
        self._lock = threading.RLock()
        self.owner = None
        self.depth = 0
        self.blocked = {}  # thread name -> Event

    def acquire(self, blocking=True, timeout=-1):
        me = threading.current_thread().name
        if not self._lock.acquire(blocking=False):
            self.blocked.setdefault(me, threading.Event()).set()
            self._lock.acquire()
        self.owner, self.depth = me, self.depth + 1
        return True

    def release(self):
        self.depth -= 1
        if self.depth == 0:
            self.owner = None
        self._lock.release()

    def __enter__(self):
        return self.acquire()

    def __exit__(self, *exc):
        self.release()
        return False

    def wait_blocked(self, name):
        return self.blocked.setdefault(name, threading.Event()).wait(GUARD_S)


def _run(ledger_factory=Ledger):
    ledger = ledger_factory()
    permits = PermitStore(ledger=ledger)
    paypal = MockPayPalClient()
    verifier = ReleaseVerifier(paypal, permits, ledger=ledger)
    flow = SpendPipeline(permits, paypal, verifier, ledger=ledger)
    permit, _ = permits.grant(
        "agent", 10_000, ["m"], datetime.now(timezone.utc) + timedelta(hours=1)
    )
    data = b"artifact"
    attempt = flow.spend(
        permit.permit_id, 1_000, "m", PredicateType.D, hashlib.sha256(data).hexdigest(),
        agent_id=permit.agent_id,
    )
    assert attempt.allowed

    gate = ObservedGate()
    permits.settlement_gate = gate
    estop_receipted = threading.Event()
    out = {}

    real_append = ledger.append

    def append(event_type, payload):
        r = real_append(event_type, payload)
        if event_type == "E-STOP":
            estop_receipted.set()
        return r

    ledger.append = append

    # Hook the start of the capture commit (settle_capture appends the first CAPTURED).
    # It runs before any permit lock is taken, so waiting here cannot block estop_cascade.
    real_settle_capture = permits.settle_capture

    def settle_capture(permit_id, auth_id):
        if threading.current_thread().name == "release":
            fixed_shape = gate.owner == "release" and gate.blocked.get(
                "estop", threading.Event()).is_set()
            if not fixed_shape:
                assert estop_receipted.wait(GUARD_S), "neither ordering became possible"
        return real_settle_capture(permit_id, auth_id)

    permits.settle_capture = settle_capture

    def do_estop():
        out["estop"] = flow.estop(permit.permit_id)

    estop_thread = threading.Thread(target=do_estop, name="estop", daemon=True)
    real_capture = paypal.capture

    def capture(*args, **kwargs):
        result = real_capture(*args, **kwargs)
        estop_thread.start()
        assert gate.wait_blocked("estop"), "e-stop never reached the gate"
        return result

    paypal.capture = capture

    def do_release():
        out["release"] = flow.release(attempt.escrow_id, Evidence(delivered_bytes=data))

    release_thread = threading.Thread(target=do_release, name="release", daemon=True)
    release_thread.start()
    release_thread.join(GUARD_S)
    estop_thread.join(GUARD_S)
    assert not release_thread.is_alive() and not estop_thread.is_alive()
    return ledger, verifier, attempt.escrow_id, out


def test_estop_during_capture_is_receipted_after_captured():
    ledger, verifier, escrow_id, out = _run()
    events = [r.event_type for r in ledger.receipts()]
    assert out["release"].released is True          # capture was already sent: it stands
    assert verifier.get_escrow(escrow_id).state == "CAPTURED"
    # Ledger order: every CAPTURED precedes the E-STOP (the #22 guarantee).
    estop_seq = events.index("E-STOP")
    captured = [i for i, e in enumerate(events) if e == "CAPTURED"]
    assert captured and max(captured) < estop_seq, events
    # The stop report must not call a captured escrow unresolved or voided.
    report = out["estop"]
    assert escrow_id not in report.unresolved and escrow_id not in report.voided
