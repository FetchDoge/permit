"""Unconfirmed-void regression: cap stays held until VOIDED matches.

Coordinator fixture (f32e571): authorization succeeds, post-authorize
admission fails, provider void raises. Baseline releases the reservation.
These tests use the in-memory TinyPayPal stub and perform no network calls.
"""

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from permit.flow import ApprovalRequired
from tests.test_authority_layer import (
    NeedsPayerApproval,
    TinyPayPal,
    _permit_layer,
)


PRED = "delivery_hash"


def _auth_id_from(attempt):
    return attempt.receipts[0].payload["auth_id"]


def _revoking_authorize(flow, paypal, permit, provider_auth_id):
    """Authorize callback from the coordinator probe. Records pre-return cap."""
    observed = {}

    def authorize(amount_cents, merchant_id, *args, **kwargs):
        paypal.authorize_calls.append((amount_cents, merchant_id, kwargs))
        observed["reserved"] = permit.reserved_cents
        observed["remaining"] = permit.remaining_cents()
        observed["outstanding"] = {
            key: dict(value) for key, value in flow._outstanding.items()
        }
        permit.revoked = True
        return SimpleNamespace(auth_id=provider_auth_id, status="AUTHORIZED")

    paypal.authorize = authorize
    return observed


def _void_returning(paypal, result):
    def void(auth_id):
        paypal.void_calls.append(auth_id)
        if isinstance(result, BaseException):
            raise result
        if callable(result):
            return result(auth_id)
        return result

    paypal.void = void


def test_repro_unconfirmed_void_retains_cap_and_identity():
    """Failing fixture: TimeoutError on void must not release 3000 cents."""
    flow, paypal, _permits, permit = _permit_layer()
    observed = _revoking_authorize(flow, paypal, permit, "repro_external_hold")
    _void_returning(paypal, TimeoutError("offline unconfirmed void"))

    attempt = flow.spend(
        permit.permit_id, 3000, "merchant_1", "delivery_hash", "hash"
    )

    assert observed["reserved"] == 3000
    assert observed["remaining"] == 2000
    assert len(observed["outstanding"]) == 1
    assert attempt.reason == "revoked_during_auth"
    assert paypal.void_calls == ["repro_external_hold"]
    # Baseline f32e571 releases the cap here (reserved == 0, remaining == 5000).
    assert permit.reserved_cents == 3000
    assert permit.remaining_cents() == 2000
    auth_id = _auth_id_from(attempt)
    entry = flow._outstanding[auth_id]
    assert entry["paypal_auth_id"] == "repro_external_hold"
    assert entry.get("cleanup_pending") is True
    assert len(paypal.capture_calls) == 0


@pytest.mark.parametrize(
    "result",
    [
        TimeoutError("offline unconfirmed void"),
        RuntimeError("provider exploded"),
        None,
        SimpleNamespace(auth_id="other_hold", status="VOIDED"),
        SimpleNamespace(auth_id="repro_external_hold", status="PENDING"),
        SimpleNamespace(auth_id="repro_external_hold", status="CAPTURED"),
        SimpleNamespace(auth_id="repro_external_hold"),
    ],
)
def test_non_voided_responses_retain_cap(result):
    flow, paypal, _permits, permit = _permit_layer()
    _revoking_authorize(flow, paypal, permit, "repro_external_hold")
    _void_returning(paypal, result)

    attempt = flow.spend(permit.permit_id, 3000, "merchant_1", PRED, "hash")

    assert attempt.reason == "revoked_during_auth"
    assert permit.reserved_cents == 3000
    auth_id = _auth_id_from(attempt)
    assert flow._outstanding[auth_id]["paypal_auth_id"] == "repro_external_hold"
    assert paypal.authorize_calls and len(paypal.authorize_calls) == 1
    assert paypal.capture_calls == []


def test_matching_voided_releases_cap_once():
    flow, paypal, _permits, permit = _permit_layer()
    _revoking_authorize(flow, paypal, permit, "repro_external_hold")

    def void(auth_id):
        paypal.void_calls.append(auth_id)
        return SimpleNamespace(auth_id=auth_id, status="VOIDED")

    paypal.void = void
    attempt = flow.spend(permit.permit_id, 3000, "merchant_1", PRED, "hash")
    assert attempt.reason == "revoked_during_auth"
    assert permit.reserved_cents == 0
    assert permit.remaining_cents() == 5000
    assert flow._outstanding == {}
    assert paypal.void_calls == ["repro_external_hold"]


def test_retry_cleanup_same_identity_is_idempotent_after_success():
    flow, paypal, _permits, permit = _permit_layer()
    _revoking_authorize(flow, paypal, permit, "repro_external_hold")
    mode = {"fail": True}

    def void(auth_id):
        paypal.void_calls.append(auth_id)
        if mode["fail"]:
            raise TimeoutError("offline unconfirmed void")
        return SimpleNamespace(auth_id=auth_id, status="VOIDED")

    paypal.void = void
    attempt = flow.spend(permit.permit_id, 3000, "merchant_1", PRED, "hash")
    auth_id = _auth_id_from(attempt)
    assert permit.reserved_cents == 3000
    assert flow.retry_cleanup(auth_id) is False
    assert permit.reserved_cents == 3000
    assert paypal.void_calls == ["repro_external_hold", "repro_external_hold"]

    mode["fail"] = False
    authorizes = len(paypal.authorize_calls)
    assert flow.retry_cleanup(auth_id) is True
    assert permit.reserved_cents == 0
    assert paypal.void_calls == ["repro_external_hold"] * 3
    assert flow.retry_cleanup(auth_id) is True
    assert paypal.void_calls == ["repro_external_hold"] * 3
    assert len(paypal.authorize_calls) == authorizes
    assert paypal.capture_calls == []
    assert auth_id not in flow._outstanding


def test_resume_cleanup_pending_does_not_reauthorize():
    paypal = TinyPayPal()
    paypal.raise_on_authorize = NeedsPayerApproval("ord_1", "https://approve/1")
    flow, paypal, _permits, permit = _permit_layer(paypal=paypal)
    with pytest.raises(ApprovalRequired) as exc_info:
        flow.spend(permit.permit_id, 3000, "merchant_1", PRED, "hash")
    appr = exc_info.value
    order_calls = []
    mode = {"fail": True}

    def authorize_order(order_id, amount_cents, merchant_id):
        order_calls.append((order_id, amount_cents, merchant_id))
        return SimpleNamespace(auth_id="resume_hold", status="AUTHORIZED")

    def void(auth_id):
        paypal.void_calls.append(auth_id)
        if mode["fail"]:
            raise TimeoutError("offline unconfirmed void")
        return SimpleNamespace(auth_id=auth_id, status="VOIDED")

    paypal.authorize_order = authorize_order
    paypal.void = void
    permit.revoked = True

    first = flow.resume_operation(appr)
    assert first.reason == "revoked_during_auth"
    assert permit.reserved_cents == 3000
    assert order_calls == [("ord_1", 3000, "merchant_1")]
    assert flow._outstanding[appr.auth_id]["paypal_auth_id"] == "resume_hold"

    second = flow.resume_operation(appr)
    assert second.allowed is False
    assert second.reason == "cleanup_pending"
    assert order_calls == [("ord_1", 3000, "merchant_1")]
    assert paypal.void_calls == ["resume_hold", "resume_hold"]
    assert paypal.capture_calls == []

    mode["fail"] = False
    third = flow.resume_operation(appr)
    assert third.reason == "cleanup_confirmed"
    assert permit.reserved_cents == 0
    assert order_calls == [("ord_1", 3000, "merchant_1")]
    assert paypal.void_calls == ["resume_hold"] * 3

    fourth = flow.resume_operation(appr)
    assert fourth.reason == "cleanup_confirmed"
    assert appr.auth_id not in flow._outstanding
    assert order_calls == [("ord_1", 3000, "merchant_1")]
    assert paypal.void_calls == ["resume_hold"] * 3
    assert paypal.capture_calls == []


def test_register_escrow_rejection_tracks_identity_before_void():
    flow, paypal, permits, permit = _permit_layer()
    check = permits.check(permit.permit_id, 3000, "merchant_1")
    auth_id = check.receipt.payload["auth_id"]
    seen = {}

    def void(provider_auth_id):
        seen["during"] = {
            key: dict(value) for key, value in flow._outstanding.items()
        }
        paypal.void_calls.append(provider_auth_id)
        raise TimeoutError("offline unconfirmed void")

    paypal.void = void
    permit.revoked = True
    with pytest.raises(RuntimeError, match="revoked/expired during registration"):
        flow.register_escrow(
            permit_id=permit.permit_id,
            auth_id=auth_id,
            paypal_auth_id="pp_direct",
            amount_cents=3000,
            merchant_id="merchant_1",
            predicate_type=PRED,
            artifact_hash="hash",
        )
    assert auth_id in seen["during"]
    assert seen["during"][auth_id]["paypal_auth_id"] == "pp_direct"
    assert permit.reserved_cents == 3000
    assert flow._outstanding[auth_id]["paypal_auth_id"] == "pp_direct"
    assert flow._outstanding[auth_id].get("cleanup_pending") is True


def test_spend_does_not_drop_pending_entry_when_registration_rejects():
    flow, paypal, _permits, permit = _permit_layer()

    def void(auth_id):
        paypal.void_calls.append(auth_id)
        raise TimeoutError("offline unconfirmed void")

    paypal.void = void
    real_register = flow.register_escrow

    def revoke_then_register(*args, **kwargs):
        permit.revoked = True
        return real_register(*args, **kwargs)

    flow.register_escrow = revoke_then_register
    with pytest.raises(RuntimeError, match="revoked/expired during registration"):
        flow.spend(permit.permit_id, 3000, "merchant_1", PRED, "hash")
    assert permit.reserved_cents == 3000
    assert len(flow._outstanding) == 1
    entry = next(iter(flow._outstanding.values()))
    assert entry.get("cleanup_pending") is True
    assert entry.get("paypal_auth_id")
    assert paypal.capture_calls == []


def _track(flow, permit, auth_id, provider_auth_id=None):
    flow._track_outstanding(auth_id, permit.permit_id)
    if provider_auth_id is not None:
        flow._set_outstanding_paypal_auth(auth_id, provider_auth_id)


def test_estop_unconfirmed_outstanding_is_unresolved():
    flow, paypal, permits, permit = _permit_layer()
    check = permits.check(permit.permit_id, 3000, "merchant_1")
    auth_id = check.receipt.payload["auth_id"]
    _track(flow, permit, auth_id, "hold_unconfirmed")

    def void(provider_auth_id):
        paypal.void_calls.append(provider_auth_id)
        raise TimeoutError("offline unconfirmed void")

    paypal.void = void
    result = flow.estop(permit.permit_id)
    receipt, voided = result
    assert receipt.event_type == "E-STOP"
    assert voided == []
    assert auth_id in result.unresolved
    assert auth_id not in result.unknown_open
    assert permit.reserved_cents == 3000
    assert flow._outstanding[auth_id]["paypal_auth_id"] == "hold_unconfirmed"


def test_estop_unknown_provider_id_is_unresolved():
    flow, paypal, permits, permit = _permit_layer()
    check = permits.check(permit.permit_id, 3000, "merchant_1")
    auth_id = check.receipt.payload["auth_id"]
    _track(flow, permit, auth_id)

    result = flow.estop(permit.permit_id)
    receipt, voided = result
    assert receipt.event_type == "E-STOP"
    assert voided == []
    assert paypal.void_calls == []
    assert auth_id in result.unresolved
    assert auth_id not in result.unknown_open
    assert permit.reserved_cents == 3000
    assert auth_id in flow._outstanding
    assert "paypal_auth_id" not in flow._outstanding[auth_id]


def _registered(flow, paypal, permit):
    attempt = flow.spend(permit.permit_id, 3000, "merchant_1", PRED, "hash")
    escrow_id = attempt.escrow_id
    flow.verifier.get_escrow = lambda eid: flow.verifier.escrows.get(eid)
    return attempt, escrow_id


def test_estop_registered_cleanup_pending_is_unresolved_not_unknown():
    flow, paypal, _permits, permit = _permit_layer()
    _attempt, escrow_id = _registered(flow, paypal, permit)
    flow.verifier.escrows[escrow_id].state = "CLEANUP_PENDING"
    called = []

    def void(escrow_id):
        called.append(escrow_id)
        return True

    flow.verifier.void = void
    result = flow.estop(permit.permit_id)
    receipt, voided = result
    assert receipt.event_type == "E-STOP"
    assert called == []
    assert voided == []
    assert escrow_id in result.unresolved
    assert escrow_id not in result.unknown_open
    assert permit.reserved_cents == 3000


def test_estop_registered_void_false_while_reserved_is_unresolved():
    flow, paypal, _permits, permit = _permit_layer()
    _attempt, escrow_id = _registered(flow, paypal, permit)

    def void(_escrow_id):
        return False

    flow.verifier.void = void
    result = flow.estop(permit.permit_id)
    _receipt, voided = result
    assert voided == []
    assert escrow_id in result.unresolved
    assert escrow_id not in result.unknown_open
    assert permit.reserved_cents == 3000


def test_estop_registered_void_failure_is_unresolved():
    flow, paypal, _permits, permit = _permit_layer()
    _attempt, escrow_id = _registered(flow, paypal, permit)

    def void(_escrow_id):
        raise TimeoutError("registered cleanup failed")

    flow.verifier.void = void
    result = flow.estop(permit.permit_id)
    _receipt, voided = result
    assert voided == []
    assert escrow_id in result.unresolved
    assert result.unknown_open == []
    assert permit.reserved_cents == 3000


def test_estop_unknown_capture_stays_unknown_open():
    flow, paypal, _permits, permit = _permit_layer()
    _attempt, escrow_id = _registered(flow, paypal, permit)
    flow.verifier.escrows[escrow_id].state = "UNKNOWN"
    result = flow.estop(permit.permit_id)
    receipt, voided = result
    assert receipt.event_type == "E-STOP"
    assert voided == []
    assert result.unknown_open == [escrow_id]
    assert result.unresolved == []
    assert permit.reserved_cents == 3000
    assert paypal.void_calls == []
