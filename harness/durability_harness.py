"""
Offline crash-resume harness — subprocess fork/kill/reload runner.

Usage:
  python -m harness.durability_harness --kill-point K1 --work-dir /tmp/dur-XXX --verbose
  python -m harness.durability_harness --all --verbose
  python harness/durability_harness.py --all

All PayPal interactions via MockPayPalClient (no network, no secrets).
"""
from __future__ import annotations

import argparse
import hashlib
import os
import signal
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Ensure repo root on path
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from permit.durability import (
    DurableLedger,
    DurableMockPayPalClient,
    DurablePermitStore,
    DurableReleaseVerifier,
    DurableSpendPipeline,
)
from settlement.verifier import Evidence, PredicateType


def _build(durable_dir: Path):
    ledger = DurableLedger(durable_dir=durable_dir)
    permits = DurablePermitStore(ledger=ledger, durable_dir=durable_dir)
    paypal = DurableMockPayPalClient(durable_dir=durable_dir)
    verifier = DurableReleaseVerifier(paypal, permits, ledger=ledger, durable_dir=durable_dir, allow_demo_key=True)
    flow = DurableSpendPipeline(permits, paypal, verifier, ledger=ledger, durable_dir=durable_dir)
    return ledger, permits, paypal, verifier, flow


def _close_ledger(ledger) -> None:
    """Release the exclusive durable writer lock (required before reload/fork)."""
    close = getattr(ledger, "close", None)
    if callable(close):
        close()


def _grant(permits: DurablePermitStore):
    permit, _ = permits.grant(
        agent_id="durability_agent",
        cap_cents=5000,
        allowlist=["merchant_1"],
        expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    return permit


def _artifact():
    b = b"durability-deliverable"
    return b, hashlib.sha256(b).hexdigest()


KILL_POINTS = ("K1", "K2", "K3", "K4")


def _run_kill_point(kill_point: str, durable_dir: Path, verbose: bool = False) -> dict:
    """Run one kill-point scenario. Returns dict with PASS/FAIL per expectation."""
    import multiprocessing

    artifact, digest = _artifact()
    ledger, permits, paypal, verifier, flow = _build(durable_dir)
    permit = _grant(permits)
    permit_id = permit.permit_id
    # Release writer lock before fork/reload so the child (and the post-kill
    # fresh instances) can acquire exclusive ownership of durable_dir.
    _close_ledger(ledger)

    # Use multiprocessing with fork for SIGKILL
    ctx = multiprocessing.get_context("fork") if "fork" in multiprocessing.get_all_start_methods() else multiprocessing.get_context()

    # Sentinel files
    sentinel = durable_dir / f"sentinel_{kill_point}"
    if sentinel.exists():
        sentinel.unlink()

    # For K4, we need to drive to UNKNOWN via timeout then kill before reconcile
    # For all, child does spend with hooks that write sentinel at kill point

    def child_main(q, kill_point_inner, durable_dir_str):
        # Re-build inside child (same dir, but new objects)
        import pathlib
        d = pathlib.Path(durable_dir_str)
        from permit.durability import DurableLedger, DurablePermitStore, DurableMockPayPalClient, DurableReleaseVerifier, DurableSpendPipeline
        from settlement.verifier import PredicateType, Evidence
        import hashlib, time, sys
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]) if '__file__' in dir() else '.')
        ledger_c = DurableLedger(durable_dir=d)
        permits_c = DurablePermitStore(ledger=ledger_c, durable_dir=d)
        paypal_c = DurableMockPayPalClient(durable_dir=d)
        verifier_c = DurableReleaseVerifier(paypal_c, permits_c, ledger=ledger_c, durable_dir=d, allow_demo_key=True)
        flow_c = DurableSpendPipeline(permits_c, paypal_c, verifier_c, ledger=ledger_c, durable_dir=d)
        permit_c = permits_c.get(permit_id)
        if permit_c is None:
            # Permit not found — should not happen
            q.put(("error", "permit not found in child"))
            return
        # Monkey-patch at kill point
        original_authorize = paypal_c.authorize
        original_register = verifier_c.register
        original_verify = verifier_c.verify_and_capture

        sentinel_path = d / f"sentinel_{kill_point_inner}"

        if kill_point_inner == "K1":
            # K1: before authorize — after check reserves + _track but before authorize
            orig_track = flow_c._track_outstanding

            def patched_track(auth_id, pid):
                # Call original which persists
                orig_track(auth_id, pid)
                # Signal parent
                try:
                    sentinel_path.write_text(auth_id)
                    sentinel_path.parent.mkdir(parents=True, exist_ok=True)
                except Exception:
                    pass
                # Sleep so parent can SIGKILL before authorize
                time.sleep(60)

            flow_c._track_outstanding = patched_track
            try:
                flow_c.spend(permit_id, 3000, "merchant_1", PredicateType.D, digest, agent_id=flow_c.permits.get(permit_id).agent_id)
            except Exception as e:
                q.put(("error", f"K1 child exception: {e}"))
                return
            q.put(("done", "K1 child completed without kill"))

        elif kill_point_inner == "K2":
            def patched_authorize(amount_cents, merchant_id, idempotency_key=None):
                res = original_authorize(amount_cents, merchant_id, idempotency_key=idempotency_key)
                try:
                    sentinel_path.write_text(res.auth_id)
                except Exception:
                    pass
                time.sleep(60)
                return res

            paypal_c.authorize = patched_authorize
            try:
                flow_c.spend(permit_id, 3000, "merchant_1", PredicateType.D, digest, agent_id=flow_c.permits.get(permit_id).agent_id)
            except Exception as e:
                q.put(("error", f"K2 child exception: {e}"))
                return
            q.put(("done", "K2 child completed"))

        elif kill_point_inner == "K3":
            def patched_register(escrow):
                receipt = original_register(escrow)
                try:
                    sentinel_path.write_text(escrow.escrow_id)
                except Exception:
                    pass
                time.sleep(60)
                return receipt

            verifier_c.register = patched_register
            try:
                flow_c.spend(permit_id, 3000, "merchant_1", PredicateType.D, digest, agent_id=flow_c.permits.get(permit_id).agent_id)
            except Exception as e:
                q.put(("error", f"K3 child exception: {e}"))
                return
            q.put(("done", "K3 child completed"))

        elif kill_point_inner == "K4":
            # Drive to UNKNOWN then sentinel
            paypal_c.inject_capture_timeout = "after_apply"
            paypal_c._persist()
            attempt = flow_c.spend(permit_id, 3000, "merchant_1", PredicateType.D, digest, agent_id=flow_c.permits.get(permit_id).agent_id)
            escrow_id = attempt.escrow_id
            # Now trigger UNKNOWN via verify_and_capture
            try:
                result = flow_c.release(escrow_id, Evidence(delivered_bytes=artifact))
                # Should be unknown_after_timeout
                try:
                    sentinel_path.write_text(escrow_id + ":" + result.reason)
                except Exception:
                    pass
                time.sleep(60)
            except Exception as e:
                q.put(("error", f"K4 child exception: {e}"))
                return
            q.put(("done", "K4 child completed"))
        else:
            q.put(("error", f"unknown kill point {kill_point_inner}"))

    # Use a queue to get child status if it doesn't die
    q = ctx.Queue()
    p = ctx.Process(target=child_main, args=(q, kill_point, str(durable_dir)))
    p.start()

    # Wait for sentinel
    deadline = time.time() + 10
    while time.time() < deadline:
        if sentinel.exists():
            break
        if not p.is_alive():
            break
        time.sleep(0.05)

    if not sentinel.exists():
        # Child may have exited or failed
        try:
            msg = q.get_nowait()
        except Exception:
            msg = None
        if not p.is_alive():
            return {"kill_point": kill_point, "error": f"child exited before sentinel: {msg}", "pass": False}
        # Still no sentinel — force kill anyway after timeout
        if p.is_alive():
            try:
                p.kill()
            except Exception:
                try:
                    os.kill(p.pid, signal.SIGKILL)
                except Exception:
                    pass
            p.join(timeout=2)
        return {"kill_point": kill_point, "error": "sentinel not reached within 10s", "pass": False}

    # Sentinel reached — SIGKILL child before it can proceed
    pid = p.pid
    if p.is_alive():
        try:
            p.kill()
        except Exception:
            try:
                os.kill(pid, signal.SIGKILL)
            except Exception:
                pass
        p.join(timeout=5)
        # Ensure killed
        if p.is_alive():
            try:
                p.terminate()
            except Exception:
                pass
            p.join(timeout=2)

    time.sleep(0.2)  # let fs finish

    # Fresh process reload: new objects from same dir (lock free after kill).
    ledger2, permits2, paypal2, verifier2, flow2 = _build(durable_dir)
    permit2 = permits2.get(permit_id)

    result: dict = {"kill_point": kill_point, "pass": True, "details": []}

    def check(name: str, cond: bool, detail: str = ""):
        status = "PASS" if cond else "FAIL"
        result["details"].append(f"{name}: {status} {detail}".strip())
        if not cond:
            result["pass"] = False
        return cond

    # Common checks
    if permit2 is None:
        check("permit_exists", False, "permit missing after reload")
        return result

    ok, reason = ledger2.verify_chain()
    check("ledger_chain", ok, reason)

    # Retained reservation
    check("retained_reservation", permit2.reserved_cents == 3000, f"reserved={permit2.reserved_cents} expected 3000")
    check("remaining_cents", permit2.remaining_cents() == 2000, f"remaining={permit2.remaining_cents()}")
    check("in_flight_present", len(permit2.in_flight) == 1, f"in_flight={permit2.in_flight}")

    # Stable idempotency: auth_id from durable files should match sentinel or ledger
    auth_id = None
    if permit2.in_flight:
        auth_id = list(permit2.in_flight.keys())[0]
        check("stable_idempotency", auth_id.startswith("auth_"), f"auth_id={auth_id}")
        key = f"{permit_id}:{auth_id}:capture"
        # Check that key would be stable on second computation
        # Find escrow if exists, else compute from verifier
        escrow = None
        for e in verifier2._escrows.values():
            if e.auth_id == auth_id:
                escrow = e
                break
        if escrow is not None:
            computed_key = verifier2._capture_key(escrow)
            check("capture_key_stable", computed_key == key, f"key={computed_key}")
    else:
        # For K3/K4, in_flight may be empty because escrow registered and outstanding dropped
        # But permit should still have reserved via escrow
        # Actually after register, reserved stays via in_flight, but _auth_to_escrow holds mapping
        # Check via escrow state
        escrows = list(verifier2._escrows.values())
        if escrows:
            escrow = escrows[0]
            check("escrow_exists", True, f"escrow={escrow.escrow_id} state={escrow.state}")
            auth_id = escrow.auth_id
            check("stable_idempotency_escrow", auth_id.startswith("auth_"), f"auth_id={auth_id}")
            key = f"{permit_id}:{auth_id}:capture"
            computed_key = verifier2._capture_key(escrow)
            check("capture_key_stable", computed_key == key, f"key={computed_key}")
        else:
            check("in_flight_or_escrow", False, "neither in_flight nor escrow found")

    # No duplicate authorize
    authorize_calls = len(paypal2.authorize_calls)
    # After reload, we should have exactly 1 authorize for K2/K3/K4, 0 for K1 (since killed before authorize)
    if kill_point == "K1":
        check("no_duplicate_authorize", authorize_calls == 0, f"authorize_calls={authorize_calls} expected 0 for K1")
    else:
        check("no_duplicate_authorize", authorize_calls == 1, f"authorize_calls={authorize_calls} expected 1")

    # No duplicate capture
    capture_calls = len(paypal2.capture_calls)
    if kill_point in ("K1", "K2", "K3"):
        check("no_duplicate_capture", capture_calls == 0, f"capture_calls={capture_calls}")
    elif kill_point == "K4":
        # K4 had one capture that went UNKNOWN (after_apply records capture then times out)
        check("capture_recorded_once", capture_calls == 1, f"capture_calls={capture_calls} expected 1 for K4 UNKNOWN")
        captures = len(paypal2.captures)
        check("captures_dict_once", captures == 1, f"captures={captures}")

    # UNKNOWN -> reconcile path for K4
    if kill_point == "K4":
        escrows = list(verifier2._escrows.values())
        if escrows:
            escrow = escrows[0]
            check("unknown_state", escrow.state == "UNKNOWN", f"state={escrow.state} expected UNKNOWN")
            # Fresh reload reconcile should converge to CAPTURED without duplicate capture
            before_captures = len(paypal2.captures)
            before_calls = len(paypal2.capture_calls)
            reconciled = verifier2.reconcile(escrow.escrow_id)
            check("reconcile_resolved", reconciled.resolved, f"outcome={reconciled.outcome}")
            check("reconcile_captured", reconciled.outcome == "captured", f"outcome={reconciled.outcome}")
            # Reload paypal to verify no duplicate after reconcile
            paypal3 = DurableMockPayPalClient(durable_dir=durable_dir)
            check("no_duplicate_after_reconcile", len(paypal3.capture_calls) == before_calls, f"calls before={before_calls} after={len(paypal3.capture_calls)}")
            check("captures_still_one", len(paypal3.captures) == before_captures, f"captures={len(paypal3.captures)}")
            # Escrow should now be CAPTURED
            verifier3 = DurableReleaseVerifier(paypal3, permits2, ledger=ledger2, durable_dir=durable_dir, allow_demo_key=True)
            escrow3 = verifier3.get_escrow(escrow.escrow_id)
            if escrow3:
                check("escrow_captured_after_reconcile", escrow3.state == "CAPTURED", f"state={escrow3.state}")
            # Second reconcile should be idempotent
            second = verifier3.reconcile(escrow.escrow_id)
            check("second_reconcile_idempotent", not second.resolved and second.outcome == "already_resolved", f"outcome={second.outcome}")
        else:
            check("unknown_escrow_exists", False, "no escrow for K4")

    # Fresh process resume: verify we used new instances (trivially true) and chain ok
    check("fresh_reload_chain", ok, "fresh instances verified chain")

    if verbose:
        print(f"[{kill_point}] {'PASS' if result['pass'] else 'FAIL'}")
        for d in result["details"]:
            print(f"  {d}")

    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description="Permit durability crash-resume harness (offline mock)")
    ap.add_argument("--kill-point", choices=KILL_POINTS, help="single kill point")
    ap.add_argument("--all", action="store_true", help="run all kill points")
    ap.add_argument("--work-dir", help="durable dir (default: mktemp)")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)

    if not args.kill_point and not args.all:
        ap.error("specify --kill-point K1|K2|K3|K4 or --all")

    kill_points = KILL_POINTS if args.all else (args.kill_point,)

    work_dir = Path(args.work_dir).expanduser() if args.work_dir else Path(tempfile.mkdtemp(prefix="dur-"))
    work_dir.mkdir(parents=True, exist_ok=True)
    if args.verbose:
        print(f"work-dir: {work_dir}")
        print("OFFLINE MOCK ONLY: no network, no credentials")

    overall_pass = True
    for kp in kill_points:
        # Each kill point gets its own subdir to isolate
        sub = work_dir / kp
        sub.mkdir(parents=True, exist_ok=True)
        res = _run_kill_point(kp, sub, verbose=args.verbose or args.all)
        if not args.verbose and not args.all:
            # Single mode: print details
            print(f"[{kp}] {'PASS' if res['pass'] else 'FAIL'}")
            for d in res.get("details", []):
                print(f"  {d}")
            if res.get("error"):
                print(f"  error: {res['error']}")
        if args.all and not args.verbose:
            print(f"[{kp}] {'PASS' if res['pass'] else 'FAIL'}")
            for d in res.get("details", []):
                print(f"  {d}")
        if not res["pass"]:
            overall_pass = False
            if res.get("error"):
                print(f"  error: {res['error']}")

    if overall_pass:
        print("ALL KILL POINTS PASS — retained reservation, stable idempotency, no duplicate, UNKNOWN->reconcile, fresh reload")
        if args.all:
            print("LEDGER VERIFIED: crash-resume harness green")
        return 0
    else:
        print("HARNESS FAIL — see details above")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
