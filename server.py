#!/usr/bin/env python3
"""
Permit service: a minimal HTTP server exposing the core verbs.

    issue permit      POST /api/permits            {agent_id, cap_cents, allowlist, expiry_hours}
    permit state      GET  /api/permits/<permit_id>
    check authority   POST /api/permits/<permit_id>/check   {amount_cents, merchant_id}
                      (read-only: reserves nothing, writes no receipt)
    spend (allowed)   POST /api/permits/<permit_id>/spend   {amount_cents, merchant_id, predicate, artifact_hash}
                      sandbox mode may answer 202 approval_required with
                      {operation_id, order_id, approval_url}; the reservation
                      stays held and the SAME order is resumed via:
    resume approval   POST /api/operations/<operation_id>/resume   {}
    release escrow    POST /api/escrows/<escrow_id>/release {delivered_bytes_b64} | {acceptance_signature}
    reconcile unknown POST /api/escrows/<escrow_id>/reconcile   {}
    retry cleanup     POST /api/escrows/<escrow_id>/retry-cleanup {}
    e-stop            POST /api/permits/<permit_id>/estop   {}
                      revokes the permit and every descendant (cascade);
                      voids in-flight holds across the subtree
    delegate permit   POST /api/permits/<permit_id>/delegate  {agent_id, cap_cents, allowlist, expiry_hours}
                      carves a sub-permit from the parent's remaining cap
    revoke cascade    POST /api/permits/<permit_id>/revoke-cascade  {}
                      revokes the permit and every descendant, voids
                      in-flight holds across the subtree, releases
                      unspent carves post-order
    ledger            GET  /api/ledger
    debug (mock only) GET  /debug/paypal -> mock call counts

Runs in mock mode by default (no network, no credentials). --sandbox wires
the real SandboxPayPalClient against PayPal's sandbox REST API; it needs
PERMIT_PAYPAL_CLIENT_ID and PERMIT_PAYPAL_CLIENT_SECRET, and each order
still needs interactive payer approval (NeedsPayerApproval) — so scripted
camera runs stay in mock mode.

Stdlib only. JSON in, JSON out.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from permit.flow import ApprovalRequired, SpendPipeline
from permit.ledger import Ledger
from permit.permit import PermitStore, UnknownAuthId, UnknownPermit
from settlement.paypal_client import MockPayPalClient
from settlement.verifier import (
    Evidence,
    PredicateType,
    ReleaseVerifier,
)

# ---------------------------------------------------------------- state

ledger = Ledger()
permits = PermitStore(ledger=ledger)
paypal = None          # set in main()
verifier = None        # set in main()
flow = None            # set in main()
MOCK_MODE = True

# Approval-continuation registry: operation_id -> ApprovalRequired.
# Retains the operation, the PayPal order, and the cap reservation
# (the reservation stays held from the original spend's check()).
# Resume re-authorizes the SAME order — never a second one.
import threading
import uuid as _uuid

PENDING_OPS: dict[str, ApprovalRequired] = {}
PENDING_OPS_LOCK = threading.Lock()
# operation_id -> monotonic timestamp of retention. A payer-approval
# operation holds a REAL cap reservation; without a TTL an abandoned
# browser flow would hold it forever. 15 minutes, matching the
# principal-approval path's ttl_minutes.
_PENDING_META: dict[str, float] = {}
_PENDING_OPS_TTL_S = 15 * 60


def _pending_put(operation_id: str, appr: ApprovalRequired) -> None:
    """Retain an operation with its retention timestamp (under lock)."""
    with PENDING_OPS_LOCK:
        PENDING_OPS[operation_id] = appr
        _PENDING_META[operation_id] = time.monotonic()


def _pending_expired(operation_id: str) -> bool:
    """True when the operation is missing or past its TTL (fail closed)."""
    with PENDING_OPS_LOCK:
        if operation_id not in PENDING_OPS:
            return True
        return time.monotonic() - _PENDING_META.get(operation_id, 0) > _PENDING_OPS_TTL_S


def sweep_expired_pending() -> int:
    """
    Reap TTL-expired payer-approval operations: void the PayPal hold
    best-effort, release the cap reservation, receipt the expiry.
    Returns the number of operations reaped.
    """
    cutoff = time.monotonic() - _PENDING_OPS_TTL_S
    expired: list[tuple[str, ApprovalRequired]] = []
    with PENDING_OPS_LOCK:
        for oid in [o for o, ts in _PENDING_META.items() if ts <= cutoff]:
            appr = PENDING_OPS.pop(oid, None)
            _PENDING_META.pop(oid, None)
            if appr is not None:
                expired.append((oid, appr))
    for oid, appr in expired:
        try:
            paypal.void(appr.order_id)
        except Exception:
            pass  # best-effort; the order expires provider-side anyway
        try:
            permits.settle_void(appr.permit_id, appr.auth_id)
        except (UnknownPermit, UnknownAuthId):
            pass  # reservation already gone; still receipt the expiry
        ledger.append(
            "OPERATION_EXPIRED",
            {
                "operation_id": oid,
                "permit_id": appr.permit_id,
                "auth_id": appr.auth_id,
                "order_id": appr.order_id,
                "amount_cents": appr.amount_cents,
                "merchant_id": appr.merchant_id,
                "reason": "payer_approval_ttl_expired",
            },
        )
    return len(expired)


def _sweeper() -> None:
    """Background reaper for expired pending operations (daemon)."""
    while True:
        time.sleep(60)
        try:
            sweep_expired_pending()
        except Exception:
            pass


def _authorized(handler: BaseHTTPRequestHandler) -> bool:
    """
    Bearer-token gate for mutating routes. Fail closed: when
    PERMIT_API_TOKEN is unset, every mutating call is denied — an
    unauthenticated payment authority is not a payment authority.
    """
    token = os.environ.get("PERMIT_API_TOKEN", "")
    auth = handler.headers.get("Authorization", "")
    if not token or not auth.startswith("Bearer "):
        return False
    presented = auth[len("Bearer "):].strip()
    if not presented:
        return False
    return hmac.compare_digest(presented, token)


# ---------------------------------------------------------------- logging

import logging


class _JsonFormatter(logging.Formatter):
    """Single-line JSON per record: the operational log."""

    def format(self, record: logging.LogRecord) -> str:
        return json.dumps({
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname.lower(),
            "component": "permit-server",
            "msg": record.getMessage(),
        })


def _configure_logging() -> logging.Logger:
    handler = logging.StreamHandler()
    handler.setFormatter(_JsonFormatter())
    log = logging.getLogger("permit")
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    log.propagate = False
    return log


log = _configure_logging()


def receipt_summary(r):
    return {"seq": r.seq, "event": r.event_type, "hash": r.hash[:12], "payload": r.payload}


# ---------------------------------------------------------------- handler

class Handler(BaseHTTPRequestHandler):
    server_version = "Permit/0.1"

    # -- plumbing ----------------------------------------------------
    def _read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    def _send(self, code, obj):
        body = json.dumps(obj, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, code, message):
        self._send(code, {"error": message})

    def log_message(self, fmt, *args):  # keep server logs quiet-ish
        pass

    # -- routing -----------------------------------------------------
    def do_GET(self):
        m = re.fullmatch(r"/api/permits/([\w-]+)", self.path)
        if m:
            p = permits.get(m.group(1))
            if p is None:
                return self._error(404, "unknown_permit")
            return self._send(200, {
                "permit_id": p.permit_id,
                "agent_id": p.agent_id,
                "cap_cents": p.cap_cents,
                "allowlist": list(p.allowlist),
                "expiry": p.expiry.isoformat(),
                "revoked": p.revoked,
                "reserved_cents": p.reserved_cents,
                "captured_cents": p.captured_cents,
                "remaining_cents": p.remaining_cents(),
                "in_flight": len(p.in_flight),
                "parent_id": p.parent_id,
                # Advisory only (Sol 6.1): never an authority clause.
                "calibration_tau": p.calibration_tau,
            })
        if self.path == "/api/ledger":
            ok, reason = ledger.verify_chain()
            return self._send(200, {
                "chain": {"ok": ok, "reason": reason},
                "receipts": [receipt_summary(r) for r in ledger.receipts()],
            })
        if self.path == "/debug/paypal":
            if not MOCK_MODE:
                return self._error(404, "debug only available in mock mode")
            return self._send(200, {
                "authorizations": len(paypal.authorizations),
                "captures": len(paypal.captures),
                "voids": len(paypal.voids),
            })
        return self._error(404, "not_found")

    def do_POST(self):
        # Every mutating route requires the bearer token. No classifier,
        # no exceptions: a single gate means no route is forgotten.
        if not _authorized(self):
            return self._error(401, "unauthorized: bearer token required")
        body = self._read_json()

        # issue permit
        if self.path == "/api/permits":
            try:
                agent_id = body["agent_id"]
                cap_cents = int(body["cap_cents"])
                allowlist = list(body["allowlist"])
                hours = float(body.get("expiry_hours", 1))
            except (KeyError, TypeError, ValueError):
                return self._error(400, "need agent_id, cap_cents, allowlist, expiry_hours")
            permit, receipt = permits.grant(
                agent_id=agent_id,
                cap_cents=cap_cents,
                allowlist=allowlist,
                expiry=datetime.now(timezone.utc) + timedelta(hours=hours),
            )
            return self._send(201, {"permit_id": permit.permit_id, "receipt": receipt_summary(receipt)})

        m = re.fullmatch(r"/api/permits/([\w-]+)/delegate", self.path)
        if m:
            try:
                agent_id = body["agent_id"]
                cap_cents = int(body["cap_cents"])
                allowlist = list(body["allowlist"])
                hours = float(body.get("expiry_hours", 1))
            except (KeyError, TypeError, ValueError):
                return self._error(400, "need agent_id, cap_cents, allowlist, expiry_hours")
            res = permits.delegate(
                m.group(1), agent_id, cap_cents, allowlist,
                expiry=datetime.now(timezone.utc) + timedelta(hours=hours),
            )
            if not res.ok:
                if res.reason == "unknown_parent":
                    return self._error(404, "unknown_parent")
                return self._error(400, res.reason)
            return self._send(201, {
                "permit_id": res.permit.permit_id,
                "parent_id": res.permit.parent_id,
                "receipt": receipt_summary(res.receipt),
            })

        m = re.fullmatch(r"/api/permits/([\w-]+)/check", self.path)
        if m:
            try:
                raw_amount = body["amount_cents"]; merchant = body["merchant_id"]
            except (KeyError, TypeError):
                return self._error(400, "need amount_cents, merchant_id")
            if isinstance(raw_amount, bool) or not isinstance(raw_amount, int) or raw_amount <= 0:
                return self._error(400, "amount_cents must be a positive integer")
            amount = raw_amount
            # Read-only eligibility: no reservation, no receipt.
            check = permits.eligible(m.group(1), amount, merchant)
            return self._send(200, {
                "allowed": check.allowed, "reason": check.reason,
            })

        m = re.fullmatch(r"/api/permits/([\w-]+)/spend", self.path)
        if m:
            try:
                raw_amount = body["amount_cents"]; merchant = body["merchant_id"]
                predicate = PredicateType(body.get("predicate", "delivery_hash"))
                artifact_hash = body["artifact_hash"]
            except (KeyError, TypeError, ValueError):
                return self._error(400, "need amount_cents, merchant_id, predicate, artifact_hash")
            if isinstance(raw_amount, bool) or not isinstance(raw_amount, int) or raw_amount <= 0:
                return self._error(400, "amount_cents must be a positive integer")
            amount = raw_amount
            try:
                attempt = flow.spend(m.group(1), amount, merchant, predicate, artifact_hash)
            except ApprovalRequired as appr:
                # Buyer approval needed: the cap reservation stays held and
                # the operation is retained for resume. 202, not an error.
                operation_id = f"op_{_uuid.uuid4().hex[:12]}"
                _pending_put(operation_id, appr)
                return self._send(202, {
                    "status": "approval_required",
                    "operation_id": operation_id,
                    "order_id": appr.order_id,
                    "approval_url": appr.approval_url,
                    "reservation": "held",
                    "next": f"POST /api/operations/{operation_id}/resume after payer approval",
                })
            return self._send(200, {
                "allowed": attempt.allowed, "reason": attempt.reason,
                "escrow_id": attempt.escrow_id,
                "receipts": [receipt_summary(r) for r in attempt.receipts],
            })

        m = re.fullmatch(r"/api/operations/([\w-]+)/resume", self.path)
        if m:
            operation_id = m.group(1)
            with PENDING_OPS_LOCK:
                appr = PENDING_OPS.get(operation_id)
            if appr is None:
                return self._error(404, "unknown_operation")
            if _pending_expired(operation_id):
                # TTL lapsed: reap now so the reservation is released
                # before we answer. 410, not 404 — it existed.
                sweep_expired_pending()
                return self._error(410, "operation_expired")
            try:
                attempt = flow.resume_operation(appr)
            except ApprovalRequired as still:
                # Still not approved — keep the operation retained,
                # with a fresh retention timestamp.
                _pending_put(operation_id, still)
                return self._send(202, {
                    "status": "approval_required",
                    "operation_id": operation_id,
                    "order_id": still.order_id,
                    "approval_url": still.approval_url,
                    "reservation": "held",
                })
            with PENDING_OPS_LOCK:
                PENDING_OPS.pop(operation_id, None)
                _PENDING_META.pop(operation_id, None)
            return self._send(200, {
                "allowed": attempt.allowed, "reason": attempt.reason,
                "escrow_id": attempt.escrow_id,
                "receipts": [receipt_summary(r) for r in attempt.receipts],
            })

        m = re.fullmatch(r"/api/permits/([\w-]+)/estop", self.path)
        if m:
            try:
                receipt, voided = flow.estop(m.group(1))
            except UnknownPermit:
                return self._error(404, "unknown_permit")
            return self._send(200, {
                "revoked": True, "voided_escrows": voided,
                "receipt": receipt_summary(receipt),
            })

        m = re.fullmatch(r"/api/permits/([\w-]+)/revoke-cascade", self.path)
        if m:
            pid = m.group(1)
            if permits.get(pid) is None:
                return self._error(404, "unknown_permit")
            # descendants before the revoke, so the response can name them
            cascaded = []
            queue = list(permits.children_of(pid))
            while queue:
                cid = queue.pop(0)
                cascaded.append(cid)
                queue.extend(permits.children_of(cid))
            receipt, voided = flow.revoke_cascade(pid)
            return self._send(200, {
                "revoked": True, "cascaded_to": cascaded,
                "voided_escrows": voided,
                "receipt": receipt_summary(receipt),
            })

        m = re.fullmatch(r"/api/permits/([\w-]+)/tighten", self.path)
        if m:
            permit_id = m.group(1)
            kwargs: dict = {}
            if "cap_cents" in body:
                raw = body["cap_cents"]
                if isinstance(raw, bool) or not isinstance(raw, int) or raw <= 0:
                    return self._error(400, "cap_cents must be a positive integer")
                kwargs["cap_cents"] = raw
            if "approval_threshold_cents" in body:
                raw = body["approval_threshold_cents"]
                if isinstance(raw, bool) or not isinstance(raw, int) or raw <= 0:
                    return self._error(400, "approval_threshold_cents must be a positive integer")
                kwargs["approval_threshold_cents"] = raw
            if "remove_merchants" in body:
                rm = body["remove_merchants"]
                if not isinstance(rm, list) or not rm:
                    return self._error(400, "remove_merchants must be a non-empty list")
                kwargs["remove_merchants"] = rm
            if "expiry" in body:
                try:
                    kwargs["expiry"] = datetime.fromisoformat(body["expiry"])
                except (TypeError, ValueError):
                    return self._error(400, "expiry must be an ISO-8601 datetime")
            if "actor" in body:
                kwargs["actor"] = body["actor"]
            try:
                permit, receipt = permits.tighten(permit_id, **kwargs)
            except UnknownPermit:
                return self._error(404, "unknown_permit")
            except ValueError as e:
                return self._error(400, str(e))
            return self._send(200, {
                "tightened": True, "permit_id": permit.permit_id,
                "changes": receipt.payload.get("changes", {}),
                "receipt": receipt_summary(receipt),
            })

        m = re.fullmatch(r"/api/escrows/([\w-]+)/release", self.path)
        if m:
            escrow_id = m.group(1)
            delivered_b64 = body.get("delivered_bytes_b64")
            sig = body.get("acceptance_signature")
            delivered = None
            if delivered_b64 is not None:
                try:
                    delivered = base64.b64decode(delivered_b64, validate=True)
                except (binascii.Error, ValueError):
                    return self._error(400, "delivered_bytes_b64 is not valid base64")
            evidence = Evidence(delivered_bytes=delivered, acceptance_signature=sig)
            result = flow.release(escrow_id, evidence)
            return self._send(200, {
                "released": result.released, "reason": result.reason,
                "capture_id": result.capture.capture_id if result.capture else None,
            })

        m = re.fullmatch(r"/api/escrows/([\w-]+)/reconcile", self.path)
        if m:
            escrow_id = m.group(1)
            rec = verifier.reconcile(escrow_id)
            return self._send(200, {
                "resolved": rec.resolved, "outcome": rec.outcome,
                "capture_id": rec.capture.capture_id if rec.capture else None,
                "receipt": receipt_summary(rec.receipt) if rec.receipt else None,
            })

        m = re.fullmatch(r"/api/escrows/([\w-]+)/retry-cleanup", self.path)
        if m:
            cleared = verifier.retry_cleanup(m.group(1))
            return self._send(200, {"cleanup_cleared": cleared})

        return self._error(404, "not_found")


# ---------------------------------------------------------------- main

def _verifier_kwargs(args):
    """Acceptance-key kwargs for ReleaseVerifier (issue #53).

    No --demo-key: no demo fallback at all; a configured key is required
    and an invalid one is fatal. With --demo-key and --db, the generated
    key persists in a 0600 sidecar file next to the db so it does not
    change silently across a restart; without --db it is per-run.
    """
    if not args.demo_key:
        return {}
    if args.db and "PERMIT_ACCEPTANCE_KEY" not in os.environ:
        from settlement.verifier import load_or_create_demo_key_file
        try:
            key = load_or_create_demo_key_file(args.db + ".demo-key")
        except ValueError as e:
            raise SystemExit(f"error: {e}") from None
        return {"acceptance_key": key}
    return {"allow_demo_key": True}


def _make_verifier(pp, ps, lg, vkwargs):
    try:
        return ReleaseVerifier(pp, ps, ledger=lg, **vkwargs)
    except ValueError as e:
        raise SystemExit(
            f"error: {e}\nFix: set PERMIT_ACCEPTANCE_KEY to a key of at "
            "least 32 bytes, or pass --demo-key to opt in to a generated "
            "demo key (issue #53)."
        ) from None


def main():
    global paypal, verifier, flow, MOCK_MODE, ledger, permits
    ap = argparse.ArgumentParser(description="Permit service")
    ap.add_argument("--port", type=int, default=8741)
    ap.add_argument("--db", type=str, default=None,
                    help="SQLite path for the durable receipt ledger;"
                         " default is in-memory (no persistence)")
    ap.add_argument("--sandbox", action="store_true",
                    help="use the real sandbox rail (needs env creds + interactive payer approval)")
    ap.add_argument("--demo-key", action="store_true",
                    help="opt in to a generated demo acceptance key when "
                         "PERMIT_ACCEPTANCE_KEY is unset (off by default, "
                         "#53); with --db the key persists in a 0600 "
                         "<db>.demo-key sidecar so it survives restarts")
    args = ap.parse_args()
    vkwargs = _verifier_kwargs(args)

    if args.sandbox:
        from settlement.sandbox_client import SandboxPayPalClient
        client_id = os.environ.get("PERMIT_PAYPAL_CLIENT_ID")
        client_secret = os.environ.get("PERMIT_PAYPAL_CLIENT_SECRET")
        if not client_id or not client_secret:
            raise SystemExit("sandbox mode needs PERMIT_PAYPAL_CLIENT_ID and PERMIT_PAYPAL_CLIENT_SECRET")
        merchant_id = os.environ.get("PERMIT_PAYPAL_MERCHANT_ID")
        paypal = SandboxPayPalClient(client_id, client_secret,
                                     merchant_account_id=merchant_id)
        MOCK_MODE = False
        log.info("sandbox rail armed"
                 + (f" (merchant bound to {merchant_id})" if merchant_id
                    else " (WARNING: no PERMIT_PAYPAL_MERCHANT_ID — merchant binding disabled)"))
    else:
        paypal = MockPayPalClient()
        log.info("mock rail (no network, no credentials)")

    verifier = _make_verifier(paypal, permits, ledger, vkwargs)
    flow = SpendPipeline(permits, paypal, verifier, ledger=ledger)

    if args.db:
        # Durable mode: open (verifying) the SQLite ledger, then fold the
        # restored chain into the permit store. SqliteLedger.__init__
        # raises instead of serving a corrupt chain — fail closed.
        from permit.sqlite_ledger import SqliteLedger, fold_receipts
        db_ledger = SqliteLedger(args.db)
        folded = fold_receipts(db_ledger.receipts())
        folded.ledger = db_ledger
        ledger, permits = db_ledger, folded
        verifier = _make_verifier(paypal, permits, ledger, vkwargs)
        flow = SpendPipeline(permits, paypal, verifier, ledger=ledger)
        log.info(f"durable ledger at {args.db}"
                 f" ({len(ledger)} receipts restored)")

    # Reap TTL-expired payer-approval operations (daemon; 60s cadence).
    # /resume also reaps on hit, so an expired op never captures.
    sweeper = threading.Thread(target=_sweeper, daemon=True)
    sweeper.start()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    log.info(f"listening on 127.0.0.1:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
