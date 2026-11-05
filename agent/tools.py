"""
Tools the demo agent may call. Each tool is a thin, honest wrapper around
the SpendPipeline: the agent decides WHAT to attempt, Permit decides
whether it happens. The agent can never bypass the permit check, touch
PayPal directly, or release an escrow itself.
"""

from __future__ import annotations

import hashlib
import json

from permit.flow import SpendPipeline
from settlement.verifier import Evidence, PredicateType


class SpendTools:
    """
    catalog: purpose -> artifact bytes the marketplace precommits.
    The escrow's artifact_hash is committed at spend time from the catalog;
    deliver() submits the matching bytes (honest merchant), while the
    harness may submit tampered bytes to demonstrate REFUSED.
    """

    def __init__(
        self,
        flow: SpendPipeline,
        permit_id: str,
        merchant_id: str,
        catalog: dict[str, bytes],
    ):
        self.flow = flow
        self.permit_id = permit_id
        self.merchant_id = merchant_id
        self.catalog = catalog
        self._escrow_purpose: dict[str, str] = {}

    # -- tools the LLM may call -------------------------------------------

    def attempt_spend(self, amount_cents: int, purpose: str) -> str:
        if purpose not in self.catalog:
            return json.dumps({"ok": False, "error": f"unknown purpose {purpose!r}"})
        artifact_hash = hashlib.sha256(self.catalog[purpose]).hexdigest()
        attempt = self.flow.spend(
            self.permit_id, amount_cents, self.merchant_id,
            PredicateType.D, artifact_hash,
        )
        if not attempt.allowed:
            if attempt.reason == "pending_principal_approval":
                return json.dumps({
                    "ok": False,
                    "decision": "PENDING",
                    "reason": "pending_principal_approval",
                    "approval_id": attempt.approval_id,
                    "message": (
                        f"Spend of ${amount_cents/100:.2f} exceeds your "
                        "permit's approval threshold and needs the "
                        "principal's word. Use check_approval to poll, "
                        "then complete_approved_spend once approved."
                    ),
                    "paypal_called": False,
                })
            return json.dumps({
                "ok": False,
                "decision": "BLOCKED",
                "reason": attempt.reason,
                "paypal_called": False,
            })
        self._escrow_purpose[attempt.escrow_id] = purpose
        auth_receipt = attempt.receipts[1]
        return json.dumps({
            "ok": True,
            "decision": "ALLOWED",
            "escrow_id": attempt.escrow_id,
            "paypal_auth_id": auth_receipt.payload["paypal_auth_id"],
            "amount_cents": amount_cents,
        })

    def deliver(self, escrow_id: str) -> str:
        """The merchant delivers the bytes matching the precommitment."""
        purpose = self._escrow_purpose.get(escrow_id)
        if purpose is None:
            return json.dumps({"ok": False, "error": "unknown escrow_id"})
        result = self.flow.release(
            escrow_id, Evidence(delivered_bytes=self.catalog[purpose]))
        return json.dumps({
            "ok": result.released,
            "released": result.released,
            "reason": result.reason,
            "capture_id": result.capture.capture_id if result.capture else None,
        })

    def check_permit(self) -> str:
        permit = self.flow.permits.get(self.permit_id)
        if permit is None:
            return json.dumps({"ok": False, "error": "permit not found"})
        return json.dumps({
            "ok": True,
            "permit_id": permit.permit_id,
            "cap_cents": permit.cap_cents,
            "reserved_cents": permit.reserved_cents,
            "captured_cents": permit.captured_cents,
            "remaining_cents": permit.remaining_cents(),
            "revoked": permit.revoked,
            "parent_id": permit.parent_id,
        })

    def delegate_subpermit(
        self, cap_cents: int, agent_id: str, expiry_minutes: int = 60
    ) -> str:
        """
        Carve a sub-permit out of this permit's remaining cap for another
        agent. The child inherits this permit's merchant allowlist, cannot
        outlive it, and cannot exceed its remaining cap. The carved amount
        is reserved here until the child spends or is revoked.
        """
        from datetime import datetime, timedelta, timezone

        permit = self.flow.permits.get(self.permit_id)
        if permit is None:
            return json.dumps({"ok": False, "error": "permit not found"})
        result = self.flow.delegate(
            parent_permit_id=self.permit_id,
            agent_id=agent_id,
            cap_cents=cap_cents,
            allowlist=list(permit.allowlist),
            expiry=datetime.now(timezone.utc)
            + timedelta(minutes=expiry_minutes),
        )
        if not result.ok:
            return json.dumps({"ok": False, "error": result.reason})
        child = result.permit
        return json.dumps({
            "ok": True,
            "child_permit_id": child.permit_id,
            "agent_id": child.agent_id,
            "cap_cents": child.cap_cents,
            "parent_remaining_cents": self.flow.permits.get(
                self.permit_id
            ).remaining_cents(),
        })

    def check_approval(self, approval_id: str) -> str:
        """Poll a principal-approval request: pending/approved/denied/expired."""
        approval = self.flow.permits.get_approval(approval_id)
        if approval is None:
            return json.dumps({"ok": False, "error": "unknown approval"})
        return json.dumps({
            "ok": True,
            "approval_id": approval.approval_id,
            "status": approval.status,
            "amount_cents": approval.amount_cents,
            "merchant_id": approval.merchant_id,
            "expires_at": approval.expires_at,
        })

    def complete_approved_spend(self, approval_id: str) -> str:
        """
        Execute a principal-approved spend. Only the exact approved
        (amount, merchant) can complete; the authority check re-runs.
        """
        attempt = self.flow.complete_approved_spend(approval_id)
        if not attempt.allowed:
            return json.dumps({
                "ok": False,
                "decision": "BLOCKED",
                "reason": attempt.reason,
                "paypal_called": False,
            })
        # Mirror attempt_spend's success shape so the agent's deliver()
        # flow works unchanged.
        auth_receipt = attempt.receipts[1]
        approval = self.flow.permits.get_approval(approval_id)
        # Register the escrow's catalog purpose (reverse-lookup by artifact
        # hash) so deliver() can submit the matching bytes.
        for purpose, blob in self.catalog.items():
            if hashlib.sha256(blob).hexdigest() == approval.artifact_hash:
                self._escrow_purpose[attempt.escrow_id] = purpose
                break
        return json.dumps({
            "ok": True,
            "decision": "ALLOWED",
            "escrow_id": attempt.escrow_id,
            "paypal_auth_id": auth_receipt.payload.get("paypal_auth_id"),
            "amount_cents": approval.amount_cents,
        })

    def tighten_permit(
        self,
        cap_cents: int | None = None,
        remove_merchants: list[str] | None = None,
        expiry_minutes: int | None = None,
        approval_threshold_cents: int | None = None,
    ) -> str:
        """
        Voluntarily narrow this permit's authority. Tighten-only: every
        supplied parameter must strictly narrow current authority.
        """
        from datetime import datetime, timedelta, timezone

        permit = self.flow.permits.get(self.permit_id)
        if permit is None:
            return json.dumps({"ok": False, "error": "permit not found"})

        expiry_dt = None
        if expiry_minutes is not None:
            if not isinstance(expiry_minutes, (int, float)) or expiry_minutes <= 0:
                return json.dumps({"ok": False, "error": "expiry_minutes must be positive"})
            expiry_dt = datetime.now(timezone.utc) + timedelta(minutes=expiry_minutes)

        try:
            tightened, receipt = self.flow.permits.tighten(
                self.permit_id,
                cap_cents=cap_cents,
                remove_merchants=remove_merchants,
                expiry=expiry_dt,
                approval_threshold_cents=approval_threshold_cents,
                actor=f"agent:{permit.agent_id}",
            )
            with tightened._lock:
                eff_cap, _, eff_allow, eff_expiry, _ = self.flow.permits._effective(tightened)
                eff_threshold = self.flow.permits._effective_threshold(tightened)
            return json.dumps({
                "ok": True,
                "tightened": True,
                "permit_id": tightened.permit_id,
                "effective_cap_cents": eff_cap,
                "remaining_cents": tightened.remaining_cents(),
                "effective_allowlist": sorted(list(eff_allow)),
                "effective_expiry": eff_expiry.isoformat(),
                "effective_approval_threshold_cents": eff_threshold,
            })
        except Exception as err:
            return json.dumps({"ok": False, "error": str(err)})

    # -- harness-only (NOT exposed to the LLM) ------------------------------

    def deliver_tampered(self, escrow_id: str) -> str:
        """Simulate a compromised worker submitting wrong bytes."""
        result = self.flow.release(
            escrow_id, Evidence(delivered_bytes=b"tampered-bytes"))
        return json.dumps({
            "ok": result.released,
            "released": result.released,
            "reason": result.reason,
            "capture_id": result.capture.capture_id if result.capture else None,
        })
