# Permit — PayPal AI Hackathon Package

## Submission Position

**Permit — Safe Spending Authority for AI Agents**

Permit is a human-directed authority layer between AI agents and PayPal. It lets agents participate in commerce while keeping spending scoped, auditable, revocable, and evidence-producing.

## Problem

AI agents can research and initiate commercial actions, but unrestricted payment access creates replay, overspend, fraud, and accountability risks. Permit addresses the missing trust layer: enforceable, inspectable spending authority.

## Solution

Permit issues scoped permits to AI agents and enforces budget caps, approved scope, expiry, revocation, delegation constraints, idempotent capture, emergency stop, and hash-chained evidence.

## Why PayPal + AI Are Essential

- **AI** understands intent, researches eligible options, generates structured proposals, and explains decisions.
- **PayPal** provides the payment rail and transaction evidence for approved actions.
- **Permit** sits between them as the policy and evidence layer.

## Demo Flow

1. Grant
2. AI proposal
3. Policy authorization
4. PayPal sandbox capture
5. Evidence ledger
6. Over-cap block and emergency revoke

## Judge-Facing Proof Points

- Fail-closed authorization gate
- No payment without an active, valid Permit
- Over-cap and revoked-Permit requests blocked before PayPal
- Idempotent capture protection
- SHA-256 hash-chained receipt ledger
- Visible emergency stop
- Clear separation between AI proposal and deterministic authorization

## Devpost Copy Checklist

- [ ] Project title
- [ ] One-sentence pitch
- [ ] Problem statement
- [ ] Solution overview
- [ ] Architecture diagram
- [ ] Demo video link
- [ ] Repository link
- [ ] PayPal + AI usage explanation
- [ ] What works today
- [ ] Sandbox limitations
- [ ] Production roadmap
- [ ] Team and acknowledgements

## Architecture Summary Checklist

- [ ] Dashboard / human control surface
- [ ] Agent runner / proposal generator
- [ ] Authority gate
- [ ] Permit registry
- [ ] PayPal sandbox adapter
- [ ] Idempotency layer
- [ ] Receipt and trace ledger
- [ ] Revocation and cascade controls
- [ ] Reconciliation path

## Honest Production Gap Register

- [ ] Durable escrow restoration
- [ ] Shared-token HTTP authentication and role-based access
- [ ] Ledger checkpointing and external anchoring
- [ ] Refund and dispute path
- [ ] Multi-merchant policy model
- [ ] Observability and alerting
- [ ] Compliance review
- [ ] Threat-model-driven penetration testing

## Submission Timeline

- [ ] Integrated PayPal sandbox run
- [ ] Demo video by November 8
- [ ] Devpost package by November 10
- [ ] Final validation before November 12 deadline
