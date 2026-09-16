# Response actions

You recommend; a person decides and executes. Every recommendation names the action, the scope, and the decision owner. Prefer reversible actions first (soft delete over hard delete, block a URL over blocking a domain) unless the evidence justifies more.

## Action menu

| Action | Where | Notes |
|---|---|---|
| Approve / reject pending AIR action | Defender Action center | Fastest path for routine purge; reject if the verdict looks wrong |
| Soft delete message(s) | Threat Explorer / Action center | Recoverable; default purge for confirmed phish |
| Hard delete message(s) | Threat Explorer / Action center | Unrecoverable; reserve for malware or confirmed credential lures on large scope |
| Move to junk / quarantine | Threat Explorer | Useful when the verdict is probable but not certain |
| Block sender address or domain | Tenant Allow/Block List | Address-level first; domain-level only for attacker-controlled domains, never for a compromised legitimate partner |
| Block URL | Tenant Allow/Block List (URLs) | Low collateral; do it early for credential-harvest pages |
| Block file (hash) | Tenant Allow/Block List (files) | For malicious attachments |
| Submit to Microsoft | Submissions page | For automation-gap items with no submission, and for verdict disputes |
| Report as false positive / allow | Submissions page | For legitimate senders wrongly flagged; pair with a note to the reporter |
| Notify reporter with verdict | Defender auto-notify or manual | Only manual when automation didn't fire; don't double-notify |
| Coach reporter on Report button | Manual (email/Teams) | For forwarded-to-mailbox reports; keep it friendly, they did the right thing by reporting |
| Reset password + revoke sessions | Entra ID (IAM team) | For credential entry or MFA approval; revoke refresh tokens, not just password |
| Re-register MFA | Entra ID (IAM team) | If MFA fatigue or attacker-registered method suspected |
| Review inbox rules, forwarding, consents, delegations | Exchange / Entra (SOC or IAM) | For any suspected compromise; attackers persist via rules |
| Hold or reverse payment; verify vendor change out-of-band | Finance / AP | For BEC and vendor compromise; call the vendor on a known number, not one in the email |
| Notify vendor of compromise | Vendor management / account owner | For vendor email compromise; out-of-band |
| Open incident / escalate to IR | SOC lead / IR | For P1 with confirmed compromise, lateral movement, or data exposure |
| Hunt for same lure org-wide | Advanced Hunting | For campaigns and VIP targeting; find recipients who didn't report |

## Defaults by category

**Ambiguous** — No purge until decided. Recommend the specific check that would resolve it (out-of-band vendor call, ask the reporter a clarifying question, check click telemetry) and a holding action if risk is meaningful (move to quarantine, block URL). Owner: SOC analyst.

**BEC / impersonation** — Soft delete from all recipients; block the sender address; hunt for the same display name or Reply-To across the tenant; alert finance/AP or payroll if money or bank details were involved; if the recipient replied, escalate to User interaction. Owner: SOC analyst for mail actions, Finance for payment holds.

**High-value target** — Confirm no interaction before purge; hunt for the lure across other VIPs; consider notifying the VIP's assistant or the exec protection contact; block URL/sender. Owner: SOC analyst; SOC lead if multiple VIPs hit.

**User interaction / compromise** — Credential reset and session revocation first, then MFA review, then inbox rules/forwarding/consents, then purge and blocks, then scope the blast radius (what did the account access after the event). Open an incident. Owner: IAM for identity actions, SOC/IR for investigation, user's manager informed.

**Remediation decision** — Lay out the choice: scope (recipient count, departments, external domains), reversibility, and business impact, then a recommendation. Typical framing: "Soft delete from 142 mailboxes now, block URL; do not block the domain because 30 legitimate messages/week come from it." Owner: SOC analyst; SOC lead for large or cross-department scope.

**Automation gap** — Submit to Microsoft on the user's behalf; notify reporter manually only if the verdict won't reach them otherwise; coach on the Report button; if AIR failed, note the error for whoever owns Defender configuration. Owner: SOC analyst (submission), Defender admin (errors).

## What not to recommend

- Blocking a legitimate partner's domain because one of their mailboxes was compromised.
- Hard delete when soft delete achieves the same containment.
- Contacting the sender from the reported email or replying to the thread.
- Telling a reporter their message was "safe" when the verdict is actually inconclusive.
- Password reset without session/token revocation — the attacker keeps the session.
