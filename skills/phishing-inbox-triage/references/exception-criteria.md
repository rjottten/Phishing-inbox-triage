# Exception criteria

An item is an exception when automation has either stopped (inconclusive) or reached a decision that a human should confirm because the cost of being wrong is high. Everything below is a test for that condition. When none apply and AIR has closed the item with the reporter notified, it is not an exception — leave it in the "handled by automation" lane.

## Ambiguous

Automation could not or should not settle the verdict.

- AIR status is Pending, Running, Awaiting approval, or Failed/Error for longer than the normal window (hours, not days). Stuck investigations are exceptions once they age out; fresh ones are just "in progress."
- Verdict is "No threats found" / "Clean" but strong evidence points the other way: authentication failures, lookalike domain, external Reply-To, urgency + payment ask, or multiple independent reports of the same message.
- Verdict is Phishing but the evidence is thin and the sender is a known legitimate partner, a genuine internal system, or a marketing platform the org uses. False positives against real vendors cause their own damage (blocked invoices, broken relationships).
- The message is legitimate-looking but sits outside any pattern you can explain: correct branding, DKIM pass from the real domain, but the request or timing is odd (invoice from a real vendor with new bank details, HR document from a real HR platform that HR didn't schedule).
- Reporter's own account contradicts the metadata ("I got this on my phone, it looked different").

## BEC / impersonation

No link, no attachment, no malware — just a person asking another person to do something. Automation is weakest here because there is nothing to detonate.

Strong indicators (two or more usually settles it):

- Display name matches an executive, manager, vendor contact, or payroll/HR sender but the address doesn't, or the address is a lookalike (transposed letters, added hyphen, different TLD, homoglyph).
- Reply-To differs from From, especially to a consumer mail domain.
- First-ever message from this sender address to this recipient or to the org.
- Request involves money movement, bank-detail changes, gift cards, payroll redirection, W-2/PII, or "confidential" acquisition work.
- Urgency, secrecy, unavailability ("in a meeting, can't talk, just handle it"), pressure to bypass a process.
- Short body, mobile-signature, or "sent from my iPhone" with no thread history.
- Thread hijack: a real conversation continued from a new address, or from a legitimate-but-compromised partner mailbox (DMARC passes — which is why authentication alone doesn't clear BEC).
- Vendor email compromise: real vendor domain, real signature, authentication passes, and the only anomaly is the payment instruction.

Always ask whether the recipient acted: replied, sent anything, initiated a payment, changed vendor details. That moves the item to User interaction / compromise and usually to P1.

## High-value target

The target, not the lure, makes this an exception. Even a routine-looking phish gets analyst attention when it lands on someone whose compromise is disproportionately costly.

- Recipients or reporter include C-suite and their assistants, board members, finance and treasury approvers, payroll, legal, HR with PII access, IT/identity admins, privileged service accounts, or anyone on the org's VIP/priority-accounts list.
- The lure is tailored to the target's role (references a real deal, real system, real colleague, correct internal project name).
- Priority account tagging in Defender, if the org uses it, is the quickest signal; absence of a tag does not mean the person isn't a VIP.

For these, even if AIR closed the case as Phishing and purged the message, confirm nobody interacted before the purge and note whether the same lure hit other VIPs.

## User interaction / compromise

Anything suggesting the lure worked, even partially.

- Reporter says they clicked, opened, entered credentials, approved an MFA prompt, replied, downloaded, or "then thought better of it."
- `UrlClickEvents` or Safe Links telemetry shows a click on a URL from the message, particularly one that was allowed or bypassed.
- Sign-in logs show unfamiliar location, new device, impossible travel, or MFA fatigue patterns for the recipient shortly after delivery.
- New inbox rules, forwarding rules, consent grants, or mailbox delegations on the recipient's account after delivery.
- A payment, vendor change, or data transfer was initiated as a result.

Compromise suspected = P1 regardless of the AIR verdict. Credential reset and session revocation should be recommended before anything else.

## Remediation decision

Automation proposed or could take an action that a human should approve because of its blast radius or reversibility.

- AIR actions awaiting approval in the Action center (soft delete, hard delete, block URL/sender, turn off forwarding, etc.).
- Campaign scope is large: dozens or hundreds of recipients, multiple departments, or external partner domains — a purge or block affects business traffic, so scope and timing need a decision.
- Recommended action touches a shared mailbox, distribution list, or a mailbox with legal hold.
- Action would block a domain the org legitimately corresponds with (vendor compromise case): the right move may be tenant allow/block plus out-of-band vendor contact rather than a domain block.
- Reversal is expensive (hard delete vs. soft delete; blocking a shared SaaS sender).

## When to disagree with AIR

Disagree, and say why, when:

- Verdict is Clean but the message is a BEC pattern (AIR often has no payload to score).
- Verdict is Phishing but the sender is a verified partner and the only signal is a generic heuristic; recommend "confirm with partner out-of-band" instead of a block.
- Verdict is based on a URL that was already taken down, but the credential-harvest attempt still happened.

Agreement with AIR is the norm; disagreement should be rare and evidence-backed. If you find yourself disagreeing on most items, the org's automation is misconfigured and that itself belongs in the report's trends section.
