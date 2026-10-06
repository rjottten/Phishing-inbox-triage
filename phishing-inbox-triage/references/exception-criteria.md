# Exception criteria

An item is an exception when AIR did not cleanly resolve it, or when it did and the reporter says the lure worked anyway. The AIR gate below decides that first, before any of the category tests run. Everything after it is a test applied only to what the gate lets through.

## The AIR gate — first, every run

For each message, resolve the related AIR investigation and branch on its status:

1. **Closed.** AIR reached a verdict and remediated: malicious and pulled (actions taken or auto-approved, nothing pending), or confirmed clean. Drop it from the queue without classifying it. The one carve-out: the reporter says they clicked, entered credentials, approved an MFA prompt, replied, paid, or opened a payload. AIR pulled the message; it did not reset the account. That item stays, as User interaction / compromise.
2. **Open.** AIR is pending, running, queued, awaiting manual approval, failed, finished without a verdict, or returned a malicious verdict with nothing actioned across a large recipient set. A live exception, tagged with the AIR status as the reason.
3. **No AIR match.** No investigation found: forwarded to the mailbox and never submitted, or a submission with no investigation behind it. Also an exception, tagged "no AIR match". This means something fell through the automation entirely and should be surfaced loudly, not treated as a routine process note. A strong indicator on such an item (lookalike domain, failed authentication, reviewer-targeted text) makes it P2.

**Matching key.** Join on the original message's Message-ID (`internetMessageId`); the mailbox, the Submissions API and `EmailEvents` all expose it, and Defender's Network message ID can be recorded from hunting for the analyst's benefit but is not exposed on the mailbox side. A forward whose original carries no Message-ID falls back to sender + recipient + received time, and only when exactly one submission fits in a short window. Any item matched that way is **low-confidence**: say so in its evidence, and list "that this submission is this message" under what was not verified.

**Evidence that disagrees with a closed verdict** (a BEC-shaped message AIR called Clean; a known vendor AIR called Phishing and already purged) is not an exception. Record it as a QA note on the handled item so a sampling review can find it. Re-opening every such item is the noise the gate exists to remove.

## Ambiguous

AIR could not or should not settle the verdict — on an item the gate left open.

- AIR has been Pending, Running or Awaiting approval for longer than the normal window (hours, not days). Every open investigation is already an exception via the gate; a stuck one is additionally Ambiguous, because something has gone wrong with the investigation itself.
- Verdict is "No threats found" / "Clean" but the reporter interacted: authentication failures, lookalike domain, external Reply-To, urgency + payment ask back up the reporter's account and AIR's verdict should be disputed.
- Verdict is Phishing, actions are still awaiting approval, and the sender is a known legitimate partner, a genuine internal system, or a marketing platform the org uses. False positives against real vendors cause their own damage (blocked invoices, broken relationships), and the approval is the moment to catch them.
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

A VIP recipient on an item AIR closed is not, on its own, an exception: the gate drops it. The reporter's account of interaction is what brings it back. Where the investigation is still open, confirm nobody interacted and note whether the same lure hit other VIPs.

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

- Verdict is Clean but the reporter replied, paid, or entered credentials on a BEC-pattern message (AIR often has no payload to score). This is the carve-out that keeps a closed item in the queue.
- Verdict is Phishing, the block is awaiting approval, and the sender is a verified partner with the only signal a generic heuristic; recommend "confirm with partner out-of-band" instead of approving the block.
- Verdict is based on a URL that was already taken down, but the credential-harvest attempt still happened — again, only on the reporter's account of it.

On an item AIR closed where nobody interacted, the disagreement is a QA note, not an exception: it appears in the handled section as a sampling candidate and goes no further.

Agreement with AIR is the norm; disagreement should be rare and evidence-backed. If you find yourself writing QA notes on most closed items, the org's automation is misconfigured and that itself belongs in the report's trends section.
