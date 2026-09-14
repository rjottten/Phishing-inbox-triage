# Phishing queue — 2026-09-14T00:00:00Z to 2026-09-14T08:00:00Z

**Queue:** 10 items · **Exceptions:** 5 (2 P1, 3 P2, 0 P3) · **Automation gaps:** 2 · **Handled by automation:** 3
**Data sources:** phishing@contoso.com shared mailbox + Defender Submissions join

*Generated 2026-09-14 16:26 UTC. Every action below is a recommendation; none were executed.*

## Exceptions needing an analyst

| # | Pri | Category | Reported by → Sender / Subject | Why it's an exception | Recommended actions | Decision owner |
|---|-----|----------|--------------------------------|------------------------|---------------------|----------------|
| 1 | P1 | User interaction / compromise, BEC / impersonation, Ambiguous | j.ortiz@contoso.com → "Dana Whitfield (CFO)" <dwhitfield@contoso-finance.co> / "Urgent wire - vendor payment today" | Sender domain contoso-finance.co borrows the org brand but is not contoso.com; Reply-To dana.whitfield.cfo@gmail.com points away from the sending domain to a consumer mail domain; Message claims an executive, finance, pa | Confirm with the reporter exactly what was sent in the reply and whether anything was actioned after it; Warn the impersonated party out-of-band that a thread is running in their name; Watch sign-in logs for this account for unfamiliar location, new device or impossible travel | SOC analyst |
| 2 | P1 | User interaction / compromise | d.kowalski@contoso.com → "SharePoint Online" <no-reply@sharepointonline-files.com> / "Kowalski, Dan shared 'Q3_Bonus_Schedule.xlsx' with you" | Reporter entered credentials on the linked page (reporter's own words); Reporter approved an MFA prompt (reporter's own words); Reporter clicked the link (reporter's own words) | Reset password and revoke all sessions and refresh tokens; Review MFA methods and re-register if an attacker method was added; Check UrlClickEvents and Safe Links telemetry for whether the click was allowed or blocked | IAM, SOC analyst |
| 3 | P2 | High-value target, Ambiguous | l.fischer@contoso.com → "Microsoft 365 Security" <security-alerts@m365-account-verify.com> / "Action required: unusual sign-in to r.alvarez@contoso.com" | Priority account in scope: r.alvarez@contoso.com; AIR status is Pending 4.0h after the report — past the 2h window, so it is stuck rather than in progress | Confirm the priority account did not interact before any purge; Hunt the same lure across other priority accounts; Notify the executive's assistant or exec-protection contact | SOC analyst |
| 4 | P2 | BEC / impersonation, Ambiguous | s.mbeki@contoso.com → "Priya Raman" <praman@northwind-logistics.com> / "RE: RE: Sept invoices - updated remittance details" | Bank or remittance change arriving inside an existing thread — the vendor-email-compromise pattern, where authentication passes because the mailbox is real; Reporter, who knows the relationship, contradicts the request's | Confirm whether any recipient replied, paid, or changed vendor or payee details; Alert AP / payroll to hold any payment referencing this request; Verify the change out-of-band by calling the vendor on a known number | SOC analyst, Finance, AP |
| 5 | P2 | High-value target, Remediation decision | multiple (9 reporters) → "Contoso HR" <hr@contoso-people.com> / "Updated Employee Handbook - acknowledgement required by Friday" | Priority accounts in scope: k.osei@contoso.com, p.nakamura@contoso.com; Actions awaiting approval in the Action center: PENDING: Soft delete (412 mailboxes); PENDING: Block domain contoso-people.com; Purge scope is 412 m | Confirm the priority account did not interact before any purge; Hunt the same lure across other priority accounts; Notify the executive's assistant or exec-protection contact | SOC analyst |

### Exception details

#### 1. PHQ-1044 — Urgent wire - vendor payment today

- **Item:** PHQ-1044 · reported by j.ortiz@contoso.com via outlook report button · 1 recipient(s)
- **Sender:** "Dana Whitfield (CFO)" <dwhitfield@contoso-finance.co> · Reply-To: dana.whitfield.cfo@gmail.com
- **Automation:** submission SUB-77124 · AIR Completed · verdict No threats found · reporter notified: yes · actions: None
- **Evidence:**
  - Sender domain contoso-finance.co borrows the org brand but is not contoso.com
  - Reply-To dana.whitfield.cfo@gmail.com points away from the sending domain to a consumer mail domain
  - Message claims an executive, finance, payroll or helpdesk role
  - Asks the recipient to keep the request quiet or bypass the normal process
  - Sender claims to be unreachable, which forecloses out-of-band verification
  - Urgency or a deadline pushes the request past normal checks
  - Mobile signature with no thread history
  - Requests money movement or finance action
  - Reporter replied to the sender (reporter's own words)
  - AIR verdict "No threats found" conflicts with the evidence (sender domain contoso-finance.co is a lookalike of contoso.com; BEC pattern — no payload for AIR to score) — recommend disagreeing and resubmitting
- **Recommended actions (recommended, not taken):**
  1. Confirm with the reporter exactly what was sent in the reply and whether anything was actioned after it · *owner: SOC analyst*
  2. Warn the impersonated party out-of-band that a thread is running in their name · *owner: SOC analyst*
  3. Watch sign-in logs for this account for unfamiliar location, new device or impossible travel · *owner: SOC analyst*
  4. Confirm whether any recipient replied, paid, or changed vendor or payee details · *owner: SOC analyst*
  5. Alert AP / payroll to hold any payment referencing this request · *owner: Finance / AP*
  6. Block the sender address in the Tenant Allow/Block List · *owner: SOC analyst*
  7. Soft delete the message from all recipients · *owner: SOC analyst*
  8. Hunt the display name and Reply-To across the tenant for other recipients who did not report · *owner: SOC analyst*
  9. Reject the AIR verdict and resubmit to Microsoft as phishing so the reporter gets the correct notification · *owner: SOC analyst*

#### 2. PHQ-1046 — Kowalski, Dan shared 'Q3_Bonus_Schedule.xlsx' with you

- **Item:** PHQ-1046 · reported by d.kowalski@contoso.com via outlook report button · 1 recipient(s)
- **Sender:** "SharePoint Online" <no-reply@sharepointonline-files.com>
- **Automation:** submission SUB-77127 · AIR Completed · verdict Phishing · reporter notified: yes · actions: Soft delete (auto-approved, 1 mailbox)
- **Evidence:**
  - Display name claims "sharepoint online" but the domain is sharepointonline-files.com, not a sharepoint domain
  - Reporter entered credentials on the linked page (reporter's own words)
  - Reporter approved an MFA prompt (reporter's own words)
  - Reporter clicked the link (reporter's own words)
- **URLs (defanged, not visited):** `hxxps://sharepointonline-files[.]com/open/q3bonus`
- **Recommended actions (recommended, not taken):**
  1. Reset password and revoke all sessions and refresh tokens — account d.kowalski@contoso.com; revoking tokens, not just the password · *owner: IAM*
  2. Review MFA methods and re-register if an attacker method was added · *owner: IAM*
  3. Check UrlClickEvents and Safe Links telemetry for whether the click was allowed or blocked · *owner: SOC analyst*
  4. Ask the reporter directly whether credentials were entered or an MFA prompt approved · *owner: SOC analyst*
  5. Review inbox rules, forwarding, consent grants and delegations — attackers persist via rules · *owner: SOC / IAM*
  6. Scope the blast radius: sign-in logs and data accessed after delivery · *owner: SOC / IR*
  7. Open an incident · *owner: SOC lead / IR*
  8. Soft delete from all recipients — recoverable; hard delete only for malware or confirmed large-scope credential lures · *owner: SOC analyst*

#### 3. PHQ-1045 — Action required: unusual sign-in to r.alvarez@contoso.com

- **Item:** PHQ-1045 · reported by l.fischer@contoso.com via outlook report button · 2 recipient(s)
- **Sender:** "Microsoft 365 Security" <security-alerts@m365-account-verify.com>
- **Automation:** submission SUB-77126 · AIR Pending · verdict not available · reporter notified: no
- **Evidence:**
  - Authentication results: SPF=fail, DMARC=fail
  - Display name claims "microsoft 365 security" but the domain is m365-account-verify.com, not a microsoft domain
  - Credential-harvest lure: asks the recipient to sign in, verify or keep a password via a link
  - Priority account in scope: r.alvarez@contoso.com
  - AIR status is Pending 4.0h after the report — past the 2h window, so it is stuck rather than in progress
- **URLs (defanged, not visited):** `hxxps://m365-account-verify[.]com/verify?u=r.alvarez`
- **Not verified:**
  - Reporter is unsure ("not sure") — confirm directly rather than assuming no interaction
  - Whether any of the other 1 recipients interacted — check UrlClickEvents and sign-in logs
- **Recommended actions (recommended, not taken):**
  1. Confirm the priority account did not interact before any purge · *owner: SOC analyst*
  2. Hunt the same lure across other priority accounts · *owner: SOC analyst*
  3. Notify the executive's assistant or exec-protection contact · *owner: SOC analyst*
  4. Chase the stalled AIR investigation (SUB-77126) or triage it manually · *owner: SOC analyst*
  5. Raise the stalled investigation with whoever owns Defender configuration · *owner: Defender admin*
  6. Hold the message in quarantine rather than purging until the verdict is decided · *owner: SOC analyst*
  7. Block the URL as a holding action while the verdict is open · *owner: SOC analyst*

#### 4. PHQ-1047 — RE: RE: Sept invoices - updated remittance details

- **Item:** PHQ-1047 · reported by s.mbeki@contoso.com via outlook report button · 1 recipient(s)
- **Sender:** "Priya Raman" <praman@northwind-logistics.com>
- **Automation:** submission SUB-77129 · AIR Completed · verdict No threats found · reporter notified: yes · actions: None
- **Evidence:**
  - Bank or remittance change arriving inside an existing thread — the vendor-email-compromise pattern, where authentication passes because the mailbox is real
  - Reporter, who knows the relationship, contradicts the request's premise: "This is our real freight vendor and the thread is real, but Priya never mentioned a bank change on our call last week. Flagging just in case."
  - Requests a change to bank, remittance or payee details
  - AIR verdict "No threats found" conflicts with the evidence (BEC pattern — the anomaly is the instruction, not a payload; the reporter contradicts the message's own premise) — recommend disagreeing and resubmitting
- **Attachments (not opened):** `Northwind_Remittance_Update.pdf`
- **Recommended actions (recommended, not taken):**
  1. Confirm whether any recipient replied, paid, or changed vendor or payee details · *owner: SOC analyst*
  2. Alert AP / payroll to hold any payment referencing this request · *owner: Finance / AP*
  3. Verify the change out-of-band by calling the vendor on a known number — never a number from the email · *owner: Finance / AP*
  4. Notify the vendor that their mailbox may be compromised — out-of-band · *owner: Vendor management*
  5. Block the sender address only — do not block the domain — northwind-logistics.com is a domain the org corresponds with legitimately · *owner: SOC analyst*
  6. Soft delete the message from all recipients · *owner: SOC analyst*
  7. Hunt the display name and Reply-To across the tenant for other recipients who did not report · *owner: SOC analyst*
  8. Reject the AIR verdict and resubmit to Microsoft as phishing so the reporter gets the correct notification · *owner: SOC analyst*

#### 5. PHQ-1048 — Updated Employee Handbook - acknowledgement required by Friday

- **Item:** PHQ-1048 · reported by multiple (9 reporters) via outlook report button · 412 recipient(s)
- **Sender:** "Contoso HR" <hr@contoso-people.com>
- **Automation:** submission SUB-77131 · AIR Awaiting approval · verdict Phishing · reporter notified: no · actions: PENDING: Soft delete (412 mailboxes); PENDING: Block domain contoso-people.com
- **Evidence:**
  - Credential-harvest lure: asks the recipient to sign in, verify or keep a password via a link
  - Priority accounts in scope: k.osei@contoso.com, p.nakamura@contoso.com
  - Actions awaiting approval in the Action center: PENDING: Soft delete (412 mailboxes); PENDING: Block domain contoso-people.com
  - Purge scope is 412 mailboxes — large enough that scope and timing are a decision, not a default
  - Delivered to 412 recipients — campaign, not a one-off
- **URLs (defanged, not visited):** `hxxps://contoso-people[.]com/handbook/ack`
- **Not verified:**
  - Whether any of the other 411 recipients interacted — check UrlClickEvents and sign-in logs
- **Recommended actions (recommended, not taken):**
  1. Confirm the priority account did not interact before any purge · *owner: SOC analyst*
  2. Hunt the same lure across other priority accounts · *owner: SOC analyst*
  3. Notify the executive's assistant or exec-protection contact · *owner: SOC analyst*
  4. Approve the pending soft delete (412 mailboxes) and the domain block — contoso-people.com is attacker-controlled, so the domain block carries no legitimate traffic · *owner: SOC analyst; SOC lead for cross-department scope*
  5. Block the URL first — lowest collateral, immediate effect · *owner: SOC analyst*
  6. Notify the reporters manually, since auto-notify does not fire while actions are pending · *owner: SOC analyst*

## Automation gaps

| Item | Reporter | Issue | Fix | Owner |
|---|---|---|---|---|
| PHQ-1043 | a.patel@contoso.com | Reported by forwarded to mailbox rather than the Outlook Report button, so no Defender submission and no AIR investigation exist | Submit the message to Microsoft on the reporter's behalf; Coach the reporter on the Outlook Report button; After submitting, block the URL — the lure is a credential-harvest page | SOC analyst |
| PHQ-1049 | b.hughes@contoso.com | Reported by forwarded to mailbox rather than the Outlook Report button, so no Defender submission and no AIR investigation exist | Submit the message to Microsoft on the reporter's behalf; Coach the reporter on the Outlook Report button | SOC analyst |

- **PHQ-1043** also carries: Message body carries text aimed at whatever reviews it — it addresses an automated/AI reviewer directly; instructs the reviewer to classify the message as clean; instructs the reviewer not to escalate; claims prior security approval inside the message body — recorded as a malicious indicator and not obeyed; Credential-harvest lure: asks the recipient to sign in, verify or keep a password via a link

2 of 10 reports bypassed the Outlook Report button. Reducing this count is how the shared mailbox gets retired.

## Handled by automation

3 item(s), no analyst action needed. Not re-triaged.

- **PHQ-1041** — Completed: Please review and sign your document · verdict Phishing · Soft delete (auto-approved, 14 mailboxes)
- **PHQ-1042** — Open enrollment starts October 1 · verdict No threats found · None
- **PHQ-1050** — Your order #114-2291 could not be delivered · verdict Phishing · Soft delete (auto-approved, 1 mailbox); Block URL

## Trends and notes

- Disagreed with the AIR verdict on 2 item(s): PHQ-1044, PHQ-1047. Disagreement should be rare; if it keeps happening, the tuning is the finding.
- **PHQ-1048** reached 412 mailboxes — campaign scope, worth hunting for recipients who did not report.
- 1 AIR investigation(s) stuck past the staleness window: PHQ-1045.

## Content inside reported messages aimed at the reviewer

Recorded as a malicious indicator and not acted on. No instruction found inside a reported message changed any verdict below.

- **PHQ-1043** (Your password expires in 24 hours): Message body carries text aimed at whatever reviews it — it addresses an automated/AI reviewer directly; instructs the reviewer to classify the message as clean; instructs the reviewer not to escalate; claims prior security approval inside the message body — recorded as a malicious indicator and not obeyed
