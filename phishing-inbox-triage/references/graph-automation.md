# Graph automation: closing the automation gap

`scripts/graph_submit.py` watches the shared phishing mailbox, pulls the
*original* reported message out of each forward, and creates a Defender
`emailThreatSubmission` through the Microsoft Graph Security API. The
submission appears on the Submissions page, launches an AIR investigation, and
lets Defender's auto-notify tell the reporter what the verdict was.

This only touches the **automation gap** lane. Reports made with the Outlook
Report button never land in the shared mailbox — Defender already has them.
What lands here is what bypassed the pipeline, and that is exactly what this
script converts back into a submission.

It does not triage, decide, or remediate. The triage lanes, exception criteria,
and response actions stay where they are: with the analyst and the rest of this
skill.

## Consider the no-code option first

Before deploying a script, check **Defender portal → Settings → Email &
collaboration → User reported settings**. If your tenant routes reports to a
custom reporting mailbox, Defender can monitor that mailbox itself and raise
submissions from what it finds. If that covers your queue, use it; it is
supported, maintained by Microsoft, and has no token to rotate.

The script is for the cases that configuration does not cover: a mailbox
Defender is not monitoring, a mailbox in a different tenant or in a migration,
reports that arrive from an external ticketing system, or a backlog you need
to drain once and then retire the mailbox.

## What the script sends

```
POST https://graph.microsoft.com/beta/security/threatSubmission/emailThreats
Content-Type: application/json

{
  "@odata.type": "#microsoft.graph.security.emailContentThreatSubmission",
  "recipientEmailAddress": "j.rivera@contoso.com",
  "category": "phishing",
  "source": "user",
  "fileContent": "<base64 of the original .eml>"
}
```

`emailThreats` is a **beta** resource at the time of writing. Pin it with
`--api-version` if it graduates to `v1.0` in your tenant, and re-check the
current shape in the Graph reference before trusting a field.

Two submission shapes exist, and the difference matters:

| Shape | Field | When to use |
|---|---|---|
| `emailContentThreatSubmission` | `fileContent` (base64 `.eml`) | The message is an attachment in the shared mailbox. **This is what the script uses.** |
| `emailUrlThreatSubmission` | `messageUrl` pointing at `…/users/{id}/messages/{id}` | The message is still sitting in a mailbox you can address by id. |

The script uses the content shape because a forwarded report gives you the
original as an attachment, not as an addressable mailbox item.

### Getting the original, not the forward

This is the part that goes wrong in hand-rolled versions. If you submit the
message sitting in the shared mailbox, Defender analyses the *reporter's*
forward — which is internal, authenticated, and clean — and comes back "no
threats found". The verdict is worthless and the reporter gets told their
report was fine.

`classify_attachments()` picks the real message out of the wrapper:

- **`itemAttachment`** — Outlook's "Forward as Attachment". Fetched as raw MIME
  from `/attachments/{id}/$value`. Preferred.
- **`fileAttachment`** with content type `message/rfc822` or a `.eml` name — a
  dragged-in file. Decoded from `contentBytes`.
- **`.msg` files** — Outlook's own format, not RFC822, so the submissions API
  cannot take them. Reported as `outlook_msg_not_rfc822` for manual handling.
- **Inline images** from the forward's own body — ignored, not flagged.

If nothing submittable is attached (the user pasted a screenshot, or hit
Forward instead of Forward-as-Attachment), the message is skipped with
`no_original_attached`. `--allow-wrapper` overrides this, but read the warning
above before you use it: what you get back is a verdict on the wrong email.

### Picking the recipient

`recipientEmailAddress` is required, and Defender uses it to scope the
investigation. It should be the mailbox the phish was *delivered to*, not the
shared mailbox and not necessarily the person who forwarded it. The script
resolves, in order: `Delivered-To` / `X-Original-To` / `Envelope-To`, then
To/Cc filtered to `--org-domain`, then any To/Cc address, then the reporter.
Every result records which rule fired in `recipient_source`, so a wrong
submission is traceable.

Pass `--org-domain` for each domain you own. Without it, a phish addressed to
an external partner first will resolve to that partner.

### User reported vs. admin submission

The pasted claim that this lands in **Submissions → User reported** is true
only for submissions Microsoft attributes to a user:

- **Delegated token** (signed in as the reporter, `ThreatSubmission.ReadWrite`)
  → user submission, User reported tab.
- **App-only token** (`ThreatSubmission.ReadWrite.All`) → admin submission,
  regardless of what `source` you send.

Both create the submission and both drive AIR. The tab, and whether Defender's
user-notification templates fire, is what differs. The script sends
`--source user` by default and falls back automatically if the tenant rejects
the property; supply your own delegated token in `GRAPH_ACCESS_TOKEN` if the
User reported tab is a hard requirement. If reports end up as admin
submissions, notify reporters yourself — see `response-actions.md`, "Notify
reporter with verdict".

## Setup

### 1. App registration

Entra ID → App registrations → New registration. Record the tenant id and
application (client) id.

**Application permissions** (admin consent required):

| Permission | Why |
|---|---|
| `Mail.Read` | Read the shared mailbox and its attachments |
| `Mail.ReadWrite` | Only if you use `--mark-read` or `--move-to` |
| `ThreatSubmission.ReadWrite.All` | Create the submission |

For the delegated path instead: `Mail.Read` + `ThreatSubmission.ReadWrite`,
consented for the account whose token you use.

Prefer a certificate or a federated (workload identity) credential over a
client secret. If you use a secret, keep it in Key Vault, give it a short life,
and never in the repo.

### 2. Scope the mailbox access — do this, then prove it

`Mail.Read` as an application permission reads **every mailbox in the tenant**.
Consenting it and pointing the script at one mailbox does not narrow anything;
it just means the app is not currently using the rest of its reach. Narrow it
with one of the two mechanisms below, then verify with step 2c — the
verification is the part that matters, because a scope that was removed,
mis-typed, or never propagated looks exactly like a scope that works.

#### 2a. Exchange Online RBAC for Applications (current mechanism)

Assign the app a role whose resource scope contains only the phishing mailbox:

```powershell
Connect-ExchangeOnline

New-ServicePrincipal -AppId <application-client-id> `
    -ObjectId <enterprise-application-object-id> `
    -DisplayName "Phishing submission automation"

New-ManagementScope -Name "Phish mailbox only" `
    -RecipientRestrictionFilter "PrimarySmtpAddress -eq 'phish@contoso.com'"

New-ManagementRoleAssignment -App <application-client-id> `
    -Role "Application Mail.Read" `
    -CustomResourceScope "Phish mailbox only"

Test-ServicePrincipalAuthorization -Identity <application-client-id>
```

Use `Application Mail.ReadWrite` instead if you want `--mark-read` / `--move-to`.

#### 2b. Application access policy (older mechanism, still widely deployed)

```powershell
New-DistributionGroup -Name "Graph-Phish-Submitter-Scope" -Type Security `
    -Members phish@contoso.com

New-ApplicationAccessPolicy `
    -AppId <application-client-id> `
    -PolicyScopeGroupId Graph-Phish-Submitter-Scope@contoso.com `
    -AccessRight RestrictAccess `
    -Description "Phishing submission automation: shared phish mailbox only"

Test-ApplicationAccessPolicy -Identity phish@contoso.com -AppId <application-client-id>
Test-ApplicationAccessPolicy -Identity ceo@contoso.com  -AppId <application-client-id>
```

The first test must return `Granted`, the second `Denied`. Policy changes can
take up to an hour to propagate, so a `Granted` you did not expect may just be
a stale policy — re-test before concluding anything.

Which to use: if the tenant already has application access policies for other
apps, matching them keeps one mechanism to reason about. Otherwise prefer RBAC
for Applications. Do not rely on having configured *both* without testing —
they are evaluated separately and the interaction is not obvious.

#### 2c. Prove it from the app's side, every run

Both mechanisms are invisible to the application: a correctly scoped app and a
tenant-wide one behave identically right up until someone reads the wrong
mailbox. So the script asserts the restriction instead of trusting it.

```bash
# Deployment gate: exits 0 only if access is provably restricted, 3 otherwise
python scripts/graph_submit.py \
    --mailbox phish@contoso.com \
    --deny-check ceo@contoso.com \
    --deny-check payroll@contoso.com \
    --check-scope
```

It reads one message header from the target mailbox (must succeed) and from
each `--deny-check` address (must return 403). Pick control mailboxes that
really exist and are really sensitive — an exec, payroll, legal.

Carry the same `--deny-check` flags on the real run and the probe happens
before any mail is read; a control mailbox that turns out to be readable aborts
the run with exit 3 rather than quietly processing the queue with tenant-wide
reach. `--allow-broad-access` overrides it, and says so in the log.

Two deliberate design points:

- **A 404 is not accepted as proof.** A mailbox that does not exist is denied
  for the wrong reason, and treating that as a pass would hide a genuinely
  over-scoped app. A typo in `--deny-check` reports `inconclusive`, not
  `scoped`, and fails the gate.
- **No controls means unverified, not verified.** Running without
  `--deny-check` reports `unchecked` and fails `--check-scope`. Silence is not
  evidence.

Put `--check-scope` in whatever runs before the scheduled job — CI, the deploy
step, or a weekly cron whose failure pages someone. Scopes get removed during
unrelated Exchange work, and the first sign otherwise would be an audit log
nobody reads.

#### What cannot be scoped

`ThreatSubmission.ReadWrite.All` is tenant-wide by nature. That is acceptable:
it creates submissions, it does not read mail. There is no mailbox content
reachable through it.

### 3. Run it

```bash
export GRAPH_TENANT_ID=... GRAPH_CLIENT_ID=... GRAPH_CLIENT_SECRET=...

# See exactly what would be submitted, and to whom, without sending anything
python scripts/graph_submit.py \
    --mailbox phish@contoso.com \
    --org-domain contoso.com \
    --since 7d --dry-run --json

# Then for real, on a schedule. Keep --deny-check on the scheduled run so the
# scope is re-asserted every time, not just at deploy.
python scripts/graph_submit.py \
    --mailbox phish@contoso.com \
    --org-domain contoso.com \
    --deny-check ceo@contoso.com \
    --state /var/lib/phish-triage/state.json \
    --dedupe-original --mark-read --move-to archive
```

Always run `--dry-run --json` first against a real backlog and read the
`recipient` / `recipient_source` / `original.subject` of a dozen items. That is
the cheapest way to catch a bad `--org-domain` before you create a hundred
mis-scoped submissions.

### Flags worth knowing

| Flag | Effect |
|---|---|
| `--state PATH` | Watermark + processed-id ledger. Without it, every run re-reads `--since` and relies on nothing; with it, reruns are idempotent. |
| `--dedupe-original` | Ten people forward the same campaign → one submission, nine skips. |
| `--max-eml-bytes` | Graph caps request bodies near 4 MB and base64 inflates by a third; larger originals are skipped, not truncated. |
| `--mark-read` / `--move-to` | Mailbox housekeeping so the queue drains visibly. Needs `Mail.ReadWrite`. A failure here never discards a successful submission. |
| `--category` | `phishing`, `malware`, `spam`, `notJunk`. `notJunk` is the false-positive path. |
| `--json` | Machine-readable per-message results — feed this into the shift report's automation-gap tally. |
| `--deny-check ADDR` | Mailbox this app must not be able to read. Repeatable. Probed before any mail is read; readable means over-scoped and the run aborts. |
| `--check-scope` | Run only that probe and exit — 0 if provably restricted, 3 otherwise. A deployment gate. |
| `--allow-broad-access` | Proceed past a failed scope check. Logs a warning; you are asserting the broad access is intended. |

Exit codes: `0` clean, `1` at least one message errored, `2` the run itself
failed (auth, permissions, listing), `3` the scope check failed — the app can
read mailboxes it should not, or cannot read the one it should.

## Where to run it

- **Cron / systemd timer on an existing SOC host** — simplest. Every 15 minutes
  is plenty; the mailbox is a fallback path, not a live queue.
- **Azure Function (timer trigger)** with a managed identity — no secret to
  rotate. Acquire the token from IMDS and pass it in `GRAPH_ACCESS_TOKEN`.
- **Azure Logic App / Power Automate** — the same flow without Python: "When a
  new email arrives (V3)" on the shared mailbox → get attachments → HTTP action
  to the `emailThreats` endpoint. Easier to hand over, harder to test, and you
  will re-implement the original-vs-forward extraction yourself.

Run one instance at a time against a given mailbox. The state file is not
locked, and two concurrent runs will double-submit.

## Reading the verdict back

```
GET /beta/security/threatSubmission/emailThreats/{submissionId}
```

Returns `status` (`notStarted` / `running` / `succeeded` / `failed`) and, once
finished, the `result` with Defender's detection verdict. AIR runs separately
and is visible in the Action center. The script records the submission id per
message so you can correlate later; it deliberately does not poll, because the
verdict is an input to analyst triage, not to the submission.

## Throttling and failure

Graph throttles per-mailbox and per-app. The client honours `Retry-After` on
429, backs off exponentially on 5xx and network errors, and caps waits at two
minutes. A per-message Graph failure is recorded as `error` and the run
continues — one bad message never blocks the queue.

## What this does not do

Unchanged from the skill's guardrails, and worth restating because this script
is the one piece here that writes anywhere:

- Never fetches a URL from reported mail, never opens or detonates an
  attachment, never replies to or forwards to a sender.
- Never remediates: no purge, no block, no reset, no AIR approval.
- Never decides a verdict. It hands the message to Defender and stops.
- Logs headers only — sender, subject, message id. Bodies and URLs stay out of
  the logs.

The submission itself is the single outward action, and it is the action
`response-actions.md` already prescribes for this lane: *"Submit to Microsoft
on the user's behalf."*

## Verification checklist

1. `--check-scope --deny-check <an exec's mailbox>` exits 0. If it exits 3,
   stop and fix the scope before going further — everything below assumes the
   app can only reach the phishing mailbox.
2. `--dry-run --json` resolves the right `recipient` for a known report.
3. One real submission appears in Defender → Submissions with the **original**
   sender and subject, not `FW:` and the reporter.
4. AIR starts on it, and the reporter is notified (or you notify them, if the
   submission landed as an admin submission).
5. A second run over the same window submits nothing.
6. `--check-scope` is wired into whatever runs before the scheduled job, so a
   scope removed six months from now fails loudly instead of silently widening
   what this app can read.
