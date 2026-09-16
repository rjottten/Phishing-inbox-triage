# Deployment runbook

Getting forwarded phishing reports submitted to Defender automatically, on a
schedule, with no client secret to manage.

This is written to be handed to whoever holds Entra ID and Exchange Online admin.
It does not assume they have read anything else in this repository.

> **Status: not yet run against a live tenant.** The Graph code is unit-tested
> against recorded payload shapes, not a real Microsoft 365. `emailThreats` is a
> **beta** Graph resource, so field shapes can move. Steps 5 and 6 exist to catch
> that on the first day rather than the first incident — do not skip them.

Two companions to this: [`data-flow.md`](data-flow.md) for a security or privacy
review — what is read, sent where, and kept — and [`costs.md`](costs.md) for whoever
approves the spend. The short version of the second is that the recurring cost is
under a pound a month unless you deploy the optional model layer, **provided you
already have Defender for Office 365 Plan 2**, which step 0 is the moment to check.

## Who is needed

| Step | Role |
|---|---|
| 0 — check Defender's own setting | Security admin |
| 1–2 — app registration, permissions, consent | Entra ID (Global or Cloud Application) admin |
| 3 — scope `Mail.Read` to one mailbox | Exchange Online admin |
| 4–7 — deploy and run | Whoever owns the Azure subscription |

Steps 1 and 3 are different people in most organisations. Step 3 is the one that
matters most; see the warning in it.

---

## 0. Check whether you need any of this

**Defender portal → Settings → Email & collaboration → User reported settings.**

If Defender can monitor your reporting mailbox natively, use that instead. It is
supported by Microsoft, there is no token to rotate, and it notifies reporters —
which this deployment does not (see [What this does not do](#what-this-does-not-do)).

This runbook is for what that configuration does not cover.

---

## 1. Register the application

Entra ID → **App registrations** → **New registration**. Single tenant. Name it
something an auditor will recognise, e.g. *Phishing submission automation*.

Record the **Directory (tenant) ID** and **Application (client) ID**.

You do **not** need a client secret. The Function authenticates with a managed
identity, which is the main reason to run it in Azure — there is no credential to
store, rotate, or leak. (If you deploy somewhere else instead, see
[Running it elsewhere](#running-it-elsewhere).)

## 2. Grant Graph permissions

These are **Application** permissions, not delegated.

| Permission | Why |
|---|---|
| `Mail.Read` | Read the shared mailbox and the attached original. **Scoped in step 3.** |
| `ThreatSubmission.ReadWrite.All` | Create the Defender submission. Tenant-wide by nature |
| `Mail.ReadWrite` | Only if you want handled reports marked read or filed |
| `ThreatHunting.Read.All` | Optional. Without it, click telemetry is reported as unverified rather than guessed at |

Then **Grant admin consent** for the tenant.

`ThreatSubmission.ReadWrite.All` cannot be scoped to a mailbox. That is acceptable:
its only power is to hand a message to Microsoft for analysis, which starts an
investigation and changes nothing else.

## 3. Scope `Mail.Read` to the one mailbox

> **`Mail.Read` as an application permission reads every mailbox in the tenant.**
> Consenting it and pointing the job at one mailbox narrows nothing — it only means
> the app is not currently using the rest of its reach. Do not skip this step, and
> do not treat step 2 as having done it.

Pick **one** mechanism. If the tenant already uses application access policies for
other apps, match that; otherwise prefer RBAC for Applications.

### 3a. RBAC for Applications (current mechanism)

```powershell
Connect-ExchangeOnline

# A managed identity has both an app id and an object id; you need both here.
New-ServicePrincipal -AppId <app-or-managed-identity-client-id> `
    -ObjectId <enterprise-application-object-id> `
    -DisplayName "Phishing submission automation"

New-ManagementScope -Name "Phish mailbox only" `
    -RecipientRestrictionFilter "PrimarySmtpAddress -eq 'phish@contoso.com'"

New-ManagementRoleAssignment -App <app-or-managed-identity-client-id> `
    -Role "Application Mail.Read" `
    -CustomResourceScope "Phish mailbox only"

Test-ServicePrincipalAuthorization -Identity <app-or-managed-identity-client-id>
```

Use `Application Mail.ReadWrite` instead if you want the housekeeping flags.

### 3b. Application access policy (older, still widely deployed)

```powershell
New-DistributionGroup -Name "Graph-Phish-Submitter-Scope" -Type Security `
    -Members phish@contoso.com

New-ApplicationAccessPolicy -AppId <client-id> `
    -PolicyScopeGroupId Graph-Phish-Submitter-Scope@contoso.com `
    -AccessRight RestrictAccess `
    -Description "Phishing submission automation: shared phish mailbox only"

Test-ApplicationAccessPolicy -Identity phish@contoso.com -AppId <client-id>   # Granted
Test-ApplicationAccessPolicy -Identity ceo@contoso.com  -AppId <client-id>    # Denied
```

Changes can take up to an hour to propagate. A `Granted` you did not expect may
just be a stale policy — re-test before concluding anything. Do not configure both
mechanisms and assume they combine; they are evaluated separately.

---

## 4. Create the Function app

```bash
RG=rg-phish-triage
LOC=eastus
APP=func-phish-triage          # must be globally unique
SA=stphishtriage$RANDOM        # must be globally unique, lowercase

az group create -n $RG -l $LOC
az storage account create -n $SA -g $RG -l $LOC --sku Standard_LRS
az functionapp create -n $APP -g $RG --storage-account $SA \
    --consumption-plan-location $LOC --os-type Linux \
    --runtime python --runtime-version 3.11 --functions-version 4

az functionapp identity assign -n $APP -g $RG
```

That last command prints the managed identity's **principalId** — its object id in
Entra. Record it.

### Grant the Graph roles to the managed identity

This cannot be done in the portal UI, so it is a short PowerShell step:

```powershell
Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All","Application.Read.All"

$graph = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$mi    = Get-MgServicePrincipal -ServicePrincipalId "<principalId from above>"

foreach ($name in @("Mail.Read", "ThreatSubmission.ReadWrite.All")) {
    $role = $graph.AppRoles | Where-Object {
        $_.Value -eq $name -and $_.AllowedMemberTypes -contains "Application" }
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $mi.Id `
        -PrincipalId $mi.Id -ResourceId $graph.Id -AppRoleId $role.Id
}
```

Add `Mail.ReadWrite` and `ThreatHunting.Read.All` to that list if you are using
them. Then apply **step 3 to the managed identity's client id**, not just to the
app registration from step 1.

### Configure it

```bash
az functionapp config appsettings set -n $APP -g $RG --settings \
    PHISH_MAILBOX="phish@contoso.com" \
    PHISH_ORG_DOMAIN="contoso.com" \
    PHISH_DENY_CHECK="ceo@contoso.com"
```

`PHISH_DENY_CHECK` names a mailbox this app must **not** be able to read. The job
probes it before reading any mail and aborts if it turns out to be readable. It is
required — the deployment refuses to start without it, because a scope that never
propagated looks exactly like one that works.

Full settings list is in [Settings](#settings) below. Note there is no
`PHISH_DRY_RUN` to switch on: **runs are dry by default** and going live takes an
explicit `PHISH_DRY_RUN_OFF=true` in step 7.

### Deploy

```bash
./azure-function/prepare.sh          # copies the stdlib scripts into the app
cd azure-function
func azure functionapp publish $APP
```

`prepare.sh` copies `graph_submit.py`, `triage.py` and `parse_headers.py` in. They
are stdlib-only, so there is nothing to build. The copies are git-ignored so they
cannot drift from the originals.

---

## 5. Prove the scope, before any mail is read

From any machine with the credentials — a workstation is fine:

```bash
export GRAPH_TENANT_ID=... GRAPH_CLIENT_ID=... GRAPH_CLIENT_SECRET=...

python skills/phishing-inbox-triage/scripts/graph_submit.py \
    --mailbox phish@contoso.com --deny-check ceo@contoso.com --check-scope
```

| Exit | Meaning |
|---|---|
| `0` | Access is provably restricted. Proceed |
| `3` | Not proven. **Stop and fix step 3** |

A typo'd control mailbox reports `inconclusive` rather than passing, and no control
at all reports `unchecked`. Silence is not evidence.

Use this as a deployment gate. The Function re-runs the same probe on every firing.

## 6. Read a dry run

The Function is already running dry. Watch a firing:

```bash
az webapp log tail -n $APP -g $RG
```

Or trigger one from a workstation to see the detail:

```bash
python skills/phishing-inbox-triage/scripts/graph_submit.py \
    --mailbox phish@contoso.com --org-domain contoso.com \
    --deny-check ceo@contoso.com --since 7d \
    --dry-run --json --worklist /tmp/worklist.json
```

**Nothing is submitted.** What you are checking:

- `submitted` vs `skipped` counts — how much manual effort this actually removes.
- The worklist — what is left, and why. `python .../graph_submit.py --worklist
  /tmp/worklist.json --worklist-report` renders it. `outlook_msg_not_rfc822` there
  means users are dragging mail into a new message, which the extractor cannot read
  yet; a pile of `not_an_email_attachment` means screenshots.
- That the senders and subjects in the output are the **original** phish, not the
  colleague who forwarded it. This is the single thing most worth eyeballing — get
  it wrong and Defender analyses your own clean internal mail.

## 7. Go live

```bash
az functionapp config appsettings set -n $APP -g $RG --settings PHISH_DRY_RUN_OFF=true
```

Optionally add `PHISH_MARK_READ=true` and `PHISH_MOVE_TO=archive` so the mailbox
visibly drains. Those need `Mail.ReadWrite`.

Watch the first live firing. Then confirm in **Defender → Actions & submissions →
Submissions** that the submissions appear and AIR picks them up.

---

## Settings

| Setting | Required | Default | Meaning |
|---|---|---|---|
| `PHISH_MAILBOX` | **yes** | — | The shared reporting mailbox |
| `PHISH_ORG_DOMAIN` | **yes** | — | Your mail domain(s), comma-separated. Used to find the real recipient in the original |
| `PHISH_DENY_CHECK` | **yes** | — | Mailbox(es) this app must NOT reach, comma-separated |
| `PHISH_DRY_RUN_OFF` | no | unset | `true` to actually submit. Everything else means dry |
| `PHISH_MARK_READ` | no | `false` | Mark handled reports read. Needs `Mail.ReadWrite` |
| `PHISH_MOVE_TO` | no | — | Folder to file handled reports into. Needs `Mail.ReadWrite` |
| `PHISH_CAPTURE_REPORTER_NOTE` | no | `false` | Also read the one line the reporter typed above the forward. The strongest P1 signal there is — see the README |
| `PHISH_LOOKBACK_HOURS` | no | `24` | Window on a first run, before a watermark exists |
| `PHISH_MAX` | no | `100` | Messages per firing |
| `PHISH_STATE_CONTAINER` | no | `phish-triage` | Blob container for state and the worklist |

State and the worklist are kept in blob storage, not on the Function's disk, which
is ephemeral. Losing the state file means resubmitting everything in the lookback
window, so this matters.

The timer runs every 15 minutes (`0 */15 * * * *` in `function_app.py`). Timer
triggers hold a storage lease, so only one instance fires at a time — which is
required here, because two concurrent runs against one mailbox would double-submit.

---

## What this does not do

**It does not notify the reporter.** Defender's user-notification templates fire
for *user* submissions; an app-only token always produces an *administrator*
submission. So the "here's what your report turned out to be" mail stays manual
unless you use step 0, or a delegated token with `--source user`. Know this before
telling anyone the loop is closed.

**It does not remediate.** No purge, block, credential reset, or AIR approval.
Submitting a message for analysis is the only outward action anywhere in this
repository.

**It does not triage.** `graph_submit.py` gets reports *into* Defender.
`triage.py` sorts what comes back, and is a separate run — see the README.

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `scope check failed`, exit 3 | Step 3 not applied, applied to the wrong identity, or not yet propagated. Re-run step 5 |
| `no usable credentials` | The managed identity has no Graph role assignment, or `az functionapp identity assign` was not run |
| Everything skips with `no_recipient_resolved` | `PHISH_ORG_DOMAIN` is wrong or missing |
| Everything skips with `no_original_attached` | Users are pasting or screenshotting rather than attaching. Expected — see the worklist, and `agents/README.md` |
| Duplicate submissions after a restart | State is not persisting. Check `AzureWebJobsStorage` and the blob container |
| 403 from the submissions endpoint | Admin consent was not granted for `ThreatSubmission.ReadWrite.All` |
| Runs, submits nothing, no errors | Still in dry-run mode. `PHISH_DRY_RUN_OFF` is not `true` |

---

## Running it elsewhere

The Function is a recommendation, not a requirement — it is just a scheduled Python
process. Any of these work:

- **A host you already have, with cron or a systemd timer.** Simplest. The cost is
  a client secret to store and rotate; put it in a secret store, not a shell profile.
- **Azure Container Apps job.** Same managed-identity benefit if you prefer
  containers.
- **Not GitHub Actions.** Tenant credentials and reported mail content would pass
  through runners outside your control.

Whatever you choose: one instance at a time per mailbox, and persist the state file.
