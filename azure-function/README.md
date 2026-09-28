# Azure Function App deployment

Runs the repo's scripts on a schedule in an Azure Function App. The scripts are
deployed unchanged; `runner.py` supplies what a shell would have and a Function
does not: settings, credentials, durable state, and failures you can alert on.

| Function | Trigger | Runs | Needed? |
|---|---|---|---|
| `submit_forwarded_reports` | Timer, `PHISH_SUBMIT_SCHEDULE` | `graph_submit.py`: forwarded reports in the shared mailbox → Defender submissions | **Yes** |
| `collect_and_triage` | Timer, `PHISH_TRIAGE_SCHEDULE` | `collect_export.py` then `triage.py` → export and handover report in Blob storage | Optional |

To run only submissions, set `AzureWebJobs.collect_and_triage.Disabled=true`.

There is no separate scope-check function. Every run of either job that reads
the mailbox probes the `PHISH_DENY_CHECK` mailboxes first, and stops before
reading any mail if one of them is readable.

## Files

```
azure-function/
├── function_app.py              # the two timer triggers (Python v2 model)
├── runner.py                    # settings → flags, token, Blob state, exit codes
├── host.json                    # 10-minute timeout, extension bundle
├── requirements.txt             # azure-functions, azure-identity, azure-storage-blob
├── local.settings.json.example  # for `func start`; copy to local.settings.json
└── package.sh                   # builds dist/ with the scripts copied in
```

The tests are in `tests/test_function_runner.py`. They drive the real scripts
through the wrapper with Graph and Blob storage stubbed, so they need no Azure
SDK and run in CI with the rest.

## Deploy

### 1. Function App

Linux, Python 3.11, on Flex Consumption or Consumption. Turn on the
**system-assigned managed identity** (or attach a user-assigned identity and
set `PHISH_MANAGED_IDENTITY_CLIENT_ID`).

```bash
az functionapp create -g <rg> -n <app> --storage-account <storage> \
    --flexconsumption-location <region> --runtime python --runtime-version 3.11
az functionapp identity assign -g <rg> -n <app>
```

### 2. Storage for state and reports

The identity needs **Storage Blob Data Contributor** on the account that holds
the container (default name `phish-triage`, created on first run):

```bash
az role assignment create --assignee <identity-principal-id> \
    --role "Storage Blob Data Contributor" \
    --scope /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Storage/storageAccounts/<storage>
```

Set `PHISH_STORAGE_ACCOUNT_URL=https://<storage>.blob.core.windows.net`. Without it,
the wrapper uses the connection string in `PHISH_STORAGE_CONNECTION_STRING`, and
falls back to `AzureWebJobsStorage` if that is unset too.

Keep the container private. The run results include reporter addresses and
subjects, and with `PHISH_CAPTURE_REPORTER_NOTE` the state holds reporters'
notes.

### 3. Graph permissions for the managed identity

The portal cannot grant Graph application permissions to a managed identity, so
use PowerShell:

```powershell
Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All","Application.Read.All"
$mi    = Get-MgServicePrincipal -Filter "displayName eq '<app>'"
$graph = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

# ThreatHunting.Read.All is only needed by collect_and_triage.
foreach ($perm in "ThreatSubmission.ReadWrite.All", "ThreatHunting.Read.All") {
    $role = $graph.AppRoles | Where-Object { $_.Value -eq $perm -and $_.AllowedMemberTypes -contains "Application" }
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $mi.Id `
        -PrincipalId $mi.Id -ResourceId $graph.Id -AppRoleId $role.Id
}
```

### 4. Mailbox access, limited to the phishing mailbox

Mailbox access is granted **once, by exactly one of these**:

- **RBAC for Applications (preferred).** Do *not* grant `Mail.Read` in Entra.
  Grant it through Exchange with a scope that holds only the phishing mailbox,
  as in `references/graph-automation.md` §2a, using the identity's application
  id and object id:
  ```powershell
  New-ServicePrincipal -AppId <mi-app-id> -ObjectId <mi-object-id> -DisplayName "<app>"
  New-ManagementScope -Name "Phish mailbox only" `
      -RecipientRestrictionFilter "PrimarySmtpAddress -eq 'phish@contoso.com'"
  New-ManagementRoleAssignment -App <mi-app-id> -Role "Application Mail.Read" `
      -CustomResourceScope "Phish mailbox only"
  ```
  Use `Application Mail.ReadWrite` if you turn on `PHISH_MARK_READ` or
  `PHISH_MOVE_TO`. Exchange RBAC grants and Entra grants are added together: a
  `Mail.Read` consent left in Entra keeps access to every mailbox, whatever the
  Exchange scope says.
- **Application access policy.** Grant `Mail.Read` in Entra (the loop above), then
  restrict it with `New-ApplicationAccessPolicy` as in §2b.

Either way, `PHISH_DENY_CHECK` makes each run prove the restriction. If the app
turns out able to read an executive's mailbox, the run fails with
`ScopeCheckFailed` before any mail is read.

### 5. App settings, then publish

Set the settings below (start with `PHISH_DRY_RUN=true`), then:

```bash
./azure-function/package.sh
cd azure-function/dist && func azure functionapp publish <app> --python
```

### 6. First runs

1. Run with `PHISH_DRY_RUN=true`. In `runs/submit/<timestamp>.json`, check the
   `recipient`, `recipient_source` and `original.subject` of a dozen items.
2. Set `PHISH_DRY_RUN=false`. One submission should appear in Defender →
   Submissions with the **original** sender and subject, not `FW:` from the reporter.
3. The next run submits nothing new.
4. Alert on failed invocations of either function in Application Insights. A
   `ScopeCheckFailed` means the Exchange scope has changed.

## App settings

**Required**

| Setting | Example | Meaning |
|---|---|---|
| `PHISH_SUBMIT_SCHEDULE` | `0 */15 * * * *` | NCRONTAB (six fields, UTC unless `WEBSITE_TIME_ZONE` is set) |
| `PHISH_TRIAGE_SCHEDULE` | `0 0 6,18 * * *` | Must be set even if the function is disabled |
| `PHISH_MAILBOX` | `phish@contoso.com` | The shared reporting mailbox |
| `PHISH_DENY_CHECK` | `ceo@contoso.com,payroll@contoso.com` | Real, sensitive mailboxes that must return 403. Refused if empty unless `PHISH_ALLOW_UNVERIFIED_SCOPE=true` |
| `PHISH_ORG_DOMAINS` | `contoso.com,contoso.eu` | Your domains; used to pick the real recipient out of the original's To/Cc |

**Credentials**

| Setting | Default | Meaning |
|---|---|---|
| `PHISH_GRAPH_AUTH` | `managed_identity` | Or `client_secret`, which uses `GRAPH_TENANT_ID` / `GRAPH_CLIENT_ID` / `GRAPH_CLIENT_SECRET` (store the secret as `@Microsoft.KeyVault(SecretUri=...)`) |
| `PHISH_MANAGED_IDENTITY_CLIENT_ID` | — | Only for a user-assigned identity |
| `GRAPH_ACCESS_TOKEN` | — | **Leave unset.** The wrapper fetches a token each run and refuses to start if a static one is configured |

**Storage**

| Setting | Default |
|---|---|
| `PHISH_STORAGE_ACCOUNT_URL` | — (managed identity) |
| `PHISH_STORAGE_CONNECTION_STRING` | falls back to `AzureWebJobsStorage` |
| `PHISH_STORAGE_CONTAINER` | `phish-triage` |
| `PHISH_STATE_BLOB` | `state/graph_submit_state.json` |

**Submission job** (`graph_submit.py` flag in brackets)

| Setting | Default | |
|---|---|---|
| `PHISH_DRY_RUN` | `false` | [`--dry-run`] State is not written back on a dry run, so the real run still processes those messages |
| `PHISH_FOLDER` | `inbox` | [`--folder`] |
| `PHISH_CATEGORY` | `phishing` | [`--category`] |
| `PHISH_MAX` | `100` | [`--max`] messages per run; keep runs inside the 10-minute timeout |
| `PHISH_DEFAULT_LOOKBACK_HOURS` | `24` | [`--default-lookback-hours`] first run only |
| `PHISH_DEDUPE_ORIGINAL` | `true` | [`--dedupe-original`] |
| `PHISH_MARK_READ` | `false` | [`--mark-read`] needs Mail.ReadWrite |
| `PHISH_MOVE_TO` | — | [`--move-to`] needs Mail.ReadWrite |
| `PHISH_CAPTURE_REPORTER_NOTE` | `false` | [`--capture-reporter-note`] also feeds the notes to the triage job |
| `PHISH_SOURCE` | script default | [`--source`] |
| `PHISH_API_VERSION` | `beta` | [`--api-version`] |
| `PHISH_KEEP_RUN_RESULTS` | `true` | Write each run's per-message results to `runs/submit/<timestamp>.json` |

**Triage job**

| Setting | Default | |
|---|---|---|
| `PHISH_TRIAGE_SINCE` | `24h` | Window to collect; match it to the schedule |
| `PHISH_TRIAGE_MAX` | `200` | Items per source |
| `PHISH_COLLECT_MAILBOX` | `false` | Also read the mailbox, including message bodies. Off by default: the submit job already sends forwarded reports to Defender, so they arrive through Submissions |
| `PHISH_NO_HUNTING` | `false` | Skip Advanced Hunting enrichment (then `ThreatHunting.Read.All` is not needed) |
| `PHISH_ORG_CONTEXT_BLOB` | — | e.g. `config/org-context.json` in the container: VIPs, known vendors |
| `PHISH_STUCK_HOURS` / `PHISH_LARGE_SCOPE` | `4` / `100` | `triage.py` thresholds |

Outputs: `exports/<timestamp>.json`, `reports/<timestamp>.md`,
`reports/<timestamp>.json`, and `reports/latest.md` / `latest.json`.
`export_meta.collection_notes` is also logged as warnings, because that is
where a partial queue shows itself.

## Behaviour worth knowing

- **Failures raise.** Exit 1 (some messages failed) and exit 2 (auth, permissions
  or listing) raise `RunFailed`; exit 3 raises `ScopeCheckFailed`. State is
  written back first, so what did get submitted is not submitted again.
- **State is written with an ETag condition.** If the state blob changed during
  a run, the write fails with `StateConflict` rather than overwriting.
  Timer triggers are singletons, so this should only happen if the job is also
  run from somewhere else. Don't do that.
- **Submissions are admin submissions.** An app or managed-identity token cannot
  produce a "User reported" submission, and Defender may not notify the reporter.
  See `references/graph-automation.md`, "User reported vs. admin submission".
- **One job at a time per worker.** Both functions share a lock, because the
  scripts' stdout, stderr and the token environment variable are process-wide.
