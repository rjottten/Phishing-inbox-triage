# Azure Function App deployment

Runs the repo's scripts on a schedule in an Azure Function App. The scripts are
deployed unchanged; `runner.py` supplies what a shell would have and a Function
does not: settings, credentials, durable state, and failures you can alert on.

| Function | Trigger | Runs | Needed? |
|---|---|---|---|
| `submit_forwarded_reports` | Timer, `PHISH_SUBMIT_SCHEDULE` | `graph_submit.py`: forwarded reports in the shared mailbox → Defender submissions | **Yes** |
| `collect_and_triage` | Timer, `PHISH_TRIAGE_SCHEDULE` | `collect_export.py` then `triage.py` → export and handover report in Blob storage, and optionally one row per item to Microsoft Sentinel | Optional |

To run only submissions, set `AzureWebJobs.collect_and_triage.Disabled=true`
(`disableTriage=true` in the template).

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
├── package.sh                   # builds dist/ with the scripts copied in
├── infra/main.bicep             # the Function App, plan, storage, identity and settings
└── sentinel/                    # optional: table, ingestion rule and analytics rule, see its README
```

`.github/workflows/deploy-function.yml` publishes `dist/` to the app from
GitHub Actions, over OpenID Connect.

The tests are in `tests/test_function_runner.py`. They drive the real scripts
through the wrapper with Graph and Blob storage stubbed, so they need no Azure
SDK and run in CI with the rest.

## Deploy

Six steps. The first creates the Azure resources, the next three are grants
that have to be made in Azure, Entra and Exchange, the fifth publishes the
code, and the sixth is checking it works before it submits anything.

### 1. Resources: the template

[`infra/main.bicep`](infra/main.bicep) creates a Flex Consumption plan, the
Linux / Python 3.11 function app, a storage account with shared-key access
off, a user-assigned managed identity with the storage and monitoring roles
it needs, Application Insights, and the app settings, with `PHISH_DRY_RUN`
on. Whoever deploys it needs Contributor on the resource group and the right
to assign roles there (Owner, or User Access Administrator).

```bash
az group create -n <rg> -l <region>      # Flex Consumption is not in every region:
                                         # az functionapp list-flexconsumption-locations
az deployment group create -g <rg> -f azure-function/infra/main.bicep \
    -p appName=<app> \
       mailbox=phish@contoso.com \
       orgDomains=contoso.com,contoso.eu \
       denyCheck=ceo@contoso.com,payroll@contoso.com \
    --query properties.outputs
```

Keep the outputs: `identityPrincipalId` and `identityClientId` are the ids
the next three steps grant to. The other parameters (`submitSchedule`,
`triageSchedule`, `disableTriage`, `pythonVersion`, the Sentinel pair, an
existing `logAnalyticsWorkspaceId`) are documented in the file, and anything
else from the settings tables below goes in `extraAppSettings`:

```bash
    -p extraAppSettings='{"PHISH_CAPTURE_REPORTER_NOTE":"true","PHISH_MAX":"50"}'
```

**The template owns the app settings.** It writes the whole set on every
deployment, so a setting changed in the portal or with `az functionapp config
appsettings set` is reset the next time the template runs. Make lasting
changes through the parameters, and keep the parameter values with the
deployment (a `.bicepparam` file in your private repo, or the pipeline's
variables), not in someone's shell history.

If you would rather create the resources by hand, the app needs: Linux,
Python 3.11, Flex Consumption; a managed identity (set
`PHISH_MANAGED_IDENTITY_CLIENT_ID` if it is user-assigned); **Storage Blob
Data Contributor** for that identity on the account that holds the data
container; `PHISH_STORAGE_ACCOUNT_URL=https://<storage>.blob.core.windows.net`;
and the settings in the tables below. Without `PHISH_STORAGE_ACCOUNT_URL` the
wrapper uses `PHISH_STORAGE_CONNECTION_STRING`, then `AzureWebJobsStorage`.

Keep the data container private. The run results include reporter addresses
and subjects, and with `PHISH_CAPTURE_REPORTER_NOTE` the state holds
reporters' notes.

### 2. Graph permissions for the identity

The portal cannot grant Graph application permissions to a managed identity,
so use PowerShell, with `identityPrincipalId` from the outputs:

```powershell
Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All","Application.Read.All"
$mi    = Get-MgServicePrincipal -ServicePrincipalId <identityPrincipalId>
$graph = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

# ThreatHunting.Read.All is only needed by collect_and_triage.
foreach ($perm in "ThreatSubmission.ReadWrite.All", "ThreatHunting.Read.All") {
    $role = $graph.AppRoles | Where-Object { $_.Value -eq $perm -and $_.AllowedMemberTypes -contains "Application" }
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $mi.Id `
        -PrincipalId $mi.Id -ResourceId $graph.Id -AppRoleId $role.Id
}
```

### 3. Mailbox access, limited to the phishing mailbox

Mailbox access is granted **once, by exactly one of these**. `<mi-app-id>` is
`identityClientId` and `<mi-object-id>` is `identityPrincipalId`.

- **RBAC for Applications (preferred).** Do *not* grant `Mail.Read` in Entra.
  Grant it through Exchange with a scope that holds only the phishing mailbox,
  as in `references/graph-automation.md` §2a:
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
- **Application access policy.** Grant `Mail.Read` in Entra by adding it to the
  permission list in the loop above, then restrict it with
  `New-ApplicationAccessPolicy` as in §2b.

Either way, `PHISH_DENY_CHECK` makes each run prove the restriction. If the app
turns out able to read an executive's mailbox, the run fails with
`ScopeCheckFailed` before any mail is read.

### 4. Sentinel, if you want it

Optional. Deploy [`sentinel/main.bicep`](sentinel/README.md) with
`functionPrincipalId=<identityPrincipalId>`, then re-run the template from
step 1 with its two outputs as `sentinelDceEndpoint` and
`sentinelDcrImmutableId`.

### 5. Publish the code

**From GitHub Actions (recommended for a private repo).** The workflow
[`deploy-function.yml`](../.github/workflows/deploy-function.yml) runs the
tests, builds `dist/` and publishes it with a remote build, so the Linux
dependencies are installed on the platform rather than on the runner. It
authenticates with OpenID Connect: there is no publish profile and no secret
to rotate. Flex Consumption apps have no Kudu site, so a publish profile would
not work anyway. Set it up once:

1. Create an app registration (or another user-assigned identity) for the
   deployment and give it **Website Contributor** on the function app:
   ```bash
   az ad app create --display-name "github-deploy-<app>" --query appId -o tsv   # -> <deploy-app-id>
   az ad sp create --id <deploy-app-id>
   az role assignment create --assignee <deploy-app-id> --role "Website Contributor" \
       --scope $(az functionapp show -g <rg> -n <app> --query id -o tsv)
   ```
2. Add a federated credential for the repository's `production` environment:
   ```bash
   az ad app federated-credential create --id <deploy-app-id> --parameters '{
     "name": "github-production",
     "issuer": "https://token.actions.githubusercontent.com",
     "subject": "repo:<org>/<repo>:environment:production",
     "audiences": ["api://AzureADTokenExchange"]
   }'
   ```
3. In the repository, create an environment named `production` (Settings →
   Environments). Add required reviewers if a person should approve each
   deployment. On it, or on the repository, set the variables
   `AZURE_CLIENT_ID` (`<deploy-app-id>`), `AZURE_TENANT_ID`,
   `AZURE_SUBSCRIPTION_ID` and `AZURE_FUNCTIONAPP_NAME`. None is a secret.
4. Run the workflow from the Actions tab, or push to `main`. It also runs on
   its own whenever a push to `main` changes the wrapper or the scripts.

**From a workstation.** With Azure Functions Core Tools and a login that has
Website Contributor on the app:

```bash
./azure-function/package.sh
cd azure-function/dist && func azure functionapp publish <app> --python
```

Or without Core Tools, the same remote build the workflow asks for:

```bash
./azure-function/package.sh
(cd azure-function/dist && zip -r ../dist.zip .)
az functionapp deployment source config-zip -g <rg> -n <app> \
    --src azure-function/dist.zip --build-remote true
```

### 6. First runs

1. The template deploys with `PHISH_DRY_RUN=true`. In
   `runs/submit/<timestamp>.json` in the data container, check the
   `recipient`, `recipient_source` and `original.subject` of a dozen items.
2. Redeploy the template with `dryRun=false`. One submission should appear in
   Defender → Submissions with the **original** sender and subject, not `FW:`
   from the reporter.
3. The next run submits nothing new.
4. Alert on failed invocations of either function in Application Insights. A
   `ScopeCheckFailed` means the Exchange scope has changed.

## Running from a private copy of this repo

The whole repo moves as it is; nothing in it is tied to github.com/rjottten.

1. Create the private repository in your organisation (empty, no README), then
   mirror this one into it so every branch and tag comes across:
   ```bash
   git clone --mirror https://github.com/rjottten/Phishing-inbox-triage.git
   cd Phishing-inbox-triage.git
   git push --mirror https://github.com/<org>/<repo>.git
   ```
   A normal clone of the private repo is what you work from after that.
   To keep pulling fixes from the public repo, add it as a second remote
   (`git remote add upstream ...`) and merge `upstream/main` when you want them.
2. Check that **Actions are enabled** for the repository in your
   organisation's settings, and that the organisation allows the actions the
   workflows use (`actions/*`, `azure/login`, `Azure/functions-action`,
   `github/codeql-action`) if it keeps an allowlist.
3. `tests.yml` runs as it is. `codeql.yml` needs **GitHub Advanced Security**
   on a private repository; without that licence its runs fail. Either enable
   code scanning for the repository or delete the workflow.
4. Set up `deploy-function.yml` as in step 5 above. The federated credential's
   `subject` names your organisation and repository, so a fork or a copy
   elsewhere cannot use it.
5. Replace the badge at the top of the top-level README, which points at the
   public repository's workflow.
6. Mind what you commit. `local.settings.json` and `dist/` are ignored, and
   should stay that way; `test-data/` is synthetic. Parameter values for the
   template contain mailbox addresses, which is fine in a private repo, but no
   credential belongs in it: the design here has none to store.

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

**Microsoft Sentinel** (optional; deploy [`sentinel/main.bicep`](sentinel/README.md) first)

| Setting | Default | |
|---|---|---|
| `PHISH_SENTINEL_DCE_ENDPOINT` | — | The data collection endpoint's logs ingestion URI. With the next setting, every triage result is sent as a row of `PhishTriage_CL` |
| `PHISH_SENTINEL_DCR_IMMUTABLE_ID` | — | The data collection rule's `dcr-...` id. One of these two without the other is refused |
| `PHISH_SENTINEL_STREAM` | `Custom-PhishTriage_CL` | Only if the table was renamed |
| `PHISH_SENTINEL_HEADERS_ONLY` | `false` | `true` omits the evidence, interaction and recommended-action text; routing, indicators, sender and subject still go |

The identity needs **Monitoring Metrics Publisher** on the data collection
rule; the template grants it. A failed upload raises `SentinelUploadFailed`
after the report is in Blob storage, so the run shows as failed but the
report is not lost.

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
