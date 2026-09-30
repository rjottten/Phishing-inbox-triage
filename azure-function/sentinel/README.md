# Triage results in Microsoft Sentinel

Every run of the `collect_and_triage` function can also send its results to
Sentinel: one row per queue item, in a custom table, and an analytics rule
that opens an incident the first time an item is routed to the exception
lane at P1 or P2. Analysts then work the exceptions from the incident queue
they already use, and the "handled by automation" and "gap" rows give a
workbook the health of the Report-button pipeline over time.

```
collect_and_triage ──► reports/<stamp>.json  (Blob, as before)
                  └──► Logs Ingestion API ──► PhishTriage_CL ──► analytics rule ──► incident
```

Nothing is sent unless the two `PHISH_SENTINEL_*` settings below are set. A
failed upload raises after the report is in Blob storage, so the invocation
shows as failed in Application Insights but the shift's report is not lost.

## What lands in the table

One row per item per run, the fields of `triage.py --format json` flattened:
lane, priority, categories, indicators, reporter, sender, subject, Defender
submission id / AIR status / verdict, the evidence lines and the recommended
actions. `RunId` is the run's timestamp; `TriageId` is a stable hash of the
original message's `Message-ID`, so the same item carries the same id across
runs. The full column list is in `main.bicep`, and a test checks the runner
never emits a column that is not declared there.

**Content.** `Subject`, `Sender`, `Evidence` and `Interaction` carry text
from reported mail and, with `PHISH_CAPTURE_REPORTER_NOTE`, the reporter's own
note. Sentinel is a security store and this is the same text the handover
report already holds, so the default is to send it. Set
`PHISH_SENTINEL_HEADERS_ONLY=true` to send only the routing decision and the
indicator names: the `Evidence`, `Interaction` and `Actions` columns are then
left empty. Subject and sender are still sent, as they are in the logs.

## Deploy

The workspace must already have Microsoft Sentinel enabled; the template does
not onboard it.

**1. Roles.** Whoever runs the deployment needs Microsoft Sentinel Contributor
on the workspace (table and analytics rule), Contributor on the resource group
(endpoint and rule), and Owner or User Access Administrator on the resource
group to grant the Function App's identity its role. The Function App itself
needs nothing new in Graph or Defender.

**2. Deploy the template** into the workspace's resource group:

```bash
principal=$(az functionapp identity show -g <function-rg> -n <app> --query principalId -o tsv)

az deployment group create -g <workspace-rg> \
    -f azure-function/sentinel/main.bicep \
    -p workspaceName=<workspace> functionPrincipalId=$principal \
    --query properties.outputs
```

It creates the table `PhishTriage_CL`, the data collection endpoint
`dce-phish-triage`, the data collection rule `dcr-phish-triage`, grants the
identity **Monitoring Metrics Publisher** on that rule, and adds the analytics
rule. Pass `analyticsRuleEnabled=false` to look at the data for a few shifts
before incidents start; `incidentPriorities='["P1"]'` to alert on P1 only;
`retentionInDays` to change the default 90.

**3. App settings** on the Function App, from the deployment outputs:

| Setting | Value | |
|---|---|---|
| `PHISH_SENTINEL_DCE_ENDPOINT` | `dceLogsIngestionEndpoint` output | `https://dce-phish-triage-xxxx.<region>-1.ingest.monitor.azure.com` |
| `PHISH_SENTINEL_DCR_IMMUTABLE_ID` | `dcrImmutableId` output | `dcr-...` |
| `PHISH_SENTINEL_STREAM` | optional | default `Custom-PhishTriage_CL`; only change it if you renamed the table |
| `PHISH_SENTINEL_HEADERS_ONLY` | optional | `true` to omit evidence, interaction and actions text |

Setting one of the first two without the other is refused at startup rather
than silently sending nothing.

**4. Redeploy** the Function App (`package.sh`, then publish) so
`azure-monitor-ingestion` is installed. The role assignment can take a few
minutes to propagate; a 403 on the first run after deployment is usually that.

**5. Check.** After the next triage run:

```kusto
PhishTriage_CL
| summarize Items = count() by RunId, Lane
| order by RunId desc
```

## The analytics rule

Runs hourly over the last two hours and alerts on rows with `Lane ==
"exception"` and a priority in `incidentPriorities`, skipping any `TriageId`
already seen as such in the previous seven days. So an item that is a P1 for
three consecutive shifts opens one incident, not three. Alerts carry the
priority as severity (P1 High, P2 Medium), the reporter as a Mailbox entity,
the sender and subject as a MailMessage entity, and the categories, evidence
summary, Defender submission id and recommended actions as custom details.

The incident is the pointer; the handover report in
`reports/<RunId>.md` has the full evidence and the named decision owner for
each action. Remediation stays with the analyst, as everywhere else in this
repo: the rule opens incidents, it runs no playbook.

## Useful queries

Pipeline health per shift, the reason to send every lane and not only the exceptions:

```kusto
PhishTriage_CL
| summarize Items = count() by bin(TimeGenerated, 12h), Lane
| render columnchart
```

Gaps that keep coming back, which usually means the submit job is not running
or the reporting mailbox is not the one it watches:

```kusto
PhishTriage_CL
| where Lane == "automation_gap"
| summarize Runs = dcount(RunId), First = min(TimeGenerated), Last = max(TimeGenerated) by TriageId, GapReason, Subject
| where Runs > 1
```

Join to the Defender XDR connector's own tables for the click and delivery
detail the collector cannot read through Graph:

```kusto
PhishTriage_CL
| where Lane == "exception"
| extend SenderAddress = iff(Sender has "<", extract(@"<([^>]+)>", 1, Sender), Sender)
| join kind=leftouter (EmailEvents | project NetworkMessageId, SenderFromAddress, RecipientEmailAddress, DeliveryAction, ThreatTypes)
    on $left.SenderAddress == $right.SenderFromAddress, $left.Reporter == $right.RecipientEmailAddress
```
