# Connecting to Microsoft Graph

> **Status:** the Graph adapter's *mapping* is unit-tested against recorded payload
> shapes (`tests/test_graph.py`), but it has not been run against a live tenant.
> Expect to adjust field names on first contact — start with `--hours 1` and
> `--format summary` and compare against the Defender portal before trusting a run.

## What it reads

Nothing else. Every call is a GET against a read endpoint; the client has no code
path that sends mail, moves a message, or runs remediation.

| Source | Endpoint | Why |
|---|---|---|
| User submissions | `GET /security/threatSubmission/emailThreats` | The Report-button path, where AIR status and verdict live |
| Shared mailbox | `GET /users/{mailbox}/messages` | The forwarded-in reports — automation gaps by construction |
| Click telemetry | `POST /security/runHuntingQuery` (`UrlClickEvents`) | The fastest answer to "did anyone click?" |

## App registration

1. Entra ID → **App registrations** → New registration. Single tenant is fine.
2. **API permissions** → Microsoft Graph → **Application permissions**:
   - `ThreatSubmission.Read.All` — required
   - `Mail.Read` — required only if you pass `--mailbox`
   - `ThreatHunting.Read.All` — optional; without it click telemetry is reported as
     unverified rather than guessed at
3. **Grant admin consent.**
4. **Certificates & secrets** → new client secret. Put it in your secret store.

### Scope `Mail.Read` down to the one mailbox

`Mail.Read` as an application permission grants *every* mailbox in the tenant by
default. Restrict it before using it:

```powershell
New-ApplicationAccessPolicy `
  -AppId <client-id> `
  -PolicyScopeGroupId phishing-mailbox-readers@contoso.com `
  -AccessRight RestrictAccess `
  -Description "phishing triage: shared phishing mailbox only"

Test-ApplicationAccessPolicy -Identity phishing@contoso.com -AppId <client-id>
```

## Credentials

Read from the environment, never from a file in this repo:

```bash
export GRAPH_TENANT_ID=...
export GRAPH_CLIENT_ID=...
export GRAPH_CLIENT_SECRET=...   # from your secret store, not your shell history

python skills/phishing-inbox-triage/scripts/collect_export.py \
    --mailbox phishing@contoso.com --org-context org-context.json \
    --deny-check ceo@contoso.com --since 12h --out export.json

python skills/phishing-inbox-triage/scripts/triage.py export.json \
    --org-context org-context.json
```

`--deny-check` names a mailbox this app must *not* be able to reach, and probes it
before reading any mail. It is how you find out that the access policy above did not
propagate, rather than discovering it from an audit log later.

## Running it on a schedule

Collect, triage, then decide from the report. `triage.py --format json` gives a
runner something to branch on:

```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPTS=/opt/phishing-inbox-triage/skills/phishing-inbox-triage/scripts
STAMP=$(date -u +%Y%m%dT%H%M)

python "$SCRIPTS/collect_export.py" \
  --mailbox phishing@contoso.com \
  --org-context /etc/phish-triage/org-context.json \
  --deny-check ceo@contoso.com \
  --since 8h --out "/var/reports/export-$STAMP.json"

python "$SCRIPTS/triage.py" "/var/reports/export-$STAMP.json" \
  --org-context /etc/phish-triage/org-context.json \
  --out "/var/reports/phish-$STAMP.md"

# Page on a P1 sitting in the queue.
python "$SCRIPTS/triage.py" "/var/reports/export-$STAMP.json" \
  --org-context /etc/phish-triage/org-context.json --format json \
  | python -c 'import json,sys; sys.exit(1 if json.load(sys.stdin)["priorities"].get("P1") else 0)' \
  || page_the_on_call_analyst
```

`collect_export.py` exits non-zero if it could not run at all, so `set -e` catches a
broken credential or a revoked consent before a thin report is ever written.

Reports contain real reporter names, real senders and real lures. Write them
somewhere with the same access controls as the phishing mailbox itself — `reports/`
and `out/` are git-ignored so a stray run cannot commit one.

## When a run comes back thin

Read `export_meta.collection_notes`. A 403 on submissions usually means consent was
not granted; a 404 on the mailbox usually means the application access policy excludes
it. The collector records what it could not read rather than collecting around the
hole — a lane decision made without the Defender side is a guess, and an empty list is
never written where the truth is *unknown*.

Two notes are worth reacting to immediately:

- **Submissions unreadable** — the queue will look like nothing but automation gaps,
  and an analyst could reasonably conclude the Report button is broken.
- **URL inventory unavailable** — `triage.py` reads an empty URL list as "no link, so
  this could be BEC", so BEC findings from that run need a second look.
