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
  -Description "phish-triage: shared phishing mailbox only"

Test-ApplicationAccessPolicy -Identity phishing@contoso.com -AppId <client-id>
```

## Credentials

Read from the environment, never from a file in this repo:

```bash
export GRAPH_TENANT_ID=...
export GRAPH_CLIENT_ID=...
export GRAPH_CLIENT_SECRET=...   # from your secret store, not your shell history

phish-triage run --graph --mailbox phishing@contoso.com --hours 12 --config config.toml
```

## Running it on a schedule

The exit code is the alerting signal, so any runner works:

```bash
#!/usr/bin/env bash
set -euo pipefail

phish-triage run --graph \
  --mailbox phishing@contoso.com \
  --hours 8 \
  --config /etc/phish-triage/config.toml \
  --out "/var/reports/phish-$(date -u +%Y%m%dT%H%M).md" \
  --fail-on p1
case $? in
  0) exit 0 ;;                                   # nothing above the threshold
  1) page_the_on_call_analyst ;;                 # a P1 is sitting in the queue
  *) alert_that_the_triage_job_itself_failed ;;  # 2 — could not read a source
esac
```

Reports contain real reporter names, real senders and real lures. Write them
somewhere with the same access controls as the phishing mailbox itself — `reports/`
and `out/` are git-ignored so a stray run cannot commit one.

## When a run comes back thin

`Queue.missing_sources` is printed under **Data sources** in the report. A 403 on
submissions usually means consent was not granted; a 404 on the mailbox usually
means the application access policy excludes it. The engine reports what it could
not read rather than triaging around the hole — a lane decision made without the
Defender side is a guess.
