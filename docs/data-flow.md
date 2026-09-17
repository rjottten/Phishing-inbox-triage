# Data flow

What this reads, where it sends it, and what it keeps. Written for a security or
privacy review, and for the conversation that starts "so what leaves our tenant?"

Every claim here is a statement about the code as it stands. Where a behaviour
depends on a flag, the flag is named.

## The short answer

| Configuration | Leaves your tenant |
|---|---|
| `import_defender_csv.py` + `triage.py` | **Nothing.** No network calls at all |
| `graph_submit.py` | The reported phish, to **Microsoft Defender**, for analysis |
| `collect_export.py` | Nothing — reads from Graph, writes a local file |
| `agents/resolve_worklist.py` | Message bodies and image attachments, to the **Anthropic API** |

Only the last one sends anything to a third party, it is opt-in, it is not part of
the scheduled deployment, and it is the reason that code lives outside the skill
bundle. If mail content cannot leave your boundary, do not deploy it.

Submitting to Defender is a transfer to Microsoft, who already hold the mail.

## Trust boundaries

```
  YOUR TENANT                                       │  OUTSIDE
                                                    │
  ┌───────────────┐   forwards     ┌──────────────┐ │
  │ Reporter's    │───────────────▶│ Shared phish │ │
  │ mailbox       │                │ mailbox (EXO)│ │
  └───────────────┘                └──────┬───────┘ │
                                          │ Graph   │
                            8 fields + attachments  │
                                          ▼         │
  ┌──────────────────────────────────────────────┐  │
  │ YOUR COMPUTE (Azure Function or a host)      │  │
  │                                              │  │
  │  graph_submit.py ──── the original .eml ─────┼──┼──▶ Defender
  │                                              │  │    (Microsoft)
  │  collect_export.py ◀── Graph reads           │  │
  │         │                                    │  │
  │         ▼                                    │  │
  │    export.json ──▶ triage.py ──▶ report.md   │  │
  │         │            (no network)            │  │
  │         ▼                                    │  │
  │  state.json, worklist.json ──▶ Blob Storage  │  │
  │                                              │  │
  │  counts + subjects ──────▶ App Insights      │  │
  └──────────────────────────────────────────────┘  │
                                                    │
  ┌──────────────────────────────────────────────┐  │
  │ OPT-IN, NOT IN THE SCHEDULED DEPLOYMENT      │  │
  │  agents/resolve_worklist.py                  │  │
  │    bodies + image attachments ───────────────┼──┼──▶ Anthropic API
  └──────────────────────────────────────────────┘  │
```

## What each component touches

| Component | Reads | Writes | Network |
|---|---|---|---|
| `graph_submit.py` | Shared mailbox (8 fields), attachments | A Defender submission; optionally marks read / moves | Microsoft Graph |
| `collect_export.py` | Shared mailbox, Defender Submissions, Advanced Hunting | `export.json` locally | Microsoft Graph |
| `import_defender_csv.py` | A portal CSV on disk | `export.json` locally | **None** |
| `triage.py` | `export.json` | A report | **None** |
| `parse_headers.py` | Raw headers on disk | JSON | **None** |
| `agents/resolve_worklist.py` | Mailbox bodies + image attachments | A proposed `export.json` | Graph **and Anthropic** |

The three marked **None** import no network-capable module at all — not `urllib`,
not `socket`. CI fails the build if one gains a way to make a request, and
`tests/test_skill_bundle.py` asserts the same thing.

## Exactly what is read from the mailbox

`graph_submit.py` asks Graph for **eight fields and no others**. Each is justified
in `MAILBOX_FIELDS`, and a test drives a real run and fails if it touches anything
outside the list:

`id` · `internetMessageId` · `receivedDateTime` · `subject` · `hasAttachments` ·
`from` · `sender` · `isRead`

**Not requested:** `body`, `uniqueBody`, `toRecipients`, `ccRecipients`,
`categories`. The body of the forward is never downloaded. What *is* downloaded is
the **attached original** — the reported phish itself — because that is the thing
being submitted.

One field can be added, and only by asking: `--capture-reporter-note` widens the
selection by `bodyPreview`, the one line the reporter typed above the forward. Never
`body`, never `uniqueBody`, so a long note is truncated by Graph rather than fetched
in full. A test asserts the request is byte-for-byte the eight fields without it.

`collect_export.py` reads more, because it is building a triage queue rather than a
submission: the eight above plus `toRecipients` and `bodyPreview`, a body excerpt
(`--body-chars`, default 300), and from Advanced Hunting — `EmailEvents`,
`EmailUrlInfo`, `EmailAttachmentInfo`, `UrlClickEvents`.

## What is kept, and where

| Store | Contents | Lives |
|---|---|---|
| `state.json` | Watermark; `Message-ID` → submission id, status, timestamp. With `--capture-reporter-note`, also the reporter's note keyed by `Message-ID` | Blob Storage (Function) or disk |
| `worklist.json` | Per stuck report: reason, **subject**, **reporter address**, timestamps, mailbox ids, attachment failure reasons | Blob Storage or disk |
| `export.json` | Full queue: senders, subjects, body excerpts, defanged URLs, reporter notes, recipients | Wherever you write it |
| The report | The same, rendered for an analyst | Wherever you write it |

URLs are stored **defanged** (`hxxps://x[.]com`) everywhere they enter, so nothing
downstream can render one clickable. Nothing ever fetches one.

`export.json` and the report are the sensitive artefacts: they contain real reporter
names, real senders, real subject lines and live lure URLs. Treat them with the same
controls as the mailbox itself. `.gitignore` covers `reports/`, `out/`, `exports/`,
`*.export.json`, `org-context.json` and `state.json`, but that only protects the
repository — not wherever you point `--out`.

## Logs

Logs carry **headers only** — subjects, sender addresses, message ids, counts and
statuses. Never message bodies, never URLs, never attachment contents.

On the Azure Function that means Application Insights receives subjects and sender
addresses. If that is more than your logging policy allows for reported mail,
`function_app.py` is where to reduce it; the blob-backed worklist is the intended
place to work the queue from, not the log.

## The Anthropic path, in detail

`agents/resolve_worklist.py` is the only component that sends anything to a
non-Microsoft third party. It exists because a screenshot is not a parsing problem.

**What is sent:** for worklist entries only — entries that already failed automated
extraction — the forward's message body (up to 20,000 characters, HTML stripped)
and up to 5 image attachments of at most 4 MB each. Plus the forwarder's address and
the forward's subject as context.

**What is not sent:** anything not on the worklist. The whole mailbox is never
swept, and `--dry-run` prints exactly what would be sent without calling the model.

**What comes back:** a structured extraction with no verdict, lane, priority or
action field — the schema gives the model nothing to decide with. Every field is
re-validated before it can reach the queue.

**Retention** is governed by your Anthropic account's data retention configuration,
not by this repository. If mail content cannot leave your tenant, do not deploy this
component; `SKILL.md` is plain markdown and runs against an in-tenant model instead.

## Outbound destinations, complete

| Destination | Sent by | Carrying |
|---|---|---|
| `login.microsoftonline.com` | `graph_submit.py`, `collect_export.py` | Client credentials, or nothing when a managed identity supplies the token |
| `graph.microsoft.com` | `graph_submit.py`, `collect_export.py`, `resolve_worklist.py` | Mailbox reads; the submitted `.eml`; hunting queries |
| Azure Blob Storage | The Function | `state.json`, `worklist.json` |
| Application Insights | The Function | Subjects, senders, counts |
| `api.anthropic.com` | `resolve_worklist.py` **only** | Message bodies, image attachments |

There are no other outbound destinations. No telemetry, no analytics, no update
checks, no package installs at runtime.

## Things a reviewer should know

**The processed-message ledger is never pruned.** `state.json` accumulates one entry
per handled message — `Message-ID`, timestamp, status, submission id — indefinitely.
No subjects or senders, but the identifiers grow without bound. If you have a
retention requirement on message identifiers, that file needs a rotation policy;
there is none in the code today. Deleting it is safe apart from the watermark, and
will cause one re-scan of the lookback window.

**The reporter's note is personal correspondence.** It is off by default for that
reason. On a shared *reporting* mailbox it is the reporter deliberately telling the
security team what happened to them, which is the argument for reading it — but it
is a decision to make consciously, not a default to inherit.

**`ThreatSubmission.ReadWrite.All` cannot be scoped to a mailbox.** It is tenant-wide
by nature. Its only power is to hand a message to Microsoft for analysis, which
starts an investigation and changes nothing else.

**`Mail.Read` is tenant-wide until Exchange scoping is applied.** See
[`deployment.md`](deployment.md) step 3 — and step 5, which proves the scope rather
than trusting it, on every run.

**Nothing here has been run against a live tenant.** Field shapes may differ on
first contact; `emailThreats` is a beta Graph resource.
