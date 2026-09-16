# phishing-inbox-triage

[![tests](https://github.com/rjottten/Phishing-inbox-triage/actions/workflows/tests.yml/badge.svg)](https://github.com/rjottten/Phishing-inbox-triage/actions/workflows/tests.yml)

A Claude skill for exception-only review of a user-reported phishing queue.

Operating principle: Microsoft automation (Outlook Report button → Defender for Office 365 AIR + auto-notify → Security Copilot Phishing Triage Agent) handles routine classification and user feedback. Analysts handle exceptions — ambiguous verdicts, BEC, high-value targets, user interaction/compromise, and remediation decisions. The skill sorts every reported item into *handled by automation*, *automation gap*, or *exception*, works only the exceptions, and produces a prioritized handover report with recommended (never executed) response actions.

## Layout

```
phishing-inbox-triage/
├── SKILL.md                         # workflow, lanes, priorities, guardrails
├── references/
│   ├── exception-criteria.md        # tests for each exception category; when to disagree with AIR
│   ├── response-actions.md          # action matrix with decision owners
│   ├── report-template.md           # shift report + single-message formats
│   └── graph-automation.md          # Graph Security API setup for the submission watcher
├── scripts/
│   ├── parse_headers.py             # raw headers → JSON (auth results, mismatches, flags)
│   └── graph_submit.py              # shared mailbox → Defender emailThreatSubmission
└── evals/
    └── evals.json                   # test prompts
test-data/
└── mailbox_export.json              # synthetic 10-item queue (fictional domains) for testing
tests/
└── test_graph_submit.py             # offline unit tests for the submission watcher
.github/workflows/
└── tests.yml                        # CI: unit tests, CLI smoke tests, skill-data checks
```

## Install

Zip the `phishing-inbox-triage/` folder (or use the packaged `.skill` file) and add it as a skill in Claude, or drop the folder into a Claude Code / Cowork skills directory.

## Header parser

```
python phishing-inbox-triage/scripts/parse_headers.py headers.txt
```

## Submission watcher

Closes the *automation gap* lane: messages a user forwarded or dragged into the shared mailbox never produced a Defender submission, so no AIR investigation ran and the reporter was never told anything. `graph_submit.py` finds those, pulls the **original** message out of the forward, and creates an `emailThreatSubmission` through the Microsoft Graph Security API — Defender then investigates and notifies as if the Report button had been used.

```
export GRAPH_TENANT_ID=... GRAPH_CLIENT_ID=... GRAPH_CLIENT_SECRET=...

# inspect what would be submitted, and to whom, without sending anything
python phishing-inbox-triage/scripts/graph_submit.py \
    --mailbox phish@contoso.com --org-domain contoso.com \
    --since 7d --dry-run --json

# prove Mail.Read really is restricted to that one mailbox (exit 3 if not)
python phishing-inbox-triage/scripts/graph_submit.py \
    --mailbox phish@contoso.com --deny-check ceo@contoso.com --check-scope

# then on a schedule
python phishing-inbox-triage/scripts/graph_submit.py \
    --mailbox phish@contoso.com --org-domain contoso.com \
    --deny-check ceo@contoso.com \
    --state /var/lib/phish-triage/state.json \
    --dedupe-original --mark-read --move-to archive
```

Stdlib only, no dependencies. Read `phishing-inbox-triage/references/graph-automation.md` first — it covers app registration, restricting `Mail.Read` to just the phishing mailbox, why submitting the forward instead of the original produces a worthless verdict, and when a submission lands in *User reported* versus *Admin submissions*.

`Mail.Read` as an *application* permission reads every mailbox in the tenant, and a scope that was removed or never propagated looks identical to one that works. So the script doesn't take it on trust: `--deny-check` names a mailbox this app must not be able to reach, probes it before any mail is read, and aborts the run if it turns out to be readable. `--check-scope` runs that probe alone as a deployment gate. A typo'd control mailbox reports `inconclusive` rather than passing, and running with no control at all reports `unchecked` — silence is not evidence.

The watcher submits and nothing else. It never purges, blocks, resets, or approves an AIR action; those stay analyst decisions, as `references/response-actions.md` describes.

## Tests

```
python -m unittest discover -s tests
```

107 tests, offline — the Graph client is stubbed, so no tenant or credentials are needed. Python 3.9 or newer; no third-party packages.

The header-parser tests are written one per flag in both directions: it fires when it should, and it stays quiet when it shouldn't. The second half is the one that matters — a parser that silently stops flagging is worse than no parser, because the queue looks clean.

CI (`.github/workflows/tests.yml`) runs these on every push and pull request across Python 3.9, 3.11 and 3.13. It also checks that `graph_submit.py` fails cleanly with no credentials rather than half-running, that the skill's JSON files parse, and that every `references/` and `scripts/` path named in `SKILL.md` actually exists. The test step asserts a minimum test count, because `unittest discover` exits 0 when it finds nothing.

It deliberately does not run `--check-scope`; that needs real tenant credentials and belongs in your deploy pipeline, not here.

All test data is fictional. Never fetch URLs or open attachments from reported mail.
