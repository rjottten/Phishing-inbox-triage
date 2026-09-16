# Security notes

## Reporting a vulnerability

Open a private security advisory on this repository, or contact the maintainer
directly. Please do not open a public issue for a vulnerability.

## What this tool does and does not touch

It reads, with one exception. `graph_submit.py` creates a Defender
`emailThreatSubmission` — it hands a message to Microsoft for analysis, which starts
an investigation and changes nothing else. Its optional `--mark-read` / `--move-to`
flags tidy the reporting mailbox, and that is the full extent of the writes. Nothing
anywhere purges, blocks, quarantines, resets a credential, or approves an AIR action.
Response actions are emitted as recommendations with a named decision owner and are
executed by a person.

No code path follows a URL or opens an attachment from a reported message.
`triage.py`, `parse_headers.py` and `import_defender_csv.py` import no
network-capable module at all — not `urllib`, not `socket` — which is why they are
safe to point at a real export on day one.

These properties are enforced in code and covered by tests rather than by policy:

| Property | Test |
|---|---|
| Every exception names a decision owner | `test_triage.py::test_every_exception_names_a_decision_owner` |
| Instructions inside a reported message never change a verdict | `test_triage.py::test_injected_reviewer_text_is_flagged_not_obeyed` |
| The offline tools cannot reach the network | `test_skill_bundle.py::TestOfflineScriptsStayOffline`, and a CI step |
| URLs are stored defanged, everywhere they enter | `test_collect_export.py::test_defang_neutralises_every_dot_and_the_scheme`, `test_import_defender_csv.py::test_urls_are_stored_defanged` |
| `graph_submit.py` reads only the eight mailbox fields it justifies | `test_graph_submit.py::test_the_run_reads_no_field_outside_the_contract` |

## Handling the data

Queue exports and reports contain real reporter names, real senders, real subject
lines and live lure URLs. Treat them with the same controls as the phishing mailbox
itself:

- `reports/`, `out/`, `exports/`, `*.export.json`, `org-context.json`, `state.json`
  and `.env` are git-ignored. Check before committing anything from a real run.
- Everything committed to this repository is synthetic, and every domain in
  `test-data/` is fictional. Keep it that way.
- URLs are stored and rendered defanged (`hxxps://x[.]com`). Keep that when adding a
  collector — it is what stops a lure becoming a clickable link in a ticket.
- `collect_export.py` reads message bodies; `import_defender_csv.py` reads whatever
  the portal exported. Mind where the output lands.

## Credentials

Graph credentials come from `GRAPH_TENANT_ID`, `GRAPH_CLIENT_ID` and
`GRAPH_CLIENT_SECRET` in the environment, never from a file in the repository. The
client secret is excluded from the Graph client's repr so it cannot reach a traceback
or a log line.

`Mail.Read` as an application permission covers every mailbox in the tenant by
default. Scope it to the phishing mailbox with an application access policy before
using it — see [`docs/graph-setup.md`](docs/graph-setup.md).

A scope that was removed or never propagated looks identical to one that works, so do
not take it on trust: `--deny-check <mailbox>` names a mailbox the app must *not* be
able to reach and probes it before reading any mail, aborting if it turns out to be
readable. `--check-scope` runs that probe alone, as a deployment gate. A typo'd
control mailbox reports `inconclusive` rather than passing, and no control at all
reports `unchecked` — silence is not evidence.

## Dependencies

There are none, deliberately: a tool running inside a SOC is one less supply chain to
review, and the scripts have to run from an unzipped folder with nothing installed.
Everything is stdlib on Python 3.10+. `ruff` is used in CI and is not needed to run
or test anything. Please keep it that way.
