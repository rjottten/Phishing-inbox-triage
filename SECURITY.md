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

## The model-assisted layer (`agents/`)

Everything in the skill bundle is stdlib-only and offline. `agents/` is not: it calls
the Claude API, and it is the only place in this repository where a model reads
attacker-written content.

The rule that shapes it: **the component reading hostile content holds no tools and
makes no decisions.** `resolve_worklist.py`'s output schema has no verdict, lane,
priority or action field, so a reported message cannot steer an outcome even if it
contains text addressed to the reviewer — that text is transcribed into
`body_excerpt`, where `triage.py`'s own injection detector picks it up as an
indicator. Every field that comes back is re-validated before it can reach the queue:
URLs defanged unconditionally, lengths capped, control characters stripped, unknown
fields a hard failure, and unrecognised values failing toward "a person should look at
this" rather than toward confidence.

| Property | Test |
|---|---|
| The extraction schema has no decision field | `test_agents.py::TestSchemaGivesNothingToDecide` |
| A decision field is refused even if it arrives | `test_agents.py::test_a_decision_field_is_rejected_even_if_it_arrives` |
| The request declares no tools | `test_agents.py::test_the_request_declares_no_tools` |
| Transcribed injection text is flagged, not obeyed | `test_agents.py::test_triage_flags_the_injection_on_the_reconstructed_item` |
| URLs are defanged whatever the model returned | `test_agents.py::test_urls_are_defanged_on_the_way_out` |
| No install-needing script reaches the skill bundle | `test_skill_bundle.py::test_the_bundle_ships_no_script_that_needs_an_install` |

**What leaves the tenant.** `resolve_worklist.py` sends the body and image attachments
of messages already on the worklist to the Claude API — a real widening, since
`graph_submit.py` asks for eight fields and never downloads a body. `--dry-run` shows
exactly what would be sent without calling the model. If mail content cannot leave
your boundary, do not use it; `SKILL.md` is plain markdown and runs against an
in-tenant deployment.

It submits nothing, modifies no mailbox, and does not clear a worklist entry.

## Dependencies

The scripts have none, deliberately: a tool running inside a SOC is one less supply
chain to review, and they have to run from an unzipped folder with nothing installed.
Everything in `skills/` is stdlib on Python 3.10+, and a test fails the build if one
of them gains a third-party import. `ruff` is used in CI and is not needed to run or
test anything. Please keep it that way.

`agents/` is the one exception and is opt-in: it needs `anthropic`, and it is isolated
there precisely so the rest stays installable-free. Its SDK import is lazy, so the
whole test suite still runs with nothing installed.
