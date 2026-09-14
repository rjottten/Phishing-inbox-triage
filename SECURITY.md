# Security notes

## Reporting a vulnerability

Open a private security advisory on this repository, or contact the maintainer
directly. Please do not open a public issue for a vulnerability.

## What this tool does and does not touch

It reads. Every Graph call is a GET against a mail or security read endpoint, and
there is no code path that sends mail, moves a message, runs remediation, or follows
a URL from a reported message. Response actions are emitted as recommendations with
a named decision owner and are executed by a person.

Three properties are enforced in code and covered by tests rather than by policy:

| Property | Test |
|---|---|
| Every recommended action carries a decision owner | `test_no_action_is_ever_executed` |
| Instructions inside a reported message never change a verdict | `test_injection_text_is_recorded_as_an_indicator_and_not_obeyed` |
| URLs are never rendered clickable | `test_urls_are_never_rendered_clickable` |

## Handling the data

Queue exports and reports contain real reporter names, real senders, real subject
lines and live lure URLs. Treat them with the same controls as the phishing mailbox
itself:

- `reports/`, `out/`, `exports/`, `*.export.json`, `.env` and `config.local.*` are
  git-ignored. Check before committing anything that came out of a real run.
- Everything committed to this repository is synthetic, and every domain in
  `test-data/` is fictional. Keep it that way.
- URLs are stored and rendered defanged (`hxxps://x[.]com`). Keep that when adding a
  source adapter — it is what stops a lure becoming a clickable link in a ticket.

## Credentials

Graph credentials come from `GRAPH_TENANT_ID`, `GRAPH_CLIENT_ID` and
`GRAPH_CLIENT_SECRET` in the environment, never from a file in the repository. The
client secret is excluded from `GraphClient`'s repr so it cannot reach a traceback
or a log line.

`Mail.Read` as an application permission covers every mailbox in the tenant by
default. Scope it to the phishing mailbox with an application access policy before
using it — see [`docs/graph-setup.md`](docs/graph-setup.md).

## Dependencies

There are no runtime dependencies, deliberately: a tool running inside a SOC is one
less supply chain to review. `pytest` and `ruff` are development-only. Please keep
the runtime dependency list empty.
