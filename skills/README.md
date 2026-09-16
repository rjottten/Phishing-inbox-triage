# The Claude skill

`phishing-inbox-triage/` is the whole project: a Claude skill whose `scripts/` are
also standalone CLIs. The scripts work the queue deterministically; the skill adds
what rules cannot do — reasoning about a single pasted email, a verdict that looks
wrong, a judgement call about purge scope, a question from someone who is not going
to run a CLI.

| | `scripts/` (no Claude) | `SKILL.md` (with a model) |
|---|---|---|
| Good at | Volume, repeatability, scheduled runs | Judgement, explanation, odd cases, conversation |
| Output | Markdown / JSON handover report | The same formats, written to fit the case |
| Runs | On a timer, in a terminal, in CI | In Claude |

They are not alternatives. The skill is told to start from `triage.py`'s output
rather than re-derive the routing, and to say so explicitly when it disagrees — so
the deterministic pass does the volume and the model only works what is left.

Nothing here needs an install. The scripts are stdlib-only on Python 3.10+, so the
folder works as soon as it is unzipped, which is what makes it a skill rather than a
package with a manifest.

## Install

Claude Code or Cowork — copy the folder into a skills directory:

```bash
cp -r skills/phishing-inbox-triage ~/.claude/skills/
```

Claude.ai — zip the folder and upload it as a skill:

```bash
cd skills && zip -r phishing-inbox-triage.zip phishing-inbox-triage
```

`SKILL.md` is plain markdown and works with any capable model, not only Claude — an
in-tenant deployment such as Azure OpenAI is the obvious choice if mail content must
not leave your boundary.

Then ask it to work the queue:

> Work the phishing inbox for the overnight shift and give me the handover report.
> The export from the shared mailbox joined to Defender submissions is attached.

`test-data/mailbox_export.json` is a synthetic 10-item queue with a known correct
answer, for trying it before pointing it at anything real.

## Contents

| File | What it holds |
|---|---|
| `SKILL.md` | The workflow: lanes, exception categories, priorities, guardrails |
| `references/exception-criteria.md` | The test for each category, BEC indicators, when to disagree with AIR |
| `references/response-actions.md` | Action matrix with decision owners, and what never to recommend |
| `references/report-template.md` | Shift report and single-message formats |
| `references/graph-automation.md` | Graph Security API setup: app registration, mailbox scoping, submission shapes |
| `scripts/collect_export.py` | Graph → the JSON export. Mailbox, Submissions and Advanced Hunting, joined on the original's `Message-ID`. Covered by `tests/test_collect_export.py` |
| `scripts/import_defender_csv.py` | Defender portal CSV → the same JSON export, offline. Discovers column names rather than assuming them. Covered by `tests/test_import_defender_csv.py` |
| `scripts/triage.py` | The export → lanes, priorities, evidence, recommended actions. No network. Covered by `tests/test_triage.py` |
| `scripts/graph_submit.py` | Shared-mailbox watcher: extracts the reported original and submits it to Defender, closing the automation-gap lane. Covered by `tests/test_graph_submit.py` |
| `scripts/parse_headers.py` | Raw headers → JSON: auth results, mismatches, the first external hop, the usual tells. No network. Covered by `tests/test_parse_headers.py` |
| `evals/evals.json` | Test prompts, run against `test-data/mailbox_export.json` |

## Changing it

Change `SKILL.md` and `scripts/triage.py` together, or they drift apart and the
report an analyst gets depends on which one ran. `tests/test_triage.py` pins the
expected lanes and priorities for the sample queue, matches eval #1, and is the place
to record why a rule changed.

`tests/test_skill_bundle.py` is what keeps the bundle shippable: every script starts
with nothing installed, the offline ones import nothing network-capable, the
frontmatter parses, and every path `SKILL.md` names exists. A new script goes in its
`SHIPPED_SCRIPTS` list, or it ships unchecked.
