# The Claude skill

`phishing-inbox-triage/` is a Claude skill covering the same operating model as the
Python engine, for the cases that want reasoning rather than a table: a single pasted
email, a verdict that looks wrong, a judgement call about purge scope, a question
from someone who is not going to run a CLI.

The two are kept deliberately consistent:

| | Engine (`src/phish_triage`) | Skill (`skills/phishing-inbox-triage`) |
|---|---|---|
| Good at | Volume, repeatability, scheduled runs, exit codes | Judgement, explanation, odd cases, conversation |
| Output | Markdown / JSON handover report | The same formats, written to fit the case |
| Runs | In CI, on a timer, in a terminal | In Claude |

`scripts/parse_headers.py` is a verbatim copy of `src/phish_triage/headers.py`, which
is written dependency-free for exactly this reason. `tools/sync_skill.py` copies it
and CI fails if the two drift.

## Install

Claude Code or Cowork — copy the folder into a skills directory:

```bash
cp -r skills/phishing-inbox-triage ~/.claude/skills/
```

Claude.ai — zip the folder and upload it as a skill:

```bash
cd skills && zip -r phishing-inbox-triage.zip phishing-inbox-triage
```

Then ask it to work the queue:

> Work the phishing inbox for the overnight shift and give me the handover report.
> The export from the shared mailbox joined to Defender submissions is attached.

## Contents

| File | What it holds |
|---|---|
| `SKILL.md` | The workflow: lanes, exception categories, priorities, guardrails |
| `references/exception-criteria.md` | The test for each category, BEC indicators, when to disagree with AIR |
| `references/response-actions.md` | Action matrix with decision owners, and what never to recommend |
| `references/report-template.md` | Shift report and single-message formats |
| `scripts/parse_headers.py` | Header parser (vendored — edit `src/phish_triage/headers.py` instead) |
| `evals/evals.json` | Test prompts, run against `test-data/mailbox_export.json` |

## Changing it

Change the skill and the engine together, or they drift apart and the report an
analyst gets depends on which one ran. `tests/test_rules.py` pins the expected lanes
and priorities for the sample queue and is the place to record why a rule changed.
