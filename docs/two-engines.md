# Two implementations, one decision to make

This branch and `main` independently built the same things. Both are merged and both
are tested, so nothing is lost — but carrying two implementations of one model is a
maintenance tax, and a rule changed in one will silently diverge from the other. This
is the note for whoever decides.

The overlap has grown since this note was first written. It started as one pair — the
rules engine — and is now two:

| The job | This branch | `main` |
|---|---|---|
| Route the queue into lanes and priorities | `src/phish_triage/` (engine + `phish-triage` CLI) | `skills/…/scripts/triage.py` (795 lines) |
| Read the queue out of Microsoft Graph | `src/phish_triage/sources/graph.py` (386 lines) | `skills/…/scripts/collect_export.py` (723 lines) |

That second pair arrived a week after the first. Left alone, the pattern continues:
each side grows the piece the other already has, in a slightly different shape.

## What each triage implementation is

| | `src/phish_triage/` (this branch) | `skills/…/scripts/triage.py` (`main`) |
|---|---|---|
| Shape | Installable package, `phish-triage` CLI | One stdlib script |
| Install | `pip install -e .` | None — runs anywhere Python does |
| Ships with the skill | No (the skill vendors only `parse_headers.py`) | Yes, inside the bundle |
| Queue sources | JSON export, **Defender portal CSV** (column discovery), **Microsoft Graph** (live) | JSON export, and `collect_export.py` writes one |
| Org context | `config.toml` (`org_domain`, `vip_list`, `known_partner_domains`, `column_map`, thresholds) | `--org-context` JSON + `export_meta` |
| Lookalike detection | Registrable-label containment | Edit distance + brand table |
| Negation handling | Window before the match | Clause splitting |
| Exit codes | `--fail-on p1/p2/exception` for scheduled runs | — |
| Tests | 126 (pytest) | 59 (unittest) |

Both produce the same three lanes, the same five exception categories, the same P1–P4
scale, and the same handover report.

## What each Graph collector is

| | `sources/graph.py` (this branch) | `collect_export.py` (`main`) |
|---|---|---|
| Output | `ReportedMessage` objects, straight into the engine | `export.json` on disk, for `triage.py` to read |
| Sources read | Submissions, shared mailbox, `UrlClickEvents` | Submissions, shared mailbox, Advanced Hunting (clicks, URL inventory, attachments, auth, recipient counts) |
| Forwarded reports | Maps the forward | Pulls the **original** out of the forward |
| Missing source | `missing_sources` on the result, surfaced as a warning | `export_meta.collection_notes`, with named warnings for the two that mislead silently |
| Reporter notes | Not collected | `--reporter-notes`, joined from `graph_submit.py`'s state file |
| Scope self-check | — | `--deny-check` probes a mailbox it must *not* reach before reading any mail |
| Tests | 12 | 47 |

`collect_export.py` is the more thorough collector of the two. Its honest-degradation
handling and its `--deny-check` scope probe are things `sources/graph.py` does not do
and should.

## The trade-off

**Keeping the package** buys the CSV importer — which is the only thing that reads what
the Defender portal actually exports, and the only path to a real queue that needs no
app registration — plus a config file and an exit-code contract for cron. It costs the
property that the skill bundle is self-contained: the scripts run after `unzip`, the
package does not.

**Keeping the scripts** buys that self-containment, which is real: the bundle is the
unit people copy into a skills directory, and a skill that needs `pip install` to do
its main job is a worse skill. It costs the CSV importer, which is the shortest path
from a checkout to a real queue.

## The option that loses least

Keep both *shapes* but stop duplicating the logic: have `src/phish_triage/` be the one
place the rules and the Graph mapping live, and generate the vendored scripts from it
— the way `tools/sync_skill.py` already generates `parse_headers.py` from
`src/phish_triage/headers.py`. That pattern is established in this repository and CI
already enforces it, so a drift between the two fails the build instead of reaching an
analyst.

Going the other way is also coherent: delete `src/phish_triage/`, keep the scripts, and
port the CSV importer and the config file into `triage.py` as a second input format.
That is less code overall. It gives up the installable CLI and the `--fail-on` exit
codes.

Either is better than what exists now. The specific pieces worth carrying across
whichever direction is chosen:

- the **Defender CSV importer** with column discovery and `inspect` (only in the package)
- `collect_export.py`'s **honest degradation** — `collection_notes`, and never emitting
  `[]` for *unknown* (only in the scripts)
- `collect_export.py`'s **`--deny-check`** scope probe (only in the scripts)
- the package's **`--fail-on`** exit codes (only in the package)

## What not to do

Leave both hand-maintained. The rules *will* drift, and the two will disagree about a
P1 on the same message — which is worse than either alone, because nobody will know
which report to believe. The same goes for the collectors: two queues built from the
same tenant that quietly differ in what they contain is a worse failure than one queue
that is missing something and says so.
