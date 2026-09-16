# Two triage implementations, one decision to make

This branch and `main` independently built the same thing: SKILL.md's workflow as
deterministic rules. Both are merged and both are tested, so nothing is lost — but
carrying two implementations of one model is a maintenance tax, and a rule changed in
one will silently diverge from the other. This is the note for whoever decides.

## What each one is

| | `src/phish_triage/` (this branch) | `skills/…/scripts/triage.py` (`main`) |
|---|---|---|
| Shape | Installable package, `phish-triage` CLI | One stdlib script, ~790 lines |
| Install | `pip install -e .` | None — runs anywhere Python does |
| Ships with the skill | No (the skill vendors only `parse_headers.py`) | Yes, inside the bundle |
| Queue sources | JSON export, **Defender portal CSV** (column discovery), **Microsoft Graph** (live) | JSON export |
| Org context | `config.toml` (`org_domain`, `vip_list`, `known_partner_domains`, `column_map`, thresholds) | `--org-context` JSON + `export_meta` |
| Lookalike detection | Registrable-label containment | Edit distance + brand table |
| Negation handling | Window before the match | Clause splitting |
| Exit codes | `--fail-on p1/p2/exception` for scheduled runs | — |
| Tests | ~165 | 59 |

Both produce the same three lanes, the same five exception categories, the same P1–P4
scale, and the same handover report.

## The trade-off

**Keeping the package** buys the CSV importer — which is the only thing that reads what
the Defender portal actually exports — plus the live Graph source, a config file, and
an exit-code contract for cron. It costs the property that the skill bundle is
self-contained: `triage.py` runs after `unzip`, the package does not.

**Keeping the script** buys that self-containment, which is real: the bundle is the
unit people copy into a skills directory, and a skill that needs `pip install` to do
its main job is a worse skill. It costs the CSV importer and the Graph source, which
are the two pieces that connect this to a live tenant.

## The option that loses least

Keep both *models* but stop duplicating the rules: make `triage.py` the thin,
dependency-free entry point it already is, and have the package's engine be the one
place the rules live — with `tools/sync_skill.py` generating the vendored script the
same way it already generates `parse_headers.py` from `src/phish_triage/headers.py`.
That pattern is established in this repository and CI already enforces it.

It is more work than deleting one, and it constrains the engine to stay
dependency-free and single-file-generatable. That constraint is already met today.

## What not to do

Leave both hand-maintained. The rules *will* drift, and the two will disagree about a
P1 on the same message — which is worse than either alone, because nobody will know
which report to believe.
