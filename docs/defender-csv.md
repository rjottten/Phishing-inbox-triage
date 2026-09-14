# Importing a Defender portal CSV

The fastest way to run this against your real queue: export from the Defender
portal, feed the file straight in. No app registration, no admin consent.

```bash
phish-triage inspect --input submissions.csv    # check it reads your columns
phish-triage run     --input submissions.csv --config config.toml
```

`--input` takes a CSV or a JSON export and works out which is which, so you never
have to say.

## Always inspect first

Column names differ between export views, portal versions and tenant locales, so
the importer *discovers* them rather than assuming. `inspect` shows exactly what it
made of your file before you trust a run:

```
submissions_export.csv: 6 data row(s), 14 column(s)

Detected columns:
  submission_id        <- 'Submission ID'
  received             <- 'Submission date'
  reporter             <- 'Submitted by'
  from_address         <- 'Sender'
  air_status           <- 'Status'
  verdict              <- 'Result'
  ...

Columns in the file that were not recognised:
  'Sender IP'
  'Reason for submission'

Usable: yes
```

Unrecognised columns are not an error — most exports carry fields the engine has no
use for. They are listed so that if one of them *is* a field it needs, you can see it.

## When a column is not recognised

Map it in your config. No code change, no waiting on me:

```toml
[column_map]
from_address = "Absender"
subject      = "Betreff"
reporter     = "Gemeldet von"
```

Config overrides win outright. Canonical field names are the left-hand column in
`inspect` output; the full list is in `COLUMN_ALIASES` in
`src/phish_triage/sources/defender_csv.py`.

## Which export to use

| Export | Path in the portal | Notes |
|---|---|---|
| **Submissions** | Actions & submissions → Submissions → User reported | Best fit. Carries submission id, status, result, reporter |
| **User reported** | Actions & submissions → Submissions → User reported tab | Same shape |
| **Threat Explorer** | Explorer → All email / Phish | One row per recipient — folded automatically |
| **Advanced Hunting** | Hunting → `EmailEvents` | Richest headers and auth details, but no submission or AIR state |

Advanced Hunting exports **all** mail flow, not just reported mail, so the default
assumption that every row was reported via the Outlook button is wrong there. Set it
explicitly:

```toml
default_reported_via = "forwarded_to_mailbox"   # or "admin_submission"
```

## Rows are folded by message

A mail to 412 recipients exports as 412 rows. Rows sharing a `Network Message ID`
(or `Internet Message ID`, or `Submission ID`) become one item, and the row count
becomes the recipient count.

This matters more than it sounds: without it a campaign reads as 412 unrelated
one-recipient reports, every VIP recipient past the first is invisible, and purge
blast radius — which drives the remediation-decision lane — is always 1.

## What the importer will not do

- **It will not invent a verdict.** An unrecognised result string is passed through
  unchanged rather than guessed at. Known values (`Not junk`, `Phish`, `High
  confidence phish`, `No threat found`, …) map onto the engine's vocabulary.
- **It will not invent a filename.** Where an export carries only `AttachmentCount`
  or `UrlCount`, you get `(1 attachment; filenames not included in this export)` —
  the engine knows a payload existed without pretending to know what it was.
- **It will not hide what is missing.** Anything the export does not carry is listed
  under **Data sources** in the report. Most exports have no auto-notify flag, so a
  closed submission is treated as notified and the report says that is an inference.

## Gotchas

- **Excel adds a BOM**; handled (`utf-8-sig`). Semicolon- and tab-delimited files are
  detected too, so a European Excel export works unchanged.
- **Reporter notes are usually absent.** The Submissions export has no free-text
  field, and the reporter's own words are where interaction is normally found
  ("I clicked it and put in my password"). Without them the engine cannot see
  interaction, so items that should be P1 will come back P2. If your export has a
  comment column, map it to `reporter_note`. Otherwise treat the priorities as a
  floor, not a verdict.
- **Exports contain real data** — reporter names, live lure URLs. They are covered by
  `.gitignore` (`*.export.json`, `exports/`, `reports/`), but keep them under the same
  controls as the mailbox itself.
