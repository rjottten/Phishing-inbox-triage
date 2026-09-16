# Importing a Defender portal CSV

The fastest way to run this against your real queue: export from the Defender
portal, feed the file straight in. No app registration, no admin consent.

```bash
cd skills/phishing-inbox-triage/scripts

python import_defender_csv.py submissions.csv --inspect     # check it reads your columns
python import_defender_csv.py submissions.csv --out export.json
python triage.py export.json --org-context org-context.json
```

The importer writes the same `export.json` shape `collect_export.py` writes, so
everything downstream is identical whichever way the queue was collected. Both steps
are offline — no credentials, no network, nothing sent anywhere.

## Always inspect first

Column names differ between export views, portal versions and tenant locales, so
the importer *discovers* them rather than assuming. `--inspect` shows exactly what it
made of your file, and changes nothing:

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

Unrecognised columns are not an error — most exports carry fields triage has no use
for. They are listed so that if one of them *is* a field it needs, you can see it.

## When a column is not recognised

Name it yourself. No code change, no waiting on me — on the command line:

```bash
python import_defender_csv.py submissions.csv \
    --column-map from_address=Absender \
    --column-map subject=Betreff \
    --column-map reporter="Gemeldet von"
```

or once, in your org-context file, so you never retype it:

```json
{
  "org_domains": ["contoso.com"],
  "column_map": {
    "from_address": "Absender",
    "subject": "Betreff",
    "reporter": "Gemeldet von"
  }
}
```

Overrides win outright. Canonical field names are the left-hand column in `--inspect`
output; the full list is `COLUMN_ALIASES` at the top of
[`import_defender_csv.py`](../skills/phishing-inbox-triage/scripts/import_defender_csv.py).

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

```bash
python import_defender_csv.py events.csv --reported-via forwarded_to_mailbox
```

## Rows are folded by message

A mail to 412 recipients exports as 412 rows. Rows sharing a `Network Message ID`
(or `Internet Message ID`, or `Submission ID`) become one item, and the row count
becomes the recipient count.

This matters more than it sounds: without it a campaign reads as 412 unrelated
one-recipient reports, every VIP recipient past the first is invisible, and purge
blast radius — which drives the remediation-decision lane — is always 1.

## What a CSV cannot give you

No portal CSV carries message bodies or click telemetry, whatever columns it has.
Both come from Graph, via `collect_export.py`. The CSV path is the fastest way in and
the right one to start with; it is not the richest.

## What the importer will not do

- **It will not invent a verdict.** An unrecognised result string is passed through
  unchanged rather than guessed at. Known values (`Not junk`, `Phish`, `High
  confidence phish`, `No threat found`, …) map onto `triage.py`'s vocabulary.
- **It will not invent a filename.** Where an export carries only `AttachmentCount`
  or `UrlCount`, you get `(1 attachment; filenames not included in this export)` —
  triage knows a payload existed without pretending to know what it was.
- **It will not hide what is missing.** Everything the export could not supply is
  written into `export_meta.collection_notes` and printed to stderr on every run, the
  same way `collect_export.py` reports a source it could not read. Most exports have
  no auto-notify flag, so a closed submission is treated as notified and the notes say
  that is an inference.

**Read the notes on every run.** A quiet gap there is how a partial queue looks like a
complete one. Two are worth knowing about in advance:

- **No URL column.** `triage.py` reads an empty URL list as "no link, so this could be
  BEC". An export with no URL column is not an export with no URLs, and the note says
  so — treat BEC findings from such a run with care.
- **No comment column.** See the gotcha below.

## Gotchas

- **Excel adds a BOM**; handled (`utf-8-sig`). Semicolon- and tab-delimited files are
  detected too, so a European Excel export works unchanged.
- **Reporter notes are usually absent.** The Submissions export has no free-text
  field, and the reporter's own words are where interaction is normally found
  ("I clicked it and put in my password"). Without them triage cannot see
  interaction, so items that should be P1 will come back P2. If your export has a
  comment column, map it to `reporter_note`. Otherwise treat the priorities as a
  floor, not a verdict — or collect the queue with `collect_export.py --reporter-notes`
  instead, which carries the note across from `graph_submit.py`.
- **Exports contain real data** — reporter names, live lure URLs. They are covered by
  `.gitignore` (`*.export.json`, `exports/`, `reports/`), but keep them under the same
  controls as the mailbox itself.
