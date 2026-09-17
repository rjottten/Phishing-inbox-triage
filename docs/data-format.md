# Queue export format

`triage.py` reads a single JSON object. `test-data/mailbox_export.json` is a complete
worked example with ten items covering every lane.

Both collectors write this shape — `collect_export.py` from Graph,
`import_defender_csv.py` from a portal CSV — so nothing downstream cares where the
queue came from. A bare list of items works too, if you are assembling one by hand.

```json
{
  "export_meta": {
    "source": "phishing@contoso.com shared mailbox + Defender Submissions join",
    "window": "2026-09-14T00:00:00Z to 2026-09-14T08:00:00Z",
    "org_domains": ["contoso.com"],
    "vip_list": ["r.alvarez@contoso.com"],
    "collection_notes": ["UrlClickEvents — no ThreatHunting permission"]
  },
  "items": [ { "...": "one object per reported message" } ]
}
```

## `export_meta`

| Field | Why it matters |
|---|---|
| `source` | Printed in the report so the reader knows what was looked at |
| `window` | Also used as "now" when ageing AIR investigations, so re-running an export is stable. Must contain ` to ` — an unparseable window silently falls back to the wall clock, which ages every investigation wrongly |
| `org_domains` | Lookalike detection. Without it, `contoso-finance.co` looks like any other domain. `org_domain` (singular) is read too |
| `vip_list` | Priority accounts. A routine phish landing here is still an exception |
| `collection_notes` | What the collector could not read. Printed with the report rather than papered over |

Anything in `export_meta` can also come from `--org-context`, which is merged with it
rather than replacing it — so tenant facts live in one file and the export carries
only what it observed.

## `items[]`

| Field | Type | Notes |
|---|---|---|
| `id` | string | Your queue reference. Falls back to `ITEM-n` |
| `reporter` | string | Who reported it |
| `received` | ISO 8601 | Used for AIR staleness |
| `reported_via` | string | `outlook_report_button` or `forwarded_to_mailbox`. Anything not the button is an automation gap |
| `from_name`, `from_address` | string | Display name and address, kept separate — the gap between them is the signal |
| `reply_to` | string / null | Where a reply actually goes |
| `subject`, `body_excerpt` | string | Scanned for intent. Never rendered as HTML, never executed |
| `urls` | string[] | Store defanged (`hxxps://x[.]com`). Nothing ever fetches these |
| `attachments` | string[] | Filenames only. Nothing ever opens these |
| `auth` | object | `{"spf": "pass", "dkim": "pass", "dmarc": "none"}` |
| `recipient_count` | int | Campaign scope |
| `recipients_vip` | string[] | Priority accounts among the recipients |
| `reporter_note` | string | The reporter's own words. This is where interaction is usually discovered |
| `defender` | object | See below |

### `items[].defender`

| Field | Notes |
|---|---|
| `submission_id` | `null` when no submission exists — an automation gap |
| `air_status` | `Completed`, `Pending`, `Running`, `Awaiting approval`, `Failed` |
| `verdict` | `Phishing`, `Malware`, `Spam`, `No threats found`, `Clean` |
| `user_notified` | Whether Defender auto-notify reached the reporter |
| `actions` | Free text. `PENDING:` anywhere in it means a human has to approve |

Set `defender` to `null` or omit it when you have the mailbox but not the Defender
side. That reads as an automation gap, which is the honest answer: without a
submission id there is no evidence automation ever saw the message.

An `air_status` or `verdict` string outside the vocabulary above is *not* an error and
is kept as-is — but `triage.py` cannot route on what it does not recognise, so the
item falls through to "unrecognised AIR state" and lands in the gap lane. Both
collectors map the portal's strings onto this vocabulary for exactly that reason.

## Optional extra fields

Any field not listed above is kept on the item and a few are read if present:

| Field | Effect |
|---|---|
| `click_telemetry` | Confirmed click data from `UrlClickEvents`. Its **absence** is noted in the report as something not verified, rather than read as "nobody clicked" |
| `raw_headers` | Raw header block. `parse_headers.py` runs over it and its flags merge into the indicators |

Anything else is carried through untouched, so a collector can attach whatever
context it has without breaking the format.

## The two fields that decide the most

`reporter_note` and `defender.submission_id` between them settle most items.

The note is where interaction lives — *"I clicked it and put in my password"* — and
nothing else in the export can substitute for it. `click_telemetry` sees a click; it
cannot see credentials entered, an MFA prompt approved, or an invoice paid. An export
collected without notes turns P1s into P2s, which is why `collect_export.py` says so
in `collection_notes` when the note source was not configured.

The submission id is the difference between "automation has this" and "automation
never saw it". A `null` there routes the item to the gap lane no matter how clean it
looks, which is correct: an unreported phish has had nothing done about it.
