# Queue export format

The engine reads a single JSON object. `test-data/mailbox_export.json` is a complete
worked example with ten items covering every lane.

```json
{
  "export_meta": {
    "source": "phishing@contoso.com shared mailbox + Defender Submissions join",
    "window": "2026-09-14T00:00:00Z to 2026-09-14T08:00:00Z",
    "org_domain": "contoso.com",
    "vip_list": ["r.alvarez@contoso.com"],
    "missing_sources": ["UrlClickEvents — no ThreatHunting permission"]
  },
  "items": [ { "...": "one object per reported message" } ]
}
```

## `export_meta`

| Field | Why it matters |
|---|---|
| `source` | Printed in the report so the reader knows what was looked at |
| `window` | Also used as "now" when ageing AIR investigations, so re-running an export is stable |
| `org_domain` | Lookalike detection. Without it, `contoso-finance.co` looks like any other domain |
| `vip_list` | Priority accounts. A routine phish landing here is still an exception |
| `missing_sources` | What you could not read. Surfaces in the report rather than being papered over |

Anything in `export_meta` can also come from `--config`; the config wins.

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
side. The engine then reports AIR status as not available and says where to look,
rather than guessing — most lane decisions depend on that field.

## Optional extra fields

Any field not listed above is kept on the item and a few are read if present:

| Field | Effect |
|---|---|
| `recipients` | string[] of all recipients; used for VIP matching |
| `interactions` | string[] of telemetry-confirmed interactions; forces a compromise finding |
| `sender_first_seen` | truthy adds the first-seen-sender BEC signal |
| `shared_mailbox_or_dl`, `legal_hold` | truthy makes remediation scope a decision |
