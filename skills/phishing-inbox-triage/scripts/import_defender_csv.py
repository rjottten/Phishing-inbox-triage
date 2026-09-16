#!/usr/bin/env python3
"""Defender portal CSV export -> the JSON export triage.py reads.

The other way to build a queue. `collect_export.py` needs an app registration,
three Graph permissions and admin consent; this needs a file you can download
from the portal in one click:

    Actions & submissions -> Submissions -> Export

    python import_defender_csv.py submissions.csv --inspect    # what did it read?
    python import_defender_csv.py submissions.csv --out export.json
    python triage.py export.json --org-context org-context.json

That makes it the shortest path from a checkout to a real queue, and the one to
start with. What it cannot give you is anything the portal does not export:
message bodies, the reporter's note, and click telemetry all come from Graph.

Column names vary by export view (Submissions, User reported, Threat Explorer,
Advanced Hunting `EmailEvents`), by portal version, and by tenant locale. So this
*discovers* columns rather than assuming them: each canonical field carries a
list of aliases, headers match on a normalized form, and anything it cannot place
is reported rather than silently dropped. `--inspect` shows the whole mapping
before you trust a run. Anything unrecognised you can name yourself, in the
org-context file or on the command line:

    {"column_map": {"from_address": "Absender"}}
    --column-map from_address=Absender

One message can span many rows: a mail to 412 recipients exports as 412 rows in
Threat Explorer. Rows sharing a message id are folded into one item and the row
count becomes the recipient count, which is what makes campaign scope and purge
blast radius mean anything.

Offline, like triage.py: it reads a file and writes a file. No network, no
credentials, nothing sent anywhere.
"""
import argparse
import csv
import io
import json
import os
import re
import sys
from datetime import datetime, timezone

#: Canonical field -> header aliases, in normalized form (see `normalize`).
#: Order matters: the first alias that matches a header wins for that field.
COLUMN_ALIASES = {
    "submission_id": ["submission id", "submissionid", "id", "alert id", "report id"],
    "network_message_id": ["network message id", "networkmessageid"],
    "internet_message_id": ["internet message id", "internetmessageid", "message id"],
    "received": [
        "submission date", "date submitted", "submitted on", "submitted date",
        "date reported", "reported date", "received date", "date received",
        "first submission date", "timestamp", "date", "time generated",
    ],
    "reporter": [
        "submitted by", "reported by", "message reported by", "submitter",
        "reported by user", "user reported by", "submitted by user", "sender of report",
    ],
    "source": [
        "submission type", "report type", "source", "submission source",
        "reason for submission", "submission reason", "reported reason", "report reason",
    ],
    "from_address": [
        "sender", "sender address", "sender email address", "senderfromaddress",
        "sender mail from address", "sendermailfromaddress", "from address",
        "from", "senderemailaddress", "sender from address",
    ],
    "from_name": ["sender display name", "senderdisplayname", "display name", "from name", "sender name"],
    "reply_to": ["reply to", "reply-to", "replyto", "reply to address"],
    "subject": ["subject", "email subject", "message subject", "mail subject"],
    "recipient": [
        "recipient", "recipients", "recipient email address", "recipientemailaddress",
        "recipient address", "to", "to address", "recipient email",
    ],
    "air_status": [
        "status", "rescan status", "submission status", "investigation status",
        "air status", "analysis status",
    ],
    "verdict": [
        "result", "rescan result", "verdict", "filter verdict", "original verdict",
        "threat types", "threattypes", "detection", "delivery reason", "threat",
    ],
    "user_notified": ["user notified", "notified", "reporter notified", "result shared with user"],
    "actions": [
        "actions", "action taken", "remediation action", "email action", "emailaction",
        "tenant allow block list", "tenant allow/block list", "action",
    ],
    # Counts before names: 'AttachmentCount' must not be read as a filename, which
    # is what a loose match on 'attachment' would otherwise do.
    "url_count": ["url count", "urlcount", "number of urls"],
    "attachment_count": ["attachment count", "attachmentcount", "number of attachments"],
    "urls": ["urls", "url", "url domain", "urldomain", "url list"],
    "attachments": ["attachment", "attachments", "attachment name", "file name", "filename", "attachment filename"],
    "recipient_count": ["recipient count", "recipients count", "message count", "count"],
    "auth_details": ["authentication details", "authenticationdetails", "composite authentication", "auth details"],
    "spf": ["spf", "spf result"],
    "dkim": ["dkim", "dkim result"],
    "dmarc": ["dmarc", "dmarc result"],
    "reporter_note": ["user comment", "comments", "comment", "note", "notes", "user reported reason", "additional information"],
    "phish_confidence": ["phish confidence level", "confidence level", "confidencelevel"],
    "delivery_location": ["latest delivery location", "delivery location", "original delivery location", "deliverylocation"],
}

#: Defender result strings -> the verdict vocabulary triage.py speaks.
VERDICT_VALUES = {
    "phish": "Phishing",
    "phishing": "Phishing",
    "high confidence phish": "Phishing",
    "highconfidencephish": "Phishing",
    "spoof": "Phishing",
    "credential phish": "Phishing",
    "malware": "Malware",
    "spam": "Spam",
    "high confidence spam": "Spam",
    "highconfidencespam": "Spam",
    "bulk": "Spam",
    "should have been blocked": "Phishing",
    "not junk": "No threats found",
    "no threats found": "No threats found",
    "no threat found": "No threats found",
    "nothreatsfound": "No threats found",
    "clean": "No threats found",
    "legitimate": "No threats found",
    "allowed by policy": "No threats found",
    "should not have been blocked": "No threats found",
    "no threats": "No threats found",
}

#: Defender status strings -> the AIR status vocabulary.
STATUS_VALUES = {
    "completed": "Completed",
    "complete": "Completed",
    "rescan completed": "Completed",
    "finished": "Completed",
    "done": "Completed",
    "in progress": "Running",
    "inprogress": "Running",
    "running": "Running",
    "started": "Running",
    "rescan in progress": "Running",
    "analysis in progress": "Running",
    "pending": "Pending",
    "submitted": "Pending",
    "queued": "Pending",
    "not started": "Pending",
    "awaiting approval": "Awaiting approval",
    "pending approval": "Awaiting approval",
    "error": "Failed",
    "failed": "Failed",
    "terminated": "Failed",
    "partially completed": "Failed",
}

#: `source` values -> `reported_via`. Substring match, first hit wins.
SOURCE_VALUES = [
    ("admin", "admin_submission"),
    ("analyst", "admin_submission"),
    ("user report", "outlook_report_button"),
    ("user submission", "outlook_report_button"),
    ("user", "outlook_report_button"),
    ("report button", "outlook_report_button"),
    ("outlook", "outlook_report_button"),
    ("forward", "forwarded_to_mailbox"),
    ("mailbox", "forwarded_to_mailbox"),
]

TRUE_VALUES = {"true", "yes", "y", "1", "notified", "sent"}
DATE_FORMATS = (
    "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d",
    "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M", "%m/%d/%Y",
    "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%d/%m/%Y",
    "%b %d, %Y %I:%M:%S %p", "%d %b %Y %H:%M:%S",
)
SPLIT_RE = re.compile(r"[;,]\s*|\s{2,}")

COMPLETED_STATUSES = {"Completed"}


class CsvError(ValueError):
    """The export could not be read as a queue. The message names what to fix."""


# --------------------------------------------------------------------------
# Column discovery
# --------------------------------------------------------------------------

def normalize(header):
    """Fold a header to its comparable form: 'Sender_IP ' -> 'sender ip'."""
    return re.sub(r"[^a-z0-9]+", " ", (header or "").strip().lower()).strip()


class ColumnMapping(object):
    """What the importer made of the file's headers."""

    def __init__(self):
        self.mapped = {}
        self.unmapped_headers = []
        self.overrides = {}

    @property
    def usable(self):
        """Enough to identify a message. Without a sender or a subject there is
        nothing to triage, whatever else the file contains."""
        return bool(self.mapped.get("from_address") or self.mapped.get("subject"))

    def describe(self):
        lines = ["Detected columns:"]
        for canonical in COLUMN_ALIASES:
            header = self.mapped.get(canonical)
            if header:
                via = " (from column_map)" if canonical in self.overrides else ""
                lines.append("  %-20s <- %r%s" % (canonical, header, via))
        missing = [c for c in COLUMN_ALIASES if c not in self.mapped]
        if missing:
            lines.append("")
            lines.append("Not found (optional unless noted):")
            lines.append("  " + ", ".join(missing))
        if self.unmapped_headers:
            lines.append("")
            lines.append("Columns in the file that were not recognised:")
            for header in self.unmapped_headers:
                lines.append("  %r" % header)
            lines.append("")
            lines.append("If one of those is a field above, name it yourself:")
            lines.append("  --column-map <field>=%s" % self.unmapped_headers[0])
        return "\n".join(lines)


def detect_mapping(headers, column_map=None):
    """Match the file's headers to canonical fields.

    Explicit overrides win outright; otherwise a header is matched on its
    normalized form, exact alias first and a contains-match second, so 'Sender
    Email Address (UPN)' still lands on `from_address`.
    """
    column_map = column_map or {}
    mapping = ColumnMapping()
    by_normal = {}
    for h in headers:
        if h:
            by_normal.setdefault(normalize(h), h)
    claimed = set()

    for canonical, header in column_map.items():
        match = by_normal.get(normalize(header))
        if match:
            mapping.mapped[canonical] = match
            mapping.overrides[canonical] = match
            claimed.add(match)

    for canonical, aliases in COLUMN_ALIASES.items():
        if canonical in mapping.mapped:
            continue
        for alias in aliases:
            header = by_normal.get(alias)
            if header and header not in claimed:
                mapping.mapped[canonical] = header
                claimed.add(header)
                break

    # Second pass: looser containment, for headers carrying extra qualifiers.
    for canonical, aliases in COLUMN_ALIASES.items():
        if canonical in mapping.mapped:
            continue
        for alias in aliases:
            if len(alias) < 4:
                continue  # 'spf'/'to' would match far too much
            for normal, header in by_normal.items():
                if header not in claimed and (alias in normal or normal in alias):
                    mapping.mapped[canonical] = header
                    claimed.add(header)
                    break
            if canonical in mapping.mapped:
                break

    mapping.unmapped_headers = [h for h in headers if h and h not in claimed]
    return mapping


# --------------------------------------------------------------------------
# Cell readers
# --------------------------------------------------------------------------

def value(row, mapping, canonical):
    header = mapping.mapped.get(canonical)
    return (row.get(header) or "").strip() if header else ""


def count(row, mapping, canonical):
    """Read a numeric column, tolerating '1', ' 1 ', and an empty cell."""
    raw = re.sub(r"[^0-9]", "", value(row, mapping, canonical))
    return int(raw) if raw else 0


def parse_date(text):
    if not text:
        return None
    cleaned = text.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(cleaned)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    for fmt in DATE_FORMATS:
        try:
            return datetime.strptime(text.strip(), fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def split(text):
    return [part.strip() for part in SPLIT_RE.split(text) if part.strip()] if text else []


def defang(url):
    """Store URLs defanged so nothing downstream can make one clickable."""
    if not url.lower().startswith(("http://", "https://")):
        return url
    return url.replace("http", "hxxp", 1).replace(".", "[.]", 1)


def parse_auth(row, mapping):
    """Authentication results, from either discrete columns or the JSON blob that
    Advanced Hunting puts in `AuthenticationDetails`."""
    auth = {}
    for mech in ("spf", "dkim", "dmarc"):
        raw = value(row, mapping, mech).lower()
        if raw:
            auth[mech] = raw.split()[0].strip(",;")

    blob = value(row, mapping, "auth_details")
    if blob:
        try:
            parsed = json.loads(blob)
            if isinstance(parsed, dict):
                for key, val in parsed.items():
                    key = key.strip().lower()
                    if key in ("spf", "dkim", "dmarc", "compauth") and val:
                        auth.setdefault(key, str(val).strip().lower())
        except (ValueError, TypeError):
            for mech in ("spf", "dkim", "dmarc", "compauth"):
                found = re.search(
                    r"\b%s\W{0,3}(pass|fail|softfail|neutral|none|permerror|temperror|bestguesspass)\b" % mech,
                    blob, re.I)
                if found:
                    auth.setdefault(mech, found.group(1).lower())
    return auth


def map_value(text, table):
    """Map an exported string onto our vocabulary, keeping the original when we do
    not recognise it — a guessed verdict is worse than an unfamiliar one."""
    if not text:
        return ""
    key = text.strip().lower()
    if key in table:
        return table[key]
    for known, mapped in table.items():
        if known in key:
            return mapped
    return text.strip()


def reported_via(text, default):
    key = text.strip().lower()
    if not key:
        return default
    for needle, via in SOURCE_VALUES:
        if needle in key:
            return via
    return default


def row_key(row, mapping, index):
    """Rows describing the same message must fold together, or a 412-recipient
    campaign reads as 412 unrelated one-recipient reports."""
    for canonical in ("network_message_id", "internet_message_id", "submission_id"):
        found = value(row, mapping, canonical)
        if found:
            return "%s:%s" % (canonical, found.lower())
    sender = value(row, mapping, "from_address").lower()
    subject = value(row, mapping, "subject").lower()
    if sender or subject:
        return "composite:%s|%s" % (sender, subject)
    return "row:%d" % index


# --------------------------------------------------------------------------
# Rows -> export items
# --------------------------------------------------------------------------

def build_item(key, rows, mapping, default_via, vip):
    """One export item from the rows that describe one message."""
    first = rows[0]
    recipients = []
    for row in rows:
        recipients.extend(r.lower() for r in split(value(row, mapping, "recipient")))
    recipients = list(dict.fromkeys(recipients))

    declared = re.sub(r"[^0-9]", "", value(first, mapping, "recipient_count"))
    recipient_count = max(int(declared) if declared else 0, len(recipients), len(rows), 1)

    reporters = [r for r in (value(row, mapping, "reporter") for row in rows) if r]
    reporter = reporters[0] if reporters else ""
    if len(set(reporters)) > 1:
        reporter = "multiple (%d reporters)" % len(set(reporters))

    urls, attachments, notes = [], [], []
    for row in rows:
        urls.extend(split(value(row, mapping, "urls")))
        attachments.extend(split(value(row, mapping, "attachments")))
        note = value(row, mapping, "reporter_note")
        if note and note not in notes:
            notes.append(note)

    # An export may say only *how many* URLs or attachments there were. That still
    # tells triage.py a payload existed; say so plainly rather than inventing names.
    if not urls:
        n = count(first, mapping, "url_count")
        if n:
            urls = ["(%d URL%s; addresses not included in this export)" % (n, "s" if n > 1 else "")]
    if not attachments:
        n = count(first, mapping, "attachment_count")
        if n:
            attachments = ["(%d attachment%s; filenames not included in this export)" % (n, "s" if n > 1 else "")]

    submission_id = value(first, mapping, "submission_id") or None
    verdict = map_value(value(first, mapping, "verdict"), VERDICT_VALUES)
    status = map_value(value(first, mapping, "air_status"), STATUS_VALUES)
    notified_raw = value(first, mapping, "user_notified")
    notified = notified_raw.strip().lower() in TRUE_VALUES
    actions = "; ".join(dict.fromkeys(
        a for a in (value(row, mapping, "actions") for row in rows) if a))

    # Defender does not export an auto-notify flag in most views. Rather than read
    # its absence as "the reporter was left in the dark", treat a closed submission
    # as notified and say so in collection_notes.
    if not notified and mapping.mapped.get("user_notified") is None:
        notified = status in COMPLETED_STATUSES and bool(verdict)

    received = parse_date(value(first, mapping, "received"))
    note_text = " ".join(notes)

    return {
        "id": (submission_id
               or value(first, mapping, "network_message_id")
               or key.split(":", 1)[-1][:64]
               or key),
        "received": received.isoformat() if received else None,
        "reporter": reporter,
        "reported_via": reported_via(value(first, mapping, "source"), default_via),
        "from_name": value(first, mapping, "from_name"),
        "from_address": value(first, mapping, "from_address").lower(),
        "reply_to": value(first, mapping, "reply_to").lower() or None,
        "subject": value(first, mapping, "subject"),
        # The portal exports no message body. The reporter's note is the only prose
        # there is, so it stands in for the excerpt rather than leaving it empty.
        "body_excerpt": note_text,
        "urls": [defang(u) for u in dict.fromkeys(urls)],
        "attachments": list(dict.fromkeys(attachments)),
        "auth": parse_auth(first, mapping),
        "recipient_count": recipient_count,
        "recipients_vip": [r for r in recipients if r in vip],
        "reporter_note": note_text,
        "defender": {
            "submission_id": submission_id,
            "air_status": status or None,
            "verdict": verdict or None,
            "user_notified": notified,
            "actions": actions,
        },
    }


def collection_notes(mapping):
    """What this export could not tell us. A quiet gap here is how a partial queue
    looks like a complete one, so each one is named."""
    notes = []
    if "air_status" not in mapping.mapped and "verdict" not in mapping.mapped:
        notes.append("AIR status and verdict: no status or result column in this export, "
                     "so every item will look like it has no Defender outcome")
    if "user_notified" not in mapping.mapped:
        notes.append("reporter-notified flag: not exported, inferred from submission status")
    if "recipient" not in mapping.mapped and "recipient_count" not in mapping.mapped:
        notes.append("recipient scope: no recipient column, so campaign size is unknown")
    if "urls" not in mapping.mapped and "url_count" not in mapping.mapped:
        notes.append("URL inventory: not exported. triage.py reads an empty URL list as "
                     "'no link, so this could be BEC' — treat BEC findings with care")
    if "reporter_note" not in mapping.mapped:
        notes.append("reporter notes: not exported. Compromise detection falls back to the "
                     "message itself, which cannot see credentials entered or a payment made")
    notes.append("message bodies and click telemetry are never in a portal CSV; "
                 "collect_export.py reads both from Graph")
    if mapping.unmapped_headers:
        notes.append("%d unrecognised column(s): %s — run with --inspect"
                     % (len(mapping.unmapped_headers), ", ".join(
                         repr(h) for h in mapping.unmapped_headers[:5])))
    return notes


def parse_rows(rows, headers, column_map=None, default_via="outlook_report_button",
               vip_list=None, org_domains=None, source_label="Defender CSV export"):
    """Turn parsed CSV rows into the export shape. Pure; no file I/O."""
    mapping = detect_mapping(headers, column_map)
    if not mapping.usable:
        raise CsvError(
            "could not find a sender or subject column in this export.\n\n"
            + mapping.describe()
            + "\n\nRun with --inspect to see this, then name the columns with "
              "--column-map <field>=<header>.")

    vip = set(v.lower() for v in (vip_list or []))
    grouped = {}
    order = []
    for index, row in enumerate(rows):
        if not any((v or "").strip() for v in row.values()):
            continue
        key = row_key(row, mapping, index)
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        grouped[key].append(row)

    items = [build_item(key, grouped[key], mapping, default_via, vip) for key in order]
    items.sort(key=lambda it: it["received"] or "")

    dates = [it["received"] for it in items if it["received"]]
    meta = {
        "source": source_label,
        "window": "%s to %s" % (min(dates), max(dates)) if dates else "",
        "collection_notes": collection_notes(mapping),
        "columns_detected": dict(mapping.mapped),
    }
    if org_domains:
        meta["org_domains"] = list(org_domains)
    if vip_list:
        meta["vip_list"] = list(vip_list)
    return meta, items, mapping


def read_rows(path):
    """Read a CSV/TSV, coping with the BOM Excel and the portal both like to add."""
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        text = fh.read()
    if not text.strip():
        raise CsvError("%s is empty" % path)
    try:
        dialect = csv.Sniffer().sniff(text[:8192], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    headers = [h for h in (reader.fieldnames or []) if h is not None]
    if not headers:
        raise CsvError("%s has no header row" % path)
    return list(reader), headers


def inspect_report(path, column_map=None):
    """Human-readable account of what the importer makes of a file."""
    rows, headers = read_rows(path)
    mapping = detect_mapping(headers, column_map)
    out = ["%s: %d data row(s), %d column(s)" % (os.path.basename(path), len(rows), len(headers)), ""]
    out.append(mapping.describe())
    if rows:
        out.extend(["", "First row as the importer reads it:"])
        for canonical in COLUMN_ALIASES:
            header = mapping.mapped.get(canonical)
            if header:
                cell = (rows[0].get(header) or "").strip()
                out.append("  %-20s = %r" % (canonical, cell[:80]))
    out.append("")
    out.append("Usable: yes" if mapping.usable
               else "Usable: NO - needs at least a sender or subject column")
    return "\n".join(out)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def load_org_context(path):
    if not path:
        return {}
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def parse_column_map(pairs):
    out = {}
    for pair in pairs or []:
        if "=" not in pair:
            raise CsvError("--column-map wants field=Header, got %r" % pair)
        field, header = pair.split("=", 1)
        field = field.strip()
        if field not in COLUMN_ALIASES:
            raise CsvError("unknown field %r. Known fields: %s"
                           % (field, ", ".join(sorted(COLUMN_ALIASES))))
        out[field] = header.strip()
    return out


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Turn a Defender portal CSV export into the JSON export triage.py reads.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Offline: reads a file, writes a file. No network, no credentials.")
    parser.add_argument("csv_path", help="the exported CSV (or TSV) from the Defender portal")
    parser.add_argument("--out", help="write the export here (default: stdout)")
    parser.add_argument("--inspect", action="store_true",
                        help="show how the columns were read and exit, changing nothing")
    parser.add_argument("--org-context", help="JSON with org_domains, vip, and optionally column_map")
    parser.add_argument("--column-map", action="append", metavar="FIELD=HEADER",
                        help="name a column yourself; repeatable")
    parser.add_argument("--reported-via", default="outlook_report_button",
                        choices=["outlook_report_button", "forwarded_to_mailbox", "admin_submission"],
                        help="how these were reported, when the export does not say")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        ctx = load_org_context(args.org_context)
        column_map = dict(ctx.get("column_map") or {})
        column_map.update(parse_column_map(args.column_map))

        if args.inspect:
            print(inspect_report(args.csv_path, column_map))
            return 0

        rows, headers = read_rows(args.csv_path)
        meta, items, mapping = parse_rows(
            rows, headers,
            column_map=column_map,
            default_via=args.reported_via,
            vip_list=ctx.get("vip") or ctx.get("vip_list") or [],
            org_domains=ctx.get("org_domains") or [],
            source_label="Defender CSV export (%s)" % os.path.basename(args.csv_path))
    except CsvError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    except OSError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    payload = {"export_meta": meta, "items": items}
    text = json.dumps(payload, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print("wrote %s: %d item(s) from %d row(s)" % (args.out, len(items), len(rows)),
              file=sys.stderr)
    else:
        print(text)

    for note in meta["collection_notes"]:
        print("note: %s" % note, file=sys.stderr)
    if not mapping.usable:  # pragma: no cover - parse_rows raises first
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
