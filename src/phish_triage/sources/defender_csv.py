"""Read a queue from a Defender portal CSV export.

The portal's column names vary by export (Submissions, User reported, Threat
Explorer, Advanced Hunting `EmailEvents`), by portal version, and by tenant
locale. So this module *discovers* columns rather than assuming them: each
canonical field carries a list of aliases, headers are matched on a normalized
form, and anything it cannot place is reported rather than silently dropped.

    phish-triage inspect --input submissions.csv    # what did it map, and to what?
    phish-triage run --input submissions.csv

When a column is not recognised, add it to `[column_map]` in your config — no code
change needed:

    [column_map]
    sender = "Absender"

One message can span many rows: a mail to 412 recipients exports as 412 rows in
Threat Explorer. Rows sharing a message id are folded into one item, and the row
count becomes the recipient count — which is what makes campaign scope and purge
blast radius mean anything.
"""
from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ..models import DefenderState, Queue, ReportedMessage

#: Canonical field -> header aliases, in normalized form (see `_normalize`).
#: Order matters: the first alias that matches a header wins for that field.
COLUMN_ALIASES: dict[str, list[str]] = {
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

#: Defender result strings -> the verdict vocabulary the rules engine speaks.
VERDICT_VALUES: dict[str, str] = {
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
STATUS_VALUES: dict[str, str] = {
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
SOURCE_VALUES: list[tuple[str, str]] = [
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


class DefenderCsvError(ValueError):
    """The export could not be read as a queue. The message names what to fix."""


def _normalize(header: str) -> str:
    """Fold a header to its comparable form: 'Sender_IP ' -> 'sender ip'."""
    return re.sub(r"[^a-z0-9]+", " ", (header or "").strip().lower()).strip()


@dataclass
class ColumnMapping:
    """What the importer made of the file's headers."""

    mapped: dict[str, str] = field(default_factory=dict)
    unmapped_headers: list[str] = field(default_factory=list)
    overrides: dict[str, str] = field(default_factory=dict)

    @property
    def usable(self) -> bool:
        """Enough to identify a message. Without a sender or a subject there is
        nothing to triage, whatever else the file contains."""
        return bool(self.mapped.get("from_address") or self.mapped.get("subject"))

    def describe(self) -> str:
        lines = ["Detected columns:"]
        for canonical in COLUMN_ALIASES:
            header = self.mapped.get(canonical)
            if header:
                via = " (from config [column_map])" if canonical in self.overrides else ""
                lines.append(f"  {canonical:<20} <- {header!r}{via}")
        missing = [c for c in COLUMN_ALIASES if c not in self.mapped]
        if missing:
            lines.append("")
            lines.append("Not found (optional unless noted):")
            lines.append("  " + ", ".join(missing))
        if self.unmapped_headers:
            lines.append("")
            lines.append("Columns in the file that were not recognised:")
            for header in self.unmapped_headers:
                lines.append(f"  {header!r}")
            lines.append("")
            lines.append("If one of those is a field above, map it in your config:")
            lines.append("  [column_map]")
            lines.append(f'  <field> = "{self.unmapped_headers[0]}"')
        return "\n".join(lines)


def detect_mapping(headers: list[str], column_map: dict[str, str] | None = None) -> ColumnMapping:
    """Match the file's headers to canonical fields.

    Config overrides win outright; otherwise a header is matched on its normalized
    form, exact alias first and a contains-match second, so 'Sender Email Address
    (UPN)' still lands on `from_address`.
    """
    column_map = column_map or {}
    mapping = ColumnMapping()
    by_normal = {_normalize(h): h for h in headers if h}
    claimed: set[str] = set()

    for canonical, header in column_map.items():
        match = by_normal.get(_normalize(header))
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


def _value(row: dict[str, str], mapping: ColumnMapping, canonical: str) -> str:
    header = mapping.mapped.get(canonical)
    return (row.get(header) or "").strip() if header else ""


def _count(row: dict[str, str], mapping: ColumnMapping, canonical: str) -> int:
    """Read a numeric column, tolerating '1', ' 1 ', and an empty cell."""
    raw = re.sub(r"[^0-9]", "", _value(row, mapping, canonical))
    return int(raw) if raw else 0


def _parse_date(value: str) -> datetime | None:
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    for fmt in DATE_FORMATS:
        try:
            return datetime.strptime(value.strip(), fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _split(value: str) -> list[str]:
    return [part.strip() for part in SPLIT_RE.split(value) if part.strip()] if value else []


def _defang(url: str) -> str:
    """Store URLs defanged so nothing downstream can make one clickable."""
    if not url.lower().startswith(("http://", "https://")):
        return url
    return url.replace("http", "hxxp", 1).replace(".", "[.]", 1)


def _parse_auth(row: dict[str, str], mapping: ColumnMapping) -> dict[str, str]:
    """Authentication results, from either discrete columns or the JSON blob that
    Advanced Hunting puts in `AuthenticationDetails`."""
    auth: dict[str, str] = {}
    for mech in ("spf", "dkim", "dmarc"):
        value = _value(row, mapping, mech).lower()
        if value:
            auth[mech] = value.split()[0].strip(",;")

    blob = _value(row, mapping, "auth_details")
    if blob:
        try:
            parsed = json.loads(blob)
            if isinstance(parsed, dict):
                for key, value in parsed.items():
                    key = key.strip().lower()
                    if key in ("spf", "dkim", "dmarc", "compauth") and value:
                        auth.setdefault(key, str(value).strip().lower())
        except (ValueError, TypeError):
            for mech in ("spf", "dkim", "dmarc", "compauth"):
                found = re.search(rf"\b{mech}\W{{0,3}}(pass|fail|softfail|neutral|none|permerror|temperror|bestguesspass)\b", blob, re.I)
                if found:
                    auth.setdefault(mech, found.group(1).lower())
    return auth


def _map_value(value: str, table: dict[str, str]) -> str:
    """Map an exported string onto our vocabulary, keeping the original when we do
    not recognise it — a guessed verdict is worse than an unfamiliar one."""
    if not value:
        return ""
    key = value.strip().lower()
    if key in table:
        return table[key]
    for known, mapped in table.items():
        if known in key:
            return mapped
    return value.strip()


def _reported_via(value: str, default: str) -> str:
    key = value.strip().lower()
    if not key:
        return default
    for needle, via in SOURCE_VALUES:
        if needle in key:
            return via
    return default


def _row_key(row: dict[str, str], mapping: ColumnMapping, index: int) -> str:
    """Rows describing the same message must fold together, or a 412-recipient
    campaign reads as 412 unrelated one-recipient reports."""
    for canonical in ("network_message_id", "internet_message_id", "submission_id"):
        value = _value(row, mapping, canonical)
        if value:
            return f"{canonical}:{value.lower()}"
    sender = _value(row, mapping, "from_address").lower()
    subject = _value(row, mapping, "subject").lower()
    return f"composite:{sender}|{subject}" if (sender or subject) else f"row:{index}"


def _build_message(key: str, rows: list[dict[str, str]], mapping: ColumnMapping, default_via: str, vip: set[str]) -> ReportedMessage:
    first = rows[0]
    recipients = []
    for row in rows:
        recipients.extend(r.lower() for r in _split(_value(row, mapping, "recipient")))
    recipients = list(dict.fromkeys(recipients))

    declared = _value(first, mapping, "recipient_count")
    try:
        declared_count = int(re.sub(r"[^0-9]", "", declared)) if declared else 0
    except ValueError:
        declared_count = 0
    recipient_count = max(declared_count, len(recipients), len(rows), 1)

    reporters = [r for r in (_value(row, mapping, "reporter") for row in rows) if r]
    reporter = reporters[0] if reporters else ""
    if len(set(reporters)) > 1:
        reporter = f"multiple ({len(set(reporters))} reporters)"

    urls, attachments, notes = [], [], []
    for row in rows:
        urls.extend(_split(_value(row, mapping, "urls")))
        attachments.extend(_split(_value(row, mapping, "attachments")))
        note = _value(row, mapping, "reporter_note")
        if note and note not in notes:
            notes.append(note)

    # An export may say only *how many* URLs or attachments there were. That still
    # tells the engine a payload existed; say so plainly rather than inventing names.
    if not urls:
        count = _count(first, mapping, "url_count")
        if count:
            urls = [f"({count} URL{'s' if count > 1 else ''}; addresses not included in this export)"]
    if not attachments:
        count = _count(first, mapping, "attachment_count")
        if count:
            attachments = [f"({count} attachment{'s' if count > 1 else ''}; filenames not included in this export)"]

    submission_id = _value(first, mapping, "submission_id") or None
    verdict = _map_value(_value(first, mapping, "verdict"), VERDICT_VALUES)
    status = _map_value(_value(first, mapping, "air_status"), STATUS_VALUES)
    notified_raw = _value(first, mapping, "user_notified")
    actions = "; ".join(dict.fromkeys(a for a in (_value(row, mapping, "actions") for row in rows) if a))

    message = ReportedMessage(
        id=submission_id or _value(first, mapping, "network_message_id") or key.split(":", 1)[-1][:64] or key,
        reporter=reporter,
        received=_parse_date(_value(first, mapping, "received")),
        reported_via=_reported_via(_value(first, mapping, "source"), default_via),
        from_name=_value(first, mapping, "from_name"),
        from_address=_value(first, mapping, "from_address").lower(),
        reply_to=_value(first, mapping, "reply_to").lower() or None,
        subject=_value(first, mapping, "subject"),
        body_excerpt=" ".join(notes),
        urls=[_defang(u) for u in dict.fromkeys(urls)],
        attachments=list(dict.fromkeys(attachments)),
        auth=_parse_auth(first, mapping),
        recipient_count=recipient_count,
        recipients_vip=[r for r in recipients if r in vip],
        reporter_note=" ".join(notes),
        defender=DefenderState(
            submission_id=submission_id,
            air_status=status or None,
            verdict=verdict or None,
            user_notified=notified_raw.strip().lower() in TRUE_VALUES,
            actions=actions,
        ),
        raw={"source": "defender_csv", "recipients": recipients, "row_count": len(rows)},
    )

    # Defender does not export an auto-notify flag in most views. Rather than read
    # its absence as "the reporter was left in the dark", treat a closed submission
    # as notified and say so in the report's data-source line.
    if not message.defender.user_notified and mapping.mapped.get("user_notified") is None:
        message.defender.user_notified = message.defender.air_completed and bool(verdict)
    return message


def parse_rows(
    rows: list[dict[str, str]],
    headers: list[str],
    column_map: dict[str, str] | None = None,
    default_reported_via: str = "outlook_report_button",
    vip_list: list[str] | None = None,
    org_domain: str = "",
    source_label: str = "Defender CSV export",
) -> Queue:
    """Turn parsed CSV rows into a `Queue`. Pure; no file I/O."""
    mapping = detect_mapping(headers, column_map)
    if not mapping.usable:
        raise DefenderCsvError(
            "could not find a sender or subject column in this export.\n\n"
            + mapping.describe()
            + "\n\nRun `phish-triage inspect --input <file>` to see this, then map the "
            "columns in your config under [column_map]."
        )

    vip = {v.lower() for v in (vip_list or [])}
    grouped: dict[str, list[dict[str, str]]] = {}
    for index, row in enumerate(rows):
        if not any((v or "").strip() for v in row.values()):
            continue
        grouped.setdefault(_row_key(row, mapping, index), []).append(row)

    items = [_build_message(key, group, mapping, default_reported_via, vip) for key, group in grouped.items()]
    items.sort(key=lambda m: m.received or datetime.min.replace(tzinfo=timezone.utc))

    missing: list[str] = []
    if "air_status" not in mapping.mapped and "verdict" not in mapping.mapped:
        missing.append("AIR status and verdict (no status or result column in this export)")
    if "user_notified" not in mapping.mapped:
        missing.append("reporter-notified flag (inferred from submission status)")
    if "recipient" not in mapping.mapped and "recipient_count" not in mapping.mapped:
        missing.append("recipient scope (no recipient column, so campaign size is unknown)")
    if mapping.unmapped_headers:
        missing.append(f"{len(mapping.unmapped_headers)} unrecognised column(s) — run `phish-triage inspect`")

    dates = [m.received for m in items if m.received]
    window = f"{min(dates).isoformat()} to {max(dates).isoformat()}" if dates else ""

    return Queue(
        items=items,
        org_domain=org_domain,
        vip_list=list(vip_list or []),
        window=window,
        source=source_label,
        missing_sources=missing,
    )


def read_rows(path: str | Path) -> tuple[list[dict[str, str]], list[str]]:
    """Read a CSV/TSV, coping with the BOM Excel and the portal both like to add."""
    text = Path(path).read_text(encoding="utf-8-sig", errors="replace")
    if not text.strip():
        raise DefenderCsvError(f"{path} is empty")
    try:
        dialect = csv.Sniffer().sniff(text[:8192], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    headers = [h for h in (reader.fieldnames or []) if h is not None]
    if not headers:
        raise DefenderCsvError(f"{path} has no header row")
    return list(reader), headers


def load_queue(
    path: str | Path,
    column_map: dict[str, str] | None = None,
    default_reported_via: str = "outlook_report_button",
    vip_list: list[str] | None = None,
    org_domain: str = "",
) -> Queue:
    """Read a Defender CSV export as a triage queue."""
    rows, headers = read_rows(path)
    return parse_rows(
        rows,
        headers,
        column_map=column_map,
        default_reported_via=default_reported_via,
        vip_list=vip_list,
        org_domain=org_domain,
        source_label=f"Defender CSV export ({Path(path).name})",
    )


def inspect(path: str | Path, column_map: dict[str, str] | None = None) -> str:
    """Human-readable account of what the importer makes of a file."""
    rows, headers = read_rows(path)
    mapping = detect_mapping(headers, column_map)
    out = [f"{Path(path).name}: {len(rows)} data row(s), {len(headers)} column(s)", ""]
    out.append(mapping.describe())
    if rows:
        out.extend(["", "First row as the importer reads it:"])
        for canonical in COLUMN_ALIASES:
            header = mapping.mapped.get(canonical)
            if header:
                value = (rows[0].get(header) or "").strip()
                out.append(f"  {canonical:<20} = {value[:80]!r}")
    out.append("")
    out.append("Usable: yes" if mapping.usable else "Usable: NO — needs at least a sender or subject column")
    return "\n".join(out)
