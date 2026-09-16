#!/usr/bin/env python3
"""Build the triage export from live Microsoft 365 data, so nobody exports by hand.

Produces the JSON `triage.py` consumes, from two sources that together are the
whole queue:

  A. The shared phishing mailbox  -> reports that were *forwarded*, i.e. the
     automation-gap items. These never reached Defender, which is precisely why
     they are sitting in a mailbox.
  B. Defender submissions         -> reports made with the Outlook Report
     button. These never land in the mailbox, so source A alone would miss
     them and the queue would look like nothing but gaps.

Both are then enriched from Advanced Hunting (recipient count, URLs,
attachments, authentication, click telemetry) where the permission is present.

    python collect_export.py --mailbox phish@contoso.com \\
        --org-context org-context.json --since 24h --out export.json
    python triage.py export.json --org-context org-context.json

Auth and permissions are graph_submit.py's, plus hunting:
    Mail.Read                     read the shared mailbox (scope it!)
    ThreatSubmission.Read.All     list Defender submissions
    ThreatHunting.Read.All        Advanced Hunting enrichment

Every source is optional and every failure degrades honestly: a source that
403s or is switched off is recorded in `export_meta.collection_notes`, and the
fields it would have filled are left absent rather than guessed. `triage.py`
already treats a missing Defender block as "unknown - check Submissions".

Minimal-extraction deployment
-----------------------------
If the only thing you want out of the shared mailbox is enough to submit the
forwarded mail to Defender, run this collector with --no-mailbox and let
graph_submit.py be the single tool that touches it:

    graph_submit.py  --mailbox phish@...      mailbox -> Defender (submit only)
    collect_export.py --no-mailbox            Defender -> export.json
    triage.py                                 export.json -> report

The mailbox is then read once, for one purpose, and no message body, preview or
recipient list is extracted from it for triage. The cost is stated plainly in
the README: the reporter's own note ("I clicked it and entered my password")
lives only in the mailbox, and without it compromise detection falls back to
Defender click telemetry, which sees clicks but not credentials entered or
payments sent.

Read-only. This never submits, purges, blocks, or modifies a mailbox. It does
read message bodies, so mind where the output file lands.
"""
import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from email import policy
from email.parser import BytesParser

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import graph_submit as gs          # GraphClient, mailbox reads, scope guard
import parse_headers as ph         # header analysis
import triage as tr                # build_context, for --org-context

MAILBOX_SELECT = ("id,internetMessageId,receivedDateTime,subject,hasAttachments,"
                  "from,sender,toRecipients,bodyPreview,isRead")
SUBMISSIONS_PATH = "security/threatSubmission/emailThreats"
HUNTING_PATH = "security/runHuntingQuery"

URL_RX = re.compile(r"""https?://[^\s<>"'\)\]]+""", re.IGNORECASE)
TAG_RX = re.compile(r"<[^>]+>")

# The Submissions API speaks its own vocabulary; the export format speaks the
# Defender portal's, which is what triage.py routes on. Translating here is the
# collector's job — triage.py sending an unrecognised status to the analyst
# rather than filing it as handled is correct, and we must not rely on it.
AIR_STATUS = {
    "notstarted": "Pending", "not started": "Pending", "queued": "Pending",
    "running": "Running", "inprogress": "Running", "in progress": "Running",
    "succeeded": "Completed", "completed": "Completed", "success": "Completed",
    "failed": "Failed", "error": "Failed", "terminated": "Failed",
}
VERDICT = {
    "nothreatsfound": "No threats found", "no threats found": "No threats found",
    "notjunk": "Not junk", "not junk": "Not junk", "clean": "No threats found",
    "phishing": "Phishing", "phish": "Phishing",
    "highconfidencephishing": "High confidence phishing",
    "malware": "Malware", "spam": "Spam",
}


def defang(url):
    """Make a URL non-clickable in reports and terminals. Never fetched either way."""
    if not url:
        return url
    return (url.replace("http://", "hxxp://")
               .replace("https://", "hxxps://")
               .replace(".", "[.]"))


def map_air_status(value):
    """Submissions API status -> the vocabulary triage.py routes on."""
    if not value:
        return None
    return AIR_STATUS.get(str(value).strip().lower(), str(value))


def map_verdict(value):
    """Submissions API result -> the vocabulary triage.py routes on."""
    if not value:
        return None
    return VERDICT.get(str(value).strip().lower(), str(value))


def short_id(key):
    """Stable, short, readable id derived from the message id."""
    return "PHQ-" + hashlib.sha1((key or "").encode("utf-8")).hexdigest()[:8].upper()


def norm_mid(value):
    """Normalise a Message-ID for joining: angle brackets off, lowercased."""
    return (value or "").strip().strip("<>").lower()


# --------------------------------------------------------------------------
# Reading an .eml (offline; no network, nothing opened or executed)
# --------------------------------------------------------------------------

def _text_parts(msg):
    for part in msg.walk() if msg.is_multipart() else [msg]:
        if part.get_content_maintype() != "text":
            continue
        if (part.get("Content-Disposition") or "").lower().startswith("attachment"):
            continue
        try:
            payload = part.get_payload(decode=True)
        except Exception:
            continue
        if payload is None:
            continue
        charset = part.get_content_charset() or "utf-8"
        try:
            text = payload.decode(charset, "replace")
        except (LookupError, UnicodeDecodeError):
            text = payload.decode("utf-8", "replace")
        yield part.get_content_subtype(), text


def body_excerpt(eml_bytes, limit=300):
    """First `limit` characters of the body, plain text preferred."""
    if not eml_bytes:
        return ""
    msg = BytesParser(policy=policy.compat32).parsebytes(eml_bytes)
    plain, html = "", ""
    for subtype, text in _text_parts(msg):
        if subtype == "plain" and not plain:
            plain = text
        elif subtype == "html" and not html:
            html = text
    text = plain or TAG_RX.sub(" ", html)
    return re.sub(r"\s+", " ", text).strip()[:limit]


def extract_urls(eml_bytes, limit=25):
    """URLs as strings, from the body. Defanged, never resolved or fetched.

    This matters more than it looks: `triage.py` uses an empty URL list as the
    BEC gate, so emitting [] when we simply could not tell would misclassify
    every credential-harvest lure as business email compromise. Reading them out
    of the message ourselves means the field is never silently wrong.
    """
    if not eml_bytes:
        return []
    msg = BytesParser(policy=policy.compat32).parsebytes(eml_bytes)
    found, seen = [], set()
    for _, text in _text_parts(msg):
        for raw in URL_RX.findall(text):
            url = raw.rstrip(".,;:)")
            key = url.lower()
            if key in seen:
                continue
            seen.add(key)
            found.append(defang(url))
            if len(found) >= limit:
                return found
    return found


def attachment_names(eml_bytes):
    if not eml_bytes:
        return []
    msg = BytesParser(policy=policy.compat32).parsebytes(eml_bytes)
    names = []
    for part in msg.walk() if msg.is_multipart() else [msg]:
        name = part.get_filename()
        if name and name not in names:
            names.append(name)
    return names


def item_from_eml(eml_bytes, body_chars):
    """The message-derived half of an export item, from headers and body."""
    analysis = ph.analyze(eml_bytes.decode("utf-8", "replace") if eml_bytes else "")
    auth = analysis.get("authentication") or {}
    return {
        "message_id": norm_mid(analysis.get("message_id")),
        "from_name": (analysis.get("from") or {}).get("name") or "",
        "from_address": (analysis.get("from") or {}).get("address") or "",
        "reply_to": ((analysis.get("reply_to") or {}) or {}).get("address"),
        "subject": analysis.get("subject") or "",
        "date": analysis.get("date"),
        "body_excerpt": body_excerpt(eml_bytes, body_chars),
        "urls": extract_urls(eml_bytes),
        "attachments": attachment_names(eml_bytes),
        "auth": {k: auth.get(k) for k in ("spf", "dkim", "dmarc") if auth.get(k)},
        "header_flags": analysis.get("flags") or [],
    }


# --------------------------------------------------------------------------
# Source A: the shared mailbox (the gap items)
# --------------------------------------------------------------------------

def collect_mailbox(client, mailbox, folder, since, max_items, body_chars, notes):
    """Forwarded reports. The original message is pulled out of each forward."""
    import urllib.parse
    path = "users/%s/mailFolders/%s/messages" % (
        urllib.parse.quote(mailbox), urllib.parse.quote(folder))
    params = {"$select": MAILBOX_SELECT, "$filter": "receivedDateTime gt %s" % since,
              "$orderby": "receivedDateTime asc", "$top": "50"}

    items = []
    try:
        messages = list(client.paged(path, params=params, max_items=max_items))
    except gs.GraphError as exc:
        notes.append("mailbox %s unreadable (%s %s); no forwarded reports collected"
                     % (mailbox, exc.status, exc.code or ""))
        return items

    for message in messages:
        reporter = (message.get("from") or message.get("sender") or {}).get(
            "emailAddress", {}).get("address")
        try:
            eml, provenance = gs.fetch_original_eml(client, mailbox, message)
        except gs.GraphError as exc:
            notes.append("could not read attachments of %s (%s)"
                         % (message.get("subject") or message.get("id"), exc.code or exc.status))
            eml, provenance = None, {"source": None, "unsupported": []}

        if eml is None:
            # No original attached: the user hit Forward, or pasted a screenshot.
            # Record it as a gap with what little we have rather than dropping it,
            # because an unreportable report is itself a process finding.
            unsupported = provenance.get("unsupported") or []
            items.append({
                "id": short_id(message.get("internetMessageId") or message.get("id")),
                "received": message.get("receivedDateTime"),
                "reporter": reporter,
                "reported_via": "forwarded_to_mailbox",
                "from_name": "", "from_address": "", "reply_to": None,
                "subject": message.get("subject") or "",
                "body_excerpt": "", "urls": [], "attachments": [],
                "auth": {}, "recipient_count": 0, "recipients_vip": [],
                "reporter_note": (message.get("bodyPreview") or "").strip(),
                "collection": {
                    "original_attached": False,
                    "note": "no submittable original; "
                            + (", ".join(u.get("reason", "") for u in unsupported)
                               if unsupported else "nothing attached"),
                },
                "defender": {"submission_id": None, "air_status": None, "verdict": None,
                             "user_notified": False, "actions": None},
            })
            continue

        derived = item_from_eml(eml, body_chars)
        items.append({
            "id": short_id(derived["message_id"] or message.get("internetMessageId")),
            "received": derived.get("date") or message.get("receivedDateTime"),
            "reporter": reporter,
            "reported_via": "forwarded_to_mailbox",
            "from_name": derived["from_name"],
            "from_address": derived["from_address"],
            "reply_to": derived["reply_to"],
            "subject": derived["subject"],
            "body_excerpt": derived["body_excerpt"],
            "urls": derived["urls"],
            "attachments": derived["attachments"],
            "auth": derived["auth"],
            "recipient_count": 0,
            "recipients_vip": [],
            # The forward's own preview is what the user typed above the quoted
            # original -- which is where "I clicked it and entered my password"
            # lives, and that single field decides most P1s.
            "reporter_note": (message.get("bodyPreview") or "").strip(),
            "message_id": derived["message_id"],
            "header_flags": derived["header_flags"],
            "collection": {"original_attached": True,
                           "extracted_from": provenance.get("source")},
            "defender": {"submission_id": None, "air_status": None, "verdict": None,
                         "user_notified": False, "actions": None},
        })
    return items


# --------------------------------------------------------------------------
# Source B: Defender submissions (the Report-button items)
# --------------------------------------------------------------------------

def submission_verdict(entry):
    """Defender reports a result as a string or a nested object depending on shape."""
    result = entry.get("result")
    if isinstance(result, dict):
        return result.get("detail") or result.get("value") or result.get("result")
    return result


def collect_submissions(client, since, max_items, notes):
    """Report-button submissions. These never appear in the shared mailbox."""
    try:
        entries = list(client.paged(SUBMISSIONS_PATH,
                                    params={"$filter": "createdDateTime gt %s" % since,
                                            "$top": "50"},
                                    max_items=max_items))
    except gs.GraphError as exc:
        notes.append("Defender submissions unavailable (%s %s); Report-button reports "
                     "are missing from this export and the queue will look like gaps"
                     % (exc.status, exc.code or ""))
        return []

    items = []
    for entry in entries:
        mid = norm_mid(entry.get("internetMessageId") or entry.get("messageId"))
        recipient = entry.get("recipientEmailAddress")
        status = entry.get("status")
        items.append({
            "id": short_id(mid or entry.get("id")),
            "received": entry.get("receivedDateTime") or entry.get("createdDateTime"),
            "reporter": entry.get("createdBy", {}).get("user", {}).get("email") or recipient,
            "reported_via": "outlook_report_button",
            "from_name": entry.get("senderDisplayName") or "",
            "from_address": entry.get("sender") or entry.get("senderEmailAddress") or "",
            "reply_to": None,
            "subject": entry.get("subject") or "",
            "body_excerpt": "",
            "urls": None,          # unknown here; hunting fills it, see merge_urls
            "attachments": [],
            "auth": {},
            "recipient_count": 0,
            "recipients_vip": [],
            "reporter_note": "",
            "message_id": mid,
            "collection": {"source": "submissions"},
            "defender": {
                "submission_id": entry.get("id"),
                "air_status": map_air_status(status),
                "verdict": map_verdict(submission_verdict(entry)),
                "user_notified": bool(entry.get("userNotified")),
                "actions": entry.get("tenantAllowOrBlockListAction") or None,
            },
        })
    return items


# --------------------------------------------------------------------------
# Enrichment: Advanced Hunting
# --------------------------------------------------------------------------

def hunt(client, query):
    response = client.post(HUNTING_PATH, {"Query": query})
    return response.get("results") or []


def kql_list(values):
    return "dynamic([%s])" % ", ".join(json.dumps(v) for v in values if v)


def enrich_from_hunting(client, items, since, notes, chunk=40):
    """Fill recipient count, URLs, attachments, auth and clicks from EmailEvents."""
    keyed = {}
    for item in items:
        mid = item.get("message_id")
        if mid:
            keyed.setdefault(mid, []).append(item)
    if not keyed:
        notes.append("no Message-IDs available to join on; hunting enrichment skipped")
        return

    mids = list(keyed)
    for start in range(0, len(mids), chunk):
        batch = ["<%s>" % m for m in mids[start:start + chunk]]
        events_q = (
            "let ids = %s;\n"
            "EmailEvents\n"
            "| where Timestamp >= datetime(%s)\n"
            "| where InternetMessageId in~ (ids)\n"
            "| summarize RecipientCount = dcount(RecipientEmailAddress),\n"
            "            Recipients = make_set(RecipientEmailAddress, 200),\n"
            "            Auth = any(AuthenticationDetails),\n"
            "            Nmids = make_set(NetworkMessageId, 20),\n"
            "            Subject = any(Subject)\n"
            "  by InternetMessageId" % (kql_list(batch), since)
        )
        try:
            rows = hunt(client, events_q)
        except gs.GraphError as exc:
            notes.append("Advanced Hunting unavailable (%s %s); recipient counts, URL "
                         "inventory and click telemetry are absent from this export"
                         % (exc.status, exc.code or ""))
            return

        nmid_to_mid = {}
        for row in rows:
            mid = norm_mid(row.get("InternetMessageId"))
            for item in keyed.get(mid, []):
                item["recipient_count"] = row.get("RecipientCount") or 0
                item["recipients"] = row.get("Recipients") or []
                auth = row.get("Auth")
                if auth and not item.get("auth"):
                    item["auth"] = parse_auth_details(auth)
                if not item.get("subject") and row.get("Subject"):
                    item["subject"] = row["Subject"]
            for nmid in row.get("Nmids") or []:
                nmid_to_mid[nmid] = mid

        if nmid_to_mid:
            enrich_urls_and_clicks(client, nmid_to_mid, keyed, since, notes)


def parse_auth_details(value):
    """EmailEvents.AuthenticationDetails is a JSON blob of SPF/DKIM/DMARC/CompAuth."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    if not isinstance(value, dict):
        return {}
    out = {}
    for src, dst in (("SPF", "spf"), ("DKIM", "dkim"), ("DMARC", "dmarc"),
                     ("CompAuth", "compauth")):
        raw = value.get(src)
        if raw:
            out[dst] = str(raw).strip().lower()
    return out


def enrich_urls_and_clicks(client, nmid_to_mid, keyed, since, notes):
    nmids = kql_list(list(nmid_to_mid))
    queries = {
        "urls": ("let n = %s;\nEmailUrlInfo\n| where NetworkMessageId in (n)\n"
                 "| summarize Urls = make_set(Url, 50) by NetworkMessageId" % nmids),
        "attachments": ("let n = %s;\nEmailAttachmentInfo\n| where NetworkMessageId in (n)\n"
                        "| summarize Files = make_set(FileName, 20) by NetworkMessageId" % nmids),
        "clicks": ("let n = %s;\nUrlClickEvents\n| where Timestamp >= datetime(%s)\n"
                   "| where NetworkMessageId in (n)\n"
                   "| summarize Clicked = count(), Action = any(ActionType),\n"
                   "            ClickTime = min(Timestamp) by NetworkMessageId"
                   % (nmids, since)),
    }
    for kind, query in queries.items():
        try:
            rows = hunt(client, query)
        except gs.GraphError as exc:
            notes.append("%s enrichment unavailable (%s)" % (kind, exc.code or exc.status))
            continue
        for row in rows:
            mid = nmid_to_mid.get(row.get("NetworkMessageId"))
            for item in keyed.get(mid, []):
                if kind == "urls" and row.get("Urls"):
                    # Defender's inventory is authoritative over our body scrape.
                    item["urls"] = [defang(u) for u in row["Urls"]]
                elif kind == "attachments" and row.get("Files"):
                    item["attachments"] = row["Files"]
                elif kind == "clicks" and row.get("Clicked"):
                    item["click_telemetry"] = {
                        "url_clicked": True,
                        "safe_links_action": row.get("Action"),
                        "click_time": row.get("ClickTime"),
                    }


# --------------------------------------------------------------------------
# Assembly
# --------------------------------------------------------------------------

def merge_sources(mailbox_items, submission_items, notes):
    """Union the two sources, deduping on the original Message-ID.

    A user can both click Report and forward the same message. That is one queue
    item with a Defender verdict and a reporter's note, not two.
    """
    merged, by_mid = [], {}
    for item in submission_items + mailbox_items:
        mid = item.get("message_id")
        existing = by_mid.get(mid) if mid else None
        if existing is None:
            if mid:
                by_mid[mid] = item
            merged.append(item)
            continue
        # Keep the submission's Defender block; take the mailbox's richer content.
        for field in ("from_name", "from_address", "reply_to", "subject", "body_excerpt",
                      "attachments", "auth", "reporter_note", "header_flags"):
            if item.get(field) and not existing.get(field):
                existing[field] = item[field]
        if item.get("urls") and not existing.get("urls"):
            existing["urls"] = item["urls"]
        if item.get("reported_via") == "forwarded_to_mailbox":
            existing.setdefault("collection", {})["also_forwarded"] = True
        notes.append("%s was both reported and forwarded; merged into one item"
                     % existing.get("id"))
    return merged


def finalize(items, ctx, notes):
    """Last pass: VIP tagging, and never leave `urls` ambiguous."""
    for item in items:
        if item.get("urls") is None:
            # Unknown, not "none". Emitting [] here would tell triage.py the
            # message has no link, which is its BEC gate.
            item["urls"] = []
            item.setdefault("collection", {})["urls_unknown"] = True
            notes.append("%s: URL inventory unavailable; BEC classification may be "
                         "over-eager for this item" % item.get("id"))
        recipients = [r.lower() for r in item.pop("recipients", []) if r]
        vips = sorted({r for r in recipients if r in ctx["vip"]})
        reporter = (item.get("reporter") or "").lower()
        if reporter in ctx["vip"] and reporter not in vips:
            vips.append(reporter)
        if vips:
            item["recipients_vip"] = vips
    return items


def build_export(items, meta, notes):
    return {
        "export_meta": dict(meta, collection_notes=notes,
                            generated_by="collect_export.py",
                            generated_at=datetime.now(timezone.utc)
                            .strftime("%Y-%m-%dT%H:%M:%SZ")),
        "items": items,
    }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Collect the phishing queue from Microsoft 365 into a triage export.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("--mailbox", help="shared phishing mailbox (source A: forwarded reports)")
    p.add_argument("--folder", default="inbox", help="folder to read")
    p.add_argument("--since", default="24h", help="ISO timestamp or duration (6h, 2d, 90m)")
    p.add_argument("--org-context", help="JSON with org_domains, vip, known_vendor_domains")
    p.add_argument("--org-domain", action="append", default=[], help="repeatable")
    p.add_argument("--vip", action="append", default=[], help="repeatable")
    p.add_argument("--max", type=int, default=200, help="max items per source")
    p.add_argument("--body-chars", type=int, default=300,
                   help="characters of message body to include")
    p.add_argument("--no-mailbox", action="store_true", help="skip source A")
    p.add_argument("--no-submissions", action="store_true", help="skip source B")
    p.add_argument("--no-hunting", action="store_true", help="skip Advanced Hunting enrichment")
    p.add_argument("--deny-check", action="append", default=[], metavar="ADDRESS",
                   help="mailbox this app must NOT be able to read; aborts if it can")
    p.add_argument("--allow-broad-access", action="store_true",
                   help="proceed even if the scope check fails")
    p.add_argument("--api-version", default="beta", help="Graph API version")
    p.add_argument("--out", help="write here instead of stdout")
    args = p.parse_args(argv)
    if args.no_mailbox and args.no_submissions:
        p.error("--no-mailbox and --no-submissions together collect nothing")
    if not args.no_mailbox and not args.mailbox:
        p.error("--mailbox is required unless --no-mailbox is given")
    return args


def main(argv=None):
    args = parse_args(argv)
    client = gs.GraphClient(
        tenant_id=os.environ.get("GRAPH_TENANT_ID"),
        client_id=os.environ.get("GRAPH_CLIENT_ID"),
        client_secret=os.environ.get("GRAPH_CLIENT_SECRET"),
        access_token=os.environ.get("GRAPH_ACCESS_TOKEN"),
        api_version=args.api_version,
    )
    ctx = tr.build_context({}, args.org_context, args.org_domain, args.vip)
    since = gs.normalize_since(args.since)
    notes = []

    if args.mailbox and args.deny_check and not args.no_mailbox:
        try:
            report = gs.verify_scope(client, args.mailbox, args.deny_check)
        except gs.GraphError as exc:
            gs.log("fatal: scope check could not complete: %s" % exc)
            return 2
        gs.report_scope(report)
        if report["verdict"] in ("over_scoped", "target_unreadable"):
            if not args.allow_broad_access:
                gs.log("refusing to run: %s" % report["detail"])
                return 3
            notes.append("scope check failed and was overridden: %s" % report["detail"])

    mailbox_items, submission_items = [], []
    if not args.no_mailbox:
        gs.log("Reading %s/%s since %s" % (args.mailbox, args.folder, since))
        mailbox_items = collect_mailbox(client, args.mailbox, args.folder, since,
                                        args.max, args.body_chars, notes)
        gs.log("  %d forwarded report(s)" % len(mailbox_items))
    else:
        notes.append(
            "mailbox source skipped (--no-mailbox): nothing was read from the shared "
            "mailbox. If graph_submit.py is submitting the forwarded reports, they "
            "appear here via Submissions instead and nothing is missing; if it is "
            "not, forwarded reports are absent from this queue entirely.")

    if not args.no_submissions:
        gs.log("Reading Defender submissions since %s" % since)
        submission_items = collect_submissions(client, since, args.max, notes)
        gs.log("  %d submission(s)" % len(submission_items))
    else:
        notes.append("submissions source skipped (--no-submissions); Report-button "
                     "reports absent, so the queue will look like nothing but gaps")

    items = merge_sources(mailbox_items, submission_items, notes)

    if not args.no_hunting:
        gs.log("Enriching %d item(s) from Advanced Hunting" % len(items))
        try:
            enrich_from_hunting(client, items, since, notes)
        except gs.GraphError as exc:
            notes.append("hunting enrichment failed (%s %s)" % (exc.status, exc.code or ""))
    else:
        notes.append("Advanced Hunting skipped (--no-hunting); recipient counts, URL "
                     "inventory and click telemetry absent")

    items = finalize(items, ctx, notes)
    items.sort(key=lambda i: i.get("received") or "")

    meta = {
        "source": "collect_export.py: %s%s" % (
            args.mailbox or "(no mailbox)",
            "" if args.no_submissions else " + Defender Submissions"),
        "window": "%s to %s" % (since, datetime.now(timezone.utc)
                                .strftime("%Y-%m-%dT%H:%M:%SZ")),
        "org_domains": sorted(ctx["org_domains"]),
        "vip_list": sorted(ctx["vip"]),
    }
    export = build_export(items, meta, notes)

    text = json.dumps(export, indent=2, default=str)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        gs.log("wrote %s (%d items, %d note(s))" % (args.out, len(items), len(notes)))
    else:
        print(text)
    for note in notes:
        gs.log("  note: %s" % note)
    return 0


if __name__ == "__main__":
    sys.exit(main())
