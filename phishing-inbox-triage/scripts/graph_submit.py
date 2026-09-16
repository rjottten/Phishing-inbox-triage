#!/usr/bin/env python3
"""Watch a shared phishing mailbox and submit reported mail to Microsoft Defender.

Closes the *automation gap* lane: messages a user forwarded or dragged into the
shared mailbox never produced a Defender submission, so no AIR investigation ran
and the reporter was never notified. This script finds those messages, extracts
the *original* reported email out of the forward, and creates an
``emailThreatSubmission`` via the Microsoft Graph Security API. Defender then
runs AIR and notifies the reporter as if the Report button had been used.

Usage:
    python graph_submit.py --mailbox phish@contoso.com --dry-run
    python graph_submit.py --mailbox phish@contoso.com --state ~/.phish-state.json \\
        --org-domain contoso.com --mark-read --move-to submitted

Auth (app-only, client credentials):
    GRAPH_TENANT_ID, GRAPH_CLIENT_ID, GRAPH_CLIENT_SECRET
Auth (bring your own token, e.g. delegated or managed identity):
    GRAPH_ACCESS_TOKEN

Graph permissions: Mail.Read (or Mail.ReadWrite for --mark-read/--move-to) on
the shared mailbox, plus ThreatSubmission.ReadWrite.All. See
references/graph-automation.md for app registration and mailbox scoping.

Mail.Read as an *application* permission reads every mailbox in the tenant
unless an Exchange application access policy or RBAC scope narrows it. Pass
--deny-check with a mailbox this app must not reach (an exec's, say) and the
run aborts if it turns out to be readable; --check-scope runs that probe alone
as a deployment gate.

Guardrails, same as the rest of the skill: never fetches a URL from reported
mail, never opens or executes an attachment, never replies to a sender, and
never takes a remediation action. Submitting to Microsoft is the one write it
performs, plus the opt-in mailbox housekeeping behind --mark-read/--move-to.
"""
import argparse
import base64
import json
import os
import random
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from email import policy
from email.parser import BytesHeaderParser
from email.utils import getaddresses, parseaddr

LOGIN_HOST = "https://login.microsoftonline.com"
GRAPH_HOST = "https://graph.microsoft.com"
DEFAULT_API_VERSION = "beta"  # emailThreats lives in beta; see reference doc

ITEM_ATTACHMENT = "#microsoft.graph.itemAttachment"
FILE_ATTACHMENT = "#microsoft.graph.fileAttachment"
REFERENCE_ATTACHMENT = "#microsoft.graph.referenceAttachment"
EML_CONTENT_TYPES = {"message/rfc822"}
MSG_CONTENT_TYPES = {"application/vnd.ms-outlook", "application/x-msg"}

CATEGORIES = ("phishing", "malware", "spam", "notJunk")
SOURCES = ("user", "administrator")

# Graph rejects request bodies over ~4 MB; base64 inflates by 4/3. Anything
# larger is reported as skipped so an analyst can submit it by hand.
DEFAULT_MAX_EML_BYTES = 2_500_000

MESSAGE_SELECT = (
    "id,internetMessageId,receivedDateTime,subject,hasAttachments,"
    "from,sender,toRecipients,isRead"
)


def log(msg):
    print(msg, file=sys.stderr)


# --------------------------------------------------------------------------
# Graph client
# --------------------------------------------------------------------------

class GraphError(RuntimeError):
    """A non-retryable Graph response."""

    def __init__(self, status, body, url):
        self.status = status
        self.body = body
        self.url = url
        code = ""
        try:
            code = json.loads(body).get("error", {}).get("code", "")
        except (ValueError, AttributeError):
            pass
        self.code = code
        super().__init__("Graph %s on %s: %s" % (status, url, (body or "")[:400]))


class GraphClient:
    """Minimal Graph client: stdlib only, retries throttling and transient 5xx."""

    def __init__(self, tenant_id=None, client_id=None, client_secret=None,
                 access_token=None, api_version=DEFAULT_API_VERSION,
                 timeout=60, max_retries=5):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.api_version = api_version
        self.timeout = timeout
        self.max_retries = max_retries
        self._token = access_token
        self._token_expires_at = float("inf") if access_token else 0.0

    # -- auth --------------------------------------------------------------

    def token(self):
        if self._token and time.time() < self._token_expires_at - 60:
            return self._token
        if not (self.tenant_id and self.client_id and self.client_secret):
            raise SystemExit(
                "no usable credentials: set GRAPH_ACCESS_TOKEN, or all of "
                "GRAPH_TENANT_ID / GRAPH_CLIENT_ID / GRAPH_CLIENT_SECRET"
            )
        url = "%s/%s/oauth2/v2.0/token" % (LOGIN_HOST, self.tenant_id)
        data = urllib.parse.urlencode({
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": GRAPH_HOST + "/.default",
            "grant_type": "client_credentials",
        }).encode()
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise GraphError(exc.code, exc.read().decode("utf-8", "replace"), url)
        self._token = payload["access_token"]
        self._token_expires_at = time.time() + int(payload.get("expires_in", 3600))
        return self._token

    # -- transport ---------------------------------------------------------

    def _url(self, path):
        if path.startswith("http"):
            return path
        return "%s/%s/%s" % (GRAPH_HOST, self.api_version, path.lstrip("/"))

    def request(self, method, path, *, params=None, body=None, raw=False, headers=None):
        url = self._url(path)
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
        payload = json.dumps(body).encode("utf-8") if body is not None else None

        for attempt in range(self.max_retries + 1):
            hdrs = {"Authorization": "Bearer " + self.token()}
            if payload is not None:
                hdrs["Content-Type"] = "application/json"
            if not raw:
                hdrs["Accept"] = "application/json"
            hdrs.update(headers or {})
            req = urllib.request.Request(url, data=payload, headers=hdrs, method=method)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    data = resp.read()
                if raw:
                    return data
                return json.loads(data.decode("utf-8")) if data else {}
            except urllib.error.HTTPError as exc:
                text = exc.read().decode("utf-8", "replace")
                retryable = exc.code == 429 or 500 <= exc.code < 600
                if not retryable or attempt == self.max_retries:
                    raise GraphError(exc.code, text, url)
                delay = self._retry_delay(exc, attempt)
                log("  throttled/transient (%s), retrying in %.1fs" % (exc.code, delay))
                time.sleep(delay)
            except urllib.error.URLError as exc:
                if attempt == self.max_retries:
                    raise
                delay = min(2 ** attempt, 16) + random.random()
                log("  network error (%s), retrying in %.1fs" % (exc.reason, delay))
                time.sleep(delay)
        raise AssertionError("unreachable")

    @staticmethod
    def _retry_delay(exc, attempt):
        retry_after = exc.headers.get("Retry-After") if exc.headers else None
        if retry_after:
            try:
                return min(float(retry_after), 120.0)
            except ValueError:
                pass
        return min(2 ** attempt, 32) + random.random()

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, body, **kw):
        return self.request("POST", path, body=body, **kw)

    def patch(self, path, body, **kw):
        return self.request("PATCH", path, body=body, **kw)

    def paged(self, path, *, params=None, max_items=None):
        """Yield items across @odata.nextLink pages, stopping at max_items."""
        seen = 0
        page = self.get(path, params=params)
        while True:
            for item in page.get("value", []):
                yield item
                seen += 1
                if max_items is not None and seen >= max_items:
                    return
            nxt = page.get("@odata.nextLink")
            if not nxt:
                return
            page = self.get(nxt)


# --------------------------------------------------------------------------
# Pure helpers (no network — these are what the tests cover)
# --------------------------------------------------------------------------

def normalize_since(value, default_hours=24):
    """Turn --since (ISO timestamp or '<N>[mhd]') into a Graph-safe UTC string."""
    now = datetime.now(timezone.utc)
    if not value:
        dt = now - timedelta(hours=default_hours)
    else:
        m = re.fullmatch(r"(\d+)\s*([mhd])", value.strip(), re.IGNORECASE)
        if m:
            n, unit = int(m.group(1)), m.group(2).lower()
            delta = {"m": timedelta(minutes=n), "h": timedelta(hours=n), "d": timedelta(days=n)}[unit]
            dt = now - delta
        else:
            text = value.strip().replace("Z", "+00:00")
            try:
                dt = datetime.fromisoformat(text)
            except ValueError:
                raise SystemExit("--since must be an ISO timestamp or a duration like 6h / 2d / 90m")
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def classify_attachments(attachments):
    """Split a message's attachments into submittable candidates and unsupported ones.

    A user who forwards phishing correctly attaches the original message, which
    Graph surfaces either as an itemAttachment (Outlook "Forward as Attachment")
    or as a fileAttachment with content type message/rfc822 (a dragged-in .eml).
    Candidates come back best-first; anything we cannot turn into RFC822 bytes
    lands in `unsupported` with a reason an analyst can act on.
    """
    candidates, unsupported = [], []
    for att in attachments or []:
        odata = (att.get("@odata.type") or "").lower()
        name = att.get("name") or ""
        ctype = (att.get("contentType") or "").split(";")[0].strip().lower()
        lowered = name.lower()
        entry = {"id": att.get("id"), "name": name, "contentType": ctype,
                 "size": att.get("size"), "isInline": bool(att.get("isInline"))}

        if odata == ITEM_ATTACHMENT.lower():
            candidates.append(dict(entry, kind="item", rank=0))
        elif odata == FILE_ATTACHMENT.lower() and (
            ctype in EML_CONTENT_TYPES or lowered.endswith(".eml")
        ):
            candidates.append(dict(entry, kind="file", rank=1))
        elif lowered.endswith(".msg") or ctype in MSG_CONTENT_TYPES:
            unsupported.append(dict(entry, reason="outlook_msg_not_rfc822"))
        elif odata == REFERENCE_ATTACHMENT.lower():
            unsupported.append(dict(entry, reason="reference_attachment_not_fetched"))
        elif att.get("isInline"):
            continue  # inline images in the forward body are not the report
        else:
            unsupported.append(dict(entry, reason="not_an_email_attachment"))

    candidates.sort(key=lambda c: (c["rank"], -(c.get("size") or 0)))
    return candidates, unsupported


def _header_addresses(msg, header):
    return [addr.lower() for _, addr in getaddresses(msg.get_all(header, [])) if addr]


def infer_recipient(eml_bytes, fallback=None, org_domains=()):
    """Work out which mailbox the original phish was delivered to.

    Defender wants the recipient in whose mailbox the message landed, not the
    shared mailbox that received the forward. Delivery headers are the most
    reliable source; To/Cc filtered to the org's own domains is the next best;
    the reporter (who forwarded it) is the last resort.
    """
    org = {d.lower().lstrip("@") for d in org_domains if d}
    msg = BytesHeaderParser(policy=policy.compat32).parsebytes(eml_bytes or b"")

    for header in ("Delivered-To", "X-Original-To", "Envelope-To", "X-Envelope-To"):
        for addr in _header_addresses(msg, header):
            return addr, "header:" + header

    recipients = _header_addresses(msg, "To") + _header_addresses(msg, "Cc")
    if org:
        for addr in recipients:
            if addr.rsplit("@", 1)[-1] in org:
                return addr, "header:To/Cc(org-domain)"
    if recipients:
        return recipients[0], "header:To/Cc"

    if fallback:
        return fallback.lower(), "reporter"
    return None, "unknown"


def summarize_eml(eml_bytes):
    """Headers-only summary for logging. Never includes the body or any URL."""
    msg = BytesHeaderParser(policy=policy.compat32).parsebytes(eml_bytes or b"")
    from_name, from_addr = parseaddr(msg.get("From", "") or "")
    return {
        "from_name": from_name or None,
        "from_address": from_addr or None,
        "subject": msg.get("Subject") or None,
        "date": msg.get("Date") or None,
        "message_id": (msg.get("Message-ID") or "").strip() or None,
    }


def build_submission(eml_bytes, recipient, category="phishing", source=None):
    """Body for POST /security/threatSubmission/emailThreats."""
    if not recipient:
        raise ValueError("recipientEmailAddress is required by the submissions API")
    if category not in CATEGORIES:
        raise ValueError("category must be one of %s" % (CATEGORIES,))
    body = {
        "@odata.type": "#microsoft.graph.security.emailContentThreatSubmission",
        "recipientEmailAddress": recipient,
        "category": category,
        "fileContent": base64.b64encode(eml_bytes).decode("ascii"),
    }
    if source:
        if source not in SOURCES:
            raise ValueError("source must be one of %s" % (SOURCES,))
        body["source"] = source
    return body


# --------------------------------------------------------------------------
# State
# --------------------------------------------------------------------------

class StateStore:
    """Watermark + processed-id ledger so reruns never double-submit."""

    def __init__(self, path=None):
        self.path = os.path.expanduser(path) if path else None
        self.data = {"last_received": None, "processed": {}, "originals": {}}
        if self.path and os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict):
                self.data.update(loaded)
        self.data.setdefault("processed", {})
        self.data.setdefault("originals", {})

    @staticmethod
    def key(message):
        return message.get("internetMessageId") or message.get("id") or ""

    def seen(self, message):
        return self.key(message) in self.data["processed"]

    def original_seen(self, message_id):
        return bool(message_id) and message_id in self.data["originals"]

    def record(self, message, result):
        key = self.key(message)
        if key:
            self.data["processed"][key] = {
                "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "status": result.get("status"),
                "submission_id": result.get("submission_id"),
            }
        original = (result.get("original") or {}).get("message_id")
        if original and result.get("status") == "submitted":
            self.data["originals"][original] = result.get("submission_id")
        received = message.get("receivedDateTime")
        if received and (not self.data["last_received"] or received > self.data["last_received"]):
            self.data["last_received"] = received

    def save(self):
        if not self.path:
            return
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh, indent=2, sort_keys=True)
        os.replace(tmp, self.path)


# --------------------------------------------------------------------------
# Mailbox + submission operations
# --------------------------------------------------------------------------

def list_reports(client, mailbox, folder, since, max_items):
    path = "users/%s/mailFolders/%s/messages" % (
        urllib.parse.quote(mailbox), urllib.parse.quote(folder)
    )
    params = {
        "$select": MESSAGE_SELECT,
        "$filter": "receivedDateTime gt %s" % since,
        "$orderby": "receivedDateTime asc",
        "$top": "50",
    }
    return client.paged(path, params=params, max_items=max_items)


def fetch_original_eml(client, mailbox, message):
    """Return (eml_bytes, provenance_dict) for the message the user reported.

    Prefers the attached original; falls back to the forward itself only when
    the caller allows it, because submitting the wrapper makes Defender analyse
    the reporter's own mail rather than the phish.
    """
    mb = urllib.parse.quote(mailbox)
    mid = urllib.parse.quote(message["id"], safe="")
    attachments = []
    if message.get("hasAttachments"):
        attachments = list(client.paged(
            "users/%s/messages/%s/attachments" % (mb, mid),
            params={"$select": "id,name,contentType,size,isInline"},
        ))
    candidates, unsupported = classify_attachments(attachments)

    for cand in candidates:
        aid = urllib.parse.quote(cand["id"], safe="")
        if cand["kind"] == "item":
            raw = client.get(
                "users/%s/messages/%s/attachments/%s/$value" % (mb, mid, aid), raw=True
            )
        else:
            att = client.get(
                "users/%s/messages/%s/attachments/%s" % (mb, mid, aid),
                params={"$select": "id,name,contentType,contentBytes"},
            )
            content = att.get("contentBytes")
            if not content:
                continue
            raw = base64.b64decode(content)
        if raw:
            return raw, {"source": "attachment:" + cand["kind"], "name": cand["name"],
                         "unsupported": unsupported}
    return None, {"source": None, "unsupported": unsupported,
                  "attachment_count": len(attachments)}


def fetch_wrapper_eml(client, mailbox, message):
    mb = urllib.parse.quote(mailbox)
    mid = urllib.parse.quote(message["id"], safe="")
    return client.get("users/%s/messages/%s/$value" % (mb, mid), raw=True)


def submit_threat(client, body):
    """POST the submission, retrying once without `source` if Graph rejects it.

    `source` is only honoured for delegated (user) tokens; app-only tokens
    record an administrator submission no matter what we send, and some tenants
    reject the property outright.
    """
    try:
        return client.post("security/threatSubmission/emailThreats", body), None
    except GraphError as exc:
        if exc.status == 400 and "source" in body and "source" in (exc.body or "").lower():
            stripped = {k: v for k, v in body.items() if k != "source"}
            return client.post("security/threatSubmission/emailThreats", stripped), \
                "source property rejected by tenant; submitted without it"
        raise


def housekeep(client, mailbox, message, *, mark_read, move_to):
    mb = urllib.parse.quote(mailbox)
    mid = urllib.parse.quote(message["id"], safe="")
    done = []
    if mark_read and not message.get("isRead"):
        client.patch("users/%s/messages/%s" % (mb, mid), {"isRead": True})
        done.append("marked_read")
    if move_to:
        client.post("users/%s/messages/%s/move" % (mb, mid), {"destinationId": move_to})
        done.append("moved:" + move_to)
    return done


# --------------------------------------------------------------------------
# Least-privilege preflight
# --------------------------------------------------------------------------

def classify_probe(status):
    """Map a mailbox read probe's HTTP status onto what it proves about scoping."""
    if status == 200:
        return "readable"
    if status == 403:
        return "denied"          # an access policy or RBAC scope is doing its job
    if status == 404:
        return "not_found"       # proves nothing: the mailbox may simply not exist
    if status == 401:
        return "unauthorized"    # the token itself is bad; scoping is untested
    return "error"


def probe_mailbox_access(client, address):
    """Cheapest possible read against a mailbox, to see whether we can reach it."""
    path = "users/%s/messages" % urllib.parse.quote(address)
    try:
        client.get(path, params={"$top": "1", "$select": "id"})
        return {"address": address, "access": "readable", "status": 200, "code": None}
    except GraphError as exc:
        return {"address": address, "access": classify_probe(exc.status),
                "status": exc.status, "code": exc.code or None}


def verify_scope(client, mailbox, deny_addresses):
    """Prove this app's Mail.Read really is restricted to the phishing mailbox.

    `Mail.Read` as an *application* permission reads every mailbox in the tenant
    unless an Exchange application access policy or RBAC scope narrows it. That
    narrowing is invisible from the app's side and silently stops working if the
    policy is removed, so assert it instead of trusting it: the target mailbox
    must be readable, and every mailbox named in `deny_addresses` must come back
    403.

    A 404 is deliberately *not* treated as proof — a mailbox that does not exist
    is denied for the wrong reason, and would hide a genuinely over-scoped app.
    """
    report = {
        "target": probe_mailbox_access(client, mailbox),
        "must_be_denied": [],
        "verdict": None,
        "detail": None,
    }

    if report["target"]["access"] != "readable":
        # Nothing to learn from the control probes: if we cannot read the mailbox
        # we are pointed at, the run is dead regardless of how it is scoped.
        report["verdict"] = "target_unreadable"
        report["detail"] = ("cannot read %s (%s); the run would fail anyway"
                            % (mailbox, report["target"]["access"]))
        return report

    report["must_be_denied"] = [probe_mailbox_access(client, a) for a in deny_addresses]

    reachable = [p["address"] for p in report["must_be_denied"] if p["access"] == "readable"]
    if reachable:
        report["verdict"] = "over_scoped"
        report["detail"] = ("this app can read mailboxes it should not: %s"
                            % ", ".join(reachable))
    elif not deny_addresses:
        report["verdict"] = "unchecked"
        report["detail"] = "no --deny-check mailbox given; scoping was not verified"
    elif all(p["access"] == "denied" for p in report["must_be_denied"]):
        report["verdict"] = "scoped"
        report["detail"] = "every control mailbox returned 403"
    else:
        inconclusive = ["%s=%s" % (p["address"], p["access"])
                        for p in report["must_be_denied"] if p["access"] != "denied"]
        report["verdict"] = "inconclusive"
        report["detail"] = ("not a clean 403, so scoping is unproven: %s"
                            % ", ".join(inconclusive))
    return report


def report_scope(report):
    log("Scope check: %s — %s" % (report["verdict"], report["detail"]))
    log("  target   %s -> %s (%s)" % (report["target"]["address"],
                                      report["target"]["access"],
                                      report["target"]["status"]))
    for probe in report["must_be_denied"]:
        log("  control  %s -> %s (%s)" % (probe["address"], probe["access"], probe["status"]))


# --------------------------------------------------------------------------
# Per-message pipeline
# --------------------------------------------------------------------------

def process_message(client, message, args, state):
    reporter = (message.get("from") or message.get("sender") or {}).get(
        "emailAddress", {}).get("address")
    result = {
        "mailbox_message_id": message.get("id"),
        "internet_message_id": message.get("internetMessageId"),
        "received": message.get("receivedDateTime"),
        "reporter": reporter,
        "forward_subject": message.get("subject"),
        "status": None,
        "detail": None,
        "original": None,
        "submission_id": None,
        "actions": [],
    }

    eml, provenance = fetch_original_eml(client, args.mailbox, message)
    if eml is None:
        if not args.allow_wrapper:
            result["status"] = "skipped"
            result["detail"] = "no_original_attached"
            result["unsupported_attachments"] = provenance.get("unsupported") or []
            return result
        eml = fetch_wrapper_eml(client, args.mailbox, message)
        provenance = {"source": "wrapper", "unsupported": provenance.get("unsupported") or []}

    if len(eml) > args.max_eml_bytes:
        result["status"] = "skipped"
        result["detail"] = "too_large:%d_bytes" % len(eml)
        return result

    summary = summarize_eml(eml)
    result["original"] = dict(summary, extracted_from=provenance.get("source"))
    if provenance.get("unsupported"):
        result["unsupported_attachments"] = provenance["unsupported"]

    if args.dedupe_original and state.original_seen(summary.get("message_id")):
        result["status"] = "skipped"
        result["detail"] = "original_already_submitted"
        result["submission_id"] = state.data["originals"].get(summary["message_id"])
        return result

    recipient, how = infer_recipient(eml, fallback=reporter, org_domains=args.org_domain)
    result["recipient"] = recipient
    result["recipient_source"] = how
    if not recipient:
        result["status"] = "skipped"
        result["detail"] = "no_recipient_resolved"
        return result

    body = build_submission(eml, recipient, category=args.category, source=args.source)

    if args.dry_run:
        result["status"] = "dry_run"
        result["detail"] = "would submit %d bytes as %s" % (len(eml), args.category)
        return result

    response, warning = submit_threat(client, body)
    result["status"] = "submitted"
    result["submission_id"] = response.get("id")
    result["defender_status"] = response.get("status")
    if warning:
        result["detail"] = warning

    if args.mark_read or args.move_to:
        try:
            result["actions"] = housekeep(
                client, args.mailbox, message,
                mark_read=args.mark_read, move_to=args.move_to,
            )
        except GraphError as exc:
            result["actions"] = []
            result["detail"] = "submitted, but housekeeping failed: %s" % exc.code
    return result


def run(client, args, state):
    since = args.since or state.data.get("last_received")
    since = normalize_since(since, default_hours=args.default_lookback_hours)
    log("Scanning %s/%s for messages after %s" % (args.mailbox, args.folder, since))

    results = []
    try:
        for message in list_reports(client, args.mailbox, args.folder, since, args.max):
            if state.seen(message):
                log("  skip (already processed): %s" % (message.get("subject") or "")[:70])
                continue
            try:
                result = process_message(client, message, args, state)
            except GraphError as exc:
                result = {
                    "mailbox_message_id": message.get("id"),
                    "internet_message_id": message.get("internetMessageId"),
                    "received": message.get("receivedDateTime"),
                    "status": "error",
                    "detail": "%s %s" % (exc.status, exc.code or ""),
                }
            results.append(result)
            state.record(message, result)
            log("  %-9s %-40s %s" % (
                result["status"],
                ((result.get("original") or {}).get("subject") or message.get("subject") or "")[:40],
                result.get("submission_id") or result.get("detail") or "",
            ))
    finally:
        # A failure part-way through must not replay the messages already
        # submitted on the next run.
        state.save()
    return results


def summarize(results):
    counts = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    return counts


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Submit shared-mailbox phishing reports to Defender via Microsoft Graph.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--mailbox", required=True,
                   help="shared phishing mailbox UPN or object id")
    p.add_argument("--folder", default="inbox",
                   help="well-known folder name or folder id to watch")
    p.add_argument("--since",
                   help="ISO timestamp or duration (6h, 2d, 90m); defaults to the state watermark")
    p.add_argument("--default-lookback-hours", type=int, default=24,
                   help="window used when there is no --since and no saved watermark")
    p.add_argument("--state", help="path to the JSON state file (watermark + processed ids)")
    p.add_argument("--category", default="phishing", choices=CATEGORIES,
                   help="Defender submission category")
    p.add_argument("--source", default="user", choices=SOURCES + ("none",),
                   help="'user' aims for the User reported tab (delegated tokens only); "
                        "'none' omits the property")
    p.add_argument("--org-domain", action="append", default=[],
                   help="your own mail domain; repeatable. Used to pick the real "
                        "recipient out of the original To/Cc")
    p.add_argument("--max", type=int, default=100, help="maximum messages per run")
    p.add_argument("--max-eml-bytes", type=int, default=DEFAULT_MAX_EML_BYTES,
                   help="skip originals larger than this; Graph caps request bodies near 4 MB")
    p.add_argument("--allow-wrapper", action="store_true",
                   help="if no original is attached, submit the forward itself "
                        "(Defender then analyses the reporter's mail, not the phish)")
    p.add_argument("--dedupe-original", action="store_true",
                   help="skip an original whose Message-ID was already submitted")
    p.add_argument("--mark-read", action="store_true",
                   help="mark handled reports as read (needs Mail.ReadWrite)")
    p.add_argument("--move-to",
                   help="folder id or well-known name to move handled reports into")
    p.add_argument("--dry-run", action="store_true",
                   help="extract and resolve everything, but do not submit or modify mail")
    p.add_argument("--deny-check", action="append", default=[], metavar="ADDRESS",
                   help="mailbox this app must NOT be able to read, e.g. an exec's. "
                        "Repeatable. Probed before each run; a readable one aborts the "
                        "run, because it means Mail.Read is not scoped to --mailbox")
    p.add_argument("--check-scope", action="store_true",
                   help="run only the scope check and exit; 0 if access is provably "
                        "restricted, 3 otherwise. Use as a deployment gate")
    p.add_argument("--allow-broad-access", action="store_true",
                   help="proceed even if the scope check shows this app can read other "
                        "mailboxes. You are asserting that is intended")
    p.add_argument("--api-version", default=DEFAULT_API_VERSION,
                   help="Graph API version for the submissions endpoint")
    p.add_argument("--json", action="store_true", help="print the per-message results as JSON")
    args = p.parse_args(argv)
    if args.source == "none":
        args.source = None
    return args


def main(argv=None):
    args = parse_args(argv)
    client = GraphClient(
        tenant_id=os.environ.get("GRAPH_TENANT_ID"),
        client_id=os.environ.get("GRAPH_CLIENT_ID"),
        client_secret=os.environ.get("GRAPH_CLIENT_SECRET"),
        access_token=os.environ.get("GRAPH_ACCESS_TOKEN"),
        api_version=args.api_version,
    )
    if args.check_scope or args.deny_check:
        try:
            report = verify_scope(client, args.mailbox, args.deny_check)
        except GraphError as exc:
            log("fatal: scope check could not complete: %s" % exc)
            return 2
        report_scope(report)
        if args.json:
            print(json.dumps({"scope_check": report}, indent=2))
        if args.check_scope:
            # Gate mode: only a proven-restricted app passes.
            return 0 if report["verdict"] == "scoped" else 3
        if report["verdict"] in ("over_scoped", "target_unreadable"):
            if not args.allow_broad_access:
                log("refusing to run: %s (override with --allow-broad-access)"
                    % report["detail"])
                return 3
            log("WARNING: continuing with broader mailbox access than needed")

    state = StateStore(args.state)
    try:
        results = run(client, args, state)
    except GraphError as exc:
        log("fatal: %s" % exc)
        return 2

    counts = summarize(results)
    if args.json:
        print(json.dumps({"counts": counts, "results": results}, indent=2))
    else:
        log("Done: " + (", ".join("%s=%d" % kv for kv in sorted(counts.items())) or "nothing to do"))
    return 1 if counts.get("error") else 0


if __name__ == "__main__":
    sys.exit(main())
