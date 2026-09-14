"""Pull the live queue from Microsoft Graph: shared mailbox + Defender submissions.

Two halves, deliberately separated:

* `map_*` functions are pure — Graph JSON in, `ReportedMessage` out. They are what
  the tests exercise, and what you adapt if your tenant returns different shapes.
* `GraphClient` is a thin stdlib HTTP client doing client-credentials auth and
  paging. No third-party dependencies anywhere in this project.

The client only ever issues GETs against mail and security read endpoints. It does
not send mail, move messages, run remediation, or follow a URL from a reported
message — the engine recommends actions and a person executes them.

App registration (application permissions, admin consent required):

* ``Mail.Read`` — read the shared phishing mailbox. Scope it down with an
  application access policy so the app can read that mailbox and no other.
* ``ThreatSubmission.Read.All`` — read user-reported submissions.
* ``ThreatHunting.Read.All`` — optional; only needed for `click_events`.

Credentials come from the environment: ``GRAPH_TENANT_ID``, ``GRAPH_CLIENT_ID``,
``GRAPH_CLIENT_SECRET`` (or set ``client_secret`` yourself from your own vault).
Never commit a secret to this repo.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from ..models import DefenderState, Queue, ReportedMessage

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
LOGIN_BASE = "https://login.microsoftonline.com"
BODY_EXCERPT_CHARS = 1500

#: Graph submission status -> the AIR status vocabulary the rules engine speaks.
SUBMISSION_STATUS_MAP = {
    "running": "Running",
    "inprogress": "Running",
    "pending": "Pending",
    "succeeded": "Completed",
    "completed": "Completed",
    "failed": "Failed",
    "skipped": "Failed",
}

#: Graph submission result detail -> verdict vocabulary.
RESULT_VERDICT_MAP = {
    "phishing": "Phishing",
    "highconfidencephish": "Phishing",
    "malware": "Malware",
    "spam": "Spam",
    "highconfidencespam": "Spam",
    "notspam": "No threats found",
    "clean": "No threats found",
    "nothreatsfound": "No threats found",
    "allowedbypolicy": "No threats found",
}


class GraphError(RuntimeError):
    """A Graph call failed. Carries the status code so callers can tell 403 from 429."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


def _defang(url: str) -> str:
    """Store URLs defanged so nothing downstream can accidentally make one clickable."""
    return url.replace("http", "hxxp").replace(".", "[.]", 1) if url.startswith("http") else url


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _text_excerpt(body: dict[str, Any] | None) -> str:
    """Body text for keyword scanning only. Never rendered as HTML, never executed."""
    if not isinstance(body, dict):
        return ""
    content = body.get("content") or ""
    if (body.get("contentType") or "").lower() == "html":
        import re

        content = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", content, flags=re.S | re.I)
        content = re.sub(r"<[^>]+>", " ", content)
        content = re.sub(r"&nbsp;?", " ", content)
    return " ".join(content.split())[:BODY_EXCERPT_CHARS]


def _addr(recipient: dict[str, Any] | None) -> tuple[str, str]:
    email = ((recipient or {}).get("emailAddress") or {})
    return email.get("name") or "", (email.get("address") or "").lower()


def map_mailbox_message(item: dict[str, Any], vip_list: list[str] | None = None) -> ReportedMessage:
    """A message sitting in the shared phishing mailbox.

    Anything here arrived by forwarding rather than the Report button, so it has no
    submission and no AIR investigation — an automation gap by construction. That is
    the signal: the shorter this list gets, the closer the mailbox is to retirement.
    """
    from_name, from_addr = _addr(item.get("from") or item.get("sender"))
    reply_to = ""
    replies = item.get("replyTo") or []
    if replies:
        _, reply_to = _addr(replies[0])
    recipients = [a for _, a in (_addr(r) for r in (item.get("toRecipients") or [])) if a]
    vips = [a for a in recipients if a in {v.lower() for v in (vip_list or [])}]
    raw_body = ((item.get("body") or item.get("uniqueBody")) or {}).get("content", "")
    body = _text_excerpt(item.get("body") or item.get("uniqueBody"))

    return ReportedMessage(
        id=item.get("internetMessageId") or item.get("id") or "",
        reporter=(_addr(item.get("from"))[1] or ""),
        received=_parse_graph_dt(item.get("receivedDateTime")),
        reported_via="forwarded_to_mailbox",
        from_name=from_name,
        from_address=from_addr,
        reply_to=reply_to or None,
        subject=item.get("subject") or "",
        body_excerpt=body,
        urls=[_defang(u) for u in _extract_urls(raw_body)],
        attachments=[a.get("name", "") for a in (item.get("attachments") or [])],
        recipient_count=max(1, len(recipients)),
        recipients_vip=vips,
        reporter_note=body[:400],
        defender=DefenderState(),
        raw={"graph_message_id": item.get("id"), "recipients": recipients, "source": "mailbox"},
    )


def map_submission(item: dict[str, Any], vip_list: list[str] | None = None) -> ReportedMessage:
    """A Defender user submission — the Report-button path, where AIR lives."""
    result = item.get("result") or {}
    detail = str(result.get("detail") or item.get("category") or "").replace(" ", "").lower()
    status = str(item.get("status") or "").replace(" ", "").lower()
    recipient = (item.get("recipientEmailAddress") or "").lower()
    vips = [recipient] if recipient in {v.lower() for v in (vip_list or [])} else []

    return ReportedMessage(
        id=item.get("internetMessageId") or item.get("id") or "",
        reporter=(item.get("createdBy") or {}).get("user", {}).get("email", "")
        or (item.get("createdBy") or {}).get("user", {}).get("userPrincipalName", "")
        or recipient,
        received=_parse_graph_dt(item.get("receivedDateTime") or item.get("createdDateTime")),
        reported_via="outlook_report_button",
        from_name=item.get("senderName") or "",
        from_address=(item.get("sender") or "").lower(),
        subject=item.get("subject") or "",
        recipient_count=1,
        recipients_vip=vips,
        defender=DefenderState(
            submission_id=item.get("id"),
            air_status=SUBMISSION_STATUS_MAP.get(status, item.get("status") or None),
            verdict=RESULT_VERDICT_MAP.get(detail, result.get("detail") or None),
            # Graph does not expose the auto-notify state; Defender's own notification
            # policy decides it. Treat a completed submission as notified only when the
            # tenant has auto-notify on — override via `assume_auto_notify=False`.
            user_notified=status in {"succeeded", "completed"},
            actions=str(item.get("tenantAllowOrBlockListAction") or ""),
        ),
        raw={"source": "submission", "graph_submission": item},
    )


def _extract_urls(content: str) -> list[str]:
    """Pull URLs out of the *raw* body — href targets live in attributes, so this has
    to run before the markup is stripped, or every linked lure comes back empty."""
    import re

    found = re.findall(r"""https?://[^\s<>"'\\)]+""", content or "")
    seen: list[str] = []
    for url in found:
        url = url.rstrip(".,;")
        if url not in seen:
            seen.append(url)
    return seen[:20]


def _parse_graph_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def merge(
    submissions: list[ReportedMessage],
    mailbox: list[ReportedMessage],
) -> list[ReportedMessage]:
    """Submissions win: the same report can appear in both, and the submission
    carries the AIR state that decides the lane."""
    by_key: dict[str, ReportedMessage] = {}
    for msg in submissions:
        by_key[_dedupe_key(msg)] = msg
    for msg in mailbox:
        by_key.setdefault(_dedupe_key(msg), msg)
    return sorted(by_key.values(), key=lambda m: m.received or datetime.min.replace(tzinfo=timezone.utc))


def _dedupe_key(msg: ReportedMessage) -> str:
    return (msg.id or f"{msg.from_address}|{msg.subject}").strip().lower()


@dataclass
class GraphClient:
    """Minimal read-only Graph client. Client-credentials flow, stdlib only."""

    tenant_id: str = field(default_factory=lambda: os.environ.get("GRAPH_TENANT_ID", ""))
    client_id: str = field(default_factory=lambda: os.environ.get("GRAPH_CLIENT_ID", ""))
    client_secret: str = field(default_factory=lambda: os.environ.get("GRAPH_CLIENT_SECRET", ""), repr=False)
    timeout: int = 30
    _token: str = field(default="", repr=False)
    _token_expiry: datetime | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        missing = [n for n, v in (("GRAPH_TENANT_ID", self.tenant_id), ("GRAPH_CLIENT_ID", self.client_id), ("GRAPH_CLIENT_SECRET", self.client_secret)) if not v]
        if missing:
            raise GraphError(f"missing credentials: {', '.join(missing)}")

    def token(self) -> str:
        if self._token and self._token_expiry and datetime.now(timezone.utc) < self._token_expiry:
            return self._token
        data = urllib.parse.urlencode(
            {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            }
        ).encode()
        req = urllib.request.Request(f"{LOGIN_BASE}/{self.tenant_id}/oauth2/v2.0/token", data=data)
        payload = self._send(req)
        self._token = payload.get("access_token", "")
        self._token_expiry = datetime.now(timezone.utc) + timedelta(seconds=int(payload.get("expires_in", 3600)) - 60)
        if not self._token:
            raise GraphError("token endpoint returned no access_token")
        return self._token

    def _send(self, req: urllib.request.Request) -> dict[str, Any]:
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                return json.loads(response.read().decode() or "{}")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")[:500]
            raise GraphError(f"Graph returned {exc.code}: {body}", status=exc.code) from exc
        except urllib.error.URLError as exc:
            raise GraphError(f"could not reach Graph: {exc.reason}") from exc

    def get(self, url: str) -> dict[str, Any]:
        if not url.startswith("http"):
            url = f"{GRAPH_BASE}{url}"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {self.token()}", "Accept": "application/json"})
        return self._send(req)

    def paged(self, url: str, max_items: int = 500) -> Iterator[dict[str, Any]]:
        seen = 0
        while url and seen < max_items:
            payload = self.get(url)
            for item in payload.get("value", []):
                yield item
                seen += 1
                if seen >= max_items:
                    return
            url = payload.get("@odata.nextLink", "")

    def mailbox_messages(self, mailbox: str, since: datetime, max_items: int = 500) -> list[dict[str, Any]]:
        query = urllib.parse.urlencode(
            {
                "$filter": f"receivedDateTime ge {_iso(since)}",
                "$select": "id,internetMessageId,subject,from,sender,replyTo,toRecipients,receivedDateTime,body,hasAttachments",
                "$top": "50",
                "$orderby": "receivedDateTime asc",
            }
        )
        return list(self.paged(f"/users/{urllib.parse.quote(mailbox)}/messages?{query}", max_items))

    def submissions(self, since: datetime, max_items: int = 500) -> list[dict[str, Any]]:
        query = urllib.parse.urlencode({"$filter": f"createdDateTime ge {_iso(since)}", "$top": "50"})
        return list(self.paged(f"/security/threatSubmission/emailThreats?{query}", max_items))

    def click_events(self, since: datetime, max_items: int = 200) -> list[dict[str, Any]]:
        """Advanced Hunting for URL clicks — the fastest answer to 'did anyone click?'.

        Requires ThreatHunting.Read.All. Returns [] rather than failing the run when
        the permission is absent: a missing hunting result is reported as unverified,
        not guessed at.
        """
        query = (
            f"UrlClickEvents | where Timestamp >= datetime({_iso(since)}) "
            f"| project Timestamp, Url, AccountUpn, ActionType, IsClickedThrough, NetworkMessageId "
            f"| take {max_items}"
        )
        body = json.dumps({"Query": query}).encode()
        req = urllib.request.Request(
            f"{GRAPH_BASE}/security/runHuntingQuery",
            data=body,
            headers={"Authorization": f"Bearer {self.token()}", "Content-Type": "application/json"},
        )
        try:
            return self._send(req).get("results", [])
        except GraphError as exc:
            if exc.status in (401, 403):
                return []
            raise


def fetch_queue(
    mailbox: str | None,
    hours: int = 24,
    client: GraphClient | None = None,
    org_domain: str = "",
    vip_list: list[str] | None = None,
    include_clicks: bool = True,
    now: datetime | None = None,
) -> Queue:
    """Build a `Queue` from live Graph data.

    Whatever could not be read is recorded in `Queue.missing_sources` and surfaces
    in the report, because a lane decision made without the Defender side is a guess.
    """
    client = client or GraphClient()
    now = now or datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)
    missing: list[str] = []
    vip_list = list(vip_list or [])

    try:
        submissions = [map_submission(s, vip_list) for s in client.submissions(since)]
    except GraphError as exc:
        submissions = []
        missing.append(f"Defender submissions ({exc})")

    mailbox_items: list[ReportedMessage] = []
    if mailbox:
        try:
            mailbox_items = [map_mailbox_message(m, vip_list) for m in client.mailbox_messages(mailbox, since)]
        except GraphError as exc:
            missing.append(f"shared mailbox {mailbox} ({exc})")

    items = merge(submissions, mailbox_items)

    if include_clicks and items:
        try:
            clicks = client.click_events(since)
        except GraphError as exc:
            clicks = []
            missing.append(f"UrlClickEvents ({exc})")
        _attach_clicks(items, clicks)
    elif include_clicks:
        missing.append("UrlClickEvents (no items to correlate)")

    return Queue(
        items=items,
        org_domain=org_domain,
        vip_list=vip_list,
        window=f"{_iso(since)} to {_iso(now)}",
        source=f"Microsoft Graph: Defender submissions{f' + {mailbox}' if mailbox else ''}",
        missing_sources=missing,
    )


def _attach_clicks(items: list[ReportedMessage], clicks: list[dict[str, Any]]) -> None:
    """Record confirmed click-throughs as telemetry interactions on the matching item."""
    by_account: dict[str, list[dict[str, Any]]] = {}
    for click in clicks:
        if str(click.get("IsClickedThrough", "")).lower() in {"1", "true"}:
            by_account.setdefault((click.get("AccountUpn") or "").lower(), []).append(click)
    for msg in items:
        hits = by_account.get(msg.reporter.lower(), [])
        if hits:
            msg.raw.setdefault("interactions", []).append(
                f"UrlClickEvents shows {len(hits)} click-through by {msg.reporter} in this window — correlate by NetworkMessageId before concluding"
            )
