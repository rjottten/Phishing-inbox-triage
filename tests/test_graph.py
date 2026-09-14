"""Graph mapping, exercised against recorded payload shapes. No network."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from phish_triage import Config, triage_message
from phish_triage.models import Lane
from phish_triage.sources.graph import (
    GraphClient,
    GraphError,
    _attach_clicks,
    fetch_queue,
    map_mailbox_message,
    map_submission,
    merge,
)

SUBMISSION = {
    "id": "SUB-77124",
    "createdDateTime": "2026-09-14T03:20:00Z",
    "receivedDateTime": "2026-09-14T03:18:00Z",
    "sender": "dwhitfield@contoso-finance.co",
    "senderName": "Dana Whitfield (CFO)",
    "subject": "Urgent wire - vendor payment today",
    "recipientEmailAddress": "j.ortiz@contoso.com",
    "internetMessageId": "<abc123@contoso-finance.co>",
    "status": "succeeded",
    "result": {"detail": "notSpam"},
    "createdBy": {"user": {"email": "j.ortiz@contoso.com"}},
}

MAILBOX_MESSAGE = {
    "id": "AAMkAD",
    "internetMessageId": "<lure@contoso-support.help>",
    "receivedDateTime": "2026-09-14T02:05:00Z",
    "subject": "FW: Your password expires in 24 hours",
    "from": {"emailAddress": {"name": "Anita Patel", "address": "a.patel@contoso.com"}},
    "toRecipients": [{"emailAddress": {"address": "phishing@contoso.com"}}],
    "body": {"contentType": "html", "content": "<p>Forwarding this, looks fake? <a href='https://contoso-support.help/keep-password'>link</a></p><script>x()</script>"},
}


class FakeClient:
    """Stands in for GraphClient; records what was asked for."""

    def __init__(self, submissions=None, mailbox=None, clicks=None, fail=()):
        self._submissions = submissions or []
        self._mailbox = mailbox or []
        self._clicks = clicks or []
        self._fail = set(fail)

    def submissions(self, since, max_items=500):
        if "submissions" in self._fail:
            raise GraphError("Graph returned 403: Forbidden", status=403)
        return self._submissions

    def mailbox_messages(self, mailbox, since, max_items=500):
        if "mailbox" in self._fail:
            raise GraphError("Graph returned 404: mailbox not found", status=404)
        return self._mailbox

    def click_events(self, since, max_items=200):
        return self._clicks


def test_submission_maps_to_the_report_button_lane():
    msg = map_submission(SUBMISSION, vip_list=["j.ortiz@contoso.com"])
    assert msg.reported_via == "outlook_report_button"
    assert msg.defender.submission_id == "SUB-77124"
    assert msg.defender.air_status == "Completed"
    assert msg.defender.verdict == "No threats found"
    assert msg.defender.user_notified is True
    assert msg.recipients_vip == ["j.ortiz@contoso.com"]


def test_unknown_submission_status_is_passed_through_not_guessed():
    msg = map_submission({**SUBMISSION, "status": "somethingNew", "result": {"detail": "unmapped"}})
    assert msg.defender.air_status == "somethingNew"
    assert msg.defender.verdict == "unmapped"


def test_mailbox_message_is_a_gap_by_construction():
    """Anything in the shared mailbox arrived by forwarding, so no AIR ran on it."""
    msg = map_mailbox_message(MAILBOX_MESSAGE)
    assert msg.reported_via == "forwarded_to_mailbox"
    assert msg.defender.submission_id is None
    result = triage_message(msg, Config(org_domain="contoso.com"))
    assert result.lane is Lane.GAP


def test_html_body_is_stripped_of_markup_and_scripts():
    msg = map_mailbox_message(MAILBOX_MESSAGE)
    assert "<script>" not in msg.body_excerpt
    assert "x()" not in msg.body_excerpt
    assert "Forwarding this, looks fake?" in msg.body_excerpt


def test_urls_are_stored_defanged():
    msg = map_mailbox_message(MAILBOX_MESSAGE)
    assert msg.urls
    assert all(not u.startswith("http") for u in msg.urls)


def test_merge_prefers_the_submission_which_carries_the_air_state():
    submission = map_submission(SUBMISSION)
    duplicate = map_mailbox_message({**MAILBOX_MESSAGE, "internetMessageId": SUBMISSION["internetMessageId"]})
    merged = merge([submission], [duplicate])
    assert len(merged) == 1
    assert merged[0].defender.submission_id == "SUB-77124"


def test_fetch_queue_records_what_it_could_not_read():
    """A lane decision made without the Defender side is a guess, so say so."""
    queue = fetch_queue(
        mailbox="phishing@contoso.com",
        client=FakeClient(mailbox=[MAILBOX_MESSAGE], fail=["submissions"]),
        org_domain="contoso.com",
        now=datetime(2026, 9, 14, 8, tzinfo=timezone.utc),
    )
    assert len(queue) == 1
    assert any("Defender submissions" in m for m in queue.missing_sources)
    assert "403" in queue.missing_sources[0]


def test_fetch_queue_builds_a_window_and_source_label():
    queue = fetch_queue(
        mailbox=None,
        hours=8,
        client=FakeClient(submissions=[SUBMISSION]),
        now=datetime(2026, 9, 14, 8, tzinfo=timezone.utc),
        include_clicks=False,
    )
    assert queue.window == "2026-09-14T00:00:00Z to 2026-09-14T08:00:00Z"
    assert "Defender submissions" in queue.source


def test_click_telemetry_becomes_an_interaction_finding():
    msg = map_submission(SUBMISSION)
    _attach_clicks([msg], [{"AccountUpn": "j.ortiz@contoso.com", "IsClickedThrough": "1", "Url": "hxxps://x"}])
    result = triage_message(msg, Config(org_domain="contoso.com"))
    assert any(f.code == "telemetry_interaction" for f in result.findings)
    assert result.lane is Lane.EXCEPTION


def test_click_events_without_clickthrough_are_ignored():
    msg = map_submission(SUBMISSION)
    _attach_clicks([msg], [{"AccountUpn": "j.ortiz@contoso.com", "IsClickedThrough": "0"}])
    assert "interactions" not in msg.raw


def test_client_refuses_to_start_without_credentials(monkeypatch):
    for var in ("GRAPH_TENANT_ID", "GRAPH_CLIENT_ID", "GRAPH_CLIENT_SECRET"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(GraphError, match="missing credentials"):
        GraphClient()


def test_client_secret_is_not_in_the_repr(monkeypatch):
    for var, value in (("GRAPH_TENANT_ID", "t"), ("GRAPH_CLIENT_ID", "c"), ("GRAPH_CLIENT_SECRET", "s3cret")):
        monkeypatch.setenv(var, value)
    assert "s3cret" not in repr(GraphClient())
