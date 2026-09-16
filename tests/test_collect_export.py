#!/usr/bin/env python3
"""Tests for collect_export.py — building the triage export from live Graph data.

No network: the Graph client is a recorder that replays canned responses.

The tests concentrate on the two ways a collector quietly ruins downstream
triage. First, a field that is *unknown* being emitted as a confident value —
above all `urls`, because `triage.py` reads an empty URL list as "no link, so
this could be BEC". Second, a source silently going missing: if Defender
submissions can't be read, the queue is all gaps and an analyst would conclude
the Report button is broken. Both must show up in collection_notes.

The last test is the one that matters most: output of the collector, straight
into triage.py, must produce the right lanes.

Run: python -m unittest discover -s tests
"""
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT_DIR = os.path.join(ROOT, "phishing-inbox-triage", "scripts")
sys.path.insert(0, SCRIPT_DIR)

import collect_export as ce  # noqa: E402
import graph_submit as gs    # noqa: E402
import triage as tr          # noqa: E402

PHISH_EML = b"""\
From: "IT Helpdesk" <helpdesk@contoso-support.help>
To: j.rivera@contoso.com
Subject: Your password expires in 24 hours
Message-ID: <phish-1@contoso-support.help>
Date: Mon, 14 Sep 2026 00:31:00 +0000
Authentication-Results: spf=pass dkim=none dmarc=none
Content-Type: text/plain; charset="utf-8"

Your password expires tomorrow. Keep it by visiting
https://contoso-support.help/verify?u=jrivera now.
"""

BEC_EML = b"""\
From: "Dana Whitfield (CFO)" <dwhitfield@contoso-finance.co>
Reply-To: dana.cfo@gmail.com
To: j.ortiz@contoso.com
Subject: Urgent wire - vendor payment today
Message-ID: <bec-1@contoso-finance.co>
Content-Type: text/plain; charset="utf-8"

I'm stuck in board prep. Please pay the Halvorsen invoice today by wire.
Keep this between us.
"""

HTML_EML = b"""\
From: "Billing" <billing@example.invalid>
Subject: Invoice
Message-ID: <html-1@example.invalid>
Content-Type: text/html; charset="utf-8"

<html><body><p>Please <a href="https://evil.invalid/pay">pay here</a>.</p></body></html>
"""


def mailbox_message(**over):
    base = {
        "id": "AAMk-1",
        "internetMessageId": "<fwd-1@contoso.com>",
        "receivedDateTime": "2026-09-14T01:00:00Z",
        "subject": "FW: Your password expires in 24 hours",
        "hasAttachments": True,
        "bodyPreview": "Forwarding this, looks fake?",
        "from": {"emailAddress": {"address": "a.patel@contoso.com"}},
    }
    base.update(over)
    return base


class FakeClient:
    """Replays canned Graph responses and records what was asked for."""

    def __init__(self, messages=None, submissions=None, hunting=None, eml=PHISH_EML,
                 fail=()):
        self.messages = messages if messages is not None else [mailbox_message()]
        self.submissions = submissions or []
        self.hunting = hunting or {}
        self.eml = eml
        self.fail = set(fail)
        self.queries = []

    def _maybe_fail(self, what):
        if what in self.fail:
            raise gs.GraphError(403, '{"error":{"code":"Forbidden"}}', what)

    def paged(self, path, params=None, max_items=None):
        if "mailFolders" in path:
            self._maybe_fail("mailbox")
            return iter(self.messages)
        if "threatSubmission" in path:
            self._maybe_fail("submissions")
            return iter(self.submissions)
        if "/attachments" in path:
            return iter([{"@odata.type": "#microsoft.graph.itemAttachment",
                          "id": "ITEM1", "name": "original", "size": 1000}])
        raise AssertionError("unexpected paged " + path)

    def get(self, path, params=None, raw=False):
        if path.endswith("/$value"):
            return self.eml
        raise AssertionError("unexpected get " + path)

    def post(self, path, body, **kw):
        if path.endswith("runHuntingQuery"):
            self._maybe_fail("hunting")
            query = body["Query"]
            self.queries.append(query)
            for table, rows in self.hunting.items():
                if table in query:
                    return {"results": rows}
            return {"results": []}
        raise AssertionError("unexpected post " + path)


CTX = {"org_domains": {"contoso.com"}, "vip": {"r.alvarez@contoso.com"},
       "known_vendor_domains": set()}


# --------------------------------------------------------------------------
# Reading an .eml offline
# --------------------------------------------------------------------------

class TestEmlReading(unittest.TestCase):
    def test_body_excerpt_plain(self):
        text = ce.body_excerpt(PHISH_EML)
        self.assertTrue(text.startswith("Your password expires tomorrow"))
        self.assertNotIn("\n", text)

    def test_body_excerpt_strips_html(self):
        text = ce.body_excerpt(HTML_EML)
        self.assertIn("pay here", text)
        self.assertNotIn("<a href", text)

    def test_body_excerpt_respects_limit(self):
        self.assertEqual(len(ce.body_excerpt(PHISH_EML, limit=20)), 20)

    def test_body_excerpt_empty_input(self):
        self.assertEqual(ce.body_excerpt(b""), "")
        self.assertEqual(ce.body_excerpt(None), "")

    def test_urls_extracted_and_defanged(self):
        urls = ce.extract_urls(PHISH_EML)
        self.assertEqual(len(urls), 1)
        self.assertIn("contoso-support", urls[0])
        self.assertTrue(urls[0].startswith("hxxps://"), urls[0])

    def test_urls_found_in_html(self):
        urls = ce.extract_urls(HTML_EML)
        self.assertEqual(len(urls), 1)
        self.assertIn("evil[.]invalid", urls[0])

    def test_defang_neutralises_every_dot_and_the_scheme(self):
        # A half-defanged host still autolinks in most mail clients and terminals,
        # and an analyst reading the report must not be one misclick from the lure.
        self.assertEqual(ce.defang("https://a.b.evil.invalid/x.php"),
                         "hxxps://a[.]b[.]evil[.]invalid/x[.]php")
        self.assertEqual(ce.defang("http://x.invalid"), "hxxp://x[.]invalid")
        self.assertIsNone(ce.defang(None))

    def test_no_urls_when_there_are_none(self):
        self.assertEqual(ce.extract_urls(BEC_EML), [])

    def test_item_from_eml_shape(self):
        derived = ce.item_from_eml(BEC_EML, 300)
        self.assertEqual(derived["from_address"], "dwhitfield@contoso-finance.co")
        self.assertEqual(derived["reply_to"], "dana.cfo@gmail.com")
        self.assertEqual(derived["message_id"], "bec-1@contoso-finance.co")
        self.assertEqual(derived["urls"], [])
        self.assertEqual(derived["auth"], {})

    def test_auth_carried_through(self):
        self.assertEqual(ce.item_from_eml(PHISH_EML, 300)["auth"],
                         {"spf": "pass", "dkim": "none", "dmarc": "none"})

    def test_short_id_is_stable_and_short(self):
        a, b = ce.short_id("<x@y>"), ce.short_id("<x@y>")
        self.assertEqual(a, b)
        self.assertNotEqual(a, ce.short_id("<z@y>"))
        self.assertLessEqual(len(a), 12)

    def test_norm_mid(self):
        self.assertEqual(ce.norm_mid("<A@B.com>"), "a@b.com")
        self.assertEqual(ce.norm_mid(None), "")


# --------------------------------------------------------------------------
# Source A: the mailbox
# --------------------------------------------------------------------------

class TestCollectMailbox(unittest.TestCase):
    def collect(self, client, notes=None):
        notes = [] if notes is None else notes
        return ce.collect_mailbox(client, "phish@contoso.com", "inbox",
                                  "2026-09-14T00:00:00Z", 100, 300, notes), notes

    def test_extracts_the_original_not_the_forward(self):
        items, _ = self.collect(FakeClient())
        self.assertEqual(len(items), 1)
        item = items[0]
        self.assertEqual(item["from_address"], "helpdesk@contoso-support.help")
        self.assertEqual(item["subject"], "Your password expires in 24 hours")
        self.assertEqual(item["reported_via"], "forwarded_to_mailbox")
        self.assertTrue(item["collection"]["original_attached"])

    def test_reporter_note_comes_from_the_forward_preview(self):
        # This field decides most P1s, so it must be the user's own words.
        items, _ = self.collect(FakeClient())
        self.assertEqual(items[0]["reporter_note"], "Forwarding this, looks fake?")
        self.assertEqual(items[0]["reporter"], "a.patel@contoso.com")

    def test_item_with_no_original_is_kept_and_marked(self):
        client = FakeClient(messages=[mailbox_message(hasAttachments=False)])
        items, _ = self.collect(client)
        self.assertEqual(len(items), 1)
        self.assertFalse(items[0]["collection"]["original_attached"])
        self.assertEqual(items[0]["reported_via"], "forwarded_to_mailbox")
        self.assertEqual(items[0]["reporter_note"], "Forwarding this, looks fake?")

    def test_unreadable_mailbox_is_a_note_not_a_crash(self):
        items, notes = self.collect(FakeClient(fail=["mailbox"]))
        self.assertEqual(items, [])
        self.assertTrue(any("unreadable" in n for n in notes))


# --------------------------------------------------------------------------
# Source B: submissions
# --------------------------------------------------------------------------

class TestApiVocabulary(unittest.TestCase):
    """The Submissions API and the export format use different words.

    Translating is the collector's job. triage.py routing an unrecognised status
    to the analyst rather than filing it as handled is correct behaviour, so it
    will not paper over a bad mapping — it will just make every submission look
    like an automation gap.
    """

    def test_status_mapping(self):
        self.assertEqual(ce.map_air_status("succeeded"), "Completed")
        self.assertEqual(ce.map_air_status("notStarted"), "Pending")
        self.assertEqual(ce.map_air_status("running"), "Running")
        self.assertEqual(ce.map_air_status("failed"), "Failed")

    def test_verdict_mapping(self):
        self.assertEqual(ce.map_verdict("noThreatsFound"), "No threats found")
        self.assertEqual(ce.map_verdict("phishing"), "Phishing")
        self.assertEqual(ce.map_verdict("malware"), "Malware")

    def test_unknown_values_pass_through_rather_than_being_guessed(self):
        self.assertEqual(ce.map_air_status("someNewState"), "someNewState")
        self.assertEqual(ce.map_verdict("someNewVerdict"), "someNewVerdict")
        self.assertIsNone(ce.map_air_status(None))
        self.assertIsNone(ce.map_verdict(""))

    def test_mapped_values_are_ones_triage_actually_recognises(self):
        # The point of the mapping: every output must land in triage.py's
        # vocabulary, or the translation is decorative.
        for api in ("succeeded", "completed"):
            self.assertIn(ce.map_air_status(api).lower(), tr.COMPLETED)
        for api in ("notStarted", "running", "queued"):
            self.assertIn(ce.map_air_status(api).lower(), tr.IN_PROGRESS)
        self.assertIn(ce.map_air_status("failed").lower(), tr.FAILED)
        self.assertIn(ce.map_verdict("noThreatsFound").lower(), tr.CLEAN_VERDICTS)
        for api in ("phishing", "malware", "spam"):
            self.assertIn(ce.map_verdict(api).lower(), tr.BAD_VERDICTS)


class TestCollectSubmissions(unittest.TestCase):
    ENTRY = {"id": "SUB-1", "createdDateTime": "2026-09-14T02:00:00Z",
             "internetMessageId": "<phish-1@contoso-support.help>",
             "recipientEmailAddress": "j.rivera@contoso.com",
             "subject": "Your password expires in 24 hours",
             "status": "succeeded", "result": "phishing"}

    def test_maps_to_the_export_shape(self):
        items = ce.collect_submissions(FakeClient(submissions=[self.ENTRY]),
                                       "2026-09-14T00:00:00Z", 100, [])
        self.assertEqual(len(items), 1)
        item = items[0]
        self.assertEqual(item["reported_via"], "outlook_report_button")
        self.assertEqual(item["defender"]["submission_id"], "SUB-1")
        self.assertEqual(item["defender"]["verdict"], "Phishing")
        self.assertEqual(item["defender"]["air_status"], "Completed")
        self.assertEqual(item["message_id"], "phish-1@contoso-support.help")

    def test_nested_result_object(self):
        entry = dict(self.ENTRY, result={"detail": "No threats found"})
        items = ce.collect_submissions(FakeClient(submissions=[entry]),
                                       "2026-09-14T00:00:00Z", 100, [])
        self.assertEqual(items[0]["defender"]["verdict"], "No threats found")

    def test_urls_are_unknown_not_empty(self):
        # Critical: submissions carry no URL inventory. Emitting [] would tell
        # triage.py the message had no link, which is its BEC gate.
        items = ce.collect_submissions(FakeClient(submissions=[self.ENTRY]),
                                       "2026-09-14T00:00:00Z", 100, [])
        self.assertIsNone(items[0]["urls"])

    def test_missing_submissions_source_is_loudly_noted(self):
        notes = []
        items = ce.collect_submissions(FakeClient(fail=["submissions"]),
                                       "2026-09-14T00:00:00Z", 100, notes)
        self.assertEqual(items, [])
        self.assertTrue(any("look like gaps" in n for n in notes), notes)


# --------------------------------------------------------------------------
# Enrichment
# --------------------------------------------------------------------------

class TestHuntingEnrichment(unittest.TestCase):
    def base_item(self):
        return {"id": "PHQ-1", "message_id": "phish-1@contoso-support.help",
                "urls": None, "auth": {}, "subject": ""}

    def test_fills_recipients_urls_attachments_and_clicks(self):
        client = FakeClient(hunting={
            "EmailEvents": [{"InternetMessageId": "<phish-1@contoso-support.help>",
                             "RecipientCount": 14, "Recipients": ["a@contoso.com"],
                             "Auth": '{"SPF":"pass","DKIM":"none","DMARC":"fail"}',
                             "Nmids": ["nm1"], "Subject": "Your password expires"}],
            "EmailUrlInfo": [{"NetworkMessageId": "nm1",
                              "Urls": ["https://contoso-support.help/verify"]}],
            "EmailAttachmentInfo": [{"NetworkMessageId": "nm1", "Files": ["a.pdf"]}],
            "UrlClickEvents": [{"NetworkMessageId": "nm1", "Clicked": 1,
                                "Action": "ClickAllowed",
                                "ClickTime": "2026-09-14T04:31:00Z"}],
        })
        item = self.base_item()
        notes = []
        ce.enrich_from_hunting(client, [item], "2026-09-14T00:00:00Z", notes)
        self.assertEqual(item["recipient_count"], 14)
        self.assertEqual(item["auth"], {"spf": "pass", "dkim": "none", "dmarc": "fail"})
        self.assertTrue(item["urls"][0].startswith("hxxps://"))
        self.assertEqual(item["attachments"], ["a.pdf"])
        self.assertTrue(item["click_telemetry"]["url_clicked"])
        self.assertEqual(item["click_telemetry"]["safe_links_action"], "ClickAllowed")

    def test_hunting_denied_is_a_note_not_a_crash(self):
        item, notes = self.base_item(), []
        ce.enrich_from_hunting(FakeClient(fail=["hunting"]), [item],
                               "2026-09-14T00:00:00Z", notes)
        self.assertTrue(any("Advanced Hunting unavailable" in n for n in notes), notes)
        self.assertIsNone(item["urls"])  # still unknown, not falsely empty

    def test_no_message_ids_to_join_on(self):
        notes = []
        ce.enrich_from_hunting(FakeClient(), [{"id": "X", "message_id": ""}],
                               "2026-09-14T00:00:00Z", notes)
        self.assertTrue(any("no Message-IDs" in n for n in notes), notes)

    def test_parse_auth_details(self):
        self.assertEqual(ce.parse_auth_details('{"SPF":"Fail","DMARC":"fail"}'),
                         {"spf": "fail", "dmarc": "fail"})
        self.assertEqual(ce.parse_auth_details("not json"), {})
        self.assertEqual(ce.parse_auth_details(None), {})

    def test_queries_are_chunked(self):
        client = FakeClient()
        items = [{"id": str(n), "message_id": "m%d@x" % n, "urls": None, "auth": {}}
                 for n in range(95)]
        ce.enrich_from_hunting(client, items, "2026-09-14T00:00:00Z", [], chunk=40)
        event_queries = [q for q in client.queries if "EmailEvents" in q]
        self.assertEqual(len(event_queries), 3)


# --------------------------------------------------------------------------
# Merge and finalize
# --------------------------------------------------------------------------

class TestMergeAndFinalize(unittest.TestCase):
    def test_reported_and_forwarded_is_one_item(self):
        sub = {"id": "A", "message_id": "m@x", "reported_via": "outlook_report_button",
               "subject": "S", "from_name": "", "reporter_note": "", "urls": None,
               "defender": {"submission_id": "SUB-1"}}
        fwd = {"id": "B", "message_id": "m@x", "reported_via": "forwarded_to_mailbox",
               "subject": "S", "from_name": "IT", "reporter_note": "I clicked it",
               "urls": ["hxxps://x"], "defender": {"submission_id": None}}
        notes = []
        merged = ce.merge_sources([fwd], [sub], notes)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["defender"]["submission_id"], "SUB-1")
        self.assertEqual(merged[0]["reporter_note"], "I clicked it")
        self.assertTrue(merged[0]["collection"]["also_forwarded"])
        self.assertTrue(any("both reported and forwarded" in n for n in notes))

    def test_distinct_messages_are_kept_apart(self):
        a = {"id": "A", "message_id": "a@x", "urls": None, "defender": {}}
        b = {"id": "B", "message_id": "b@x", "urls": None, "defender": {}}
        self.assertEqual(len(ce.merge_sources([a], [b], [])), 2)

    def test_unknown_urls_become_empty_but_are_flagged(self):
        item = {"id": "PHQ-1", "urls": None}
        notes = []
        ce.finalize([item], CTX, notes)
        self.assertEqual(item["urls"], [])
        self.assertTrue(item["collection"]["urls_unknown"])
        self.assertTrue(any("BEC classification may be over-eager" in n for n in notes))

    def test_known_empty_urls_are_not_flagged(self):
        item = {"id": "PHQ-1", "urls": []}
        notes = []
        ce.finalize([item], CTX, notes)
        self.assertEqual(notes, [])
        self.assertNotIn("collection", item)

    def test_vip_tagging_from_recipients_and_reporter(self):
        item = {"id": "A", "urls": [], "recipients": ["R.Alvarez@contoso.com", "x@contoso.com"]}
        ce.finalize([item], CTX, [])
        self.assertEqual(item["recipients_vip"], ["r.alvarez@contoso.com"])
        reporter_item = {"id": "B", "urls": [], "reporter": "R.Alvarez@contoso.com"}
        ce.finalize([reporter_item], CTX, [])
        self.assertEqual(reporter_item["recipients_vip"], ["r.alvarez@contoso.com"])

    def test_recipients_helper_field_is_not_exported(self):
        item = {"id": "A", "urls": [], "recipients": ["x@contoso.com"]}
        ce.finalize([item], CTX, [])
        self.assertNotIn("recipients", item)


# --------------------------------------------------------------------------
# End to end: the collector's output must feed triage.py
# --------------------------------------------------------------------------

class TestFeedsTriage(unittest.TestCase):
    def test_collected_export_triages_into_the_right_lanes(self):
        client = FakeClient(
            messages=[mailbox_message(bodyPreview="I clicked it and entered my password")],
            submissions=[{"id": "SUB-9", "createdDateTime": "2026-09-14T02:00:00Z",
                          "internetMessageId": "<other@example.invalid>",
                          "recipientEmailAddress": "m.silva@contoso.com",
                          "subject": "Newsletter", "status": "succeeded",
                          "result": "No threats found", "userNotified": True}],
        )
        notes = []
        mailbox_items = ce.collect_mailbox(client, "phish@contoso.com", "inbox",
                                           "2026-09-14T00:00:00Z", 100, 300, notes)
        submission_items = ce.collect_submissions(client, "2026-09-14T00:00:00Z", 100, notes)
        items = ce.finalize(ce.merge_sources(mailbox_items, submission_items, notes),
                            CTX, notes)
        export = ce.build_export(items, {"org_domains": ["contoso.com"]}, notes)

        # Round-trips as JSON, which is how triage.py will actually receive it.
        reloaded = json.loads(json.dumps(export, default=str))
        results = {r["id"]: r for r in tr.triage(reloaded["items"], CTX)}
        self.assertEqual(len(results), 2)

        forwarded = [r for r in results.values()
                     if r["reported_via"] == "forwarded_to_mailbox"][0]
        self.assertEqual(forwarded["lane"], "exception")
        self.assertEqual(forwarded["priority"], "P1")
        self.assertIn("user_interaction", forwarded["categories"])

        reported = [r for r in results.values()
                    if r["reported_via"] == "outlook_report_button"][0]
        self.assertEqual(reported["lane"], "handled_by_automation")

    def test_export_meta_carries_the_collection_notes(self):
        export = ce.build_export([], {"source": "x"}, ["hunting unavailable"])
        self.assertEqual(export["export_meta"]["collection_notes"], ["hunting unavailable"])
        self.assertEqual(export["export_meta"]["generated_by"], "collect_export.py")
        self.assertIn("generated_at", export["export_meta"])


class TestReporterNotes(unittest.TestCase):
    """The covering note, carried from graph_submit.py without a second mailbox read."""

    def state_file(self, payload):
        import tempfile
        fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(payload, fh)
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        return fh.name

    def test_notes_attach_by_original_message_id(self):
        path = self.state_file({"notes": {"phish-1@x": {
            "note": "I clicked it and entered my password",
            "reporter": "a.patel@contoso.com"}}})
        items = [{"id": "A", "message_id": "phish-1@x", "urls": []},
                 {"id": "B", "message_id": "other@x", "urls": []}]
        notes = []
        ce.attach_reporter_notes(items, ce.load_reporter_notes(path, notes), notes)
        self.assertEqual(items[0]["reporter_note"], "I clicked it and entered my password")
        self.assertEqual(items[0]["reporter"], "a.patel@contoso.com")
        self.assertNotIn("reporter_note", items[1])
        self.assertTrue(any("attached 1 reporter note" in n for n in notes))

    def test_no_state_file_means_no_notes_and_no_noise(self):
        notes = []
        self.assertEqual(ce.load_reporter_notes(None, notes), {})
        self.assertEqual(notes, [])

    def test_unreadable_state_file_says_what_is_lost(self):
        notes = []
        self.assertEqual(ce.load_reporter_notes("/nonexistent/state.json", notes), {})
        self.assertTrue(any("credentials entered" in n for n in notes), notes)

    def test_state_without_notes_hints_at_the_missing_flag(self):
        notes = []
        ce.load_reporter_notes(self.state_file({"processed": {}}), notes)
        self.assertTrue(any("--capture-reporter-note" in n for n in notes), notes)

    def test_an_existing_note_is_not_overwritten(self):
        path = self.state_file({"notes": {"m@x": {"note": "from state"}}})
        items = [{"id": "A", "message_id": "m@x", "urls": [], "reporter_note": "already here"}]
        ce.attach_reporter_notes(items, ce.load_reporter_notes(path, []), [])
        self.assertEqual(items[0]["reporter_note"], "already here")

    def test_the_note_is_what_turns_a_routine_item_into_a_p1(self):
        """The whole point of the field, proven end to end through triage.py."""
        item = {"id": "PHQ-1", "message_id": "m@x", "reported_via": "outlook_report_button",
                "reporter": "a.patel@contoso.com", "subject": "Shared file",
                "from_name": "SharePoint", "from_address": "no-reply@sharepoint-files.invalid",
                "urls": ["hxxps://x[.]invalid"], "attachments": [], "auth": {},
                "recipient_count": 1, "recipients_vip": [], "reporter_note": "",
                "defender": {"submission_id": "S", "air_status": "Completed",
                             "verdict": "Phishing", "user_notified": True,
                             "actions": "Soft delete (auto-approved, 1 mailbox)"}}
        without = tr.classify(dict(item), CTX, None, 4, 100)
        self.assertEqual(without["lane"], "handled_by_automation")

        path = self.state_file({"notes": {"m@x": {
            "note": "I clicked it and entered my password", "reporter": "a.patel@contoso.com"}}})
        withnote = [dict(item)]
        ce.attach_reporter_notes(withnote, ce.load_reporter_notes(path, []), [])
        classified = tr.classify(withnote[0], CTX, None, 4, 100)
        self.assertEqual(classified["lane"], "exception")
        self.assertEqual(classified["priority"], "P1")
        self.assertIn("user_interaction", classified["categories"])
        self.assertTrue(any(a["owner"] == "IAM" for a in classified["actions"]))


class TestCommandLine(unittest.TestCase):
    def test_requires_a_mailbox_or_an_explicit_skip(self):
        with self.assertRaises(SystemExit):
            ce.parse_args([])

    def test_skipping_both_sources_is_refused(self):
        with self.assertRaises(SystemExit):
            ce.parse_args(["--no-mailbox", "--no-submissions"])

    def test_no_mailbox_alone_is_allowed(self):
        args = ce.parse_args(["--no-mailbox"])
        self.assertTrue(args.no_mailbox)

    def test_defaults(self):
        args = ce.parse_args(["--mailbox", "phish@contoso.com"])
        self.assertEqual(args.since, "24h")
        self.assertEqual(args.body_chars, 300)
        self.assertEqual(args.folder, "inbox")


if __name__ == "__main__":
    unittest.main()
