#!/usr/bin/env python3
"""Offline tests for graph_submit.py.

Covers the parts that decide what actually gets sent to Microsoft: picking the
original message out of a forward, resolving the recipient, building the
submission body, idempotency, and the throttling/`source` fallbacks. No network:
the Graph client is replaced by a recorder.

Run: python -m unittest discover -s tests
"""
import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

# The skill bundle lives under skills/ so it can be zipped and shipped on its own;
# graph_submit.py is a standalone script inside it, not an importable package.
SCRIPT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "skills", "phishing-inbox-triage", "scripts",
)
sys.path.insert(0, SCRIPT_DIR)

import graph_submit as gs  # noqa: E402

ORIGINAL_EML = b"""\
Received: from mail.acme-invoices.example (mail.acme-invoices.example [203.0.113.9])
 by contoso-com.mail.protection.outlook.com; Mon, 14 Sep 2026 00:31:02 +0000
Authentication-Results: spf=fail dkim=none dmarc=fail
From: "Accounts Payable" <ap@acme-invoices.example>
To: j.rivera@contoso.com, external.partner@vendor.example
Delivered-To: j.rivera@contoso.com
Reply-To: ap.remit@mail.example
Subject: Updated remittance details - action required
Message-ID: <phish-0001@acme-invoices.example>
Date: Mon, 14 Sep 2026 00:31:00 +0000

Please update our bank details before the next run.
"""

NO_DELIVERY_HEADERS_EML = b"""\
From: "IT Helpdesk" <helpdesk@contos0.example>
To: external.partner@vendor.example, m.okafor@contoso.com
Subject: Mailbox storage exceeded
Message-ID: <phish-0002@contos0.example>

Verify your mailbox.
"""


def item_attachment(**kw):
    base = {"@odata.type": "#microsoft.graph.itemAttachment", "id": "ITEM1",
            "name": "Updated remittance details", "contentType": None, "size": 14000}
    base.update(kw)
    return base


def file_attachment(**kw):
    base = {"@odata.type": "#microsoft.graph.fileAttachment", "id": "FILE1",
            "name": "report.eml", "contentType": "message/rfc822", "size": 9000}
    base.update(kw)
    return base


class FakeClient:
    """Stands in for GraphClient; records calls and replays canned responses."""

    def __init__(self, attachments=None, item_value=None, wrapper=None, submit=None):
        self.attachments = attachments or []
        self.item_value = item_value
        self.wrapper = wrapper or b"wrapper-mime"
        self.submit_result = submit or {"id": "SUB-1", "status": "running"}
        self.calls = []
        self.submitted_bodies = []
        self.reject_source = False

    def paged(self, path, params=None, max_items=None):
        self.calls.append(("paged", path))
        return iter(self.attachments)

    def get(self, path, params=None, raw=False):
        self.calls.append(("get", path))
        if path.endswith("/$value") and "/attachments/" in path:
            return self.item_value
        if path.endswith("/$value"):
            return self.wrapper
        if "/attachments/" in path:
            return dict(self.attachments[0],
                        contentBytes=base64.b64encode(self.item_value or b"").decode())
        raise AssertionError("unexpected GET " + path)

    def post(self, path, body, **kw):
        self.calls.append(("post", path))
        if path.endswith("emailThreats"):
            self.submitted_bodies.append(body)
            if self.reject_source and "source" in body:
                raise gs.GraphError(
                    400,
                    json.dumps({"error": {"code": "BadRequest",
                                          "message": "The property 'source' is read-only."}}),
                    path,
                )
            return dict(self.submit_result)
        return {}

    def patch(self, path, body, **kw):
        self.calls.append(("patch", path))
        return {}


def make_args(**overrides):
    argv = ["--mailbox", "phish@contoso.com", "--org-domain", "contoso.com"]
    for key, value in overrides.pop("flags", {}).items():
        argv += [key, value] if value is not None else [key]
    args = gs.parse_args(argv)
    for key, value in overrides.items():
        setattr(args, key, value)
    return args


class TestClassifyAttachments(unittest.TestCase):
    def test_prefers_item_attachment_over_eml_file(self):
        candidates, unsupported = gs.classify_attachments(
            [file_attachment(), item_attachment()])
        self.assertEqual([c["kind"] for c in candidates], ["item", "file"])
        self.assertEqual(unsupported, [])

    def test_eml_file_attachment_by_extension(self):
        candidates, _ = gs.classify_attachments(
            [file_attachment(contentType="application/octet-stream", name="phish.eml")])
        self.assertEqual(candidates[0]["kind"], "file")

    def test_msg_attachment_is_unsupported_with_reason(self):
        candidates, unsupported = gs.classify_attachments(
            [file_attachment(name="phish.msg", contentType="application/octet-stream")])
        self.assertEqual(candidates, [])
        self.assertEqual(unsupported[0]["reason"], "outlook_msg_not_rfc822")

    def test_msg_detected_by_content_type_without_the_extension(self):
        _, unsupported = gs.classify_attachments(
            [file_attachment(name="attachment", contentType="application/vnd.ms-outlook")])
        self.assertEqual(unsupported[0]["reason"], "outlook_msg_not_rfc822")

    def test_inline_images_are_ignored_not_flagged(self):
        candidates, unsupported = gs.classify_attachments([
            file_attachment(id="IMG", name="logo.png", contentType="image/png", isInline=True),
            item_attachment(),
        ])
        self.assertEqual([c["kind"] for c in candidates], ["item"])
        self.assertEqual(unsupported, [])

    def test_pdf_is_reported_as_not_an_email(self):
        _, unsupported = gs.classify_attachments(
            [file_attachment(name="invoice.pdf", contentType="application/pdf")])
        self.assertEqual(unsupported[0]["reason"], "not_an_email_attachment")

    def test_larger_item_attachment_wins_a_tie(self):
        candidates, _ = gs.classify_attachments([
            item_attachment(id="SMALL", size=100),
            item_attachment(id="BIG", size=9999),
        ])
        self.assertEqual(candidates[0]["id"], "BIG")

    def test_empty_input(self):
        self.assertEqual(gs.classify_attachments(None), ([], []))


class TestInferRecipient(unittest.TestCase):
    def test_delivery_header_wins(self):
        addr, how = gs.infer_recipient(ORIGINAL_EML, fallback="reporter@contoso.com",
                                       org_domains=["contoso.com"])
        self.assertEqual(addr, "j.rivera@contoso.com")
        self.assertEqual(how, "header:Delivered-To")

    def test_org_domain_picked_out_of_to_list(self):
        addr, how = gs.infer_recipient(NO_DELIVERY_HEADERS_EML,
                                       fallback="reporter@contoso.com",
                                       org_domains=["contoso.com"])
        self.assertEqual(addr, "m.okafor@contoso.com")
        self.assertIn("org-domain", how)

    def test_without_org_domain_falls_back_to_first_recipient(self):
        addr, how = gs.infer_recipient(NO_DELIVERY_HEADERS_EML, org_domains=[])
        self.assertEqual(addr, "external.partner@vendor.example")
        self.assertEqual(how, "header:To/Cc")

    def test_reporter_used_when_headers_are_bare(self):
        addr, how = gs.infer_recipient(b"Subject: none\n\nbody",
                                       fallback="Reporter@Contoso.com")
        self.assertEqual(addr, "reporter@contoso.com")
        self.assertEqual(how, "reporter")

    def test_nothing_to_go_on(self):
        self.assertEqual(gs.infer_recipient(b"", None), (None, "unknown"))

    def test_shared_mailbox_many_reporters_one_real_recipient(self):
        """The forwarder is not the recipient, and on a shared queue they vary.

        Several people forwarding the same phish to the reporting mailbox must
        all produce the mailbox it was actually delivered to, not their own —
        Defender scopes the investigation by recipientEmailAddress, so getting
        this wrong investigates the reporter instead of the victim.
        """
        for reporter in ("a.patel@contoso.com", "b.hughes@contoso.com",
                         "c.lindqvist@contoso.com"):
            addr, how = gs.infer_recipient(ORIGINAL_EML, fallback=reporter,
                                           org_domains=["contoso.com"])
            self.assertEqual(addr, "j.rivera@contoso.com", reporter)
            self.assertEqual(how, "header:Delivered-To")

    def test_shared_mailbox_falls_back_to_the_individual_forwarder(self):
        """With no delivery header, each report falls back to its own sender."""
        bare = b"From: x@y.invalid\nSubject: s\n\nbody\n"
        for reporter in ("a.patel@contoso.com", "b.hughes@contoso.com"):
            addr, how = gs.infer_recipient(bare, fallback=reporter,
                                           org_domains=["contoso.com"])
            self.assertEqual(addr, reporter)
            self.assertEqual(how, "reporter")


class TestSummarizeEml(unittest.TestCase):
    def test_headers_only_no_body_leakage(self):
        summary = gs.summarize_eml(ORIGINAL_EML)
        self.assertEqual(summary["from_address"], "ap@acme-invoices.example")
        self.assertEqual(summary["message_id"], "<phish-0001@acme-invoices.example>")
        self.assertNotIn("bank details", json.dumps(summary))


class TestBuildSubmission(unittest.TestCase):
    def test_body_shape_and_roundtrip(self):
        body = gs.build_submission(ORIGINAL_EML, "j.rivera@contoso.com", source="user")
        self.assertEqual(body["@odata.type"],
                         "#microsoft.graph.security.emailContentThreatSubmission")
        self.assertEqual(body["category"], "phishing")
        self.assertEqual(body["source"], "user")
        self.assertEqual(base64.b64decode(body["fileContent"]), ORIGINAL_EML)

    def test_source_omitted_when_none(self):
        self.assertNotIn("source", gs.build_submission(ORIGINAL_EML, "a@b.example"))

    def test_rejects_missing_recipient_and_bad_enums(self):
        with self.assertRaises(ValueError):
            gs.build_submission(ORIGINAL_EML, None)
        with self.assertRaises(ValueError):
            gs.build_submission(ORIGINAL_EML, "a@b.example", category="suspicious")
        with self.assertRaises(ValueError):
            gs.build_submission(ORIGINAL_EML, "a@b.example", source="robot")


class TestNormalizeSince(unittest.TestCase):
    def test_durations(self):
        now = datetime.now(timezone.utc)
        parsed = datetime.strptime(gs.normalize_since("6h"), "%Y-%m-%dT%H:%M:%SZ")
        delta = now.replace(tzinfo=None) - parsed
        self.assertAlmostEqual(delta.total_seconds(), timedelta(hours=6).total_seconds(), delta=90)

    def test_iso_with_z_and_naive(self):
        self.assertEqual(gs.normalize_since("2026-09-14T00:42:00Z"), "2026-09-14T00:42:00Z")
        self.assertEqual(gs.normalize_since("2026-09-14T00:42:00"), "2026-09-14T00:42:00Z")

    def test_offset_is_converted_to_utc(self):
        self.assertEqual(gs.normalize_since("2026-09-14T02:42:00+02:00"), "2026-09-14T00:42:00Z")

    def test_garbage_is_rejected(self):
        with self.assertRaises(SystemExit):
            gs.normalize_since("last tuesday")


class TestStateStore(unittest.TestCase):
    def test_roundtrip_and_watermark(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "nested", "state.json")
            store = gs.StateStore(path)
            msg = {"id": "AAA", "internetMessageId": "<fwd-1@contoso.com>",
                   "receivedDateTime": "2026-09-14T01:00:00Z"}
            self.assertFalse(store.seen(msg))
            store.record(msg, {"status": "submitted", "submission_id": "SUB-9",
                               "original": {"message_id": "<phish-0001@acme-invoices.example>"}})
            store.save()

            reloaded = gs.StateStore(path)
            self.assertTrue(reloaded.seen(msg))
            self.assertEqual(reloaded.data["last_received"], "2026-09-14T01:00:00Z")
            self.assertTrue(reloaded.original_seen("<phish-0001@acme-invoices.example>"))

    def test_watermark_only_moves_forward(self):
        store = gs.StateStore()
        store.record({"id": "A", "receivedDateTime": "2026-09-14T05:00:00Z"}, {"status": "submitted"})
        store.record({"id": "B", "receivedDateTime": "2026-09-14T01:00:00Z"}, {"status": "submitted"})
        self.assertEqual(store.data["last_received"], "2026-09-14T05:00:00Z")

    def test_failed_submission_does_not_register_original(self):
        store = gs.StateStore()
        store.record({"id": "A"}, {"status": "error",
                                   "original": {"message_id": "<phish-0001@x.example>"}})
        self.assertFalse(store.original_seen("<phish-0001@x.example>"))

    def test_no_path_means_no_file_written(self):
        store = gs.StateStore()
        store.save()  # must not raise


class TestSubmitThreat(unittest.TestCase):
    def test_retries_without_source_when_tenant_rejects_it(self):
        client = FakeClient()
        client.reject_source = True
        response, warning = gs.submit_threat(
            client, gs.build_submission(ORIGINAL_EML, "a@b.example", source="user"))
        self.assertEqual(response["id"], "SUB-1")
        self.assertIn("source", warning)
        self.assertNotIn("source", client.submitted_bodies[-1])

    def test_other_400s_propagate(self):
        client = FakeClient()

        def boom(path, body, **kw):
            raise gs.GraphError(400, '{"error":{"code":"InvalidRecipient"}}', path)

        client.post = boom
        with self.assertRaises(gs.GraphError) as ctx:
            gs.submit_threat(client, gs.build_submission(ORIGINAL_EML, "a@b.example"))
        self.assertEqual(ctx.exception.code, "InvalidRecipient")


class TestProcessMessage(unittest.TestCase):
    def setUp(self):
        self.message = {
            "id": "AAMk-forward-1",
            "internetMessageId": "<fwd-1@contoso.com>",
            "receivedDateTime": "2026-09-14T01:00:00Z",
            "subject": "FW: Updated remittance details - action required",
            "hasAttachments": True,
            "isRead": False,
            "from": {"emailAddress": {"address": "j.rivera@contoso.com"}},
        }

    def test_submits_the_attached_original_not_the_forward(self):
        client = FakeClient(attachments=[item_attachment()], item_value=ORIGINAL_EML)
        result = gs.process_message(client, self.message, make_args(), gs.StateStore())
        self.assertEqual(result["status"], "submitted")
        self.assertEqual(result["submission_id"], "SUB-1")
        self.assertEqual(result["recipient"], "j.rivera@contoso.com")
        self.assertEqual(result["original"]["extracted_from"], "attachment:item")
        self.assertEqual(result["original"]["subject"],
                         "Updated remittance details - action required")
        self.assertEqual(base64.b64decode(client.submitted_bodies[0]["fileContent"]), ORIGINAL_EML)

    def test_skips_when_no_original_is_attached(self):
        self.message["hasAttachments"] = False
        client = FakeClient()
        result = gs.process_message(client, self.message, make_args(), gs.StateStore())
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["detail"], "no_original_attached")
        self.assertEqual(client.submitted_bodies, [])

    def test_allow_wrapper_submits_the_forward_itself(self):
        self.message["hasAttachments"] = False
        client = FakeClient(wrapper=ORIGINAL_EML)
        result = gs.process_message(
            client, self.message, make_args(allow_wrapper=True), gs.StateStore())
        self.assertEqual(result["status"], "submitted")
        self.assertEqual(result["original"]["extracted_from"], "wrapper")

    def test_dry_run_submits_nothing(self):
        client = FakeClient(attachments=[item_attachment()], item_value=ORIGINAL_EML)
        result = gs.process_message(
            client, self.message, make_args(dry_run=True), gs.StateStore())
        self.assertEqual(result["status"], "dry_run")
        self.assertEqual(client.submitted_bodies, [])

    def test_oversized_original_is_skipped_not_truncated(self):
        client = FakeClient(attachments=[item_attachment()], item_value=b"x" * 5000)
        result = gs.process_message(
            client, self.message, make_args(max_eml_bytes=1000), gs.StateStore())
        self.assertEqual(result["status"], "skipped")
        self.assertTrue(result["detail"].startswith("too_large:"))
        self.assertEqual(client.submitted_bodies, [])

    def test_dedupe_original_skips_a_second_reporter(self):
        state = gs.StateStore()
        state.data["originals"]["<phish-0001@acme-invoices.example>"] = "SUB-EARLIER"
        client = FakeClient(attachments=[item_attachment()], item_value=ORIGINAL_EML)
        result = gs.process_message(
            client, self.message, make_args(dedupe_original=True), state)
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["submission_id"], "SUB-EARLIER")
        self.assertEqual(client.submitted_bodies, [])

    def test_unsupported_msg_attachment_is_surfaced(self):
        client = FakeClient(attachments=[file_attachment(name="phish.msg",
                                                         contentType="application/octet-stream")])
        result = gs.process_message(client, self.message, make_args(), gs.StateStore())
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["unsupported_attachments"][0]["reason"],
                         "outlook_msg_not_rfc822")

    def test_housekeeping_failure_does_not_lose_the_submission(self):
        client = FakeClient(attachments=[item_attachment()], item_value=ORIGINAL_EML)

        def boom(path, body, **kw):
            raise gs.GraphError(403, '{"error":{"code":"ErrorAccessDenied"}}', path)

        client.patch = boom
        result = gs.process_message(
            client, self.message, make_args(mark_read=True), gs.StateStore())
        self.assertEqual(result["status"], "submitted")
        self.assertEqual(result["submission_id"], "SUB-1")
        self.assertIn("housekeeping failed", result["detail"])


class TestRun(unittest.TestCase):
    def test_already_processed_messages_are_not_resubmitted(self):
        message = {"id": "AAMk-1", "internetMessageId": "<fwd-1@contoso.com>",
                   "receivedDateTime": "2026-09-14T01:00:00Z", "hasAttachments": True,
                   "from": {"emailAddress": {"address": "j.rivera@contoso.com"}}}

        class ListingClient(FakeClient):
            def paged(self, path, params=None, max_items=None):
                if "mailFolders" in path:
                    return iter([message])
                return iter(self.attachments)

        client = ListingClient(attachments=[item_attachment()], item_value=ORIGINAL_EML)
        state = gs.StateStore()
        args = make_args()

        first = gs.run(client, args, state)
        second = gs.run(client, args, state)
        self.assertEqual(gs.summarize(first), {"submitted": 1})
        self.assertEqual(second, [])
        self.assertEqual(len(client.submitted_bodies), 1)

    def test_graph_error_on_one_message_does_not_abort_the_run(self):
        messages = [
            {"id": "BAD", "internetMessageId": "<a@x>", "receivedDateTime": "2026-09-14T01:00:00Z",
             "hasAttachments": True, "from": {"emailAddress": {"address": "a@contoso.com"}}},
            {"id": "GOOD", "internetMessageId": "<b@x>", "receivedDateTime": "2026-09-14T02:00:00Z",
             "hasAttachments": True, "from": {"emailAddress": {"address": "b@contoso.com"}}},
        ]

        class FlakyClient(FakeClient):
            def paged(self, path, params=None, max_items=None):
                if "mailFolders" in path:
                    return iter(messages)
                if "/messages/BAD/" in path:
                    raise gs.GraphError(503, '{"error":{"code":"ServiceUnavailable"}}', path)
                return iter(self.attachments)

        client = FlakyClient(attachments=[item_attachment()], item_value=ORIGINAL_EML)
        results = gs.run(client, make_args(), gs.StateStore())
        self.assertEqual(gs.summarize(results), {"error": 1, "submitted": 1})


class ScopeClient:
    """Answers mailbox probes from a canned {address: status} map."""

    def __init__(self, statuses):
        self.statuses = statuses
        self.probed = []

    def paged(self, path, params=None, max_items=None):
        return iter([])  # an empty queue, so a run that gets this far exits cleanly

    def get(self, path, params=None, raw=False):
        address = path.split("users/")[1].split("/")[0]
        address = address.replace("%40", "@")
        self.probed.append(address)
        status = self.statuses.get(address, 404)
        if status == 200:
            return {"value": [{"id": "X"}]}
        codes = {403: "ErrorAccessDenied", 404: "ResourceNotFound",
                 401: "InvalidAuthenticationToken", 500: "InternalServerError"}
        raise gs.GraphError(status, json.dumps({"error": {"code": codes.get(status, "Unknown")}}),
                            path)


class TestClassifyProbe(unittest.TestCase):
    def test_mapping(self):
        self.assertEqual(gs.classify_probe(200), "readable")
        self.assertEqual(gs.classify_probe(403), "denied")
        self.assertEqual(gs.classify_probe(404), "not_found")
        self.assertEqual(gs.classify_probe(401), "unauthorized")
        self.assertEqual(gs.classify_probe(500), "error")


class TestVerifyScope(unittest.TestCase):
    TARGET = "phish@contoso.com"
    EXEC = "ceo@contoso.com"

    def test_properly_scoped_app_passes(self):
        client = ScopeClient({self.TARGET: 200, self.EXEC: 403})
        report = gs.verify_scope(client, self.TARGET, [self.EXEC])
        self.assertEqual(report["verdict"], "scoped")

    def test_over_scoped_app_is_caught(self):
        client = ScopeClient({self.TARGET: 200, self.EXEC: 200})
        report = gs.verify_scope(client, self.TARGET, [self.EXEC])
        self.assertEqual(report["verdict"], "over_scoped")
        self.assertIn(self.EXEC, report["detail"])

    def test_404_is_not_accepted_as_proof_of_scoping(self):
        # A mailbox that does not exist is denied for the wrong reason; treating
        # that as proof would hide a genuinely tenant-wide app.
        client = ScopeClient({self.TARGET: 200, "typo@contoso.com": 404})
        report = gs.verify_scope(client, self.TARGET, ["typo@contoso.com"])
        self.assertEqual(report["verdict"], "inconclusive")

    def test_one_readable_among_many_still_fails(self):
        client = ScopeClient({self.TARGET: 200, self.EXEC: 403, "cfo@contoso.com": 200})
        report = gs.verify_scope(client, self.TARGET, [self.EXEC, "cfo@contoso.com"])
        self.assertEqual(report["verdict"], "over_scoped")
        self.assertIn("cfo@contoso.com", report["detail"])
        self.assertNotIn(self.EXEC, report["detail"])

    def test_unreadable_target_reported_before_anything_else(self):
        client = ScopeClient({self.TARGET: 403})
        report = gs.verify_scope(client, self.TARGET, [self.EXEC])
        self.assertEqual(report["verdict"], "target_unreadable")
        self.assertEqual(client.probed, [self.TARGET])  # no pointless control probes

    def test_no_controls_means_unverified_not_verified(self):
        client = ScopeClient({self.TARGET: 200})
        report = gs.verify_scope(client, self.TARGET, [])
        self.assertEqual(report["verdict"], "unchecked")


class TestScopeGateExitCodes(unittest.TestCase):
    """--check-scope is a deployment gate: only a proven-restricted app exits 0."""

    def _main(self, statuses, argv):
        client = ScopeClient(statuses)
        orig = gs.GraphClient
        gs.GraphClient = lambda **kw: client
        try:
            return gs.main(argv)
        finally:
            gs.GraphClient = orig

    def test_gate_passes_only_when_scoped(self):
        code = self._main({"phish@contoso.com": 200, "ceo@contoso.com": 403},
                          ["--mailbox", "phish@contoso.com", "--check-scope",
                           "--deny-check", "ceo@contoso.com"])
        self.assertEqual(code, 0)

    def test_gate_fails_on_over_scope(self):
        code = self._main({"phish@contoso.com": 200, "ceo@contoso.com": 200},
                          ["--mailbox", "phish@contoso.com", "--check-scope",
                           "--deny-check", "ceo@contoso.com"])
        self.assertEqual(code, 3)

    def test_gate_fails_when_nothing_was_verified(self):
        code = self._main({"phish@contoso.com": 200},
                          ["--mailbox", "phish@contoso.com", "--check-scope"])
        self.assertEqual(code, 3)

    def test_run_aborts_before_reading_any_mail_when_over_scoped(self):
        code = self._main({"phish@contoso.com": 200, "ceo@contoso.com": 200},
                          ["--mailbox", "phish@contoso.com",
                           "--deny-check", "ceo@contoso.com"])
        self.assertEqual(code, 3)

    def test_override_is_explicit(self):
        # --allow-broad-access lets the same over-scoped app proceed to the run.
        code = self._main({"phish@contoso.com": 200, "ceo@contoso.com": 200},
                          ["--mailbox", "phish@contoso.com",
                           "--deny-check", "ceo@contoso.com", "--allow-broad-access"])
        self.assertEqual(code, 0)


class TestMailboxDataMinimisation(unittest.TestCase):
    """What leaves the shared mailbox, and nothing more.

    Users forward suspected phishing to this shared mailbox, so it fills up with
    other people's mail and whatever they typed above it. The only justification
    for reading it is to hand the original message to Defender as if the Report
    button had been used, so the field list is a deliberate contract rather than
    a convenience. These tests fail if it grows, which is the point: widening it
    should require a person to say why.
    """

    ALLOWED = {"id", "internetMessageId", "receivedDateTime", "subject",
               "hasAttachments", "from", "sender", "isRead"}

    def test_select_is_exactly_the_documented_set(self):
        self.assertEqual(set(gs.MESSAGE_SELECT.split(",")), self.ALLOWED)
        self.assertEqual(set(gs.MAILBOX_FIELDS), self.ALLOWED)

    def test_every_requested_field_has_a_stated_reason(self):
        for field, reason in gs.MAILBOX_FIELDS.items():
            self.assertTrue(reason and len(reason) > 15,
                            f"{field} is requested without a real justification")

    def test_no_body_content_is_requested(self):
        # bodyPreview is the reporter's own words; body is the whole message.
        # Neither is needed to submit the attached original, so neither is asked for.
        for field in ("body", "bodyPreview", "uniqueBody", "toRecipients",
                      "ccRecipients", "bccRecipients", "flag", "categories"):
            self.assertNotIn(field, gs.MESSAGE_SELECT,
                             f"{field} is being read without a need for it")

    def test_the_run_reads_no_field_outside_the_contract(self):
        """Prove it against a real run, not just the constant."""
        seen = {}

        class RecordingMessage(dict):
            def get(self, key, default=None):
                seen[key] = seen.get(key, 0) + 1
                return dict.get(self, key, default)

        message = RecordingMessage({
            "id": "AAMk-1", "internetMessageId": "<fwd@contoso.com>",
            "receivedDateTime": "2026-09-14T01:00:00Z", "subject": "FW: phish",
            "hasAttachments": True, "isRead": False,
            "from": {"emailAddress": {"address": "a.patel@contoso.com"}},
        })
        client = FakeClient(attachments=[item_attachment()], item_value=ORIGINAL_EML)
        gs.process_message(client, message, make_args(), gs.StateStore())

        extra = {k for k in seen if k not in self.ALLOWED}
        self.assertEqual(extra, set(), f"run touched undeclared field(s): {extra}")

    def test_body_preview_is_read_only_when_opted_into(self):
        """The one field that is allowed in, and only on request."""
        self.assertNotIn("bodyPreview", gs.message_select())
        self.assertIn("bodyPreview", gs.message_select(capture_note=True))
        # Opting in widens the request by exactly that one field, nothing else.
        self.assertEqual(set(gs.message_select(True).split(","))
                         - set(gs.message_select().split(",")),
                         {"bodyPreview"})
        self.assertNotIn("body,", gs.message_select(True) + ",")
        self.assertNotIn("uniqueBody", gs.message_select(True))

    def test_note_is_captured_and_keyed_by_the_original_message_id(self):
        client = FakeClient(attachments=[item_attachment()], item_value=ORIGINAL_EML)
        message = {"id": "AAMk-1", "internetMessageId": "<fwd@contoso.com>",
                   "receivedDateTime": "2026-09-14T01:00:00Z", "hasAttachments": True,
                   "bodyPreview": "I clicked it and entered my password",
                   "from": {"emailAddress": {"address": "a.patel@contoso.com"}}}
        state = gs.StateStore()
        result = gs.process_message(client, message, make_args(capture_reporter_note=True),
                                    state)
        state.record(message, result)
        self.assertEqual(result["reporter_note"], "I clicked it and entered my password")
        # Keyed by the original, which is what the export joins on -- not the forward.
        entry = state.data["notes"]["<phish-0001@acme-invoices.example>"]
        self.assertEqual(entry["note"], "I clicked it and entered my password")
        self.assertEqual(entry["reporter"], "a.patel@contoso.com")

    def test_no_note_is_captured_or_stored_by_default(self):
        client = FakeClient(attachments=[item_attachment()], item_value=ORIGINAL_EML)
        message = {"id": "AAMk-1", "internetMessageId": "<fwd@contoso.com>",
                   "receivedDateTime": "2026-09-14T01:00:00Z", "hasAttachments": True,
                   "bodyPreview": "I clicked it and entered my password",
                   "from": {"emailAddress": {"address": "a.patel@contoso.com"}}}
        state = gs.StateStore()
        result = gs.process_message(client, message, make_args(), state)
        state.record(message, result)
        self.assertNotIn("reporter_note", result)
        self.assertEqual(state.data["notes"], {})

    def test_only_the_attached_original_is_fetched_not_the_wrapper(self):
        """The forward itself is the reporter's mail; we submit the phish, not it."""
        client = FakeClient(attachments=[item_attachment()], item_value=ORIGINAL_EML)
        message = {"id": "AAMk-1", "internetMessageId": "<fwd@contoso.com>",
                   "receivedDateTime": "2026-09-14T01:00:00Z", "hasAttachments": True,
                   "from": {"emailAddress": {"address": "a.patel@contoso.com"}}}
        gs.process_message(client, message, make_args(), gs.StateStore())
        wrapper_reads = [p for _, p in client.calls
                         if p.endswith("/$value") and "/attachments/" not in p]
        self.assertEqual(wrapper_reads, [],
                         "the reporter's own forward was downloaded unnecessarily")
        self.assertEqual(base64.b64decode(client.submitted_bodies[0]["fileContent"]),
                         ORIGINAL_EML)


class TestRetryDelay(unittest.TestCase):
    class _Exc:
        def __init__(self, retry_after):
            self.headers = {"Retry-After": retry_after} if retry_after else {}

    def test_honours_retry_after(self):
        self.assertEqual(gs.GraphClient._retry_delay(self._Exc("12"), 0), 12.0)

    def test_caps_absurd_retry_after(self):
        self.assertEqual(gs.GraphClient._retry_delay(self._Exc("99999"), 0), 120.0)

    def test_falls_back_to_backoff(self):
        delay = gs.GraphClient._retry_delay(self._Exc(None), 3)
        self.assertGreaterEqual(delay, 8.0)
        self.assertLess(delay, 10.0)


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# The skipped-report worklist
# ---------------------------------------------------------------------------

class TestWorklistClassification(unittest.TestCase):
    """Which skips mean a person still has to act, and which do not."""

    def test_a_forward_with_no_original_needs_a_person(self):
        self.assertEqual(
            gs.worklist_reason({"status": "skipped", "detail": "no_original_attached"}),
            "no_original_attached")

    def test_too_large_matches_despite_its_byte_suffix(self):
        """The detail carries the size, so the match is on the prefix."""
        self.assertEqual(
            gs.worklist_reason({"status": "skipped", "detail": "too_large:8388608_bytes"}),
            "too_large")

    def test_an_unresolved_recipient_needs_a_person(self):
        self.assertEqual(
            gs.worklist_reason({"status": "skipped", "detail": "no_recipient_resolved"}),
            "no_recipient_resolved")

    def test_a_graph_error_needs_a_person(self):
        self.assertEqual(gs.worklist_reason({"status": "error", "detail": "500"}), "error")

    def test_a_successful_dedupe_is_not_a_worklist_item(self):
        """The deduplicator working is not manual work. Listing it would bury the
        real remainder in noise, which is the whole failure this list prevents."""
        self.assertIsNone(gs.worklist_reason(
            {"status": "skipped", "detail": "original_already_submitted"}))

    def test_a_submitted_report_is_not_a_worklist_item(self):
        self.assertIsNone(gs.worklist_reason({"status": "submitted"}))

    def test_a_dry_run_is_not_a_worklist_item(self):
        """--dry-run reaching 'would submit' is evidence the report is fine."""
        self.assertIsNone(gs.worklist_reason({"status": "dry_run", "detail": "would submit"}))

    def test_an_unrecognised_skip_is_not_silently_bucketed(self):
        self.assertIsNone(gs.worklist_reason({"status": "skipped", "detail": "something_new"}))

    def test_every_reason_carries_a_summary_and_a_fix(self):
        """An entry that cannot tell you what to do about it is just a log line."""
        for reason, pair in gs.WORKLIST_REASONS.items():
            summary, fix = pair
            self.assertTrue(summary.strip(), reason)
            self.assertTrue(len(fix.strip()) > 40, f"{reason}: no actionable fix")


class TestWorklistStore(unittest.TestCase):

    def path(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            fh.write("{}")
        self.addCleanup(os.unlink, fh.name)
        return fh.name

    def skip_result(self, key="phish-1@x", detail="no_original_attached", **kw):
        result = {
            "internet_message_id": key,
            "mailbox_message_id": "AAMk" + key,
            "status": "skipped",
            "detail": detail,
            "reporter": "a.patel@contoso.com",
            "received": "2026-09-14T04:01:00Z",
        }
        result.update(kw)
        return result

    def test_a_skip_is_recorded(self):
        wl = gs.Worklist(self.path())
        self.assertEqual(wl.record(self.skip_result(), {"subject": "Odd mail"}), "recorded")
        self.assertEqual(len(wl.data["open"]), 1)
        entry = wl.data["open"]["phish-1@x"]
        self.assertEqual(entry["reason"], "no_original_attached")
        self.assertEqual(entry["subject"], "Odd mail")

    def test_seeing_it_again_counts_rather_than_duplicating(self):
        wl = gs.Worklist(self.path())
        wl.record(self.skip_result(), {"subject": "Odd mail"})
        wl.record(self.skip_result(), {"subject": "Odd mail"})
        self.assertEqual(len(wl.data["open"]), 1)
        self.assertEqual(wl.data["open"]["phish-1@x"]["times_seen"], 2)

    def test_first_seen_survives_a_later_sighting(self):
        """How long something has been stuck is the reason to go fix it."""
        wl = gs.Worklist(self.path())
        wl.record(self.skip_result(), {})
        first = wl.data["open"]["phish-1@x"]["first_seen"]
        wl.record(self.skip_result(), {})
        self.assertEqual(wl.data["open"]["phish-1@x"]["first_seen"], first)

    def test_a_later_submission_clears_the_entry(self):
        """This is what makes --retry-skipped worth running."""
        wl = gs.Worklist(self.path())
        wl.record(self.skip_result(), {})
        outcome = wl.record({"internet_message_id": "phish-1@x", "status": "submitted"}, {})
        self.assertEqual(outcome, "resolved")
        self.assertEqual(wl.data["open"], {})
        self.assertEqual(wl.data["resolved_total"], 1)

    def test_a_submission_for_something_never_stuck_changes_nothing(self):
        wl = gs.Worklist(self.path())
        self.assertIsNone(wl.record({"internet_message_id": "other@x", "status": "submitted"}, {}))
        self.assertEqual(wl.data["resolved_total"], 0)

    def test_resolving_by_hand_clears_one_entry(self):
        wl = gs.Worklist(self.path())
        wl.record(self.skip_result(), {})
        self.assertTrue(wl.resolve("phish-1@x"))
        self.assertFalse(wl.resolve("phish-1@x"))
        self.assertEqual(wl.data["open"], {})

    def test_a_result_with_no_id_is_not_recorded_under_an_empty_key(self):
        wl = gs.Worklist(self.path())
        self.assertIsNone(wl.record({"status": "skipped", "detail": "no_original_attached"}, {}))
        self.assertEqual(wl.data["open"], {})

    def test_it_round_trips_through_the_file(self):
        path = self.path()
        wl = gs.Worklist(path)
        wl.record(self.skip_result(), {"subject": "Odd mail"})
        wl.save()
        reloaded = gs.Worklist(path)
        self.assertEqual(len(reloaded.data["open"]), 1)
        self.assertEqual(reloaded.data["open"]["phish-1@x"]["subject"], "Odd mail")

    def test_is_open_matches_the_message_as_graph_returns_it(self):
        """run() tests a Graph message, not a result, so the key must line up or
        --retry-skipped silently retries nothing."""
        wl = gs.Worklist(self.path())
        wl.record(self.skip_result(), {})
        self.assertTrue(wl.is_open({"internetMessageId": "phish-1@x", "id": "AAMk"}))
        self.assertFalse(wl.is_open({"internetMessageId": "other@x", "id": "AAMk"}))

    def test_is_open_falls_back_to_the_mailbox_id(self):
        wl = gs.Worklist(self.path())
        wl.record({"mailbox_message_id": "AAMkOnly", "status": "skipped",
                   "detail": "no_original_attached"}, {})
        self.assertTrue(wl.is_open({"id": "AAMkOnly"}))

    def test_attachment_kinds_are_counted_across_entries(self):
        """The number that says whether the remainder is one fixable format."""
        wl = gs.Worklist(self.path())
        wl.record(self.skip_result("a@x", unsupported_attachments=[
            {"name": "phish.msg", "reason": "outlook_msg_not_rfc822"}]), {})
        wl.record(self.skip_result("b@x", unsupported_attachments=[
            {"name": "other.msg", "reason": "outlook_msg_not_rfc822"},
            {"name": "shot.png", "reason": "not_an_email_attachment"}]), {})
        self.assertEqual(wl.attachment_kinds(),
                         {"outlook_msg_not_rfc822": 2, "not_an_email_attachment": 1})


class TestWorklistReport(unittest.TestCase):

    def path(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            fh.write("{}")
        self.addCleanup(os.unlink, fh.name)
        return fh.name

    def test_an_empty_worklist_says_so_plainly(self):
        self.assertIn("Nothing outstanding", gs.Worklist(self.path()).render())

    def test_the_report_groups_by_reason_and_names_the_fix(self):
        wl = gs.Worklist(self.path())
        wl.record({"internet_message_id": "a@x", "status": "skipped",
                   "detail": "too_large:9000000_bytes", "reporter": "u@contoso.com",
                   "received": "2026-09-14T04:01:00Z"}, {"subject": "Big one"})
        report = wl.render()
        self.assertIn("1 report(s) open", report)
        self.assertIn("too_large", report)
        self.assertIn("--max-eml-bytes", report, "the report must say how to clear it")
        self.assertIn("Big one", report)

    def test_msg_attachments_get_an_explanation_not_just_a_count(self):
        wl = gs.Worklist(self.path())
        wl.record({"internet_message_id": "a@x", "status": "skipped",
                   "detail": "no_original_attached",
                   "unsupported_attachments": [{"reason": "outlook_msg_not_rfc822"}]}, {})
        report = wl.render()
        self.assertIn("outlook_msg_not_rfc822", report)
        self.assertIn("dragged", report, "say why .msg happens, not just that it did")

    def test_a_pipe_in_a_subject_cannot_break_the_table(self):
        """Subjects are attacker-controlled; an unescaped pipe would corrupt the row."""
        wl = gs.Worklist(self.path())
        wl.record({"internet_message_id": "a@x", "status": "skipped",
                   "detail": "no_original_attached"}, {"subject": "pay | now"})
        row = [ln for ln in wl.render().splitlines() if "pay" in ln][0]
        self.assertIn("\\|", row)

    def test_the_report_is_plain_text_a_person_can_act_on(self):
        wl = gs.Worklist(self.path())
        wl.record({"internet_message_id": "a@x", "status": "skipped",
                   "detail": "no_recipient_resolved"}, {"subject": "s"})
        report = wl.render()
        self.assertIn("--worklist-resolve", report)
        self.assertIn("--retry-skipped", report)


class TestWorklistCli(unittest.TestCase):
    """The offline modes must work with no credentials and no network."""

    SCRIPT = os.path.join(SCRIPT_DIR, "graph_submit.py")

    def worklist_file(self, payload):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                         encoding="utf-8") as fh:
            json.dump(payload, fh)
        self.addCleanup(os.unlink, fh.name)
        return fh.name

    def run_script(self, *args):
        env = dict(os.environ)
        for var in ("GRAPH_TENANT_ID", "GRAPH_CLIENT_ID", "GRAPH_CLIENT_SECRET",
                    "GRAPH_ACCESS_TOKEN"):
            env.pop(var, None)
        return subprocess.run([sys.executable, self.SCRIPT] + list(args),
                              capture_output=True, text=True, env=env)

    def test_report_runs_with_no_credentials_at_all(self):
        """An analyst reading the list must not need the app's secret."""
        path = self.worklist_file({"open": {"a@x": {
            "reason": "no_original_attached", "subject": "Odd mail",
            "reporter": "u@contoso.com", "received": "2026-09-14T04:01:00Z",
            "times_seen": 2}}, "resolved_total": 0})
        proc = self.run_script("--mailbox", "p@example.invalid",
                               "--worklist", path, "--worklist-report")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Odd mail", proc.stdout)
        self.assertNotIn("no usable credentials", proc.stderr)

    def test_resolve_clears_the_entry_on_disk(self):
        path = self.worklist_file({"open": {"a@x": {"reason": "no_original_attached"}},
                                   "resolved_total": 0})
        proc = self.run_script("--mailbox", "p@example.invalid",
                               "--worklist", path, "--worklist-resolve", "a@x")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with open(path, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["open"], {})

    def test_resolving_something_absent_reports_rather_than_pretending(self):
        path = self.worklist_file({"open": {}, "resolved_total": 0})
        proc = self.run_script("--mailbox", "p@example.invalid",
                               "--worklist", path, "--worklist-resolve", "nope@x")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("not on the worklist", proc.stderr)

    def test_the_report_mode_needs_a_worklist_path(self):
        proc = self.run_script("--mailbox", "p@example.invalid", "--worklist-report")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("--worklist", proc.stderr)

    def test_retry_skipped_without_a_worklist_is_refused(self):
        """It would otherwise look like it was retrying and silently retry nothing."""
        proc = self.run_script("--mailbox", "p@example.invalid", "--retry-skipped")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("--retry-skipped needs --worklist", proc.stderr)


class TestWorklistThroughARun(unittest.TestCase):
    """The wiring, not the pieces: a run has to populate, retry and resolve."""

    MESSAGE = {"id": "AAMk-1", "internetMessageId": "<fwd-1@contoso.com>",
               "receivedDateTime": "2026-09-14T01:00:00Z", "hasAttachments": True,
               "subject": "Is this real?",
               "from": {"emailAddress": {"address": "j.rivera@contoso.com"}}}

    def client_for(self, attachments):
        message = self.MESSAGE

        class ListingClient(FakeClient):
            def paged(self, path, params=None, max_items=None):
                if "mailFolders" in path:
                    return iter([message])
                return iter(self.attachments)

        return ListingClient(attachments=attachments, item_value=ORIGINAL_EML)

    def test_a_msg_only_forward_lands_on_the_worklist_with_its_reason(self):
        """The case that matters: Outlook drag-and-drop produces a .msg, which the
        extractor cannot read, so the report is skipped and a person must act."""
        client = self.client_for([file_attachment(
            name="phish.msg", contentType="application/octet-stream")])
        worklist = gs.Worklist()
        results = gs.run(client, make_args(), gs.StateStore(), worklist)

        self.assertEqual(gs.summarize(results), {"skipped": 1})
        self.assertEqual(len(worklist.data["open"]), 1)
        entry = worklist.data["open"]["<fwd-1@contoso.com>"]
        self.assertEqual(entry["reason"], "no_original_attached")
        self.assertEqual(entry["subject"], "Is this real?")
        self.assertEqual(entry["reporter"], "j.rivera@contoso.com")
        self.assertEqual(worklist.attachment_kinds(), {"outlook_msg_not_rfc822": 1})
        self.assertEqual(client.submitted_bodies, [], "nothing should have been sent")

    def test_a_clean_forward_never_reaches_the_worklist(self):
        client = self.client_for([item_attachment()])
        worklist = gs.Worklist()
        gs.run(client, make_args(), gs.StateStore(), worklist)
        self.assertEqual(worklist.data["open"], {})

    def test_without_retry_skipped_a_stuck_report_is_never_revisited(self):
        """State records skips as processed, so the second run does not look at it.
        This is the behaviour --retry-skipped exists to override; pinning it here
        stops the retry path being quietly pointless."""
        client = self.client_for([file_attachment(
            name="phish.msg", contentType="application/octet-stream")])
        state, worklist = gs.StateStore(), gs.Worklist()
        gs.run(client, make_args(), state, worklist)
        second = gs.run(client, make_args(), state, worklist)
        self.assertEqual(second, [])
        self.assertEqual(worklist.data["open"]["<fwd-1@contoso.com>"]["times_seen"], 1)

    def test_retry_skipped_reprocesses_and_resolves_once_the_cause_is_fixed(self):
        """Raise the limit, rerun, and the entry clears itself. Without this the
        worklist would be a list nothing could ever take an item off."""
        state, worklist = gs.StateStore(), gs.Worklist()

        stuck = self.client_for([item_attachment()])
        tiny = make_args(max_eml_bytes=10)          # forces too_large
        gs.run(stuck, tiny, state, worklist)
        self.assertEqual(worklist.data["open"]["<fwd-1@contoso.com>"]["reason"], "too_large")

        fixed = self.client_for([item_attachment()])
        retry = make_args(retry_skipped=True)       # default limit, plus the retry
        results = gs.run(fixed, retry, state, worklist)

        self.assertEqual(gs.summarize(results), {"submitted": 1})
        self.assertEqual(worklist.data["open"], {}, "the entry should have cleared")
        self.assertEqual(worklist.data["resolved_total"], 1)

    def test_retry_skipped_only_reopens_what_is_on_the_worklist(self):
        """A successfully submitted message must not be resubmitted by a retry run."""
        state, worklist = gs.StateStore(), gs.Worklist()
        gs.run(self.client_for([item_attachment()]), make_args(), state, worklist)
        client = self.client_for([item_attachment()])
        second = gs.run(client, make_args(retry_skipped=True), state, worklist)
        self.assertEqual(second, [])
        self.assertEqual(client.submitted_bodies, [])

    def test_a_dry_run_populates_the_worklist_without_sending_anything(self):
        """The measurement run: --dry-run --json against a real mailbox is how you
        find out what the manual remainder is, before changing anything."""
        client = self.client_for([file_attachment(
            name="phish.msg", contentType="application/octet-stream")])
        worklist = gs.Worklist()
        gs.run(client, make_args(dry_run=True), gs.StateStore(), worklist)
        self.assertEqual(len(worklist.data["open"]), 1)
        self.assertEqual(client.submitted_bodies, [])
