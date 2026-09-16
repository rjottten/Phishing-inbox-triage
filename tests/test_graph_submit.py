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
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

# The skill bundle lives under skills/ so it can be zipped and shipped on its own;
# graph_submit.py is a standalone script inside it, not an importable package.
sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "skills", "phishing-inbox-triage", "scripts",
))

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
