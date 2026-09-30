#!/usr/bin/env python3
"""Offline tests for the Azure Functions wrapper (azure-function/runner.py).

The scripts run for real, through their own main(); only the edges are
replaced: Graph by a stub GraphClient, Blob storage by a dict, and the
managed-identity token by a function. No Azure SDK is needed to run these.

Run: python -m unittest discover -s tests
"""
import json
import logging
import os
import re
import sys
import unittest
from datetime import datetime, timezone
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "azure-function"))

import runner  # noqa: E402

gs = runner.graph_submit

# The wrapper logs every script line; keep the test output readable.
logging.getLogger("phish_triage").addHandler(logging.NullHandler())

ORIGINAL_EML = b"""\
From: "Accounts Payable" <ap@acme-invoices.example>
To: j.rivera@contoso.com
Delivered-To: j.rivera@contoso.com
Subject: Updated remittance details
Message-ID: <phish-0001@acme-invoices.example>
Date: Mon, 14 Sep 2026 00:31:00 +0000

Please update our bank details.
"""

BASE_ENV = {
    "PHISH_MAILBOX": "phish@contoso.com",
    "PHISH_ORG_DOMAINS": "contoso.com",
    "PHISH_DENY_CHECK": "ceo@contoso.com",
}

NOW = datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc)


class FakeStore:
    """Blob container as a dict, with the same ETag semantics as BlobStore."""

    def __init__(self, blobs=None):
        self.blobs = {}
        self.writes = []
        for name, data in (blobs or {}).items():
            self.blobs[name] = (data, "etag-0")

    def read(self, name):
        return self.blobs.get(name, (None, None))

    def write(self, name, data, etag=None, expect_absent=False, content_type=None):
        current = self.blobs.get(name)
        if etag and (current is None or current[1] != etag):
            raise runner.StateConflict(name)
        if expect_absent and current is not None:
            raise runner.StateConflict(name)
        self.writes.append(name)
        self.blobs[name] = (data, "etag-%d" % len(self.writes))

    def json(self, name):
        return json.loads(self.blobs[name][0].decode("utf-8"))


class FakeGraph(gs.GraphClient):
    """Answers the calls graph_submit / collect_export make. Records them."""

    readable = {"phish@contoso.com"}
    messages = []
    submissions = []
    calls = []
    tokens_seen = []

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        FakeGraph.tokens_seen.append(kwargs.get("access_token"))

    def request(self, method, path, *, params=None, body=None, raw=False, headers=None):
        FakeGraph.calls.append((method, path))
        if path.startswith("users/"):
            mailbox = path.split("/")[1].replace("%40", "@")
            if mailbox not in FakeGraph.readable:
                raise gs.GraphError(403, '{"error":{"code":"ErrorAccessDenied"}}', path)
        if method == "GET" and path.endswith("/messages") and params and "$filter" not in params:
            return {"value": [{"id": "probe"}]}                     # scope probe
        if method == "GET" and "/mailFolders/" in path:
            return {"value": FakeGraph.messages}
        if method == "GET" and path.endswith("/attachments"):
            return {"value": [{"@odata.type": "#microsoft.graph.itemAttachment",
                               "id": "att1", "name": "original", "size": 900}]}
        if method == "GET" and path.endswith("/$value"):
            return ORIGINAL_EML
        if method == "POST" and path == "security/threatSubmission/emailThreats":
            return {"id": "sub-%d" % len(FakeGraph.calls), "status": "notStarted"}
        if method == "GET" and path == "security/threatSubmission/emailThreats":
            return {"value": FakeGraph.submissions}
        if method == "POST" and path == "security/runHuntingQuery":
            return {"results": []}
        raise AssertionError("unexpected Graph call %s %s" % (method, path))


def forwarded(n=1):
    return [{"id": "m%d" % i, "internetMessageId": "<fwd-%d@contoso.com>" % i,
             "receivedDateTime": "2026-09-28T10:0%d:00Z" % i, "subject": "FW: remittance",
             "hasAttachments": True, "isRead": False,
             "from": {"emailAddress": {"address": "j.rivera@contoso.com"}}}
            for i in range(n)]


class WrapperTestCase(unittest.TestCase):
    def setUp(self):
        FakeGraph.readable = {"phish@contoso.com"}
        FakeGraph.messages = forwarded(1)
        FakeGraph.submissions = []
        FakeGraph.calls = []
        FakeGraph.tokens_seen = []
        patcher = mock.patch.object(gs, "GraphClient", FakeGraph)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.token_requests = []

    def token(self, client_id):
        self.token_requests.append(client_id)
        return "mi-token"

    def env(self, **extra):
        env = dict(BASE_ENV)
        env.update(extra)
        patcher = mock.patch.dict(os.environ, env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        return os.environ

    def submit(self, store, **extra):
        self.env(**extra)
        return runner.run_submit(store=store, token_provider=self.token, now=NOW)


# --------------------------------------------------------------------------
# Settings -> flags
# --------------------------------------------------------------------------

class SettingsTests(unittest.TestCase):
    def test_submit_flags_are_accepted_by_graph_submit(self):
        env = dict(BASE_ENV, PHISH_ORG_DOMAINS="contoso.com; contoso.eu",
                   PHISH_DENY_CHECK="ceo@contoso.com,payroll@contoso.com",
                   PHISH_MARK_READ="true", PHISH_MOVE_TO="archive",
                   PHISH_CAPTURE_REPORTER_NOTE="yes", PHISH_DRY_RUN="1",
                   PHISH_SOURCE="none", PHISH_API_VERSION="beta")
        args = gs.parse_args(runner.submit_argv(env, "/tmp/state.json"))
        self.assertEqual(args.mailbox, "phish@contoso.com")
        self.assertEqual(args.org_domain, ["contoso.com", "contoso.eu"])
        self.assertEqual(args.deny_check, ["ceo@contoso.com", "payroll@contoso.com"])
        self.assertEqual(args.state, "/tmp/state.json")
        self.assertTrue(args.mark_read and args.capture_reporter_note and args.dry_run)
        self.assertTrue(args.dedupe_original, "dedupe is on unless switched off")
        self.assertEqual(args.move_to, "archive")
        self.assertIsNone(args.source)
        self.assertTrue(args.json)

    def test_defaults_are_the_conservative_ones(self):
        args = gs.parse_args(runner.submit_argv(BASE_ENV, "s.json"))
        self.assertFalse(args.mark_read)
        self.assertIsNone(args.move_to)
        self.assertFalse(args.capture_reporter_note)
        self.assertFalse(args.dry_run)
        self.assertEqual(args.folder, "inbox")
        self.assertEqual(args.category, "phishing")

    def test_dedupe_can_be_switched_off(self):
        argv = runner.submit_argv(dict(BASE_ENV, PHISH_DEDUPE_ORIGINAL="false"), "s")
        self.assertNotIn("--dedupe-original", argv)

    def test_mailbox_is_required(self):
        env = dict(BASE_ENV)
        del env["PHISH_MAILBOX"]
        with self.assertRaisesRegex(runner.ConfigError, "PHISH_MAILBOX"):
            runner.submit_argv(env, "s")

    def test_deny_check_is_required_unless_waived(self):
        env = dict(BASE_ENV, PHISH_DENY_CHECK="  ")
        with self.assertRaisesRegex(runner.ConfigError, "PHISH_DENY_CHECK"):
            runner.submit_argv(env, "s")
        argv = runner.submit_argv(dict(env, PHISH_ALLOW_UNVERIFIED_SCOPE="true"), "s")
        self.assertNotIn("--deny-check", argv)

    def test_bad_boolean_and_number_are_config_errors(self):
        with self.assertRaisesRegex(runner.ConfigError, "PHISH_MARK_READ"):
            runner.submit_argv(dict(BASE_ENV, PHISH_MARK_READ="maybe"), "s")
        with self.assertRaisesRegex(runner.ConfigError, "PHISH_MAX"):
            runner.submit_argv(dict(BASE_ENV, PHISH_MAX="lots"), "s")

    def test_collect_is_minimal_extraction_by_default(self):
        args = collect_args(runner.collect_argv(BASE_ENV, "out.json"))
        self.assertTrue(args.no_mailbox)
        self.assertIsNone(args.mailbox)
        self.assertEqual(args.deny_check, [])

    def test_collect_mailbox_is_opt_in_and_carries_the_scope_check(self):
        env = dict(BASE_ENV, PHISH_COLLECT_MAILBOX="true", PHISH_NO_HUNTING="true")
        args = collect_args(runner.collect_argv(env, "out.json", "ctx.json", "notes.json"))
        self.assertFalse(args.no_mailbox)
        self.assertEqual(args.mailbox, "phish@contoso.com")
        self.assertEqual(args.deny_check, ["ceo@contoso.com"])
        self.assertTrue(args.no_hunting)
        self.assertEqual((args.org_context, args.reporter_notes), ("ctx.json", "notes.json"))

    def test_triage_flags_are_accepted_by_triage(self):
        env = dict(BASE_ENV, PHISH_STUCK_HOURS="6", PHISH_LARGE_SCOPE="50")
        args = runner.triage.parse_args(runner.triage_argv(env, "e.json", "r.md", "ctx.json"))
        self.assertEqual((args.stuck_hours, args.large_scope, args.format), (6, 50, "both"))
        self.assertEqual(args.out, "r.md")


def collect_args(argv):
    return runner.collect_export.parse_args(argv)


# --------------------------------------------------------------------------
# Credentials
# --------------------------------------------------------------------------

class CredentialTests(WrapperTestCase):
    def test_managed_identity_token_exists_only_during_the_run(self):
        env = self.env(PHISH_MANAGED_IDENTITY_CLIENT_ID="uami-client-id")
        seen = []

        def main(argv):
            seen.append(os.environ.get("GRAPH_ACCESS_TOKEN"))
            return 0
        with runner.graph_credentials(env, self.token):
            main([])
        self.assertEqual(seen, ["mi-token"])
        self.assertEqual(self.token_requests, ["uami-client-id"])
        self.assertNotIn("GRAPH_ACCESS_TOKEN", os.environ)

    def test_token_removed_even_when_the_run_raises(self):
        env = self.env()
        with self.assertRaises(ValueError):
            with runner.graph_credentials(env, self.token):
                raise ValueError("boom")
        self.assertNotIn("GRAPH_ACCESS_TOKEN", os.environ)

    def test_static_token_in_app_settings_is_refused(self):
        env = self.env(GRAPH_ACCESS_TOKEN="stale")
        with self.assertRaisesRegex(runner.ConfigError, "GRAPH_ACCESS_TOKEN"):
            with runner.graph_credentials(env, self.token):
                pass
        self.assertEqual(self.token_requests, [])

    def test_client_secret_mode_needs_all_three(self):
        env = self.env(PHISH_GRAPH_AUTH="client_secret", GRAPH_TENANT_ID="t",
                       GRAPH_CLIENT_ID="c")
        with self.assertRaisesRegex(runner.ConfigError, "GRAPH_CLIENT_SECRET"):
            with runner.graph_credentials(env, self.token):
                pass

    def test_client_secret_mode_fetches_no_managed_identity_token(self):
        env = self.env(PHISH_GRAPH_AUTH="client_secret", GRAPH_TENANT_ID="t",
                       GRAPH_CLIENT_ID="c", GRAPH_CLIENT_SECRET="s")
        with runner.graph_credentials(env, self.token):
            self.assertNotIn("GRAPH_ACCESS_TOKEN", os.environ)
        self.assertEqual(self.token_requests, [])

    def test_unknown_auth_mode(self):
        env = self.env(PHISH_GRAPH_AUTH="certificate")
        with self.assertRaisesRegex(runner.ConfigError, "PHISH_GRAPH_AUTH"):
            with runner.graph_credentials(env, self.token):
                pass


# --------------------------------------------------------------------------
# Job 1: submission, end to end through the real graph_submit.main
# --------------------------------------------------------------------------

class SubmitJobTests(WrapperTestCase):
    def test_first_run_submits_and_creates_state(self):
        store = FakeStore()
        counts = self.submit(store)
        self.assertEqual(counts, {"submitted": 1})
        self.assertEqual(FakeGraph.tokens_seen, ["mi-token"])
        state = store.json(runner.DEFAULT_STATE_BLOB)
        self.assertIn("<fwd-0@contoso.com>", state["processed"])
        self.assertIn("<phish-0001@acme-invoices.example>", state["originals"])
        results = store.json("runs/submit/20260928T120000Z.json")
        self.assertEqual(results["results"][0]["recipient"], "j.rivera@contoso.com")

    def test_second_run_resubmits_nothing(self):
        store = FakeStore()
        self.submit(store)
        FakeGraph.calls = []
        counts = self.submit(store)
        self.assertEqual(counts, {}, "already-processed messages are skipped silently")
        posts = [c for c in FakeGraph.calls if c[0] == "POST"]
        self.assertEqual(posts, [])

    def test_state_written_back_against_the_etag_it_read(self):
        store = FakeStore({runner.DEFAULT_STATE_BLOB: b'{"processed": {}}'})
        original_write = store.write

        def racing_write(name, data, **kw):
            if name == runner.DEFAULT_STATE_BLOB:
                store.blobs[name] = (b"{}", "someone-else")      # another writer won
            return original_write(name, data, **kw)
        store.write = racing_write
        with self.assertRaises(runner.StateConflict):
            self.submit(store)

    def test_dry_run_submits_nothing_and_leaves_state_alone(self):
        store = FakeStore()
        counts = self.submit(store, PHISH_DRY_RUN="true")
        self.assertEqual(counts, {"dry_run": 1})
        self.assertNotIn(runner.DEFAULT_STATE_BLOB, store.blobs,
                         "a dry run must not mark messages processed for the real run")
        self.assertFalse([c for c in FakeGraph.calls if c[0] == "POST"])

    def test_over_scoped_app_raises_scope_failure_and_reads_no_mail(self):
        FakeGraph.readable = {"phish@contoso.com", "ceo@contoso.com"}
        store = FakeStore()
        with self.assertRaises(runner.ScopeCheckFailed) as ctx:
            self.submit(store)
        self.assertEqual(ctx.exception.exit_code, 3)
        self.assertFalse([c for c in FakeGraph.calls if "/mailFolders/" in c[1]])
        self.assertEqual(store.writes, [])

    def test_per_message_error_is_raised_after_state_is_saved(self):
        FakeGraph.messages = forwarded(2)
        original = FakeGraph.request
        posts = []

        def flaky(self, method, path, **kw):
            if method == "POST" and path.endswith("emailThreats"):
                posts.append(path)
                if len(posts) == 1:
                    raise gs.GraphError(400, '{"error":{"code":"BadRequest"}}', path)
            return original(self, method, path, **kw)
        with mock.patch.object(FakeGraph, "request", flaky):
            store = FakeStore()
            with self.assertRaises(runner.RunFailed) as ctx:
                self.submit(store, PHISH_DEDUPE_ORIGINAL="false")
        self.assertEqual(ctx.exception.exit_code, 1)
        state = store.json(runner.DEFAULT_STATE_BLOB)
        self.assertEqual(sorted(v["status"] for v in state["processed"].values()),
                         ["error", "submitted"])

    def test_blank_client_secret_is_a_config_error_before_any_call(self):
        store = FakeStore()
        with self.assertRaisesRegex(runner.ConfigError, "GRAPH_CLIENT_SECRET"):
            self.submit(store, PHISH_GRAPH_AUTH="client_secret", GRAPH_TENANT_ID="t",
                        GRAPH_CLIENT_ID="c", GRAPH_CLIENT_SECRET="")
        self.assertEqual(FakeGraph.calls, [])
        self.assertEqual(store.writes, [])

    def test_config_error_touches_no_storage(self):
        store = FakeStore()
        self.env(PHISH_DENY_CHECK="")
        with self.assertRaises(runner.ConfigError):
            runner.run_submit(store=store, token_provider=self.token)
        self.assertEqual(store.writes, [])
        self.assertEqual(self.token_requests, [])


# --------------------------------------------------------------------------
# Job 2: collect + triage, end to end through the real scripts
# --------------------------------------------------------------------------

ONE_SUBMISSION = [{
    "id": "sub-1", "internetMessageId": "<phish-0001@acme-invoices.example>",
    "recipientEmailAddress": "j.rivera@contoso.com",
    "createdDateTime": "2026-09-28T09:00:00Z", "status": "succeeded",
    "result": {"detail": "phishing"}, "userNotified": True,
    "sender": "ap@acme-invoices.example", "subject": "Updated remittance details",
}]


class TriageJobTests(WrapperTestCase):
    def setUp(self):
        super().setUp()
        FakeGraph.submissions = list(ONE_SUBMISSION)

    def triage_run(self, store, **extra):
        self.env(**extra)
        return runner.run_triage(store=store, token_provider=self.token, now=NOW)

    def test_writes_export_report_and_latest(self):
        store = FakeStore()
        outcome = self.triage_run(store)
        self.assertEqual(outcome["blobs"], {
            "export": "exports/20260928T120000Z.json",
            "report": "reports/20260928T120000Z.md",
            "results": "reports/20260928T120000Z.json",
        })
        self.assertEqual(sum(outcome["counts"].values()), 1)
        export = store.json("exports/20260928T120000Z.json")
        self.assertEqual(export["items"][0]["defender"]["submission_id"], "sub-1")
        self.assertIn(b"#", store.blobs["reports/latest.md"][0])
        self.assertEqual(store.json("reports/latest.json")["counts"], outcome["counts"])

    def test_minimal_extraction_never_opens_the_mailbox(self):
        self.triage_run(FakeStore())
        self.assertFalse([c for c in FakeGraph.calls if c[1].startswith("users/")])

    def test_reporter_notes_come_from_the_submit_state(self):
        state = {"notes": {"phish-0001@acme-invoices.example": {
            "note": "I entered my password", "reporter": "j.rivera@contoso.com"}}}
        store = FakeStore({runner.DEFAULT_STATE_BLOB: json.dumps(state).encode()})
        self.triage_run(store, PHISH_CAPTURE_REPORTER_NOTE="true")
        export = store.json("exports/20260928T120000Z.json")
        self.assertEqual(export["items"][0]["reporter_note"], "I entered my password")
        self.assertEqual([w for w in store.writes if w.startswith("state/")], [],
                         "the triage job only reads the submit job's state")

    def test_org_context_blob(self):
        ctx = {"org_domains": ["contoso.com"], "vip": ["j.rivera@contoso.com"]}
        store = FakeStore({"config/org-context.json": json.dumps(ctx).encode()})
        self.triage_run(store, PHISH_ORG_CONTEXT_BLOB="config/org-context.json")
        export = store.json("exports/20260928T120000Z.json")
        self.assertEqual(export["export_meta"]["vip_list"], ["j.rivera@contoso.com"])

    def test_missing_org_context_blob_is_a_config_error(self):
        with self.assertRaisesRegex(runner.ConfigError, "PHISH_ORG_CONTEXT_BLOB"):
            self.triage_run(FakeStore(), PHISH_ORG_CONTEXT_BLOB="config/nope.json")

    def test_reading_the_mailbox_is_scope_checked(self):
        FakeGraph.readable = {"phish@contoso.com", "ceo@contoso.com"}
        store = FakeStore()
        with self.assertRaises(runner.ScopeCheckFailed):
            self.triage_run(store, PHISH_COLLECT_MAILBOX="true")
        self.assertEqual(store.writes, [])


# --------------------------------------------------------------------------
# Sentinel
# --------------------------------------------------------------------------

class FakeSink:
    """Stands in for SentinelSink: records what would have been uploaded."""

    def __init__(self, fail_with=None):
        self.batches = []
        self.fail_with = fail_with

    def upload(self, rows):
        if self.fail_with:
            raise self.fail_with
        self.batches.append(rows)


SENTINEL_ENV = {
    "PHISH_SENTINEL_DCE_ENDPOINT": "https://phish-dce-abcd.westeurope-1.ingest.monitor.azure.com",
    "PHISH_SENTINEL_DCR_IMMUTABLE_ID": "dcr-0123456789abcdef0123456789abcdef",
}


def golden_result():
    """triage.py's JSON payload for the synthetic queue."""
    export = os.path.join(ROOT, "test-data", "mailbox_export.json")
    code, stdout = runner.call_script(runner.triage.main, [export, "--format", "json"])
    assert code == 0, code
    return runner.json_documents(stdout)[-1]


class SentinelRowTests(unittest.TestCase):
    """sentinel_rows() is the contract with the table in sentinel/main.bicep."""

    @classmethod
    def setUpClass(cls):
        cls.result = golden_result()
        cls.rows = runner.sentinel_rows(cls.result, "20260928T120000Z", NOW)

    def test_one_row_per_item_carrying_the_routing_decision(self):
        self.assertEqual(len(self.rows), len(self.result["results"]))
        by_id = {r["TriageId"]: r for r in self.rows}
        p1 = by_id["PHQ-1044"]
        self.assertEqual(p1["Lane"], "exception")
        self.assertEqual(p1["Priority"], "P1")
        self.assertIn("bec", p1["Categories"])
        self.assertEqual(p1["SubmissionId"], "SUB-77124")
        self.assertEqual(p1["Verdict"], "No threats found")
        self.assertEqual(p1["InteractionTypes"], ["replied"])
        self.assertEqual(p1["RunId"], "20260928T120000Z")
        self.assertEqual(p1["TimeGenerated"], "2026-09-28T12:00:00Z")
        lanes = {r["Lane"] for r in self.rows}
        self.assertEqual(lanes, {"handled_by_automation", "automation_gap", "exception"},
                         "every lane goes in, so lane counts can be charted")

    def test_columns_match_the_bicep_table_declaration(self):
        bicep = os.path.join(ROOT, "azure-function", "sentinel", "main.bicep")
        with open(bicep, encoding="utf-8") as fh:
            template = fh.read()
        declared = set(re.findall(r"^\s*\{\s*name:\s*'(\w+)'", template, re.M))
        for row in self.rows:
            missing = set(row) - declared
            self.assertFalse(missing, "columns not declared in main.bicep: %s" % sorted(missing))

    def test_every_value_is_json_serialisable(self):
        json.dumps(self.rows)

    def test_headers_only_drops_the_quoted_text(self):
        rows = runner.sentinel_rows(self.result, "run", NOW, headers_only=True)
        for row in rows:
            for column in ("Evidence", "Interaction", "Actions"):
                self.assertNotIn(column, row)
            self.assertIn("Indicators", row)
            self.assertIn("Priority", row)
        full = {r["TriageId"]: r for r in self.rows}
        self.assertTrue(any(full[r["TriageId"]].get("Evidence") for r in rows),
                        "the full rows do carry evidence; headers-only removed it")


class SentinelSettingsTests(unittest.TestCase):
    def test_unset_means_off(self):
        self.assertIsNone(runner.sentinel_settings({}))

    def test_half_configured_is_a_config_error(self):
        for name in SENTINEL_ENV:
            with self.assertRaisesRegex(runner.ConfigError, "both"):
                runner.sentinel_settings({name: SENTINEL_ENV[name]})

    def test_endpoint_must_be_https(self):
        env = dict(SENTINEL_ENV, PHISH_SENTINEL_DCE_ENDPOINT="phish-dce.ingest.monitor.azure.com")
        with self.assertRaisesRegex(runner.ConfigError, "https"):
            runner.sentinel_settings(env)

    def test_defaults(self):
        settings = runner.sentinel_settings(dict(SENTINEL_ENV))
        self.assertEqual(settings["stream"], "Custom-PhishTriage_CL")
        self.assertFalse(settings["headers_only"])
        self.assertEqual(settings["endpoint"], SENTINEL_ENV["PHISH_SENTINEL_DCE_ENDPOINT"])


class SentinelJobTests(WrapperTestCase):
    def setUp(self):
        super().setUp()
        FakeGraph.submissions = list(ONE_SUBMISSION)

    def triage_run(self, store, sink=None, **extra):
        self.env(**extra)
        return runner.run_triage(store=store, token_provider=self.token, now=NOW, sink=sink)

    def test_not_configured_sends_nothing(self):
        sink = FakeSink()
        outcome = self.triage_run(FakeStore(), sink=sink)
        self.assertEqual(sink.batches, [])
        self.assertEqual(outcome["sentinel_rows"], 0)

    def test_configured_sends_one_row_per_item_after_the_blobs(self):
        sink, store = FakeSink(), FakeStore()
        outcome = self.triage_run(store, sink=sink, **SENTINEL_ENV)
        self.assertEqual(outcome["sentinel_rows"], 1)
        self.assertEqual(len(sink.batches), 1)
        row = sink.batches[0][0]
        self.assertEqual(row["SubmissionId"], "sub-1")
        self.assertEqual(row["Reporter"], "j.rivera@contoso.com")
        self.assertEqual(row["RunId"], "20260928T120000Z")
        self.assertEqual(store.json("reports/20260928T120000Z.json")["results"][0]["id"],
                         row["TriageId"])

    def test_headers_only_setting_is_honoured(self):
        sink = FakeSink()
        self.triage_run(FakeStore(), sink=sink, PHISH_SENTINEL_HEADERS_ONLY="true",
                        **SENTINEL_ENV)
        self.assertNotIn("Evidence", sink.batches[0][0])

    def test_upload_failure_is_raised_but_the_report_is_already_saved(self):
        sink, store = FakeSink(fail_with=RuntimeError("403 Forbidden")), FakeStore()
        with self.assertRaisesRegex(runner.SentinelUploadFailed, "Monitoring Metrics Publisher"):
            self.triage_run(store, sink=sink, **SENTINEL_ENV)
        self.assertIn("reports/latest.json", store.blobs)
        self.assertIn("reports/latest.md", store.blobs)

    def test_half_configured_fails_before_any_io(self):
        store = FakeStore()
        with self.assertRaises(runner.ConfigError):
            self.triage_run(store, sink=FakeSink(),
                            PHISH_SENTINEL_DCE_ENDPOINT=SENTINEL_ENV["PHISH_SENTINEL_DCE_ENDPOINT"])
        self.assertEqual(store.writes, [])
        self.assertEqual(FakeGraph.calls, [])


# --------------------------------------------------------------------------
# Plumbing
# --------------------------------------------------------------------------

class PlumbingTests(unittest.TestCase):
    def test_json_documents_reads_both_graph_submit_outputs(self):
        text = '{"scope_check": {"verdict": "scoped"}}\n{"counts": {"submitted": 2}}\n'
        docs = runner.json_documents(text)
        self.assertEqual(docs[1]["counts"], {"submitted": 2})
        self.assertEqual(runner.json_documents(""), [])

    def test_call_script_routes_stderr_to_logging_and_captures_stdout(self):
        def main(argv):
            print("to stderr", file=sys.stderr)
            print('{"ok": true}')
            return 0
        with self.assertLogs("phish_triage", "INFO") as logs:
            code, out = runner.call_script(main, [])
        self.assertEqual((code, out.strip()), (0, '{"ok": true}'))
        self.assertIn("to stderr", "\n".join(logs.output))

    def test_call_script_turns_system_exit_into_a_code(self):
        def message_exit(argv):
            raise SystemExit("no usable credentials")

        def argparse_exit(argv):
            raise SystemExit(2)
        with self.assertLogs("phish_triage", "ERROR"):
            self.assertEqual(runner.call_script(message_exit, [])[0], 2)
        self.assertEqual(runner.call_script(argparse_exit, [])[0], 2)

    def test_exit_codes_map_to_exceptions(self):
        runner._raise_for_exit("x", 0)
        for code, kind in ((1, runner.RunFailed), (2, runner.RunFailed),
                           (3, runner.ScopeCheckFailed)):
            with self.assertRaises(kind) as ctx:
                runner._raise_for_exit("x", code)
            self.assertEqual(ctx.exception.exit_code, code)

    def test_package_ships_every_script_collect_export_imports(self):
        with open(os.path.join(ROOT, "azure-function", "package.sh"), encoding="utf-8") as fh:
            package = fh.read()
        for name in ("graph_submit.py", "collect_export.py", "triage.py", "parse_headers.py"):
            self.assertIn(name, package)


if __name__ == "__main__":
    unittest.main()
