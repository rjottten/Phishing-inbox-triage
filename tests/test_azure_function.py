#!/usr/bin/env python3
"""Offline tests for the Azure Function's logic.

`azure-function/runner.py` holds everything of substance and imports no Azure
package at module scope, so all of it is covered here on a clean interpreter with
no azure-* installed and no credentials.

The weight is on the fail-closed rules. An unattended job holding Mail.Read is
exactly the thing that should refuse to start when its configuration cannot prove
what it is allowed to reach.

Run: python -m unittest discover -s tests
"""
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "azure-function"))
sys.path.insert(0, os.path.join(ROOT, "skills", "phishing-inbox-triage", "scripts"))

import graph_submit as gs  # noqa: E402
import runner  # noqa: E402

GOOD_ENV = {
    "PHISH_MAILBOX": "phish@atlasair.com",
    "PHISH_DENY_CHECK": "ceo@atlasair.com",
    "PHISH_ORG_DOMAIN": "atlasair.com",
    "AzureWebJobsStorage": "UseDevelopmentStorage=true",
}


def env(**overrides):
    merged = dict(GOOD_ENV)
    merged.update(overrides)
    return {k: v for k, v in merged.items() if v is not None}


class TestConfigFailsClosed(unittest.TestCase):
    """Every required setting is required because getting it wrong is silent."""

    def test_a_good_config_loads(self):
        config = runner.load_config(env())
        self.assertEqual(config["mailbox"], "phish@atlasair.com")
        self.assertEqual(config["deny_check"], ["ceo@atlasair.com"])
        self.assertEqual(config["org_domains"], ["atlasair.com"])

    def test_no_mailbox_is_refused(self):
        with self.assertRaises(runner.ConfigError) as ctx:
            runner.load_config(env(PHISH_MAILBOX=None))
        self.assertIn("PHISH_MAILBOX", str(ctx.exception))

    def test_no_scope_control_is_refused_with_the_reason(self):
        """Mail.Read is tenant-wide until Exchange scoping is applied, and a scope
        that never propagated looks exactly like one that works."""
        with self.assertRaises(runner.ConfigError) as ctx:
            runner.load_config(env(PHISH_DENY_CHECK=None))
        message = str(ctx.exception)
        self.assertIn("PHISH_DENY_CHECK", message)
        self.assertIn("tenant-wide", message)

    def test_no_org_domain_is_refused(self):
        with self.assertRaises(runner.ConfigError) as ctx:
            runner.load_config(env(PHISH_ORG_DOMAIN=None))
        self.assertIn("PHISH_ORG_DOMAIN", str(ctx.exception))

    def test_denying_the_watched_mailbox_is_refused(self):
        """Otherwise every run aborts on its own target and nobody knows why."""
        with self.assertRaises(runner.ConfigError):
            runner.load_config(env(PHISH_DENY_CHECK="phish@atlasair.com"))

    def test_the_deny_check_comparison_ignores_case(self):
        with self.assertRaises(runner.ConfigError):
            runner.load_config(env(PHISH_DENY_CHECK="PHISH@ATLASAIR.COM"))

    def test_several_controls_and_domains_are_split(self):
        config = runner.load_config(env(
            PHISH_DENY_CHECK="ceo@atlasair.com, cfo@atlasair.com",
            PHISH_ORG_DOMAIN="atlasair.com,atlasair.co.uk"))
        self.assertEqual(config["deny_check"], ["ceo@atlasair.com", "cfo@atlasair.com"])
        self.assertEqual(config["org_domains"], ["atlasair.com", "atlasair.co.uk"])


class TestDryRunIsTheDefault(unittest.TestCase):
    """A deploy that starts submitting before anyone has read a dry run is not a
    deploy anybody wanted."""

    def test_dry_run_unless_explicitly_turned_off(self):
        self.assertTrue(runner.load_config(env())["dry_run"])

    def test_going_live_takes_an_explicit_setting(self):
        self.assertFalse(runner.load_config(env(PHISH_DRY_RUN_OFF="true"))["dry_run"])

    def test_a_vague_value_does_not_go_live(self):
        for value in ("maybe", "0", "false", "no", ""):
            self.assertTrue(runner.load_config(env(PHISH_DRY_RUN_OFF=value))["dry_run"],
                            f"{value!r} must not be read as 'go live'")

    def test_truthy_accepts_the_usual_spellings(self):
        for value in ("1", "true", "TRUE", "yes", "on"):
            self.assertTrue(runner.truthy(value))
        for value in ("0", "false", "no", "off", "", None):
            self.assertFalse(runner.truthy(value))


class TestArgv(unittest.TestCase):

    def argv(self, **overrides):
        return runner.build_argv(runner.load_config(env(**overrides)),
                                 "/tmp/state.json", "/tmp/worklist.json")

    def test_the_argv_actually_parses(self):
        """The thing that would otherwise break silently on a flag rename: the
        Function builds a command line graph_submit.py has to accept."""
        args = gs.parse_args(self.argv())
        self.assertEqual(args.mailbox, "phish@atlasair.com")
        self.assertEqual(args.state, "/tmp/state.json")
        self.assertEqual(args.worklist, "/tmp/worklist.json")

    def test_a_dry_run_is_requested_by_default(self):
        self.assertTrue(gs.parse_args(self.argv()).dry_run)

    def test_live_runs_omit_dry_run(self):
        self.assertFalse(gs.parse_args(self.argv(PHISH_DRY_RUN_OFF="true")).dry_run)

    def test_every_control_mailbox_is_passed(self):
        args = gs.parse_args(self.argv(PHISH_DENY_CHECK="ceo@atlasair.com,cfo@atlasair.com"))
        self.assertEqual(args.deny_check, ["ceo@atlasair.com", "cfo@atlasair.com"])

    def test_every_org_domain_is_passed(self):
        args = gs.parse_args(self.argv(PHISH_ORG_DOMAIN="atlasair.com,atlasair.co.uk"))
        self.assertEqual(args.org_domain, ["atlasair.com", "atlasair.co.uk"])

    def test_dedupe_is_always_on(self):
        """Ten people forwarding one phish must not become ten submissions."""
        self.assertTrue(gs.parse_args(self.argv()).dedupe_original)

    def test_housekeeping_is_opt_in(self):
        self.assertFalse(gs.parse_args(self.argv()).mark_read)
        args = gs.parse_args(self.argv(PHISH_MARK_READ="true", PHISH_MOVE_TO="archive"))
        self.assertTrue(args.mark_read)
        self.assertEqual(args.move_to, "archive")

    def test_the_reporter_note_is_opt_in(self):
        self.assertFalse(gs.parse_args(self.argv()).capture_reporter_note)
        self.assertTrue(gs.parse_args(
            self.argv(PHISH_CAPTURE_REPORTER_NOTE="true")).capture_reporter_note)

    def test_a_worklist_is_always_requested(self):
        """Without it the skipped reports are log lines in App Insights, which is
        not somewhere anyone works a queue from."""
        self.assertIn("--worklist", self.argv())


class TestScriptDiscovery(unittest.TestCase):

    def test_it_finds_the_scripts_in_a_checkout(self):
        found = runner.script_dir()
        self.assertTrue(os.path.exists(os.path.join(found, "graph_submit.py")))

    def test_a_missing_deploy_step_says_which_step(self):
        with self.assertRaises(runner.ConfigError) as ctx:
            runner.script_dir(("/nonexistent/one", "/nonexistent/two"))
        self.assertIn("prepare.sh", str(ctx.exception))


class TestSummarise(unittest.TestCase):
    """Counts only — App Insights is not where reported phishing content belongs."""

    def write(self, text):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                         encoding="utf-8") as fh:
            fh.write(text)
        self.addCleanup(os.unlink, fh.name)
        return fh.name

    def test_it_counts_open_entries(self):
        path = self.write(json.dumps({"open": {"a@x": {}, "b@x": {}}}))
        self.assertEqual(runner.summarise(path), 2)

    def test_a_missing_worklist_is_zero_not_a_crash(self):
        self.assertEqual(runner.summarise("/nonexistent/worklist.json"), 0)

    def test_a_corrupt_worklist_is_zero_not_a_crash(self):
        self.assertEqual(runner.summarise(self.write("{not json")), 0)


class TestRunOnce(unittest.TestCase):
    """The wiring, with graph_submit.main stubbed — no Graph, no Azure, no token."""

    def setUp(self):
        self.calls = []
        self.logged = []
        self.real_main = gs.main

        def fake_main(argv=None):
            self.calls.append(argv)
            return self.code

        gs.main = fake_main
        self.code = 0
        self.addCleanup(setattr, gs, "main", self.real_main)
        self.work = tempfile.mkdtemp()

    def run_it(self, **overrides):
        # A supplied token is a real path (managed identity or a delegated token),
        # and it keeps azure-identity out of the test.
        settings = env(GRAPH_ACCESS_TOKEN="fake-token",
                       AzureWebJobsStorage="", **overrides)
        return runner.run_once(env=settings, work_dir=self.work,
                               log=self.logged.append)

    def test_it_runs_graph_submit_with_the_built_argv(self):
        self.assertEqual(self.run_it(), 0)
        self.assertIn("--mailbox", self.calls[0])
        self.assertIn("phish@atlasair.com", self.calls[0])

    def test_the_token_is_put_in_the_environment_for_the_run(self):
        seen = {}

        def capture(argv=None):
            seen["token"] = os.environ.get("GRAPH_ACCESS_TOKEN")
            return 0

        gs.main = capture
        self.run_it()
        self.assertEqual(seen["token"], "fake-token")

    def test_the_token_does_not_leak_into_the_process_afterwards(self):
        before = os.environ.get("GRAPH_ACCESS_TOKEN")
        self.run_it()
        self.assertEqual(os.environ.get("GRAPH_ACCESS_TOKEN"), before)

    def test_a_failed_scope_check_stops_the_run_loudly(self):
        """Exit 3 means the app can reach a mailbox it must not. That is the one
        outcome that must never be logged and shrugged off."""
        self.code = 3
        with self.assertRaises(RuntimeError) as ctx:
            self.run_it()
        self.assertIn("scope check failed", str(ctx.exception))

    def test_a_failed_run_raises(self):
        self.code = 2
        with self.assertRaises(RuntimeError):
            self.run_it()

    def test_a_single_errored_message_does_not_fail_the_firing(self):
        """It stays on the worklist and the next run picks it up."""
        self.code = 1
        self.assertEqual(self.run_it(), 1)

    def test_missing_storage_is_warned_about_not_silently_accepted(self):
        self.run_it()
        self.assertTrue(any("not persisted" in line for line in self.logged))

    def test_a_config_error_stops_before_anything_runs(self):
        with self.assertRaises(runner.ConfigError):
            self.run_it(PHISH_MAILBOX=None)
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
