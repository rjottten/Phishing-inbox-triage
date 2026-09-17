#!/usr/bin/env python3
"""Tests for secret_triage.py — collection that never writes the secret out.

The property this file exists to defend: GitHub hands back the raw credential in
the `secret` field, and a rounds bundle is a file that ends up attached to
tickets, pasted into chat and committed by accident. So the value must not
survive normalization — only a fingerprint and a short preview. That is exactly
the kind of invariant that breaks quietly during a refactor, so it is asserted
directly, on nested output, and through the CLI.

The rest pins the normalization that downstream gates depend on: a publicly
leaked secret is a public exposure whatever the repository's visibility, and
consumers nobody enumerated must stay absent rather than defaulting to empty —
an empty list is an answer, and claiming one nobody gave would open Gate 3 on a
credential whose blast radius is unknown.

Run: python -m unittest discover -s tests
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT_DIR = os.path.join(ROOT, "soc-analyst-rounds", "scripts")
sys.path.insert(0, SCRIPT_DIR)

import rounds as rd  # noqa: E402
import secret_triage as st  # noqa: E402

SCRIPT = os.path.join(SCRIPT_DIR, "secret_triage.py")
RAW_SECRET = "AKIAIOSFODNN7EXAMPLE7Q2"
TOKEN_KEYS = ("GITHUB_TOKEN", "GH_TOKEN")

NOW = datetime(2026, 9, 17, 9, 0, tzinfo=timezone.utc)


def api_alert(**over):
    base = {
        "number": 17,
        "state": "open",
        "secret_type": "aws_access_key_id",
        "secret_type_display_name": "Amazon AWS Access Key ID",
        "secret": RAW_SECRET,
        "validity": "active",
        "created_at": "2026-09-17T04:12:00Z",
        "html_url": "https://github.com/acme/payments-api/security/secret-scanning/17",
        "push_protection_bypassed": False,
        "repository": {"full_name": "acme/payments-api", "private": False},
    }
    base.update(over)
    return base


def cfg():
    return {"max_scope": 25, "no_auto_contain": False, "large_scope": 100,
            "sla": rd.DEFAULT_SLA_HOURS, "authorized_scope": [],
            "standard_catalogue": rd.DEFAULT_STANDARD_CATALOGUE,
            "noisy_rule_rate": 0.8, "stale_cr_days": 14}


class TheSecretNeverLeaves(unittest.TestCase):

    def test_normalization_drops_the_value(self):
        normalized = st.normalize_alert(api_alert())
        self.assertNotIn("secret", normalized)
        self.assertNotIn(RAW_SECRET, json.dumps(normalized))

    def test_it_survives_nowhere_in_a_rendered_bundle(self):
        alerts = [st.normalize_alert(api_alert(number=n)) for n in range(5)]
        self.assertNotIn(RAW_SECRET, json.dumps(alerts))

    def test_it_does_not_leak_through_the_markdown_triage(self):
        report = st.render_md([st.normalize_alert(api_alert())], NOW)
        self.assertNotIn(RAW_SECRET, report)

    def test_it_does_not_leak_through_the_cli(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump([api_alert()], handle)
            path = handle.name
        try:
            for fmt in ("bundle", "json", "md"):
                result = subprocess.run(
                    [sys.executable, SCRIPT, "--from-json", path, "--format", fmt],
                    capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn(RAW_SECRET, result.stdout)
        finally:
            os.unlink(path)

    def test_the_preview_is_recognizable_but_unusable(self):
        preview = st.preview(RAW_SECRET)
        self.assertEqual(preview, "AKIA...7Q2")
        self.assertNotIn(RAW_SECRET, preview)

    def test_a_short_secret_is_still_truncated(self):
        self.assertEqual(st.preview("abc123"), "abc...")

    def test_no_secret_yields_no_preview_or_fingerprint(self):
        self.assertIsNone(st.preview(None))
        self.assertIsNone(st.fingerprint(None))


class Fingerprints(unittest.TestCase):

    def test_the_same_secret_fingerprints_the_same(self):
        self.assertEqual(st.fingerprint(RAW_SECRET), st.fingerprint(RAW_SECRET))

    def test_different_secrets_fingerprint_differently(self):
        self.assertNotEqual(st.fingerprint(RAW_SECRET), st.fingerprint(RAW_SECRET + "x"))

    def test_the_fingerprint_does_not_contain_the_secret(self):
        self.assertNotIn(RAW_SECRET, st.fingerprint(RAW_SECRET))

    def test_it_is_what_collapses_one_credential_across_repos(self):
        alerts = [
            st.normalize_alert(api_alert(number=1)),
            st.normalize_alert(api_alert(
                number=2, repository={"full_name": "acme/other", "private": True})),
        ]
        collapsed = rd.collapse_secret_alerts(alerts)
        self.assertEqual(len(collapsed), 1)
        self.assertEqual(sorted(collapsed[0]["repos"]), ["acme/other", "acme/payments-api"])

    def test_an_explicit_fingerprint_is_preserved(self):
        normalized = st.normalize_alert(api_alert(secret_fingerprint="fp-given", secret=None))
        self.assertEqual(normalized["secret_fingerprint"], "fp-given")


class Exposure(unittest.TestCase):

    def test_a_public_repository_is_public_exposure(self):
        normalized = st.normalize_alert(api_alert())
        self.assertEqual(normalized["repo_visibility"], "public")

    def test_a_private_repository_is_private_exposure(self):
        normalized = st.normalize_alert(api_alert(
            repository={"full_name": "acme/internal", "private": True}))
        self.assertEqual(normalized["repo_visibility"], "private")

    def test_publicly_leaked_beats_a_private_repository(self):
        # GitHub saw it outside the repo, so the repository's visibility is
        # no longer what decides the exposure.
        normalized = st.normalize_alert(api_alert(
            repository={"full_name": "acme/internal", "private": True},
            publicly_leaked=True))
        self.assertEqual(normalized["repo_visibility"], "public")

    def test_a_publicly_leaked_secret_triages_as_p1(self):
        normalized = st.normalize_alert(api_alert(
            repository={"full_name": "acme/internal", "private": True},
            publicly_leaked=True))
        self.assertEqual(rd.triage_secret(normalized, cfg(), NOW)["priority"], "P1")

    def test_visibility_defaults_to_private_when_unknown(self):
        normalized = st.normalize_alert(api_alert(repository={"full_name": "acme/x"}))
        self.assertEqual(normalized["repo_visibility"], "private")


class Enrichment(unittest.TestCase):

    def test_ownership_is_applied_from_the_map(self):
        normalized = st.normalize_alert(api_alert(),
                                        ownership={"acme/payments-api": "acme-platform"})
        self.assertEqual(normalized["owner_team"], "acme-platform")

    def test_an_unmapped_repository_gets_no_owner(self):
        self.assertNotIn("owner_team", st.normalize_alert(api_alert(), ownership={}))

    def test_consumers_are_applied_by_fingerprint(self):
        fp = st.fingerprint(RAW_SECRET)
        normalized = st.normalize_alert(api_alert(), consumers={fp: ["svc-billing"]})
        self.assertEqual(normalized["consumers"], ["svc-billing"])
        self.assertTrue(normalized["consumers_enumerated"])

    def test_consumers_can_be_applied_by_secret_type(self):
        normalized = st.normalize_alert(
            api_alert(), consumers={"aws_access_key_id": ["svc-billing"]})
        self.assertTrue(normalized["consumers_enumerated"])

    def test_an_empty_enumerated_list_is_a_real_answer(self):
        fp = st.fingerprint(RAW_SECRET)
        normalized = st.normalize_alert(api_alert(), consumers={fp: []})
        self.assertTrue(normalized["consumers_enumerated"])
        self.assertEqual(normalized["consumers"], [])

    def test_unenumerated_consumers_stay_absent_and_block_gate_three(self):
        normalized = st.normalize_alert(api_alert(),
                                        ownership={"acme/payments-api": "acme-platform"})
        self.assertNotIn("consumers_enumerated", normalized)
        item = rd.triage_secret(normalized, cfg(), NOW)
        revoke = [a for a in item["actions"] if a["id"].endswith("-revoke")][0]
        self.assertIn("bounded_scope", revoke["gates_failed"])
        self.assertFalse(revoke["auto"])

    def test_full_enrichment_opens_the_gates(self):
        fp = st.fingerprint(RAW_SECRET)
        normalized = st.normalize_alert(
            api_alert(), ownership={"acme/payments-api": "acme-platform"},
            consumers={fp: ["svc-billing"]})
        item = rd.triage_secret(normalized, cfg(), NOW)
        revoke = [a for a in item["actions"] if a["id"].endswith("-revoke")][0]
        self.assertTrue(revoke["auto"], revoke["blocked_by"])

    def test_a_bypass_is_never_pre_marked_as_verified(self):
        normalized = st.normalize_alert(api_alert(
            push_protection_bypassed=True,
            push_protection_bypassed_reason="it's a test value"))
        self.assertFalse(normalized["bypass_verified"])
        self.assertEqual(normalized["bypass_reason"], "it's a test value")

    def test_locations_are_carried_through(self):
        normalized = st.normalize_alert(
            api_alert(), locations=[{"path": "a.tf", "commit": "abc"}])
        self.assertEqual(len(normalized["locations"]), 1)

    def test_the_id_is_stable_and_names_the_repository(self):
        self.assertEqual(st.normalize_alert(api_alert())["id"],
                         "GHS-acme-payments-api-17")


class Credentials(unittest.TestCase):

    def test_it_refuses_without_a_token(self):
        saved = {key: os.environ.pop(key, None) for key in TOKEN_KEYS}
        try:
            with self.assertRaises(SystemExit) as caught:
                st._token()
            self.assertIn("no usable credentials", str(caught.exception))
            self.assertIn("--from-json", str(caught.exception))
        finally:
            for key, value in saved.items():
                if value is not None:
                    os.environ[key] = value

    def test_either_token_variable_works(self):
        saved = {key: os.environ.pop(key, None) for key in TOKEN_KEYS}
        try:
            os.environ["GH_TOKEN"] = "t"
            self.assertEqual(st._token(), "t")
        finally:
            os.environ.pop("GH_TOKEN", None)
            for key, value in saved.items():
                if value is not None:
                    os.environ[key] = value


class CommandLine(unittest.TestCase):

    def run_cli(self, *args):
        env = {k: v for k, v in os.environ.items() if k not in TOKEN_KEYS}
        return subprocess.run([sys.executable, SCRIPT] + list(args),
                              capture_output=True, text=True, env=env)

    def setUp(self):
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump([api_alert(), api_alert(number=18, secret="ghp_other_value_11c",
                                          secret_type="github_personal_access_token")],
                  handle)
        handle.close()
        self.dump = handle.name
        self.addCleanup(os.unlink, self.dump)

    def test_collecting_without_a_token_refuses_before_the_network(self):
        result = self.run_cli("--org", "acme")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no usable credentials", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_choosing_no_source_is_refused(self):
        result = self.run_cli()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--from-json", result.stderr)

    def test_the_bundle_format_is_ready_for_rounds(self):
        result = self.run_cli("--from-json", self.dump, "--format", "bundle")
        self.assertEqual(result.returncode, 0, result.stderr)
        bundle = json.loads(result.stdout)
        self.assertIn("github_secret_alerts", bundle)
        self.assertEqual(len(bundle["github_secret_alerts"]), 2)
        self.assertIn("not collected live", bundle["rounds_meta"]["collection_notes"][0])

    def test_its_output_feeds_rounds_directly(self):
        result = self.run_cli("--from-json", self.dump, "--format", "bundle")
        bundle = json.loads(result.stdout)
        rounds_result = rd.run(bundle, cfg(), NOW)
        self.assertEqual(rounds_result["counts"]["items"], 2)

    def test_the_markdown_summary_names_the_blocked_gate(self):
        result = self.run_cli("--from-json", self.dump, "--format", "md")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Gate 3", result.stdout)

    def test_writing_to_a_file_reports_the_count(self):
        out = os.path.join(tempfile.mkdtemp(), "github.json")
        result = self.run_cli("--from-json", self.dump, "--out", out)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("2 alert(s)", result.stderr)
        with open(out, encoding="utf-8") as handle:
            self.assertEqual(len(json.load(handle)["github_secret_alerts"]), 2)


if __name__ == "__main__":
    unittest.main()
