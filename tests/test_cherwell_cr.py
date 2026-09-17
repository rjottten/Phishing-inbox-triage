#!/usr/bin/env python3
"""Tests for cherwell_cr.py — the change request a CAB member can approve.

The bar this file defends: a CR that sends its reader back to Upwind has failed.
So the tests check that the six questions CAB asks are answered in the document
(why now, what breaks, how you validate, how you get back, what if we do
nothing, who owns it), that the change class is chosen by exposure rather than
by score, that an untemplated fix type says so instead of implying a backout it
does not have, and that nothing is submitted without credentials.

Run: python -m unittest discover -s tests
"""
import json
import os
import subprocess
import sys
import unittest
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT_DIR = os.path.join(ROOT, "soc-analyst-rounds", "scripts")
sys.path.insert(0, SCRIPT_DIR)

import cherwell_cr as cc  # noqa: E402
import rounds as rd  # noqa: E402

BUNDLE = os.path.join(ROOT, "test-data", "rounds_bundle.json")
SCRIPT = os.path.join(SCRIPT_DIR, "cherwell_cr.py")

NOW = datetime(2026, 9, 17, 9, 0, tzinfo=timezone.utc)  # a Thursday
CRED_KEYS = ("CHERWELL_BASE_URL", "CHERWELL_CLIENT_ID",
             "CHERWELL_USERNAME", "CHERWELL_PASSWORD")


def load_groups():
    with open(BUNDLE, encoding="utf-8") as handle:
        bundle = json.load(handle)
    config = {"max_scope": 25, "no_auto_contain": False, "large_scope": 100,
              "sla": rd.DEFAULT_SLA_HOURS, "authorized_scope": [],
              "standard_catalogue": ["package_upgrade"],
              "noisy_rule_rate": 0.8, "stale_cr_days": 14}
    _items, groups, _ranked = rd.triage_upwind(bundle["upwind_findings"], config, NOW)
    findings_by_id = {f["id"]: f for f in bundle["upwind_findings"]}
    return groups, findings_by_id, bundle.get("rounds_meta", {})


def build(group_id, **kwargs):
    groups, findings_by_id, meta = load_groups()
    group = [g for g in groups if g["id"] == group_id][0]
    kwargs.setdefault("requested_by", "r.otten")
    return cc.build_cr(group, findings_by_id, meta, NOW, **kwargs)


class EmergencyChange(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.cr = build("CG-1")

    def test_it_is_classified_emergency(self):
        self.assertEqual(self.cr["change_class"], "emergency")
        self.assertEqual(self.cr["fields"]["risk_level"], "High")
        self.assertTrue(self.cr["cab_required"])

    def test_why_now_leads_with_exploitation_not_with_score(self):
        justification = self.cr["fields"]["justification"]
        self.assertIn("known-exploited", justification)
        self.assertIn("internet-exposed", justification)
        self.assertIn("observed loaded at runtime", justification)

    def test_every_finding_in_the_group_is_named_for_traceability(self):
        description = self.cr["fields"]["description"]
        for finding_id in ("UPW-8801", "UPW-8802", "UPW-8803", "UPW-8804"):
            self.assertIn(finding_id, description)

    def test_it_answers_what_breaks_from_the_runtime_graph(self):
        self.assertIn("svc-checkout", self.cr["fields"]["description"])

    def test_it_answers_what_happens_if_we_do_nothing(self):
        self.assertIn("Risk acceptance is the system owner's decision",
                      self.cr["fields"]["description"])

    def test_config_items_are_enumerated_not_summarized(self):
        items = self.cr["fields"]["config_items"]
        for asset in ("prod-api-1", "prod-api-2", "prod-worker-1"):
            self.assertIn(asset, items)

    def test_the_implementation_plan_is_executable(self):
        plan = self.cr["fields"]["implementation_plan"]
        self.assertIn("Rebuild the application image", plan)
        self.assertIn("readiness probe", plan)

    def test_validation_closes_the_loop_back_to_upwind(self):
        self.assertIn("Re-scan in Upwind", self.cr["fields"]["validation_plan"])

    def test_the_backout_is_a_single_step_with_a_cost(self):
        backout = self.cr["fields"]["backout_plan"]
        self.assertIn("acme/base:1.22", backout)
        self.assertIn("No data migration", backout)

    def test_an_emergency_window_is_the_next_available_slot(self):
        start = rd._parse_time(self.cr["fields"]["scheduled_start"])
        self.assertLess((start - NOW).total_seconds() / 3600.0, 4)


class StandardAndNormalChanges(unittest.TestCase):

    def test_a_catalogued_non_production_fix_needs_no_cab(self):
        cr = build("CG-2")
        self.assertEqual(cr["change_class"], "standard")
        self.assertFalse(cr["cab_required"])
        self.assertEqual(cr["fields"]["risk_level"], "Low")

    def test_a_production_config_change_is_normal(self):
        cr = build("CG-3")
        self.assertEqual(cr["change_class"], "normal")
        self.assertTrue(cr["cab_required"])

    def test_a_config_change_records_the_prior_value_first(self):
        cr = build("CG-3")
        self.assertIn("Record the current value", cr["fields"]["implementation_plan"])
        self.assertIn("Restore the recorded previous value", cr["fields"]["backout_plan"])

    def test_no_runtime_exposure_says_so_plainly(self):
        # Present on disk, never loaded, not exposed, not exploited: this is
        # remediation on schedule, and the CR must not dress it up as urgent.
        group = {"id": "CG-X", "owner_team": "acme-data-eng", "environment": "staging",
                 "fix_type": "package_upgrade", "fix_target": "curl 8.4 -> 8.9",
                 "findings": ["F-9"], "assets": ["stg-1"], "cves": ["CVE-2026-9"],
                 "dependents": [], "priority": "P4", "change_class": "standard",
                 "class_rationale": "non-production and listed in the change catalogue",
                 "asset_count": 1,
                 "title": "package_upgrade: curl 8.4 -> 8.9 on 1 asset (staging)"}
        dormant = {"id": "F-9", "cve": "CVE-2026-9", "known_exploited": False,
                   "runtime": {"running": True, "package_loaded": False,
                               "internet_exposed": False}}
        cr = cc.build_cr(group, {"F-9": dormant}, {}, NOW, requested_by="r.otten")
        self.assertIn("remediation on schedule, not on urgency",
                      cr["fields"]["justification"])

    def test_no_observed_dependents_is_not_reported_as_proof(self):
        cr = build("CG-2")
        self.assertIn("Absence of an observed dependent is not proof",
                      cr["fields"]["description"])


class Windows(unittest.TestCase):

    def test_emergency_goes_soon(self):
        start, end = cc.window_for("emergency", NOW)
        self.assertEqual((start - NOW).total_seconds() / 3600.0, 2)
        self.assertGreater(end, start)

    def test_normal_waits_for_the_next_thursday_window(self):
        start, _end = cc.window_for("normal", NOW)
        self.assertEqual(start.weekday(), 3)
        self.assertEqual(start.hour, 22)
        self.assertGreater(start, NOW)

    def test_normal_never_schedules_into_the_past(self):
        for day in range(1, 15):
            now = datetime(2026, 9, day, 12, 0, tzinfo=timezone.utc)
            start, _ = cc.window_for("normal", now)
            self.assertGreater(start, now, "day %d" % day)

    def test_standard_goes_to_the_next_morning(self):
        start, _end = cc.window_for("standard", NOW)
        self.assertEqual(start.hour, 9)
        self.assertEqual(start.date(), datetime(2026, 9, 18).date())

    def test_an_explicit_window_overrides_everything(self):
        start, _end = cc.window_for("normal", NOW, "2026-10-01T03:00:00Z")
        self.assertEqual(start.isoformat(), "2026-10-01T03:00:00+00:00")


class Helpers(unittest.TestCase):

    def test_previous_target_is_read_out_of_the_fix_string(self):
        self.assertEqual(cc._previous_target("acme/base:1.22 -> 1.24"), "acme/base:1.22")
        self.assertEqual(cc._previous_target("libxml2 2.11.4 to 2.12.6"), "libxml2 2.11.4")
        self.assertEqual(cc._previous_target("enable public access block"),
                         "the current version")

    def test_impact_scales_with_the_number_of_assets(self):
        self.assertEqual(cc.impact_for(1, "staging"), "Low")
        self.assertEqual(cc.impact_for(5, "staging"), "Medium")
        self.assertEqual(cc.impact_for(40, "staging"), "High")

    def test_one_production_asset_is_never_low_impact(self):
        self.assertEqual(cc.impact_for(1, "production"), "Medium")

    def test_an_untemplated_fix_type_admits_it_has_no_backout(self):
        group = {"id": "CG-X", "owner_team": "t", "environment": "production",
                 "fix_type": "firmware_flash", "fix_target": "v2 -> v3",
                 "findings": ["F-1"], "assets": ["a1"], "cves": [], "dependents": [],
                 "priority": "P3", "change_class": "normal",
                 "class_rationale": "production change", "asset_count": 1,
                 "title": "firmware_flash: v2 -> v3 on 1 asset (production)"}
        cr = cc.build_cr(group, {"F-1": {}}, {}, NOW, requested_by="r.otten")
        self.assertFalse(cr["templated_backout"])
        self.assertIn("PLAN NOT TEMPLATED", cr["fields"]["backout_plan"])
        self.assertIn("backout for this fix type is not templated", cc.render_md(cr))


class Payload(unittest.TestCase):

    def test_the_default_map_produces_cherwell_field_entries(self):
        payload = cc.to_payload(build("CG-1"), cc.DEFAULT_FIELD_MAP)
        self.assertEqual(payload["busObName"], "ChangeRequest")
        self.assertTrue(payload["persist"])
        names = {field["name"] for field in payload["fields"]}
        self.assertIn("Title", names)
        self.assertIn("BackoutPlan", names)
        self.assertTrue(all(field["dirty"] for field in payload["fields"]))

    def test_an_instance_specific_map_renames_fields(self):
        field_map = dict(cc.DEFAULT_FIELD_MAP)
        field_map["backout_plan"] = "CustomBackout"
        names = {f["name"] for f in cc.to_payload(build("CG-1"), field_map)["fields"]}
        self.assertIn("CustomBackout", names)
        self.assertNotIn("BackoutPlan", names)

    def test_a_field_dropped_from_the_map_is_not_sent(self):
        field_map = dict(cc.DEFAULT_FIELD_MAP)
        field_map.pop("security_finding_ref")
        names = {f["name"] for f in cc.to_payload(build("CG-1"), field_map)["fields"]}
        self.assertNotIn("SecurityFindingRef", names)


class Rendering(unittest.TestCase):

    def test_the_raiser_is_told_not_to_approve_it(self):
        self.assertIn("never approves the change", cc.render_md(build("CG-1")))

    def test_the_header_carries_class_risk_and_cab(self):
        text = cc.render_md(build("CG-1"))
        self.assertIn("**Change class:** emergency", text)
        self.assertIn("**CAB required:** yes", text)

    def test_a_standard_change_says_it_is_pre_approved(self):
        self.assertIn("pre-approved standard change", cc.render_md(build("CG-2")))


class Credentials(unittest.TestCase):

    def test_it_refuses_without_credentials_and_names_them(self):
        saved = {key: os.environ.pop(key, None) for key in CRED_KEYS}
        try:
            with self.assertRaises(SystemExit) as caught:
                cc.credentials()
            message = str(caught.exception)
            self.assertIn("no usable credentials", message)
            self.assertIn("CHERWELL_BASE_URL", message)
        finally:
            for key, value in saved.items():
                if value is not None:
                    os.environ[key] = value

    def test_a_partial_credential_set_is_still_a_refusal(self):
        saved = {key: os.environ.pop(key, None) for key in CRED_KEYS}
        os.environ["CHERWELL_BASE_URL"] = "https://example.invalid"
        try:
            with self.assertRaises(SystemExit) as caught:
                cc.credentials()
            self.assertIn("CHERWELL_PASSWORD", str(caught.exception))
        finally:
            os.environ.pop("CHERWELL_BASE_URL", None)
            for key, value in saved.items():
                if value is not None:
                    os.environ[key] = value


class CommandLine(unittest.TestCase):

    def run_cli(self, *args):
        env = {k: v for k, v in os.environ.items() if k not in CRED_KEYS}
        return subprocess.run([sys.executable, SCRIPT] + list(args),
                              capture_output=True, text=True, env=env)

    def test_list_shows_every_group_with_its_class(self):
        result = self.run_cli(BUNDLE, "--list", "--now", "2026-09-17T09:00:00Z")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("CG-1  emergency", result.stdout)
        self.assertIn("CG-2  standard", result.stdout)
        self.assertIn("CG-3  normal", result.stdout)

    def test_a_single_group_renders_markdown(self):
        result = self.run_cli(BUNDLE, "--group", "CG-1", "--now", "2026-09-17T09:00:00Z")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("# image_rebuild", result.stdout)

    def test_all_renders_every_group(self):
        result = self.run_cli(BUNDLE, "--all", "--format", "json",
                              "--now", "2026-09-17T09:00:00Z")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count('"group_id"'), 3)

    def test_the_payload_format_is_valid_json(self):
        result = self.run_cli(BUNDLE, "--group", "CG-1", "--format", "payload",
                              "--now", "2026-09-17T09:00:00Z")
        payload = json.loads(result.stdout)
        self.assertEqual(payload["busObName"], "ChangeRequest")

    def test_an_unknown_group_is_refused_helpfully(self):
        result = self.run_cli(BUNDLE, "--group", "CG-99")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--list shows what there is", result.stderr)

    def test_choosing_nothing_is_refused(self):
        result = self.run_cli(BUNDLE)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--group", result.stderr)

    def test_submitting_without_credentials_fails_before_the_network(self):
        result = self.run_cli(BUNDLE, "--group", "CG-1", "--submit")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no usable credentials", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_a_bundle_with_no_upwind_section_is_refused(self):
        result = self.run_cli(os.path.join(ROOT, "test-data", "mailbox_export.json"),
                              "--list")
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
