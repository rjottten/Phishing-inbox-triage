"""The CSV importer, against the export shapes the Defender portal actually produces.

Column names vary by export view, portal version and locale, so the importer
discovers them. These tests pin that discovery, the value normalization, the
row-folding that makes campaign scope mean anything, and the honest placeholders
it uses instead of inventing data the export does not carry.

Offline and stdlib only, like the script: no install, no network, no credentials.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT_DIR = os.path.join(ROOT, "skills", "phishing-inbox-triage", "scripts")
sys.path.insert(0, SCRIPT_DIR)

import import_defender_csv as ic  # noqa: E402
import triage as tr  # noqa: E402

FIXTURES = os.path.join(ROOT, "tests", "fixtures")
SUBMISSIONS = os.path.join(FIXTURES, "submissions_export.csv")
EMAIL_EVENTS = os.path.join(FIXTURES, "email_events_export.csv")
SCRIPT = os.path.join(SCRIPT_DIR, "import_defender_csv.py")

VIPS = ["r.alvarez@contoso.com", "p.nakamura@contoso.com", "k.osei@contoso.com"]


def load(path, **kwargs):
    """The importer's own path from file to export, as the CLI runs it."""
    rows, headers = ic.read_rows(path)
    meta, items, mapping = ic.parse_rows(rows, headers, **kwargs)
    return meta, items, mapping


def by_id(items):
    return {it["id"]: it for it in items}


def rows_only(rows, headers, **kwargs):
    return ic.parse_rows(rows, headers, **kwargs)[1]


class TestColumnDiscovery(unittest.TestCase):
    """Nothing else works if the headers land on the wrong fields."""

    def test_maps_the_submissions_export_columns(self):
        mapping = ic.detect_mapping([
            "Submission ID", "Submission date", "Submitted by", "Submission type",
            "Subject", "Sender", "Recipient", "Status", "Result", "Network Message ID",
        ])
        self.assertTrue(mapping.usable)
        self.assertEqual(mapping.mapped["submission_id"], "Submission ID")
        self.assertEqual(mapping.mapped["from_address"], "Sender")
        self.assertEqual(mapping.mapped["received"], "Submission date")
        self.assertEqual(mapping.mapped["air_status"], "Status")
        self.assertEqual(mapping.mapped["verdict"], "Result")

    def test_maps_advanced_hunting_column_names(self):
        """EmailEvents uses PascalCase with no spaces."""
        mapping = ic.detect_mapping([
            "Timestamp", "NetworkMessageId", "SenderFromAddress", "SenderDisplayName",
            "RecipientEmailAddress", "Subject", "AuthenticationDetails",
        ])
        self.assertEqual(mapping.mapped["from_address"], "SenderFromAddress")
        self.assertEqual(mapping.mapped["from_name"], "SenderDisplayName")
        self.assertEqual(mapping.mapped["recipient"], "RecipientEmailAddress")
        self.assertEqual(mapping.mapped["received"], "Timestamp")

    def test_header_matching_ignores_case_spacing_and_punctuation(self):
        mapping = ic.detect_mapping(["  SENDER_ADDRESS ", "e-mail subject", "Submitted By"])
        self.assertEqual(mapping.mapped["from_address"], "  SENDER_ADDRESS ")
        self.assertEqual(mapping.mapped["reporter"], "Submitted By")

    def test_column_map_overrides_detection(self):
        """The escape hatch for a localized or renamed export — no code change."""
        mapping = ic.detect_mapping(
            ["Absender", "Betreff"],
            column_map={"from_address": "Absender", "subject": "Betreff"})
        self.assertEqual(mapping.mapped["from_address"], "Absender")
        self.assertEqual(mapping.mapped["subject"], "Betreff")
        self.assertIn("from_address", mapping.overrides)

    def test_a_count_column_is_never_read_as_a_filename(self):
        """'AttachmentCount' = 1 must not become an attachment named '1'."""
        mapping = ic.detect_mapping(["Subject", "Sender", "UrlCount", "AttachmentCount"])
        self.assertEqual(mapping.mapped.get("attachment_count"), "AttachmentCount")
        self.assertIsNone(mapping.mapped.get("attachments"))
        self.assertIsNone(mapping.mapped.get("urls"))

    def test_a_file_without_sender_or_subject_is_refused_with_guidance(self):
        with self.assertRaises(ic.CsvError) as ctx:
            ic.parse_rows([{"Colour": "red"}], ["Colour", "Size"])
        message = str(ctx.exception)
        self.assertIn("sender or subject", message)
        self.assertIn("--column-map", message, "the error must say how to fix it")
        self.assertIn("'Colour'", message, "the error must name the headers it found")


class TestFolding(unittest.TestCase):
    """A mail to many recipients exports one row per recipient."""

    def setUp(self):
        self.meta, self.items, _ = load(SUBMISSIONS, vip_list=VIPS)
        self.by_id = by_id(self.items)

    def test_rows_for_one_message_fold_into_one_item(self):
        """Six rows, four messages — otherwise a campaign reads as unrelated reports."""
        self.assertEqual(len(self.items), 4)
        self.assertEqual(self.by_id["SUB-77126"]["recipient_count"], 2)
        self.assertEqual(self.by_id["SUB-77131"]["recipient_count"], 2)

    def test_vip_recipients_are_found_across_folded_rows(self):
        self.assertEqual(set(self.by_id["SUB-77131"]["recipients_vip"]),
                         {"p.nakamura@contoso.com", "k.osei@contoso.com"})
        self.assertEqual(self.by_id["SUB-77126"]["recipients_vip"], ["r.alvarez@contoso.com"])

    def test_multiple_reporters_are_summarised(self):
        self.assertEqual(self.by_id["SUB-77131"]["reporter"], "multiple (2 reporters)")

    def test_items_are_ordered_oldest_first(self):
        received = [it["received"] for it in self.items]
        self.assertEqual(received, sorted(received))

    def test_window_is_derived_from_the_rows(self):
        self.assertTrue(self.meta["window"].startswith("2026-09-14T03:20:00"))

    def test_the_window_is_one_triage_py_can_read(self):
        """triage.py dates the run from export_meta.window; an unparseable one
        silently falls back to 'now', which ages every investigation wrongly."""
        self.assertIsNotNone(tr.window_end(self.meta))

    def test_rows_with_no_id_fold_on_sender_and_subject(self):
        items = rows_only(
            [{"Subject": "Same", "Sender": "a@b.example", "Recipient": "x@c.example"},
             {"Subject": "Same", "Sender": "a@b.example", "Recipient": "y@c.example"}],
            ["Subject", "Sender", "Recipient"])
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["recipient_count"], 2)

    def test_different_senders_do_not_fold_together(self):
        items = rows_only(
            [{"Subject": "Same", "Sender": "a@b.example"},
             {"Subject": "Same", "Sender": "c@d.example"}],
            ["Subject", "Sender"])
        self.assertEqual(len(items), 2)


class TestValueMapping(unittest.TestCase):
    """Defender's strings, in the vocabulary triage.py speaks."""

    def setUp(self):
        _, items, _ = load(SUBMISSIONS, vip_list=VIPS)
        self.by_id = by_id(items)

    def test_defender_result_strings_map_to_our_vocabulary(self):
        self.assertEqual(self.by_id["SUB-77124"]["defender"]["verdict"], "No threats found")
        self.assertEqual(self.by_id["SUB-77131"]["defender"]["verdict"], "Phishing")
        self.assertEqual(self.by_id["SUB-77126"]["defender"]["air_status"], "Running")
        self.assertEqual(self.by_id["SUB-77131"]["defender"]["air_status"], "Awaiting approval")

    def test_the_mapped_verdicts_are_ones_triage_py_recognises(self):
        """A verdict triage.py does not know is neither clean nor bad to it, so the
        item quietly stops being routed on Defender's outcome at all."""
        for item_id in ("SUB-77124", "SUB-77131"):
            verdict = tr.lower(self.by_id[item_id]["defender"]["verdict"])
            self.assertTrue(verdict in tr.CLEAN_VERDICTS or verdict in tr.BAD_VERDICTS,
                            f"{item_id}: {verdict!r} is in neither vocabulary")

    def test_the_mapped_statuses_are_ones_triage_py_recognises(self):
        known = tr.IN_PROGRESS | tr.AWAITING | tr.COMPLETED | tr.FAILED
        for item_id in ("SUB-77124", "SUB-77126", "SUB-77131", "SUB-77140"):
            status = tr.lower(self.by_id[item_id]["defender"]["air_status"])
            self.assertIn(status, known, item_id)

    def test_unrecognised_verdict_is_kept_not_guessed(self):
        """An unfamiliar verdict is passed through; inventing one would be worse."""
        items = rows_only(
            [{"Subject": "x", "Sender": "a@b.example", "Result": "Some New Verdict"}],
            ["Subject", "Sender", "Result"])
        self.assertEqual(items[0]["defender"]["verdict"], "Some New Verdict")

    def test_admin_submissions_keep_their_own_reporting_channel(self):
        """An admin submission has a real record and no reporter to coach."""
        self.assertEqual(self.by_id["SUB-77140"]["reported_via"], "admin_submission")

    def test_user_reports_are_read_as_the_report_button(self):
        self.assertEqual(self.by_id["SUB-77124"]["reported_via"], "outlook_report_button")
        self.assertIn(self.by_id["SUB-77124"]["reported_via"], tr.REPORT_BUTTON)

    def test_us_and_iso_date_formats_both_parse(self):
        self.assertIn("T03:20:00", self.by_id["SUB-77124"]["received"])
        _, events, _ = load(EMAIL_EVENTS)
        self.assertIn("T02:05:00", events[0]["received"])

    def test_notified_is_inferred_only_for_a_closed_submission(self):
        """The portal rarely exports the flag. Absent it, a finished investigation
        counts as notified and an unfinished one does not — guessing the other way
        would turn every open case into a fake 'reporter left in the dark' gap."""
        self.assertTrue(self.by_id["SUB-77124"]["defender"]["user_notified"])   # Completed
        self.assertFalse(self.by_id["SUB-77126"]["defender"]["user_notified"])  # In progress

    def test_an_exported_notified_column_wins_over_the_inference(self):
        items = rows_only(
            [{"Subject": "x", "Sender": "a@b.example", "Status": "Completed",
              "Result": "Phish", "User notified": "No"}],
            ["Subject", "Sender", "Status", "Result", "User notified"])
        self.assertFalse(items[0]["defender"]["user_notified"])


class TestPayloadAndAuth(unittest.TestCase):

    def test_counts_become_an_honest_placeholder_not_an_invented_name(self):
        _, items, _ = load(EMAIL_EVENTS)
        found = by_id(items)
        self.assertEqual(found["NMID-100"]["attachments"],
                         ["(1 attachment; filenames not included in this export)"])
        self.assertEqual(found["NMID-101"]["urls"],
                         ["(1 URL; addresses not included in this export)"])

    def test_urls_are_stored_defanged(self):
        items = rows_only(
            [{"Subject": "x", "Sender": "a@b.example", "URLs": "https://evil.example/login"}],
            ["Subject", "Sender", "URLs"])
        self.assertEqual(items[0]["urls"], ["hxxps://evil[.]example/login"])

    def test_a_defanged_url_is_left_alone(self):
        items = rows_only(
            [{"Subject": "x", "Sender": "a@b.example", "URLs": "hxxps://evil[.]example"}],
            ["Subject", "Sender", "URLs"])
        self.assertEqual(items[0]["urls"], ["hxxps://evil[.]example"])

    def test_authentication_details_json_blob_is_parsed(self):
        _, items, _ = load(EMAIL_EVENTS)
        self.assertEqual(by_id(items)["NMID-100"]["auth"],
                         {"spf": "pass", "dkim": "pass", "dmarc": "pass", "compauth": "pass"})

    def test_discrete_auth_columns_are_parsed(self):
        items = rows_only(
            [{"Subject": "x", "Sender": "a@b.example", "SPF": "fail", "DKIM": "none", "DMARC": "fail"}],
            ["Subject", "Sender", "SPF", "DKIM", "DMARC"])
        self.assertEqual(items[0]["auth"], {"spf": "fail", "dkim": "none", "dmarc": "fail"})

    def test_a_non_json_auth_blob_is_still_read(self):
        items = rows_only(
            [{"Subject": "x", "Sender": "a@b.example",
              "AuthenticationDetails": "SPF=fail; DKIM=none; DMARC=fail; compauth=fail"}],
            ["Subject", "Sender", "AuthenticationDetails"])
        self.assertEqual(items[0]["auth"]["spf"], "fail")
        self.assertEqual(items[0]["auth"]["dmarc"], "fail")


class TestCollectionNotes(unittest.TestCase):
    """What the export could not tell us has to be said, not left blank."""

    def test_the_export_says_what_it_does_not_carry(self):
        meta, _, _ = load(SUBMISSIONS)
        notes = " ".join(meta["collection_notes"])
        self.assertIn("reporter-notified flag", notes)
        self.assertIn("unrecognised column", notes)

    def test_a_missing_url_column_is_called_out_because_it_reads_as_bec(self):
        """triage.py reads an empty URL list as 'no link, so this could be BEC'.
        An export with no URL column must not look like an export with no URLs."""
        meta, _, _ = load(SUBMISSIONS)
        self.assertIn("URL inventory", " ".join(meta["collection_notes"]))

    def test_bodies_and_clicks_are_always_declared_missing(self):
        """No portal CSV carries them, whatever the columns say."""
        meta, _, _ = load(EMAIL_EVENTS)
        notes = " ".join(meta["collection_notes"])
        self.assertIn("message bodies", notes)
        self.assertIn("collect_export.py", notes, "say where to get them instead")

    def test_detected_columns_are_recorded_in_the_export(self):
        meta, _, _ = load(SUBMISSIONS)
        self.assertEqual(meta["columns_detected"]["from_address"], "Sender")


class TestFileHandling(unittest.TestCase):

    def temp_csv(self, text, binary=False):
        mode = "wb" if binary else "w"
        kwargs = {} if binary else {"encoding": "utf-8"}
        with tempfile.NamedTemporaryFile(mode, suffix=".csv", delete=False, **kwargs) as fh:
            fh.write(text)
        self.addCleanup(os.unlink, fh.name)
        return fh.name

    def test_empty_file_is_an_error(self):
        with self.assertRaises(ic.CsvError):
            ic.read_rows(self.temp_csv(""))

    def test_a_file_with_no_header_row_is_an_error(self):
        with self.assertRaises(ic.CsvError):
            ic.read_rows(self.temp_csv("\n\n"))

    def test_semicolon_delimited_export_is_read(self):
        """European Excel exports semicolon-delimited CSV."""
        path = self.temp_csv("Submission ID;Subject;Sender\nSUB-1;Hello;a@b.example\n")
        _, items, _ = load(path)
        self.assertEqual(items[0]["from_address"], "a@b.example")

    def test_tab_delimited_export_is_read(self):
        path = self.temp_csv("Submission ID\tSubject\tSender\nSUB-1\tHello\ta@b.example\n")
        _, items, _ = load(path)
        self.assertEqual(items[0]["from_address"], "a@b.example")

    def test_byte_order_mark_does_not_break_the_first_column(self):
        """Excel writes a BOM; without utf-8-sig the header becomes '\\ufeffSubmission ID'."""
        path = self.temp_csv(b"\xef\xbb\xbfSubmission ID,Subject,Sender\n"
                             b"SUB-1,Hello,a@b.example\n", binary=True)
        _, items, _ = load(path)
        self.assertEqual(items[0]["defender"]["submission_id"], "SUB-1")

    def test_blank_rows_are_skipped(self):
        path = self.temp_csv("Subject,Sender\nHello,a@b.example\n,\n\n")
        _, items, _ = load(path)
        self.assertEqual(len(items), 1)


class TestInspect(unittest.TestCase):

    def test_inspect_explains_the_mapping_and_the_leftovers(self):
        report = ic.inspect_report(SUBMISSIONS)
        self.assertIn("submission_id        <- 'Submission ID'", report)
        self.assertIn("Columns in the file that were not recognised:", report)
        self.assertIn("'Sender IP'", report)
        self.assertIn("Usable: yes", report)

    def test_inspect_says_so_when_a_file_is_unusable(self):
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, encoding="utf-8") as fh:
            fh.write("Colour,Size\nred,large\n")
        self.addCleanup(os.unlink, fh.name)
        self.assertIn("Usable: NO", ic.inspect_report(fh.name))


class TestCli(unittest.TestCase):
    """The script as an operator runs it."""

    def run_script(self, *args):
        return subprocess.run([sys.executable, SCRIPT] + list(args),
                              capture_output=True, text=True)

    def test_inspect_changes_nothing_and_exits_clean(self):
        proc = self.run_script(SUBMISSIONS, "--inspect")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Detected columns:", proc.stdout)

    def test_the_export_goes_to_stdout_as_json(self):
        proc = self.run_script(SUBMISSIONS)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(len(payload["items"]), 4)
        self.assertIn("collection_notes", payload["export_meta"])

    def test_collection_notes_reach_stderr_where_an_operator_sees_them(self):
        proc = self.run_script(SUBMISSIONS)
        self.assertIn("note:", proc.stderr)

    def test_an_unreadable_file_fails_with_a_message_not_a_traceback(self):
        proc = self.run_script(os.path.join(FIXTURES, "does-not-exist.csv"))
        self.assertEqual(proc.returncode, 2)
        self.assertIn("error:", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)

    def test_a_file_it_cannot_map_fails_with_a_message_not_a_traceback(self):
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, encoding="utf-8") as fh:
            fh.write("Colour,Size\nred,large\n")
        self.addCleanup(os.unlink, fh.name)
        proc = self.run_script(fh.name)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("sender or subject", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)

    def test_an_unknown_column_map_field_is_refused(self):
        proc = self.run_script(SUBMISSIONS, "--column-map", "nonsense=Sender IP")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("unknown field", proc.stderr)

    def test_a_malformed_column_map_is_refused(self):
        proc = self.run_script(SUBMISSIONS, "--column-map", "no-equals-sign")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("field=Header", proc.stderr)

    def test_column_map_on_the_command_line_is_applied(self):
        proc = self.run_script(SUBMISSIONS, "--column-map", "delivery_location=Sender IP", "--inspect")
        self.assertIn("delivery_location", proc.stdout)
        self.assertIn("(from column_map)", proc.stdout)


class TestEndToEnd(unittest.TestCase):
    """CSV in, handover report out — the whole reason the importer exists."""

    def setUp(self):
        self.ctx = {"org_domains": ["contoso.com"], "vip": VIPS}
        meta, items, _ = load(SUBMISSIONS, vip_list=VIPS, org_domains=["contoso.com"])
        self.meta, self.items = meta, items

    def triaged(self):
        ctx = tr.build_context(self.meta, None, (), ())
        ctx["org_domains"].add("contoso.com")
        ctx["vip"].update(VIPS)
        now = tr.window_end(self.meta)
        return {r["id"]: r for r in tr.triage(self.items, ctx, now=now)}

    def test_the_imported_queue_triages_without_error(self):
        results = self.triaged()
        self.assertEqual(len(results), 4)
        for result in results.values():
            self.assertIn(result["lane"],
                          {"exception", "automation_gap", "handled_by_automation"})

    def test_a_lookalike_sender_is_caught_from_csv_columns_alone(self):
        """No body, no headers — the sender domain is all the CSV gives, and it is
        enough. This is the whole claim the CSV path makes."""
        results = self.triaged()
        self.assertEqual(results["SUB-77131"]["lane"], "exception")
        self.assertIn("bec", results["SUB-77131"]["categories"])

    def test_a_vip_recipient_survives_the_fold_into_triage(self):
        results = self.triaged()
        self.assertIn("high_value_target", results["SUB-77126"]["categories"])

    def test_a_pending_remediation_becomes_a_decision_for_a_person(self):
        results = self.triaged()
        self.assertIn("remediation_decision", results["SUB-77131"]["categories"])

    def test_the_export_shape_matches_what_triage_py_loads(self):
        """load_export is the contract between the two scripts; a renamed key here
        shows up as an empty report rather than an error."""
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
            json.dump({"export_meta": self.meta, "items": self.items}, fh)
        self.addCleanup(os.unlink, fh.name)
        meta, items = tr.load_export(fh.name)
        self.assertEqual(len(items), 4)
        self.assertEqual(meta["source"], self.meta["source"])


class TestOffline(unittest.TestCase):

    def test_the_importer_imports_nothing_network_capable(self):
        """It is documented as safe to point at a real export. CI checks this too;
        the test is here so it fails before a push, not after one."""
        import ast
        with open(SCRIPT, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), SCRIPT)
        found = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                found.add(node.module.split(".")[0])
        network = {"urllib", "http", "socket", "requests", "httpx", "ftplib",
                   "smtplib", "telnetlib", "xmlrpc", "webbrowser", "asyncio"}
        self.assertEqual(found & network, set())


if __name__ == "__main__":
    unittest.main()
