"""The CSV importer, against the export shapes the Defender portal actually produces.

Column names vary by export view, portal version and locale, so the importer
discovers them. These tests pin that discovery, the value normalization, and the
row-folding that makes campaign scope mean anything.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from phish_triage import Category, Config, Lane, triage
from phish_triage.sources.defender_csv import (
    DefenderCsvError,
    detect_mapping,
    inspect,
    load_queue,
    parse_rows,
)

FIXTURES = Path(__file__).parent / "fixtures"
SUBMISSIONS = FIXTURES / "submissions_export.csv"
EMAIL_EVENTS = FIXTURES / "email_events_export.csv"


@pytest.fixture(scope="module")
def submissions_queue():
    return load_queue(
        SUBMISSIONS,
        vip_list=["r.alvarez@contoso.com", "p.nakamura@contoso.com", "k.osei@contoso.com"],
        org_domain="contoso.com",
    )


def test_maps_the_submissions_export_columns():
    mapping = detect_mapping([
        "Submission ID", "Submission date", "Submitted by", "Submission type",
        "Subject", "Sender", "Recipient", "Status", "Result", "Network Message ID",
    ])
    assert mapping.usable
    assert mapping.mapped["submission_id"] == "Submission ID"
    assert mapping.mapped["from_address"] == "Sender"
    assert mapping.mapped["received"] == "Submission date"
    assert mapping.mapped["air_status"] == "Status"
    assert mapping.mapped["verdict"] == "Result"


def test_maps_advanced_hunting_column_names():
    """EmailEvents uses PascalCase with no spaces."""
    mapping = detect_mapping([
        "Timestamp", "NetworkMessageId", "SenderFromAddress", "SenderDisplayName",
        "RecipientEmailAddress", "Subject", "AuthenticationDetails",
    ])
    assert mapping.mapped["from_address"] == "SenderFromAddress"
    assert mapping.mapped["from_name"] == "SenderDisplayName"
    assert mapping.mapped["recipient"] == "RecipientEmailAddress"
    assert mapping.mapped["received"] == "Timestamp"


def test_header_matching_ignores_case_spacing_and_punctuation():
    mapping = detect_mapping(["  SENDER_ADDRESS ", "e-mail subject", "Submitted By"])
    assert mapping.mapped["from_address"] == "  SENDER_ADDRESS "
    assert mapping.mapped["reporter"] == "Submitted By"


def test_config_column_map_overrides_detection():
    """The escape hatch for a localized or renamed export — no code change."""
    mapping = detect_mapping(["Absender", "Betreff"], column_map={"from_address": "Absender", "subject": "Betreff"})
    assert mapping.mapped["from_address"] == "Absender"
    assert mapping.mapped["subject"] == "Betreff"
    assert "from_address" in mapping.overrides


def test_a_count_column_is_never_read_as_a_filename():
    """'AttachmentCount' = 1 must not become an attachment named '1'."""
    mapping = detect_mapping(["Subject", "Sender", "UrlCount", "AttachmentCount"])
    assert mapping.mapped.get("attachment_count") == "AttachmentCount"
    assert mapping.mapped.get("attachments") is None
    assert mapping.mapped.get("urls") is None


def test_counts_become_an_honest_placeholder_not_an_invented_name():
    queue = load_queue(EMAIL_EVENTS, org_domain="contoso.com")
    by_id = {m.id: m for m in queue.items}
    assert by_id["NMID-100"].attachments == ["(1 attachment; filenames not included in this export)"]
    assert by_id["NMID-100"].has_payload
    assert by_id["NMID-101"].urls == ["(1 URL; addresses not included in this export)"]


def test_rows_for_one_message_fold_into_one_item(submissions_queue):
    """A mail to many recipients exports one row per recipient. Six rows, four
    messages — otherwise a campaign reads as unrelated single reports."""
    assert len(submissions_queue) == 4
    by_id = {m.id: m for m in submissions_queue.items}
    assert by_id["SUB-77126"].recipient_count == 2
    assert by_id["SUB-77131"].recipient_count == 2


def test_vip_recipients_are_found_across_folded_rows(submissions_queue):
    by_id = {m.id: m for m in submissions_queue.items}
    assert set(by_id["SUB-77131"].recipients_vip) == {"p.nakamura@contoso.com", "k.osei@contoso.com"}
    assert by_id["SUB-77126"].recipients_vip == ["r.alvarez@contoso.com"]


def test_multiple_reporters_are_summarised(submissions_queue):
    by_id = {m.id: m for m in submissions_queue.items}
    assert by_id["SUB-77131"].reporter == "multiple (2 reporters)"


def test_defender_result_strings_map_to_our_vocabulary(submissions_queue):
    by_id = {m.id: m for m in submissions_queue.items}
    assert by_id["SUB-77124"].defender.verdict == "No threats found"   # "Not junk"
    assert by_id["SUB-77131"].defender.verdict == "Phishing"           # "Phish"
    assert by_id["SUB-77126"].defender.air_status == "Running"         # "In progress"
    assert by_id["SUB-77131"].defender.air_status == "Awaiting approval"


def test_unrecognised_verdict_is_kept_not_guessed():
    """An unfamiliar verdict is passed through; inventing one would be worse."""
    queue = parse_rows(
        [{"Subject": "x", "Sender": "a@b.example", "Result": "Some New Verdict"}],
        ["Subject", "Sender", "Result"],
    )
    assert queue.items[0].defender.verdict == "Some New Verdict"


def test_admin_submissions_are_not_mistaken_for_a_reporting_gap(submissions_queue):
    """An admin submission has a real record and no reporter to coach."""
    result = next(r for r in triage(submissions_queue, Config(org_domain="contoso.com")) if r.message.id == "SUB-77140")
    codes = {f.code for f in result.findings}
    assert "not_reported_via_button" not in codes
    assert "submission_missing" not in codes


def test_us_and_iso_date_formats_both_parse(submissions_queue):
    received = {m.id: m.received for m in submissions_queue.items}
    assert received["SUB-77124"].hour == 3          # 9/14/2026 3:20:00 AM
    assert load_queue(EMAIL_EVENTS).items[0].received.hour == 2   # 2026-09-14T02:05:00Z


def test_window_is_derived_from_the_rows(submissions_queue):
    assert submissions_queue.window.startswith("2026-09-14T03:20:00")


def test_queue_reports_what_the_export_does_not_carry(submissions_queue):
    """A lane decision made on missing data is a guess — say what was absent."""
    missing = " ".join(submissions_queue.missing_sources)
    assert "reporter-notified flag" in missing
    assert "unrecognised column" in missing


def test_urls_are_stored_defanged():
    queue = parse_rows(
        [{"Subject": "x", "Sender": "a@b.example", "URLs": "https://evil.example/login"}],
        ["Subject", "Sender", "URLs"],
    )
    assert queue.items[0].urls == ["hxxps://evil[.]example/login"]


def test_authentication_details_json_blob_is_parsed():
    queue = load_queue(EMAIL_EVENTS)
    by_id = {m.id: m for m in queue.items}
    assert by_id["NMID-100"].auth == {"spf": "pass", "dkim": "pass", "dmarc": "pass", "compauth": "pass"}


def test_discrete_auth_columns_are_parsed():
    queue = parse_rows(
        [{"Subject": "x", "Sender": "a@b.example", "SPF": "fail", "DKIM": "none", "DMARC": "fail"}],
        ["Subject", "Sender", "SPF", "DKIM", "DMARC"],
    )
    assert queue.items[0].auth == {"spf": "fail", "dkim": "none", "dmarc": "fail"}


def test_the_imported_queue_triages_end_to_end(submissions_queue):
    results = triage(submissions_queue, Config(org_domain="contoso.com"))
    by_id = {r.message.id: r for r in results}
    assert by_id["SUB-77131"].lane is Lane.EXCEPTION
    assert Category.REMEDIATION_DECISION in by_id["SUB-77131"].categories
    assert Category.HIGH_VALUE_TARGET in by_id["SUB-77126"].categories
    assert Category.BEC in by_id["SUB-77124"].categories


def test_a_file_without_sender_or_subject_fails_with_guidance(tmp_path):
    bad = tmp_path / "wrong.csv"
    bad.write_text("Colour,Size\nred,large\n")
    with pytest.raises(DefenderCsvError) as exc:
        load_queue(bad)
    message = str(exc.value)
    assert "sender or subject" in message
    assert "column_map" in message, "the error must say how to fix it"
    assert "'Colour'" in message, "the error must name the headers it actually found"


def test_empty_file_is_an_error(tmp_path):
    empty = tmp_path / "empty.csv"
    empty.write_text("")
    with pytest.raises(DefenderCsvError, match="empty"):
        load_queue(empty)


def test_semicolon_delimited_export_is_read(tmp_path):
    """European Excel exports semicolon-delimited CSV."""
    path = tmp_path / "eu.csv"
    path.write_text("Submission ID;Subject;Sender\nSUB-1;Hello;a@b.example\n")
    queue = load_queue(path)
    assert queue.items[0].from_address == "a@b.example"


def test_byte_order_mark_does_not_break_the_first_column(tmp_path):
    """Excel writes a BOM; without utf-8-sig the first header becomes '\\ufeffSubmission ID'."""
    path = tmp_path / "bom.csv"
    path.write_bytes(b"\xef\xbb\xbfSubmission ID,Subject,Sender\nSUB-1,Hello,a@b.example\n")
    queue = load_queue(path)
    assert queue.items[0].defender.submission_id == "SUB-1"


def test_blank_rows_are_skipped(tmp_path):
    path = tmp_path / "blanks.csv"
    path.write_text("Subject,Sender\nHello,a@b.example\n,\n\n")
    assert len(load_queue(path)) == 1


def test_inspect_explains_the_mapping_and_the_leftovers():
    report = inspect(SUBMISSIONS)
    assert "submission_id        <- 'Submission ID'" in report
    assert "Columns in the file that were not recognised:" in report
    assert "'Sender IP'" in report
    assert "Usable: yes" in report
