"""The report is the product. These tests guard what an analyst sees."""
from __future__ import annotations

import json
import re

from phish_triage.models import Lane
from phish_triage.report import shift_report, single_message, summary_counts, to_json


def test_summary_counts_match_the_queue(results):
    counts = summary_counts(results)
    assert counts == {"total": 10, "exceptions": 5, "gaps": 2, "handled": 3, "p1": 2, "p2": 3, "p3": 0}


def test_report_leads_with_the_summary_line(results, queue):
    body = shift_report(results, queue)
    assert body.startswith("# Phishing queue —")
    assert "**Queue:** 10 items · **Exceptions:** 5 (2 P1, 3 P2, 0 P3)" in body


def test_report_names_its_data_sources(results, queue):
    assert "**Data sources:** phishing@contoso.com shared mailbox" in shift_report(results, queue)


def test_exceptions_come_before_gaps_and_handled(results, queue):
    body = shift_report(results, queue)
    assert body.index("## Exceptions needing an analyst") < body.index("## Automation gaps") < body.index("## Handled by automation")


def test_p1_items_are_first_in_the_table(results, queue):
    table = shift_report(results, queue).split("### Exception details")[0]
    rows = [line for line in table.splitlines() if line.startswith("| ") and " P1 " in line or " P2 " in line]
    priorities = [r.split("|")[2].strip() for r in rows]
    assert priorities == sorted(priorities)


def test_urls_are_never_rendered_clickable(results, queue):
    body = shift_report(results, queue)
    assert "https://" not in body.replace("https://claude", "")
    assert "hxxps" in body


def test_handled_items_get_a_line_not_a_re_analysis(results, queue):
    handled = shift_report(results, queue).split("## Handled by automation")[1]
    assert "no analyst action needed. Not re-triaged." in handled
    assert "Recommended actions" not in handled.split("## ")[0]


def test_injection_attempts_get_their_own_section(results, queue):
    body = shift_report(results, queue)
    assert "## Content inside reported messages aimed at the reviewer" in body
    assert "No instruction found inside a reported message changed any verdict" in body
    assert "PHQ-1043" in body.split("## Content inside reported messages")[1]


def test_report_states_that_nothing_was_executed(results, queue):
    assert "none were executed" in shift_report(results, queue)


def test_pipes_in_a_subject_cannot_break_the_table(results, queue):
    """Subjects are attacker-chosen; a bare pipe would forge table columns."""
    results[0].message.subject = "Urgent | wire | today"
    body = shift_report(results, queue)
    row = next(line for line in body.splitlines() if "Urgent" in line and line.startswith("|"))
    assert "\\|" in row, "the pipes in the subject must be escaped"
    unescaped = len(re.findall(r"(?<!\\)\|", row))
    assert unescaped == 8, f"forged table columns: {row}"


def test_single_message_format(by_id):
    body = single_message(by_id["PHQ-1044"])
    assert body.startswith("**Lane:** Exception — User interaction / compromise, BEC / impersonation, Ambiguous (P1)")
    assert "**Evidence**" in body
    assert "**Recommended actions (in order — recommendations, not executed)**" in body
    assert "**Decision owner:**" in body


def test_json_output_is_machine_readable(results, queue):
    payload = json.loads(to_json(results, queue))
    assert payload["summary"]["exceptions"] == 5
    assert len(payload["items"]) == 10
    first = payload["items"][0]
    assert first["lane"] == Lane.EXCEPTION.value
    assert first["recommended_actions"][0]["owner"]


def test_missing_sources_are_surfaced(results, queue):
    queue.missing_sources = ["Defender Submissions (403)"]
    try:
        assert "**not available:** Defender Submissions (403)" in shift_report(results, queue)
    finally:
        queue.missing_sources = []


def test_gaps_table_stays_scannable(results, queue):
    """The Issue column describes the process failure; lure detail goes below it."""
    gaps = shift_report(results, queue).split("## Automation gaps")[1].split("## Handled")[0]
    row = next(line for line in gaps.splitlines() if line.startswith("| PHQ-1043"))
    assert "Report button" in row
    assert "Credential-harvest lure" not in row
    assert "**PHQ-1043** also carries:" in gaps
    assert "Credential-harvest lure" in gaps


def test_legitimate_broadcast_is_not_reported_as_a_campaign(results, queue):
    """PHQ-1042 reached 2,300 mailboxes and is real internal mail. Not a campaign."""
    trends = shift_report(results, queue).split("## Trends and notes")[1]
    assert "PHQ-1048" in trends, "the 412-mailbox phish is a campaign"
    assert "PHQ-1042" not in trends


def test_injection_matches_collapse_into_one_finding(by_id):
    findings = [f for f in by_id["PHQ-1043"].findings if f.code == "prompt_injection_attempt"]
    assert len(findings) == 1
    assert findings[0].detail.count("recorded as a malicious indicator") == 1
