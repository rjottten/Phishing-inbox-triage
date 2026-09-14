"""The lane, category and priority decisions — the part that has to be right.

Expectations come from `skills/phishing-inbox-triage/evals/evals.json`, which
describes what an analyst should get for the sample queue.
"""
from __future__ import annotations

import pytest

from phish_triage import Category, Config, Lane, Priority, triage_message
from phish_triage.models import DefenderState, ReportedMessage

EXPECTED_LANES = {
    "PHQ-1041": Lane.HANDLED,
    "PHQ-1042": Lane.HANDLED,
    "PHQ-1043": Lane.GAP,
    "PHQ-1044": Lane.EXCEPTION,
    "PHQ-1045": Lane.EXCEPTION,
    "PHQ-1046": Lane.EXCEPTION,
    "PHQ-1047": Lane.EXCEPTION,
    "PHQ-1048": Lane.EXCEPTION,
    "PHQ-1049": Lane.GAP,
    "PHQ-1050": Lane.HANDLED,
}

EXPECTED_PRIORITIES = {
    "PHQ-1044": Priority.P1,
    "PHQ-1045": Priority.P2,
    "PHQ-1046": Priority.P1,
    "PHQ-1047": Priority.P2,
    "PHQ-1048": Priority.P2,
}


@pytest.mark.parametrize(("item_id", "lane"), EXPECTED_LANES.items())
def test_lane_assignment(by_id, item_id, lane):
    assert by_id[item_id].lane is lane


@pytest.mark.parametrize(("item_id", "priority"), EXPECTED_PRIORITIES.items())
def test_exception_priorities(by_id, item_id, priority):
    assert by_id[item_id].priority is priority


def test_results_are_ordered_exceptions_first_then_priority(results):
    lanes = [r.lane for r in results]
    assert lanes == sorted(lanes, key=lambda x: {Lane.EXCEPTION: 0, Lane.GAP: 1, Lane.HANDLED: 2}[x])
    exceptions = [r.priority.value for r in results if r.lane is Lane.EXCEPTION]
    assert exceptions == sorted(exceptions)


def test_handled_items_are_not_re_triaged(by_id):
    """The failure mode this engine exists to prevent: re-working closed items."""
    for item_id in ("PHQ-1041", "PHQ-1042", "PHQ-1050"):
        result = by_id[item_id]
        assert result.categories == []
        assert result.actions == []


def test_bec_detected_on_lookalike_with_consumer_reply_to(by_id):
    result = by_id["PHQ-1044"]
    assert Category.BEC in result.categories
    codes = {f.code for f in result.findings}
    assert "lookalike_sender_domain" in codes
    assert "reply_to_mismatch" in codes


def test_reply_to_bec_is_p1_even_though_nothing_was_sent(by_id):
    """The reporter engaged with a live payment request. Money not yet moved is not
    the same as no exposure."""
    result = by_id["PHQ-1044"]
    assert result.priority is Priority.P1
    assert any(f.code == "replied_to_sender" for f in result.findings)


def test_credential_entry_and_mfa_approval_is_compromise(by_id):
    result = by_id["PHQ-1046"]
    codes = {f.code for f in result.findings}
    assert {"credentials_entered", "mfa_approved", "clicked_link"} <= codes
    assert result.priority is Priority.P1
    first_actions = [a.action.lower() for a in result.actions[:2]]
    assert any("revoke" in a for a in first_actions), "session revocation must come before mail actions"


def test_vendor_compromise_pattern_fires_on_its_own(by_id):
    """Real domain, real thread, DMARC pass — the bank change is the only tell."""
    result = by_id["PHQ-1047"]
    assert Category.BEC in result.categories
    codes = {f.code for f in result.findings}
    assert "thread_hijack_bank_change" in codes
    assert "reporter_contradicts_premise" in codes


def test_vendor_compromise_never_recommends_a_domain_block(by_id):
    actions = " ".join(a.action.lower() + " " + a.note.lower() for a in by_id["PHQ-1047"].actions)
    assert "do not block the domain" in actions
    assert "out-of-band" in actions


def test_attacker_controlled_lookalike_domain_block_is_fine(by_id):
    """Blocking contoso-people.com costs nothing; the caution is for real partners."""
    actions = " ".join(a.action.lower() + " " + a.note.lower() for a in by_id["PHQ-1048"].actions)
    assert "domain block" in actions
    assert "attacker-controlled" in actions


def test_vip_recipient_makes_it_an_exception(by_id):
    result = by_id["PHQ-1045"]
    assert Category.HIGH_VALUE_TARGET in result.categories
    assert any("r.alvarez@contoso.com" in f.detail for f in result.findings)


def test_stale_air_investigation_is_ambiguous(by_id):
    result = by_id["PHQ-1045"]
    assert Category.AMBIGUOUS in result.categories
    assert any(f.code == "air_stale" for f in result.findings)


def test_pending_actions_need_a_human_decision(by_id):
    result = by_id["PHQ-1048"]
    assert Category.REMEDIATION_DECISION in result.categories
    assert any(f.code == "large_purge_scope" for f in result.findings)


def test_clean_verdict_contradicted_by_evidence_is_flagged(by_id):
    for item_id in ("PHQ-1044", "PHQ-1047"):
        result = by_id[item_id]
        assert any(f.code == "disagree_with_air" for f in result.findings), item_id


def test_forwarded_reports_are_process_gaps_not_security_exceptions(by_id):
    for item_id in ("PHQ-1043", "PHQ-1049"):
        result = by_id[item_id]
        assert result.lane is Lane.GAP
        actions = " ".join(a.action.lower() for a in result.actions)
        assert "submit the message to microsoft" in actions
        assert "report button" in actions


def test_gap_item_with_a_credential_lure_still_gets_the_url_blocked(by_id):
    actions = " ".join(a.action.lower() for a in by_id["PHQ-1043"].actions)
    assert "block the url" in actions


def test_injection_text_is_recorded_as_an_indicator_and_not_obeyed(by_id):
    """PHQ-1043's body tells reviewers to mark it clean. It must not work."""
    result = by_id["PHQ-1043"]
    injections = [f for f in result.findings if f.code == "prompt_injection_attempt"]
    assert injections, "reviewer-directed text must be detected"
    assert result.lane is not Lane.HANDLED
    assert any("not obeyed" in f.detail for f in injections)


def test_no_action_is_ever_executed(results):
    """Structural guarantee: the engine returns recommendations with owners, nothing else."""
    for result in results:
        for action in result.actions:
            assert action.owner, f"{result.message.id}: {action.action} has no decision owner"


def test_clean_internal_mail_stays_handled():
    """A legitimate internal notice with DMARC pass must not become an exception."""
    msg = ReportedMessage(
        id="T-1",
        reporter="a@example.com",
        reported_via="outlook_report_button",
        from_name="Example Benefits",
        from_address="noreply@benefits.example.com",
        subject="Open enrollment starts October 1",
        body_excerpt="Open enrollment begins October 1. Log in via the intranet to review options.",
        auth={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        recipient_count=2300,
        defender=DefenderState("SUB-1", "Completed", "No threats found", True, "None"),
    )
    result = triage_message(msg, Config(org_domain="example.com"))
    assert result.lane is Lane.HANDLED
    assert result.categories == []


def test_money_request_alone_is_not_bec():
    """One signal is not a pattern. A real invoice from a real domain stays quiet."""
    msg = ReportedMessage(
        id="T-2",
        reporter="ap@example.com",
        reported_via="outlook_report_button",
        from_name="Contoso Billing",
        from_address="billing@contoso-billing.example",
        subject="Invoice 4471 attached",
        body_excerpt="Please find invoice 4471 for payment on the usual terms.",
        auth={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        defender=DefenderState("SUB-2", "Completed", "No threats found", True, "None"),
    )
    result = triage_message(msg, Config(org_domain="example.com"))
    assert Category.BEC not in result.categories


def test_known_partner_flagged_as_phishing_is_ambiguous_not_a_block():
    """False positives against real vendors cause their own damage."""
    msg = ReportedMessage(
        id="T-3",
        reporter="a@example.com",
        reported_via="outlook_report_button",
        from_name="Northwind",
        from_address="noreply@northwind.example",
        subject="Your monthly statement",
        body_excerpt="Your statement is ready.",
        auth={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        defender=DefenderState("SUB-3", "Completed", "Phishing", True, "Soft delete"),
    )
    config = Config(org_domain="example.com", known_partner_domains=["northwind.example"])
    result = triage_message(msg, config)
    assert Category.AMBIGUOUS in result.categories
    assert any(f.code == "possible_false_positive" for f in result.findings)


def test_negated_interaction_is_not_counted():
    msg = ReportedMessage(
        id="T-4",
        reporter="a@example.com",
        reported_via="outlook_report_button",
        from_address="x@bad.example",
        subject="Verify your account",
        body_excerpt="Sign in to verify.",
        urls=["hxxps://bad[.]example/verify"],
        reporter_note="I did not click and I never entered my password.",
        defender=DefenderState("SUB-4", "Completed", "Phishing", True, "Soft delete"),
    )
    result = triage_message(msg, Config(org_domain="example.com"))
    assert Category.USER_INTERACTION not in result.categories


def test_uncertain_reporter_becomes_an_unverified_item_not_an_assumption(by_id):
    result = by_id["PHQ-1045"]
    assert any("unsure" in u.lower() for u in result.unverified)
