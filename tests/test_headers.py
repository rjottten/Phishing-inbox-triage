"""Header parsing and the tells it exists to surface."""
from __future__ import annotations

from phish_triage.headers import is_lookalike, parse, registrable_label, sending_host

BEC_HEADERS = """From: "Dana Whitfield (CFO)" <dwhitfield@contoso-finance.co>
Reply-To: dana.whitfield.cfo@gmail.com
Return-Path: bounce@mailer-x.example
To: ap-team@contoso.com
Subject: Urgent wire - vendor payment today
Date: Sun, 14 Sep 2026 03:20:00 +0000
Message-ID: <abc123@contoso-finance.co>
Authentication-Results: spf=pass smtp.mailfrom=contoso-finance.co; dkim=pass header.d=contoso-finance.co; dmarc=none header.from=contoso-finance.co; compauth=pass reason=100
X-Forefront-Antispam-Report: CIP:203.0.113.9;CTRY:NG;SCL:1;SFV:NSPM;DIR:INB
Received: from mail.contoso-finance.co (203.0.113.9) by eu-protection.outlook.com; Sun, 14 Sep 2026 03:20:00 +0000
"""


def test_extracts_identities_and_auth():
    parsed = parse(BEC_HEADERS, org_domain="contoso.com")
    assert parsed["from"]["address"] == "dwhitfield@contoso-finance.co"
    assert parsed["reply_to"]["address"] == "dana.whitfield.cfo@gmail.com"
    assert parsed["authentication"] == {
        "spf": "pass", "dkim": "pass", "dmarc": "none",
        "compauth": "pass", "dkim_header_from": "contoso-finance.co", "compauth_reason": "100",
    }
    assert parsed["antispam"]["CIP"] == "203.0.113.9"
    assert parsed["antispam"]["CTRY"] == "NG"


def test_flags_the_bec_tells():
    flags = set(parse(BEC_HEADERS, org_domain="contoso.com")["flags"])
    assert {"reply_to_different_domain", "reply_to_consumer_domain", "return_path_different_domain",
            "dmarc_none", "urgency_or_finance_subject", "sender_domain_lookalike_of_org"} <= flags


def test_authentication_passing_does_not_clear_a_lookalike():
    """SPF and DKIM pass here because the attacker owns the domain. The lookalike
    flag is the point — auth results alone never settle BEC."""
    parsed = parse(BEC_HEADERS, org_domain="contoso.com")
    assert parsed["authentication"]["spf"] == "pass"
    assert "sender_domain_lookalike_of_org" in parsed["flags"]


def test_display_name_mismatch_flagged():
    flags = parse('From: "Mark Chen" <billing@unrelated.example>\n')["flags"]
    assert "display_name_address_mismatch" in flags


def test_no_flags_on_ordinary_internal_mail():
    flags = parse(
        "From: Contoso Benefits <noreply@benefits.contoso.com>\n"
        "Subject: Open enrollment starts October 1\n"
        "Authentication-Results: spf=pass; dkim=pass; dmarc=pass\n",
        org_domain="contoso.com",
    )["flags"]
    assert flags == []


def test_auth_failures_are_flagged():
    flags = parse("From: a@b.example\nAuthentication-Results: spf=fail; dkim=none; dmarc=fail; compauth=fail\n")["flags"]
    assert {"spf_fail", "dmarc_fail", "compauth_fail"} <= set(flags)


def test_allow_rule_bypass_is_flagged():
    """SFV:SKN means a tenant allow rule skipped filtering — worth knowing."""
    flags = parse("From: a@b.example\nX-Forefront-Antispam-Report: SFV:SKN;SCL:-1\n")["flags"]
    assert "filter_skipped_by_allow_rule" in flags


def test_lookalike_detection():
    assert is_lookalike("contoso-finance.co", "contoso.com")
    assert is_lookalike("contoso-people.com", "contoso.com")
    assert not is_lookalike("benefits.contoso.com", "contoso.com")
    assert not is_lookalike("contoso.com", "contoso.com")
    assert not is_lookalike("northwind-logistics.com", "contoso.com")


def test_registrable_label_handles_two_part_tlds():
    assert registrable_label("contoso.co.uk") == "contoso"
    assert registrable_label("mail.contoso.com") == "contoso"


def test_empty_input_does_not_crash():
    parsed = parse("")
    assert parsed["from"]["address"] == ""
    assert parsed["flags"] == []


SINGLE_EXTERNAL_HOP = """From: "Accounts Payable" <ap@acme-invoices.example>
Subject: Updated remittance details
Received: from mail.acme-invoices.example (mail.acme-invoices.example [203.0.113.9])
 by contoso-com.mail.protection.outlook.com; Mon, 14 Sep 2026 00:31:02 +0000
"""


def test_first_external_hop_is_found_on_the_boundary_hop():
    """The external sender hands off *to* Microsoft, so 'protection.outlook.com'
    appears in that hop's `by` clause. Matching the whole line skipped exactly the
    hop that matters and reported None for every ordinary inbound phish."""
    hop = parse(SINGLE_EXTERNAL_HOP)["first_external_hop"]
    assert hop is not None, "the one external hop must not be skipped"
    assert "mail.acme-invoices.example" in hop


def test_sending_host_reads_the_from_clause_not_the_by_clause():
    assert sending_host("from mail.evil.example (1.2.3.4) by x.protection.outlook.com") == "mail.evil.example"


def test_hop_without_a_from_clause_identifies_no_sender():
    """A hop that names no sender is skipped rather than guessed at."""
    assert sending_host("by contoso-com.mail.protection.outlook.com; Mon, 14 Sep 2026") == ""


def test_internal_only_mail_has_no_external_hop():
    raw = (
        "From: hr@contoso.com\nSubject: hi\n"
        "Received: from CO1PR.namprd.prod.protection.outlook.com by "
        "CO2PR.namprd.prod.protection.outlook.com; Mon, 14 Sep 2026 00:31:02 +0000\n"
    )
    assert parse(raw)["first_external_hop"] is None
