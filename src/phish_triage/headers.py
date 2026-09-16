#!/usr/bin/env python3
"""Parse raw email headers into triage-relevant JSON.

Usage:
    python parse_headers.py headers.txt
    python parse_headers.py --org-domain contoso.com headers.txt
    cat headers.txt | python parse_headers.py

Extracts sender identities (From, Reply-To, Return-Path), authentication results
(SPF, DKIM, DMARC, compauth), Microsoft anti-spam markers, the Received chain, and
flags the common phishing/BEC tells (display-name vs address mismatch, Reply-To to a
different domain, auth failures, consumer-domain Reply-To, lookalike of the org
domain). Read-only; never touches the network, never follows a URL.

This file is dependency-free on purpose: it is both `phish_triage.headers` and the
standalone `scripts/parse_headers.py` shipped inside the Claude skill. Keep it that
way — `tools/sync_skill.py` copies it verbatim and a test asserts the two match.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from email import policy
from email.parser import HeaderParser
from email.utils import parseaddr

CONSUMER_DOMAINS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "yahoo.com", "aol.com", "icloud.com", "protonmail.com", "proton.me", "gmx.com",
}

FOREFRONT_KEYS = ("CIP", "CTRY", "SCL", "BCL", "SFV", "SRV", "PTR", "SFTY", "DIR", "IPV", "SFS")

URGENCY_SUBJECT_RE = re.compile(
    r"\b(urgent|immediately|asap|wire|invoice|payment|remittance|verify|verification|"
    r"suspended|expires?|password|mfa|gift ?card|payroll|bank details)\b",
    re.IGNORECASE,
)


def domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""


def registrable_label(domain: str) -> str:
    """Rough 'brand' label of a domain: contoso.co.uk -> contoso, mail.contoso.com -> contoso.

    Not a public-suffix implementation; good enough to spot contoso-finance.co next to
    contoso.com. Where exactness matters, the analyst checks the domain themselves.
    """
    parts = [p for p in domain.lower().split(".") if p]
    if len(parts) < 2:
        return domain.lower()
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in {"co", "com", "org", "net", "gov", "ac"}:
        return parts[-3]
    return parts[-2]


def is_lookalike(candidate: str, org_domain: str) -> bool:
    """True when `candidate` borrows the org's brand without being the org's domain."""
    if not candidate or not org_domain or candidate == org_domain:
        return False
    if candidate.endswith("." + org_domain):
        return False
    org_label = registrable_label(org_domain)
    if len(org_label) < 4:
        return False
    cand_label = registrable_label(candidate)
    return org_label in cand_label or org_label in candidate.split(".")[0]


def parse_auth_results(value: str) -> dict:
    """Pull spf/dkim/dmarc/compauth results out of an Authentication-Results header."""
    out: dict[str, str] = {}
    if not value:
        return out
    for mech in ("spf", "dkim", "dmarc", "compauth"):
        m = re.search(rf"\b{mech}=(\w+)", value, re.IGNORECASE)
        if m:
            out[mech] = m.group(1).lower()
    m = re.search(r"header\.from=([\w.\-]+)", value, re.IGNORECASE)
    if m:
        out["dkim_header_from"] = m.group(1).lower()
    m = re.search(r"reason=(\d+)", value)
    if m:
        out["compauth_reason"] = m.group(1)
    return out


def sending_host(hop: str) -> str:
    """The host in a Received header's `from` clause, lowercased.

    Only the sender identifies where a hop came from. Matching the whole header
    catches the `by` clause too, which makes every inbound hop look like
    Microsoft and hides the one hop that matters.
    """
    match = re.match(r"from\s+(\S+)", hop, re.IGNORECASE)
    return match.group(1).lower() if match else ""


def parse_forefront(value: str) -> dict:
    """X-Forefront-Antispam-Report is ;-separated KEY:VALUE pairs."""
    out: dict[str, str] = {}
    if not value:
        return out
    for part in value.split(";"):
        if ":" not in part:
            continue
        k, v = part.split(":", 1)
        k, v = k.strip(), v.strip()
        if k in FOREFRONT_KEYS:
            out[k] = v
    return out


def parse(raw: str, org_domain: str = "") -> dict:
    """Parse raw headers into the triage dict. Pure; no I/O."""
    msg = HeaderParser(policy=policy.compat32).parsestr(raw)

    from_name, from_addr = parseaddr(msg.get("From", ""))
    reply_name, reply_addr = parseaddr(msg.get("Reply-To", ""))
    _, return_path = parseaddr(msg.get("Return-Path", ""))
    from_dom, reply_dom, rp_dom = domain_of(from_addr), domain_of(reply_addr), domain_of(return_path)

    auth: dict[str, str] = {}
    for value in msg.get_all("Authentication-Results", []):
        for key, val in parse_auth_results(value).items():
            auth.setdefault(key, val)
    forefront = parse_forefront(msg.get("X-Forefront-Antispam-Report", ""))

    hops = [re.sub(r"\s+", " ", h).strip() for h in (msg.get_all("Received", []) or [])]
    # Match the sending host, not the whole line: on the boundary hop the external
    # sender hands off *to* Microsoft, so "protection.outlook.com" appears in the `by`
    # clause. Testing the whole header skipped exactly the hop that matters and
    # reported None for the ordinary single-external-sender case — every inbound phish.
    # A hop with no `from` clause identifies no sender, so it is skipped, not guessed at.
    first_external = next(
        (h for h in reversed(hops)
         if sending_host(h) and "protection.outlook.com" not in sending_host(h)),
        None,
    )

    flags: list[str] = []
    clean_name = re.sub(r"\(.*?\)|\[.*?\]|,.*$", "", from_name).strip()
    name_tokens = [t.lower() for t in re.split(r"[\s.]+", clean_name) if len(t) > 1]
    if name_tokens and from_addr and not any(t in from_addr.lower() for t in name_tokens):
        # display name shares no token with the address: "Mark Chen" <billing@random.net>
        flags.append("display_name_address_mismatch")
    if reply_addr and reply_dom != from_dom:
        flags.append("reply_to_different_domain")
    if reply_dom in CONSUMER_DOMAINS:
        flags.append("reply_to_consumer_domain")
    if return_path and rp_dom and rp_dom != from_dom:
        flags.append("return_path_different_domain")
    for mech in ("spf", "dkim", "dmarc"):
        result = auth.get(mech)
        if result in ("fail", "softfail", "permerror", "temperror"):
            flags.append(f"{mech}_{result}")
        elif mech == "dmarc" and result == "none":
            flags.append("dmarc_none")
    if auth.get("compauth") == "fail":
        flags.append("compauth_fail")
    scl = forefront.get("SCL", "")
    if scl.isdigit() and int(scl) >= 5:
        flags.append(f"scl_{scl}")
    if forefront.get("SFV") == "SPM":
        flags.append("sfv_spam")
    if forefront.get("SFV") in {"SKI", "SKN"}:
        flags.append("filter_skipped_by_allow_rule")
    subject = msg.get("Subject", "") or ""
    if URGENCY_SUBJECT_RE.search(subject):
        flags.append("urgency_or_finance_subject")
    if org_domain:
        if is_lookalike(from_dom, org_domain):
            flags.append("sender_domain_lookalike_of_org")
        if reply_dom and is_lookalike(reply_dom, org_domain):
            flags.append("reply_to_domain_lookalike_of_org")

    return {
        "from": {"name": from_name, "address": from_addr, "domain": from_dom},
        "reply_to": {"name": reply_name, "address": reply_addr, "domain": reply_dom} if reply_addr else None,
        "return_path": return_path or None,
        "subject": subject,
        "date": msg.get("Date"),
        "message_id": msg.get("Message-ID"),
        "authentication": auth,
        "antispam": forefront,
        "received_hop_count": len(hops),
        "first_external_hop": first_external,
        "flags": flags,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Parse raw email headers into triage JSON.")
    ap.add_argument("path", nargs="?", help="file with raw headers; reads stdin when omitted")
    ap.add_argument("--org-domain", default="", help="your primary domain, to flag lookalikes")
    args = ap.parse_args(argv)

    if args.path:
        with open(args.path, errors="replace") as handle:
            raw = handle.read()
    else:
        raw = sys.stdin.read()
    print(json.dumps(parse(raw, org_domain=args.org_domain), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
