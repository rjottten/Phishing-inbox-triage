#!/usr/bin/env python3
"""Parse raw email headers into triage-relevant JSON.

Usage:
    python parse_headers.py headers.txt
    cat headers.txt | python parse_headers.py

Extracts sender identities (From, Reply-To, Return-Path), authentication results
(SPF, DKIM, DMARC, compauth), Microsoft anti-spam markers, the Received chain, and
flags the common phishing/BEC tells (display-name vs address mismatch, Reply-To to a
different domain, auth failures, consumer-domain Reply-To). Read-only; never touches
the network.
"""
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


def domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""


def parse_auth_results(value: str) -> dict:
    """Pull spf/dkim/dmarc/compauth results out of an Authentication-Results header."""
    out = {}
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
    m = re.match(r"from\s+(\S+)", hop, re.IGNORECASE)
    return m.group(1).lower() if m else ""


def parse_forefront(value: str) -> dict:
    """X-Forefront-Antispam-Report is ;-separated KEY:VALUE pairs."""
    out = {}
    if not value:
        return out
    for part in value.split(";"):
        if ":" in part:
            k, v = part.split(":", 1)
            k, v = k.strip(), v.strip()
            if k in ("CIP", "CTRY", "SCL", "BCL", "SFV", "SRV", "PTR", "SFTY", "DIR", "IPV", "SFS"):
                out[k] = v
    return out


def analyze(raw: str) -> dict:
    """Turn raw header text into the triage JSON structure.

    Pure: no file, network, or stdout access, so the flag logic can be tested
    directly rather than through the CLI.
    """
    msg = HeaderParser(policy=policy.compat32).parsestr(raw)

    from_name, from_addr = parseaddr(msg.get("From", ""))
    reply_name, reply_addr = parseaddr(msg.get("Reply-To", ""))
    _, return_path = parseaddr(msg.get("Return-Path", ""))
    from_dom, reply_dom, rp_dom = domain_of(from_addr), domain_of(reply_addr), domain_of(return_path)

    auth = {}
    for v in msg.get_all("Authentication-Results", []):
        auth.update({k: val for k, val in parse_auth_results(v).items() if k not in auth})
    forefront = parse_forefront(msg.get("X-Forefront-Antispam-Report", ""))

    received = msg.get_all("Received", []) or []
    hops = [re.sub(r"\s+", " ", h).strip() for h in received]
    # Oldest hop first, so this is where the message entered the org. Hops with
    # no `from` clause identify no sender and are skipped rather than guessed at.
    first_external = next(
        (h for h in reversed(hops)
         if sending_host(h) and "protection.outlook.com" not in sending_host(h)),
        None,
    )

    flags = []
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
        if auth.get(mech) in ("fail", "softfail", "permerror", "temperror"):
            flags.append(f"{mech}_{auth[mech]}")
        elif auth.get(mech) == "none" and mech == "dmarc":
            flags.append("dmarc_none")
    if auth.get("compauth") == "fail":
        flags.append("compauth_fail")
    if forefront.get("SCL", "").isdigit() and int(forefront["SCL"]) >= 5:
        flags.append(f"scl_{forefront['SCL']}")
    if forefront.get("SFV") == "SPM":
        flags.append("sfv_spam")
    if forefront.get("SFV") == "SKI" or forefront.get("SFV") == "SKN":
        flags.append("filter_skipped_by_allow_rule")
    subj = msg.get("Subject", "") or ""
    if re.search(r"\b(urgent|immediately|asap|wire|invoice|payment|verify|suspended|password)\b", subj, re.I):
        flags.append("urgency_or_finance_subject")
    if msg.get("X-MS-Exchange-Organization-AuthAs", "").lower() == "internal" and from_dom and "protection.outlook.com" not in (first_external or ""):
        pass  # internal auth is fine; nothing to flag

    result = {
        "from": {"name": from_name, "address": from_addr, "domain": from_dom},
        "reply_to": {"name": reply_name, "address": reply_addr, "domain": reply_dom} if reply_addr else None,
        "return_path": return_path or None,
        "subject": subj,
        "date": msg.get("Date"),
        "message_id": msg.get("Message-ID"),
        "authentication": auth,
        "antispam": forefront,
        "received_hop_count": len(hops),
        "first_external_hop": first_external,
        "flags": flags,
    }
    return result


def main() -> int:
    raw = open(sys.argv[1], "r", errors="replace").read() if len(sys.argv) > 1 else sys.stdin.read()
    print(json.dumps(analyze(raw), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
