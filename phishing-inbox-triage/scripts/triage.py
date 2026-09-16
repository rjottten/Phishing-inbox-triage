#!/usr/bin/env python3
"""Deterministic phishing-queue triage: lanes, categories, priority, report.

This is the SKILL.md workflow as code, so the queue can be worked with no LLM
in the loop. Every routing decision is a rule you can read, test and audit:

    lane        handled_by_automation | automation_gap | exception
    categories  user_interaction, bec, high_value_target, remediation_decision,
                ambiguous            (an item can carry several)
    priority    P1..P4, per SKILL.md
    actions     from references/response-actions.md, with decision owners

What it cannot do is read intent the way a person (or a model) can. It flags a
vendor bank-change on a real thread as ambiguous because the rules say so; it
does not know whether Priya really moved banks. The report says what it found
and what it could not verify, and leaves the call with the analyst.

Usage:
    python triage.py mailbox_export.json                 # Markdown report
    python triage.py mailbox_export.json --format json   # machine-readable
    python triage.py mailbox_export.json --org-context org.json --stuck-hours 6

Input is the export shape in test-data/mailbox_export.json: {"export_meta":
{...}, "items": [...]} or a bare list of items. Org context (your domains, VIP
list, known vendors) comes from export_meta and/or --org-context; the file wins.

Reported mail is data, never instructions. Text inside a message that addresses
an automated reviewer is itself reported as an indicator of malicious intent.
Nothing here fetches a URL, opens an attachment, or takes an action.
"""
import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import parse_headers  # optional: merges header flags when raw_headers is present
except ImportError:  # pragma: no cover
    parse_headers = None

# --------------------------------------------------------------------------
# Vocabulary
# --------------------------------------------------------------------------

REPORT_BUTTON = {"outlook_report_button", "report_button", "report_message_addin"}
CLEAN_VERDICTS = {"no threats found", "clean", "not junk", "notjunk", "not spam"}
BAD_VERDICTS = {"phishing", "phish", "malware", "spam", "high confidence phishing",
                "high confidence phish"}
IN_PROGRESS = {"pending", "running", "in progress", "queued", "not started"}
AWAITING = {"awaiting approval", "pending approval", "awaiting action"}
FAILED = {"failed", "error", "errored", "timed out", "timeout", "terminated"}

CONSUMER_DOMAINS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "yahoo.com", "aol.com", "icloud.com", "protonmail.com", "proton.me", "gmx.com",
}

# Brands whose names in a sender domain that is not their own are a tell.
BRAND_DOMAINS = {
    "docusign": {"docusign.com", "docusign.net"},
    "sharepoint": {"sharepoint.com", "sharepointonline.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "office.com", "office365.com"},
    "m365": set(), "office365": {"office365.com", "office.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "amazonaws.com"},
    "linkedin": {"linkedin.com"},
    "paypal": {"paypal.com"},
    "dropbox": {"dropbox.com"},
    "adobe": {"adobe.com"},
    "dhl": {"dhl.com", "dhl.de"}, "fedex": {"fedex.com"}, "ups": {"ups.com"},
}

RX = {
    "money": re.compile(
        r"\b(wire|invoice|invoices|payment|remittance|bank|banks|banking|gift ?cards?|"
        r"payroll|direct deposit|w-?2|iban|swift|account (?:number|details))\b", re.I),
    "urgency": re.compile(
        r"\b(urgent|urgently|immediately|asap|today|right away|within \d+ hours|"
        r"keep this between us|confidential|discreet|can'?t (?:take calls|talk)|"
        r"in a meeting|board prep|do not (?:tell|share)|before (?:eod|end of day)|"
        r"required by \w+day)\b", re.I),
    "credential_lure": re.compile(
        r"\b(password|verify (?:your |the )?account|sign[- ]?in|log ?in|suspended|"
        r"expires?|unusual sign-in|new device|mfa|reset your)\b", re.I),
    # Authority a BEC lure borrows. "Accounts Payable" is deliberately not here:
    # real vendors send from it all day, so it is a role, not an authority.
    "exec_title": re.compile(
        r"\b(CEO|CFO|COO|CIO|CISO|CTO|President|Chairman|Director|VP|Vice President|"
        r"Controller|Treasurer|Managing Director|General Counsel|Partner)\b", re.I),
    "role_name": re.compile(
        r"\b(Payroll|HR|Human Resources|Accounts? Payable|Finance|Helpdesk|Help Desk|"
        r"IT Support|Security|Benefits|Admin)\b", re.I),
    "bank_change": re.compile(
        r"\b(new|updated?|changed?|moved) (?:our |the )?(?:bank|banks|remittance|"
        r"account details|banking details|payment details)\b|"
        r"\b(?:bank|remittance|payment) details? (?:attached|below|updated)\b|"
        r"\bmoved banks?\b", re.I),
    "thread": re.compile(r"^\s*(re|fw|fwd)\s*:", re.I),
    # Text aimed at whoever (or whatever) reviews the message.
    "injection": re.compile(
        r"(note to (?:automated )?(?:reviewers?|ai|assistants?|systems?)|"
        r"\b(?:ai|llm|automated|assistant|reviewer|bot|model)s?\b[^.\n]{0,60}"
        r"\b(?:mark|classify|treat|consider|flag|label|rate)\b[^.\n]{0,40}"
        r"\b(?:safe|clean|legitimate|benign|not (?:phishing|spam|malicious))\b|"
        r"ignore (?:all |any )?(?:previous|prior|above|earlier) (?:instructions|rules)|"
        r"this (?:message|email) (?:has been|is|was) (?:pre-?)?(?:verified|approved|"
        r"whitelisted|cleared|allow-?listed)|"
        r"you are (?:an? )?(?:ai|assistant|language model))", re.I),
}

# Reporter-note interaction verbs. Checked clause by clause so a negated clause
# ("I didn't click") never counts.
INTERACTION = {
    "credentials": re.compile(
        r"\b(?:entered|typed|put in|submitted|gave|provided)\b[^.]{0,40}"
        r"\b(?:password|credentials|login|username|passcode|code)\b|"
        r"\b(?:signed|logged) in\b", re.I),
    "mfa": re.compile(r"\b(?:approved|accepted|tapped)\b[^.]{0,30}\b(?:mfa|push|prompt|"
                      r"authenticator|number match)\b", re.I),
    "payment": re.compile(
        r"\b(?:paid|wired|transferred|processed|sent)\b[^.]{0,40}"
        r"\b(?:payment|money|wire|funds|bank details|gift ?cards?|invoice|deposit)\b|"
        r"\bchanged (?:the )?(?:vendor|bank|payment) details\b", re.I),
    "payload": re.compile(
        r"\b(?:opened|ran|downloaded|extracted|enabled (?:macros|content|editing))\b"
        r"[^.]{0,40}\b(?:attachment|file|document|macro|xlsx?|docx?|pdf|zip|exe|iso|html)\b",
        re.I),
    "replied": re.compile(r"\b(?:replied|responded|wrote back|answered|emailed (?:them|him|her) back)\b", re.I),
    "clicked": re.compile(r"\b(?:clicked|followed the link|opened the link|went to the (?:site|page|link)|"
                          r"visited the (?:site|page|link))\b", re.I),
}
NEGATION = re.compile(r"\b(?:didn'?t|did not|haven'?t|have not|hasn'?t|has not|never|"
                      r"not|no|don'?t|do not|wasn'?t|without)\b", re.I)
CLAUSE_SPLIT = re.compile(r"[.;!?]|\b(?:but|however|although|though)\b", re.I)

PRIORITY_RANK = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def lower(s):
    return (s or "").strip().lower()


def domain_of(addr):
    addr = lower(addr)
    return addr.rsplit("@", 1)[-1] if "@" in addr else ""


def parse_time(value):
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def edit_distance(a, b):
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def is_own_domain(domain, org_domains):
    domain = lower(domain)
    return any(domain == d or domain.endswith("." + d) for d in org_domains)


def is_org_lookalike(domain, org_domains):
    """contoso-finance.co, contos0.com, contoso.co — ours in spirit, not in fact."""
    domain = lower(domain)
    if not domain or is_own_domain(domain, org_domains):
        return False
    dlabel = domain.split(".")[0]
    for org in org_domains:
        olabel = org.split(".")[0]
        if len(olabel) < 4:
            continue
        if olabel in dlabel and dlabel != olabel:
            return True                      # contoso-support, mycontoso
        if edit_distance(dlabel, olabel) <= 1:
            return True                      # contos0, contosso
        if edit_distance(domain, org) <= 2 and dlabel == olabel:
            return True                      # contoso.co, contoso.cm
    return False


def brand_lookalike(domain):
    domain = lower(domain)
    if not domain:
        return None
    for brand, real in BRAND_DOMAINS.items():
        if brand in domain.replace("-", "") and not any(
                domain == r or domain.endswith("." + r) for r in real):
            return brand
    return None


def display_name_mismatch(name, addr):
    clean = re.sub(r"\(.*?\)|\[.*?\]|,.*$", "", name or "").strip()
    tokens = [t.lower() for t in re.split(r"[\s.]+", clean) if len(t) > 1]
    return bool(tokens and addr and not any(t in addr.lower() for t in tokens))


# --------------------------------------------------------------------------
# Detectors
# --------------------------------------------------------------------------

def detect_interaction(note, telemetry=None):
    """What the reporter says they did, plus click telemetry if the export has it."""
    found = {}
    for clause in CLAUSE_SPLIT.split(note or ""):
        if not clause.strip() or NEGATION.search(clause):
            continue
        for kind, rx in INTERACTION.items():
            if rx.search(clause):
                found[kind] = clause.strip()
    if telemetry and telemetry.get("url_clicked"):
        found.setdefault("clicked", "click telemetry: %s" % (
            telemetry.get("safe_links_action") or "clicked"))
    return found


def detect_injection(*texts):
    hits = []
    for text in texts:
        for m in RX["injection"].finditer(text or ""):
            snippet = text[max(0, m.start() - 20): m.end() + 40].replace("\n", " ")
            hits.append(snippet.strip())
    return hits


def indicators(item, ctx):
    """Every tell we can see from the export, as short stable strings."""
    inds = []
    from_addr = item.get("from_address") or ""
    from_dom = domain_of(from_addr)
    reply_to = item.get("reply_to") or ""
    reply_dom = domain_of(reply_to)
    subject = item.get("subject") or ""
    body = item.get("body_excerpt") or ""
    text = subject + "\n" + body
    auth = item.get("auth") or {}

    for mech in ("spf", "dkim", "dmarc"):
        val = lower(auth.get(mech))
        if val in ("fail", "softfail", "permerror", "temperror"):
            inds.append("%s_%s" % (mech, val))
    if lower(auth.get("dmarc")) == "none" and not is_own_domain(from_dom, ctx["org_domains"]):
        inds.append("dmarc_none")

    if reply_to and reply_dom != from_dom:
        inds.append("reply_to_different_domain")
    if reply_dom in CONSUMER_DOMAINS:
        inds.append("reply_to_consumer_domain")
    if display_name_mismatch(item.get("from_name"), from_addr):
        inds.append("display_name_address_mismatch")
    external = not is_own_domain(from_dom, ctx["org_domains"])
    if external and RX["exec_title"].search(item.get("from_name") or ""):
        inds.append("authority_title_external_sender")
    elif external and RX["role_name"].search(item.get("from_name") or ""):
        inds.append("functional_role_external_sender")   # informational, not a BEC signal
    if is_org_lookalike(from_dom, ctx["org_domains"]):
        inds.append("lookalike_org_domain")
    brand = brand_lookalike(from_dom)
    if brand:
        inds.append("brand_lookalike_domain:" + brand)
    if from_dom in ctx["known_vendor_domains"]:
        inds.append("known_vendor_sender")

    if RX["money"].search(text):
        inds.append("money_or_banking_language")
    if RX["urgency"].search(text):
        inds.append("urgency_or_secrecy")
    if RX["credential_lure"].search(text):
        inds.append("credential_lure_language")
    if RX["bank_change"].search(text):
        inds.append("bank_detail_change")
    if RX["thread"].search(subject):
        inds.append("reply_thread")
    if not item.get("urls") and not item.get("attachments"):
        inds.append("no_link_no_attachment")
    elif not item.get("urls"):
        inds.append("attachment_only")

    if item.get("raw_headers") and parse_headers is not None:
        for flag in parse_headers.analyze(item["raw_headers"]).get("flags", []):
            if flag not in inds:
                inds.append("hdr:" + flag)

    for _ in detect_injection(subject, body, item.get("reporter_note")):
        inds.append("reviewer_targeted_instruction")
        break
    return inds


STRONG = {
    "spf_fail", "dmarc_fail", "compauth_fail", "reply_to_consumer_domain",
    "lookalike_org_domain", "authority_title_external_sender", "bank_detail_change",
    "reviewer_targeted_instruction",
}
BEC_SIGNALS = {
    "authority_title_external_sender", "display_name_address_mismatch",
    "reply_to_consumer_domain", "reply_to_different_domain", "lookalike_org_domain",
    "money_or_banking_language", "urgency_or_secrecy", "bank_detail_change",
}


def strong_count(inds):
    return sum(1 for i in inds if i.split(":")[0] in STRONG or i.startswith("brand_lookalike"))


BEC_STRONG = {"authority_title_external_sender", "reply_to_consumer_domain",
              "lookalike_org_domain", "bank_detail_change"}


def detect_bec(item, inds):
    """No link means nothing to detonate; then it takes real social signals.

    Two signals settles it only if one is strong. A display-name quirk plus the
    word "invoice" describes half of all legitimate vendor mail, and calling
    that BEC would bury the analyst in the exact noise this exists to remove.
    Three weak signals together are enough.
    """
    if item.get("urls"):
        return False
    signals = {i for i in inds if i in BEC_SIGNALS}
    if "reply_thread" in inds and "bank_detail_change" in inds:
        return True                          # vendor email compromise pattern
    strong = signals & BEC_STRONG
    return (len(signals) >= 2 and bool(strong)) or len(signals) >= 3


# --------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------

ACTIONS = {
    "compromise": [
        ("Reset password and revoke all sessions/refresh tokens", "IAM"),
        ("Re-register MFA if an MFA prompt was approved", "IAM"),
        ("Review inbox rules, forwarding, OAuth consents, delegations", "SOC / IAM"),
        ("Scope what the account accessed after the event; open an incident", "SOC lead / IR"),
        ("Soft delete the message; block URL and sender", "SOC analyst"),
        ("Inform the user's manager", "SOC analyst"),
    ],
    "bec": [
        ("Confirm with the reporter whether anything was sent, paid, or changed", "SOC analyst"),
        ("Hold any related payment; verify vendor/bank change out-of-band on a known number", "Finance / AP"),
        ("Soft delete from all recipients; block the sender address", "SOC analyst"),
        ("Hunt the Reply-To and display name across the tenant", "SOC analyst"),
        ("Submit as phishing so the reporter gets the correct notification", "SOC analyst"),
    ],
    "vendor_compromise": [
        ("Verify the bank change by phone on a number already on file, not one in the email", "Finance / AP"),
        ("Hold payments to this vendor until verified", "Finance / AP"),
        ("Notify the vendor out-of-band that their mailbox may be compromised", "Vendor management"),
        ("Do not block the vendor domain; block the specific message/sender if confirmed", "SOC analyst"),
    ],
    "high_value_target": [
        ("Confirm directly with the VIP (or EA) that nothing was clicked or entered", "SOC analyst"),
        ("Hunt the same lure across other VIPs and their assistants", "SOC analyst"),
        ("Block URL and sender", "SOC analyst"),
        ("Notify the exec-protection contact if more than one VIP was hit", "SOC lead"),
    ],
    "remediation_decision": [
        ("Approve or reject the pending AIR actions, stating scope and reversibility", "SOC analyst; SOC lead if cross-department"),
        ("Check collateral before any domain-level block", "SOC analyst"),
    ],
    "ambiguous": [
        ("Perform the specific check that resolves it (see evidence); hold with quarantine or URL block meanwhile", "SOC analyst"),
    ],
    "clicked": [
        ("Check sign-in logs for the reporter around the click time", "SOC analyst"),
        ("Block the URL; soft delete", "SOC analyst"),
    ],
    "automation_gap": [
        ("Submit to Microsoft on the reporter's behalf (scripts/graph_submit.py)", "SOC analyst"),
        ("Coach the reporter on the Outlook Report button", "SOC analyst"),
    ],
    "air_failed": [
        ("Check the AIR error and re-submit; raise with the Defender admin if it repeats", "Defender admin"),
    ],
}


def classify(item, ctx, now, stuck_hours, large_scope):
    d = item.get("defender") or {}
    verdict = lower(d.get("verdict"))
    status = lower(d.get("air_status"))
    actions_text = d.get("actions") or ""
    notified = bool(d.get("user_notified"))
    has_submission = bool(d.get("submission_id"))
    via = lower(item.get("reported_via"))
    forwarded = bool(via) and via not in REPORT_BUTTON
    recipients = item.get("recipient_count") or 0
    reporter = lower(item.get("reporter"))

    inds = indicators(item, ctx)
    interaction = detect_interaction(item.get("reporter_note"), item.get("click_telemetry"))
    injection = detect_injection(item.get("subject"), item.get("body_excerpt"), item.get("reporter_note"))
    bec = detect_bec(item, inds)
    vendor_compromise = bec and ("reply_thread" in inds or "known_vendor_sender" in inds) \
        and "bank_detail_change" in inds
    vips = [v for v in (item.get("recipients_vip") or []) if v]
    if reporter in ctx["vip"]:
        vips.append(reporter)
    compromise = any(k in interaction for k in ("credentials", "mfa", "payment", "payload"))
    pending_actions = status in AWAITING or "pending" in actions_text.lower()

    received = parse_time(item.get("received"))
    age_h = (now - received).total_seconds() / 3600 if (received and now) else None
    stuck = status in IN_PROGRESS and age_h is not None and age_h > stuck_hours

    categories, evidence, not_verified = [], [], []

    # -- exception categories, most consequential first --------------------
    if interaction:
        categories.append("user_interaction")
        # Several kinds usually come from one sentence; quote it once.
        by_clause = defaultdict(list)
        for kind, clause in interaction.items():
            by_clause[clause].append(kind)
        for clause, kinds in by_clause.items():
            evidence.append("Reporter: %s — \"%s\"" % (", ".join(kinds), clause))
    if bec:
        categories.append("bec")
        evidence.append("BEC pattern: " + ", ".join(i for i in inds if i in BEC_SIGNALS))
        if vendor_compromise:
            evidence.append("Vendor email compromise shape: real thread, bank change, auth passes")
    if vips:
        categories.append("high_value_target")
        evidence.append("VIP recipient(s): " + ", ".join(sorted(set(vips))))
    if pending_actions or (verdict in BAD_VERDICTS and recipients >= large_scope
                           and "auto-approved" not in actions_text.lower()):
        categories.append("remediation_decision")
        evidence.append("Pending: %s (%s recipients)" % (actions_text or "scope decision", recipients))

    conflict = None
    if verdict in CLEAN_VERDICTS and (bec or compromise or strong_count(inds) >= 2):
        why = "reporter interaction" if compromise else (
            "BEC pattern" if bec else "%d strong indicators" % strong_count(inds))
        conflict = "AIR says %s; disagree — %s" % (d.get("verdict"), why)
    elif verdict in BAD_VERDICTS and "known_vendor_sender" in inds and strong_count(inds) == 0:
        conflict = "AIR says %s but sender is a known vendor with clean auth — possible false positive" % d.get("verdict")
    if conflict or stuck:
        categories.append("ambiguous")
        if conflict:
            evidence.append(conflict)
        if stuck:
            evidence.append("AIR %s for %.0fh (threshold %dh)" % (d.get("air_status"), age_h, stuck_hours))

    # -- lane ---------------------------------------------------------------
    if categories:
        lane = "exception"
    elif not has_submission or forwarded:
        lane = "automation_gap"
        gap_reason = ("Forwarded/moved to the mailbox; no submission, no AIR"
                      if forwarded or not has_submission else "No submission")
    elif status in FAILED:
        lane, gap_reason = "automation_gap", "AIR %s" % d.get("air_status")
    elif status == "completed" and not notified:
        lane, gap_reason = "automation_gap", "AIR completed but reporter not notified"
    elif status == "completed" and (verdict in CLEAN_VERDICTS or verdict in BAD_VERDICTS):
        lane = "handled_by_automation"
    elif status in IN_PROGRESS:
        lane = "handled_by_automation"      # fresh investigation; revisit if it ages out
    else:
        lane, gap_reason = "automation_gap", "Unrecognised AIR state: %r" % d.get("air_status")

    # -- priority -----------------------------------------------------------
    if lane == "exception":
        if compromise or ("replied" in interaction and bec):
            priority = "P1"
        elif bec or vips or "remediation_decision" in categories or "clicked" in interaction:
            priority = "P2"
        else:
            priority = "P3"
    elif lane == "automation_gap":
        priority = "P4"
    else:
        priority = None

    # -- actions ------------------------------------------------------------
    actions = []
    if lane == "exception":
        if compromise:
            actions += ACTIONS["compromise"]
        elif "clicked" in interaction:
            actions += ACTIONS["clicked"]
        if vendor_compromise:
            actions += ACTIONS["vendor_compromise"]
        elif bec:
            actions += ACTIONS["bec"]
        if vips:
            actions += ACTIONS["high_value_target"]
        if "remediation_decision" in categories:
            actions += ACTIONS["remediation_decision"]
        if "ambiguous" in categories:
            actions += ACTIONS["ambiguous"]
    elif lane == "automation_gap":
        actions += ACTIONS["air_failed"] if status in FAILED else ACTIONS["automation_gap"]
        if strong_count(inds) >= 1:
            actions.append(("After submission, escalate for URL/sender block — indicators: %s"
                            % ", ".join(i for i in inds if i.split(":")[0] in STRONG or i.startswith("brand_lookalike")),
                            "SOC analyst"))
    seen, deduped = set(), []
    for a in actions:
        if a[0] not in seen:
            seen.add(a[0])
            deduped.append(a)

    # -- what we could not see ---------------------------------------------
    if lane == "exception":
        if "click_telemetry" not in item:
            not_verified.append("click telemetry not in export — check UrlClickEvents")
        if vips and not interaction:
            not_verified.append("whether the VIP interacted — reporter cannot say")
        if bec and "payment" not in interaction:
            not_verified.append("whether any payment or detail change was actioned")
        if not has_submission:
            not_verified.append("no Defender submission — AIR view unavailable")

    return {
        "id": item.get("id"),
        "lane": lane,
        "gap_reason": gap_reason if lane == "automation_gap" else None,
        "categories": categories,
        "priority": priority,
        "reporter": item.get("reporter"),
        "reported_via": item.get("reported_via"),
        "from": "%s <%s>" % (item.get("from_name") or "", item.get("from_address") or ""),
        "subject": item.get("subject"),
        "recipient_count": recipients,
        "vips": sorted(set(vips)),
        "indicators": inds,
        "interaction": interaction,
        "injection": injection,
        "defender": d,
        "air_age_hours": round(age_h, 1) if age_h is not None else None,
        "evidence": evidence,
        "not_verified": not_verified,
        "actions": [{"action": a, "owner": o} for a, o in deduped],
    }


def triage(items, ctx, now=None, stuck_hours=4, large_scope=100):
    results = [classify(it, ctx, now, stuck_hours, large_scope) for it in items]
    results.sort(key=lambda r: (PRIORITY_RANK.get(r["priority"], 9), r["id"] or ""))
    return results


# --------------------------------------------------------------------------
# Context & input
# --------------------------------------------------------------------------

def build_context(meta, org_context_path=None, extra_domains=(), extra_vips=()):
    ctx = {"org_domains": set(), "vip": set(), "known_vendor_domains": set()}
    if meta.get("org_domain"):
        ctx["org_domains"].add(lower(meta["org_domain"]))
    for d in meta.get("org_domains") or []:
        ctx["org_domains"].add(lower(d))
    for v in meta.get("vip_list") or []:
        ctx["vip"].add(lower(v))
    if org_context_path:
        with open(org_context_path, encoding="utf-8") as fh:
            oc = json.load(fh)
        for d in oc.get("org_domains") or []:
            ctx["org_domains"].add(lower(d))
        for v in oc.get("vip") or oc.get("vip_list") or []:
            ctx["vip"].add(lower(v))
        for d in oc.get("known_vendor_domains") or []:
            ctx["known_vendor_domains"].add(lower(d))
    ctx["org_domains"].update(lower(d) for d in extra_domains)
    ctx["vip"].update(lower(v) for v in extra_vips)
    return ctx


def load_export(path):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, list):
        return {}, data
    return data.get("export_meta") or {}, data.get("items") or []


def window_end(meta):
    window = meta.get("window") or ""
    if " to " in window:
        return parse_time(window.split(" to ", 1)[1])
    return None


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------

def render_markdown(meta, results, ctx, now):
    by_lane = defaultdict(list)
    for r in results:
        by_lane[r["lane"]].append(r)
    exc = by_lane["exception"]
    gaps = by_lane["automation_gap"]
    handled = by_lane["handled_by_automation"]
    pri = Counter(r["priority"] for r in exc)
    in_progress = [r for r in handled if lower(r["defender"].get("air_status")) in IN_PROGRESS]

    out = []
    out.append("# Phishing queue — %s" % (meta.get("window") or (now.isoformat() if now else "")))
    out.append("")
    out.append("**Queue:** %d items · **Exceptions:** %d (%d P1, %d P2, %d P3) · "
               "**Automation gaps:** %d · **Handled by automation:** %d%s" % (
                   len(results), len(exc), pri["P1"], pri["P2"], pri["P3"], len(gaps), len(handled),
                   " (%d still in progress)" % len(in_progress) if in_progress else ""))
    out.append("**Data sources:** %s — produced by triage.py (rules only, no LLM); "
               "org domains: %s; VIPs known: %d" % (
                   meta.get("source") or "export", ", ".join(sorted(ctx["org_domains"])) or "none given",
                   len(ctx["vip"])))
    out.append("")
    out.append("## Exceptions needing an analyst")
    out.append("")
    if exc:
        out.append("| # | Pri | Category | Reported by → Sender / Subject | Why it's an exception | Recommended actions | Decision owner |")
        out.append("|---|-----|----------|------------------------------|------------------------|---------------------|----------------|")
        for n, r in enumerate(exc, 1):
            cats = ", ".join(c.replace("_", " ") for c in r["categories"])
            why = "; ".join(r["evidence"][:3])
            acts = "; ".join(a["action"] for a in r["actions"][:3])
            owners = ", ".join(sorted({a["owner"].split(";")[0].strip() for a in r["actions"]}))
            out.append("| %d | %s | %s | %s → %s / %s | %s | %s | %s |" % (
                n, r["priority"], cats, r["reporter"], md(r["from"]), md(r["subject"]),
                md(why), md(acts), owners))
        out.append("")
        out.append("### Exception details")
        out.append("")
        for n, r in enumerate(exc, 1):
            out.append("#### %d. %s — %s (%s)" % (n, r["id"], md(r["subject"]), r["priority"]))
            out.append("- **Evidence:**")
            for e in r["evidence"]:
                out.append("  - %s" % md(e))
            if r["indicators"]:
                out.append("  - Indicators: %s" % ", ".join(r["indicators"]))
            d = r["defender"]
            out.append("  - Automation's view: submission %s, AIR %s, verdict %s, reporter notified %s, actions %s" % (
                d.get("submission_id") or "none", d.get("air_status") or "none", d.get("verdict") or "none",
                "yes" if d.get("user_notified") else "no", d.get("actions") or "none"))
            out.append("  - Scope: %s recipient(s)%s" % (
                r["recipient_count"], "; VIPs: " + ", ".join(r["vips"]) if r["vips"] else ""))
            out.append("- **Not verified:** %s" % ("; ".join(r["not_verified"]) if r["not_verified"] else "—"))
            out.append("- **Recommended actions:**")
            for i, a in enumerate(r["actions"], 1):
                out.append("  %d. %s — *%s*" % (i, a["action"], a["owner"]))
            out.append("")
    else:
        out.append("None.")
        out.append("")

    out.append("## Automation gaps")
    out.append("")
    if gaps:
        out.append("| Reporter | Issue | Fix |")
        out.append("|---|---|---|")
        for r in gaps:
            strong = [i for i in r["indicators"] if i.split(":")[0] in STRONG or i.startswith("brand_lookalike")]
            issue = r["gap_reason"] + ("; indicators: " + ", ".join(strong) if strong else "; nothing alarming in headers")
            fix = "; ".join(a["action"] for a in r["actions"])
            out.append("| %s | %s | %s |" % (r["reporter"], md(issue), md(fix)))
        forwarded = sum(1 for r in gaps if r["reported_via"] and lower(r["reported_via"]) not in REPORT_BUTTON)
        out.append("")
        out.append("%d forwarded/moved report(s) this window; %d via the Report button." % (
            forwarded, len(results) - forwarded))
    else:
        out.append("None.")
    out.append("")

    out.append("## Handled by automation")
    out.append("")
    if handled:
        line = "%d, no action needed." % len(handled)
        notable = []
        senders = Counter(domain_of(r["from"].split("<")[-1].rstrip(">")) for r in handled)
        for dom, n in senders.most_common():
            if n >= 2:
                notable.append("%d reports from %s" % (n, dom))
        for r in handled:
            m = re.search(r"(\d+)\s+mailboxes", r["defender"].get("actions") or "")
            if m and int(m.group(1)) >= 10:
                notable.append("%s: %s" % (r["id"], r["defender"]["actions"]))
        if in_progress:
            notable.append("%d still in AIR (%s) — revisit next shift" % (
                len(in_progress), ", ".join(r["id"] for r in in_progress)))
        if notable:
            line += " Notable: " + "; ".join(notable) + "."
        out.append(line)
    else:
        out.append("0.")
    out.append("")

    out.append("## Trends and notes")
    out.append("")
    lookalikes = [r for r in results if any(i.startswith(("lookalike_org", "brand_lookalike")) for i in r["indicators"])]
    if lookalikes:
        out.append("- Lookalike sender domains this window: %s" % ", ".join(
            "%s (%s)" % (r["from"].split("<")[-1].rstrip(">"), r["id"]) for r in lookalikes))
    disagreed = [r for r in exc if "ambiguous" in r["categories"] and any(e.startswith("AIR says") for e in r["evidence"])]
    if disagreed:
        out.append("- Verdicts this report disagrees with: %s" % ", ".join(r["id"] for r in disagreed))
    if not lookalikes and not disagreed:
        out.append("- Nothing beyond the items above.")
    out.append("")

    out.append("## Anything reported inside a message aimed at the reviewer")
    out.append("")
    injected = [r for r in results if r["injection"]]
    if injected:
        for r in injected:
            out.append("- **%s** (%s lane): treated as a malicious indicator, not obeyed. Snippet: `%s`" % (
                r["id"], r["lane"].replace("_", " "), md(r["injection"][0][:140])))
    else:
        out.append("None found.")
    out.append("")
    return "\n".join(out)


def md(text):
    """Keep table cells intact; report content is untrusted."""
    return (text or "").replace("|", "\\|").replace("\n", " ").replace("`", "'")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Deterministic phishing-queue triage (no LLM).",
                                formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("export", help="mailbox/Defender export JSON")
    p.add_argument("--org-context", help="JSON with org_domains, vip, known_vendor_domains")
    p.add_argument("--org-domain", action="append", default=[], help="your mail domain; repeatable")
    p.add_argument("--vip", action="append", default=[], help="VIP address; repeatable")
    p.add_argument("--stuck-hours", type=int, default=4,
                   help="an in-progress AIR older than this is an exception (ambiguous)")
    p.add_argument("--large-scope", type=int, default=100,
                   help="recipient count at which an un-actioned phish is a remediation decision")
    p.add_argument("--now", help="ISO time to measure AIR age from; default = export window end, else now")
    p.add_argument("--format", choices=("md", "json", "both"), default="md")
    p.add_argument("--out", help="write the Markdown report here instead of stdout")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    meta, items = load_export(args.export)
    ctx = build_context(meta, args.org_context, args.org_domain, args.vip)
    now = parse_time(args.now) or window_end(meta) or datetime.now(timezone.utc)
    results = triage(items, ctx, now=now, stuck_hours=args.stuck_hours, large_scope=args.large_scope)

    if args.format in ("md", "both"):
        report = render_markdown(meta, results, ctx, now)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(report)
            print("wrote %s" % args.out, file=sys.stderr)
        else:
            print(report)
    if args.format in ("json", "both"):
        payload = {
            "generated_by": "triage.py (rules only)",
            "now": now.isoformat(),
            "counts": dict(Counter(r["lane"] for r in results)),
            "priorities": dict(Counter(r["priority"] for r in results if r["priority"])),
            "results": results,
        }
        print(json.dumps(payload, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
