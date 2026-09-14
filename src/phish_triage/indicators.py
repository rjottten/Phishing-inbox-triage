"""Text-level detectors used by the rules engine.

Everything here reads attacker-controlled or reporter-written text. Nothing here
follows a URL, opens an attachment, or contacts a sender. Detections are evidence,
not verdicts — `rules.py` decides what they add up to.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# How far back from a match we look for a negation ("I didn't click").
NEGATION_WINDOW = 36
NEGATION_RE = re.compile(
    r"\b(?:did\s*n[o']?t|didnt|do\s*n[o']?t|does\s*n[o']?t|have\s*n[o']?t|havent|has\s*n[o']?t|"
    r"was\s*n[o']?t|were\s*n[o']?t|never|not|no|without|almost|nearly)\b[\s\w,']{0,12}$",
    re.IGNORECASE,
)

UNCERTAINTY_RE = re.compile(
    r"\b(not sure|unsure|don'?t know|do not know|can'?t remember|cannot remember|"
    r"might have|may have|possibly|i think|not certain|no idea)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class InteractionKind:
    code: str
    detail: str
    severity: str  # "compromise" | "engaged" | "exposure"


#: Ordered most to least severe. First pattern group wins per code.
INTERACTION_PATTERNS: list[tuple[re.Pattern[str], InteractionKind]] = [
    (
        re.compile(
            r"\b(?:entered|typed|put in|gave|supplied|submitted|filled in|used)\b[^.!?]{0,30}"
            r"\b(?:password|credential|username and password|login details|sign-?in details)\b"
            r"|\b(?:password|credentials)\b[^.!?]{0,20}\b(?:entered|submitted)\b"
            r"|\blogged? in (?:to|on)\b|\bsigned in (?:to|on)\b",
            re.IGNORECASE,
        ),
        InteractionKind("credentials_entered", "Reporter entered credentials on the linked page", "compromise"),
    ),
    (
        re.compile(
            r"\b(?:approved|accepted|acknowledged|tapped|confirmed)\b[^.!?]{0,25}"
            r"\b(?:mfa|multi-?factor|2fa|push|authenticator|prompt|sign-?in request)\b"
            r"|\bmfa (?:push|prompt|request)\b[^.!?]{0,15}\b(?:approved|accepted)\b",
            re.IGNORECASE,
        ),
        InteractionKind("mfa_approved", "Reporter approved an MFA prompt", "compromise"),
    ),
    (
        re.compile(
            r"\b(?:sent|wired|transferred|paid|released|processed)\b[^.!?]{0,30}"
            r"\b(?:wire|payment|funds|invoice|money|transfer|gift ?cards?)\b"
            r"|\b(?:changed|updated|amended)\b[^.!?]{0,25}\b(?:bank|remittance|vendor|payee|account)\b"
            r"[^.!?]{0,15}\b(?:details|information|record)\b",
            re.IGNORECASE,
        ),
        InteractionKind("payment_or_data_actioned", "Reporter actioned a payment or a bank/vendor change", "compromise"),
    ),
    (
        re.compile(
            r"\b(?:opened|ran|executed|extracted|enabled macros in|downloaded and opened)\b[^.!?]{0,25}"
            r"\b(?:attachment|file|document|invoice\.|\.zip|\.docm?|\.xls[mx]?|\.pdf|macro)\b",
            re.IGNORECASE,
        ),
        InteractionKind("attachment_opened", "Reporter opened the attachment", "compromise"),
    ),
    (
        re.compile(r"\b(?:replied|responded|wrote back|answered|emailed (?:him|her|them|back))\b", re.IGNORECASE),
        InteractionKind("replied_to_sender", "Reporter replied to the sender", "engaged"),
    ),
    (
        re.compile(
            r"\b(?:clicked|click(?:ed)? (?:on )?the link|followed the link|opened the link|"
            r"went to the (?:site|page|link))\b",
            re.IGNORECASE,
        ),
        InteractionKind("clicked_link", "Reporter clicked the link", "exposure"),
    ),
    (
        re.compile(r"\bdownloaded\b(?![^.!?]{0,20}\bopened\b)", re.IGNORECASE),
        InteractionKind("downloaded_file", "Reporter downloaded the attachment", "exposure"),
    ),
]

INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(?:ai|automated|machine|llm|bot)\b[^.\n]{0,30}\b(?:reviewer|assistant|analyst|agent|system)s?\b", re.IGNORECASE),
     "addresses an automated/AI reviewer directly"),
    (re.compile(r"\b(?:ignore|disregard|override|forget)\b[^.\n]{0,30}\b(?:previous|prior|above|earlier|all)\b[^.\n]{0,20}\b(?:instruction|prompt|rule|direction)s?\b", re.IGNORECASE),
     "attempts to override reviewer instructions"),
    (re.compile(r"\b(?:classif\w+|mark|treat|flag|categoriz\w+|label)\b[^.\n]{0,25}\b(?:as )?(?:clean|safe|benign|legitimate|not phishing|non-?malicious)\b", re.IGNORECASE),
     "instructs the reviewer to classify the message as clean"),
    (re.compile(r"\bdo not\b[^.\n]{0,25}\b(?:escalate|report|flag|block|quarantine|investigate)\b", re.IGNORECASE),
     "instructs the reviewer not to escalate"),
    (re.compile(r"\b(?:pre-?verified|已verified|verified|approved|whitelisted|allow-?listed)\b[^.\n]{0,30}\b(?:by )?(?:security|it|soc|the security team|microsoft)\b", re.IGNORECASE),
     "claims prior security approval inside the message body"),
    (re.compile(r"\b(?:system prompt|you are an? (?:ai|assistant|language model)|end of instructions)\b", re.IGNORECASE),
     "contains prompt-injection scaffolding"),
]

FINANCE_INTENT_RE = re.compile(
    r"\b(wire|wire transfer|remittance|invoice|payment|pay(?:ing|ment)? (?:this|today|now)|"
    r"bank details|banking details|bank account|account details|routing|iban|swift|ach|"
    r"gift ?cards?|payroll|direct deposit|w-?2|tax form|purchase order|funds|"
    r"moved banks?|change of bank|new bank)\b",
    re.IGNORECASE,
)

BANK_CHANGE_RE = re.compile(
    r"\b(?:new|updated?|changed?|different|revised|moved|amended|revised)\b[^.\n]{0,25}"
    r"\b(?:bank(?:ing)?(?: account| details)?|remittance|payee|beneficiary|iban|swift|routing|"
    r"account (?:details|number|information)|payment (?:details|instructions))\b"
    r"|\b(?:moved|switch(?:ed|ing)?|chang(?:ed|ing))\b[^.\n]{0,15}\bbanks?\b",
    re.IGNORECASE,
)

#: A reporter saying the request does not match reality ("Priya never mentioned a
#: bank change") is some of the strongest evidence in the queue — a human who knows
#: the relationship contradicting the message's own premise.
CONTRADICTION_RE = re.compile(
    r"\b(?:never|did ?n[o']?t|does ?n[o']?t|was ?n[o']?t|were ?n[o']?t|no one|nobody)\b"
    r"[^.\n]{0,40}\b(?:mention(?:ed)?|discuss(?:ed)?|expect(?:ing|ed)?|request(?:ed)?|ask(?:ed)?|"
    r"send|sent|order(?:ed)?|sign(?:ed)? up|arrange(?:d)?|schedule[d]?|aware)\b"
    r"|\b(?:wasn.t|isn.t|is not|was not) expecting\b"
    r"|\b(?:doesn.t|does not|didn.t|did not) (?:match|look right|add up|make sense)\b"
    r"|\b(?:we|i|they) (?:don.t|do not) (?:use|work with|have an account with)\b",
    re.IGNORECASE,
)

URGENCY_RE = re.compile(
    r"\b(urgent|urgently|immediately|asap|right away|today|within \d+ ?(?:hours?|hrs?|minutes?)|"
    r"by (?:close of business|cob|eod|friday|end of day)|time[- ]sensitive|expires?|expiring|"
    r"deadline|action required|final notice|suspend(?:ed|ion)?)\b",
    re.IGNORECASE,
)

SECRECY_RE = re.compile(
    r"\b(keep this (?:between us|confidential|quiet)|don'?t (?:tell|mention|discuss)|"
    r"confidential(?:ly)?|discreet(?:ly)?|between you and me|do not loop in|without involving)\b",
    re.IGNORECASE,
)

UNAVAILABILITY_RE = re.compile(
    r"\b(can'?t (?:talk|take calls|be reached)|in a meeting|in board prep|travel(?:l)?ing|"
    r"on a (?:flight|plane|call)|unavailable|stuck in)\b",
    re.IGNORECASE,
)

CREDENTIAL_LURE_RE = re.compile(
    r"\b(password (?:expires?|expiry|reset|change)|verify your (?:account|identity|email)|"
    r"sign ?in to (?:review|verify|confirm|continue)|log ?in to (?:review|verify|confirm)|"
    r"confirm your (?:account|credentials|identity)|re-?authenticate|account (?:suspended|locked|verification)|"
    r"unusual sign-?in|keep your current password|review document|view (?:the )?(?:secure )?document)\b",
    re.IGNORECASE,
)

AUTHORITY_ROLE_RE = re.compile(
    r"\b(ceo|cfo|coo|cto|ciso|chief \w+ officer|president|vice president|vp|managing director|"
    r"head of (?:finance|hr|payroll)|payroll|hr|human resources|helpdesk|help desk|it support|"
    r"service desk|security team|accounts payable|ap team|finance team)\b",
    re.IGNORECASE,
)

MOBILE_SIGNATURE_RE = re.compile(r"\bsent from my (?:iphone|ipad|android|mobile|phone|blackberry)\b", re.IGNORECASE)

THREAD_REPLY_RE = re.compile(r"^\s*(?:re|fw|fwd)\s*:", re.IGNORECASE)


def _negated(text: str, start: int) -> bool:
    """True when a negation sits just before `start` ('I didn't click')."""
    return bool(NEGATION_RE.search(text[max(0, start - NEGATION_WINDOW): start]))


def detect_interaction(note: str) -> list[InteractionKind]:
    """Find what the reporter says they did, skipping negated statements.

    Reporter notes are free text written under stress; treat the result as a
    prompt for the analyst's confirmation question, not as proof.
    """
    if not note:
        return []
    found: list[InteractionKind] = []
    seen: set[str] = set()
    for pattern, kind in INTERACTION_PATTERNS:
        for match in pattern.finditer(note):
            if _negated(note, match.start()):
                continue
            if kind.code not in seen:
                seen.add(kind.code)
                found.append(kind)
            break
    return found


def detect_uncertainty(note: str) -> list[str]:
    """Phrases where the reporter says they don't know — things to verify, not assume."""
    return sorted({m.group(0).lower() for m in UNCERTAINTY_RE.finditer(note or "")})


def detect_injection(text: str) -> list[str]:
    """Reviewer-directed text planted in the message. An indicator, never an instruction."""
    return [why for pattern, why in INJECTION_PATTERNS if pattern.search(text or "")]


def has_finance_intent(text: str) -> bool:
    return bool(FINANCE_INTENT_RE.search(text or ""))


def has_bank_change(text: str) -> bool:
    return bool(BANK_CHANGE_RE.search(text or ""))


def contradicts_premise(note: str) -> bool:
    """The reporter says the message's own premise is false."""
    return bool(CONTRADICTION_RE.search(note or ""))


def has_urgency(text: str) -> bool:
    return bool(URGENCY_RE.search(text or ""))


def has_secrecy(text: str) -> bool:
    return bool(SECRECY_RE.search(text or ""))


def has_unavailability(text: str) -> bool:
    return bool(UNAVAILABILITY_RE.search(text or ""))


def has_credential_lure(text: str) -> bool:
    return bool(CREDENTIAL_LURE_RE.search(text or ""))


def claims_authority_role(text: str) -> bool:
    return bool(AUTHORITY_ROLE_RE.search(text or ""))


def has_mobile_signature(text: str) -> bool:
    return bool(MOBILE_SIGNATURE_RE.search(text or ""))


def is_thread_reply(subject: str) -> bool:
    return bool(THREAD_REPLY_RE.match(subject or ""))


def display_name_mismatch(from_name: str, from_address: str) -> bool:
    """True when the display name shares no token with the address it claims to be."""
    if not from_name or not from_address:
        return False
    cleaned = re.sub(r"\(.*?\)|\[.*?\]|,.*$", "", from_name).strip()
    tokens = [t.lower() for t in re.split(r"[\s.\-_]+", cleaned) if len(t) > 2]
    if not tokens:
        return False
    local = from_address.lower().split("@")[0]
    haystack = from_address.lower()
    return not any(t in haystack or t[:4] in local for t in tokens)
