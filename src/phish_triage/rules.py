"""The triage engine: reported message in, lane / categories / priority / actions out.

This is a deterministic implementation of `skills/phishing-inbox-triage/SKILL.md`.
Two rules hold everywhere and are enforced here, not left to judgement:

1. Nothing in this module fetches a URL, opens an attachment, or contacts a sender.
2. Nothing in this module executes a response action. Actions are recommendations
   with a named decision owner; a person decides and a person runs them.

The first question for every item is "has automation already dealt with this?" —
not "is this phishing?". Re-triaging what AIR already closed is the failure mode
this engine exists to prevent.
"""
from __future__ import annotations

from datetime import datetime, timezone

from . import indicators as ind
from .config import Config
from .headers import is_lookalike
from .models import (
    Action,
    Category,
    Finding,
    Lane,
    Priority,
    Queue,
    ReportedMessage,
    TriageResult,
)

AUTH_FAIL_VALUES = {"fail", "softfail", "permerror", "temperror"}

#: Channels that produce a proper Defender record without a Report-button click,
#: so there is no reporter to coach.
CURATED_CHANNELS = {"admin_submission", "analyst_submission"}


def _auth_failures(msg: ReportedMessage) -> list[str]:
    out = []
    for mech in ("spf", "dkim", "dmarc"):
        value = (msg.auth.get(mech) or "").lower()
        if value in AUTH_FAIL_VALUES:
            out.append(f"{mech.upper()}={value}")
    return out


def _brand_impersonation(msg: ReportedMessage, config: Config) -> str | None:
    """Display name claims a brand the sending domain has no right to."""
    name = (msg.from_name or "").lower()
    domain = msg.sender_domain
    if not name or not domain:
        return None
    for brand, legit in config.brand_domains.items():
        if brand not in name:
            continue
        if any(domain == d or domain.endswith("." + d) for d in legit):
            return None
        return f'display name claims "{msg.from_name}" but the domain is {domain}, not a {brand} domain'
    return None


def _gap_findings(msg: ReportedMessage, config: Config) -> list[Finding]:
    """Process failures: the item never made it cleanly through the pipeline."""
    out: list[Finding] = []
    d = msg.defender
    # Two independent facts, and conflating them misreads the queue: which channel
    # the report arrived through (a coaching question), and whether a Defender record
    # exists at all (a pipeline question). An admin submission has a real submission
    # and no Report-button click; a forwarded mail has neither.
    if msg.reported_via == "pasted":
        if not d.has_submission:
            out.append(
                Finding(
                    "no_defender_record",
                    "Pasted for review — no Defender submission or AIR investigation exists for this message",
                )
            )
    else:
        if not msg.reported_by_button and msg.reported_via not in CURATED_CHANNELS:
            detail = f"Reported by {msg.reported_via.replace('_', ' ')} rather than the Outlook Report button"
            detail += (
                ", though a submission was raised for it afterwards"
                if d.has_submission
                else ", so no Defender submission and no AIR investigation exist"
            )
            out.append(Finding("not_reported_via_button", detail))
        if not d.has_submission and (msg.reported_by_button or msg.reported_via in CURATED_CHANNELS):
            out.append(
                Finding(
                    "submission_missing",
                    f"Recorded as {msg.reported_via.replace('_', ' ')} but no Defender submission is present — "
                    "check the Submissions page before assuming the pipeline ran",
                )
            )
    if d.air_errored:
        out.append(Finding("air_errored", f"AIR investigation status is {d.air_status} — the investigation did not complete"))
    if d.air_completed and not d.user_notified:
        out.append(Finding("reporter_not_notified", "AIR completed but the reporter was not notified of the verdict"))
    return out


def _age_hours(msg: ReportedMessage, now: datetime) -> float | None:
    if not msg.received:
        return None
    received = msg.received if msg.received.tzinfo else msg.received.replace(tzinfo=timezone.utc)
    return (now - received).total_seconds() / 3600.0


def _assess_bec(msg: ReportedMessage, config: Config, findings: list[Finding]) -> bool:
    """BEC is a person asking a person to do something. There is nothing to detonate,
    which is exactly why automation is weakest here and why authentication passing
    proves nothing."""
    text = msg.text
    finance = ind.has_finance_intent(text)
    bank_change = ind.has_bank_change(text)
    if not (finance or bank_change):
        return False

    signals: list[Finding] = []
    sender_dom = msg.sender_domain

    if config.org_domain and is_lookalike(sender_dom, config.org_domain):
        signals.append(Finding("lookalike_sender_domain", f"Sender domain {sender_dom} borrows the org brand but is not {config.org_domain}", Category.BEC))
    if msg.reply_to and msg.reply_to_domain != sender_dom:
        consumer = msg.reply_to_domain in ind_consumer_domains()
        detail = f"Reply-To {msg.reply_to} points away from the sending domain"
        if consumer:
            detail += " to a consumer mail domain"
        signals.append(Finding("reply_to_mismatch", detail, Category.BEC))
    if ind.display_name_mismatch(msg.from_name, msg.from_address):
        signals.append(Finding("display_name_mismatch", f'Display name "{msg.from_name}" shares nothing with {msg.from_address}', Category.BEC))
    brand = _brand_impersonation(msg, config)
    if brand:
        signals.append(Finding("brand_impersonation", brand.capitalize(), Category.BEC))
    if ind.claims_authority_role(msg.from_name) or ind.claims_authority_role(text):
        signals.append(Finding("authority_role_claimed", "Message claims an executive, finance, payroll or helpdesk role", Category.BEC))
    if ind.has_secrecy(text):
        signals.append(Finding("secrecy_pressure", "Asks the recipient to keep the request quiet or bypass the normal process", Category.BEC))
    if ind.has_unavailability(text):
        signals.append(Finding("unavailability_pretext", "Sender claims to be unreachable, which forecloses out-of-band verification", Category.BEC))
    if ind.has_urgency(text):
        signals.append(Finding("urgency_pressure", "Urgency or a deadline pushes the request past normal checks", Category.BEC))
    if bank_change and ind.is_thread_reply(msg.subject):
        signals.append(
            Finding(
                "thread_hijack_bank_change",
                "Bank or remittance change arriving inside an existing thread — the vendor-email-compromise "
                "pattern, where authentication passes because the mailbox is real",
                Category.BEC,
            )
        )
    if ind.has_mobile_signature(text) and not ind.is_thread_reply(msg.subject):
        signals.append(Finding("mobile_signature_no_thread", "Mobile signature with no thread history", Category.BEC))
    if msg.raw.get("sender_first_seen"):
        signals.append(Finding("first_seen_sender", "First message ever seen from this sender to the org", Category.BEC))
    if ind.contradicts_premise(msg.reporter_note):
        signals.append(
            Finding(
                "reporter_contradicts_premise",
                f"Reporter, who knows the relationship, contradicts the request's premise: \"{msg.reporter_note.strip()}\"",
                Category.BEC,
            )
        )

    # A money ask alone is not BEC; a money ask plus an impersonation or pressure
    # signal is. Two independent signals is the bar in exception-criteria.md — except
    # for the vendor-compromise pattern, where a bank change arriving inside a real
    # thread is the whole tell and everything else looks legitimate by design.
    decisive = {"thread_hijack_bank_change", "reporter_contradicts_premise"}
    if len(signals) < 2 and not any(f.code in decisive for f in signals):
        return False
    findings.extend(signals)
    if bank_change:
        findings.append(Finding("bank_detail_change", "Requests a change to bank, remittance or payee details", Category.BEC))
    elif finance:
        findings.append(Finding("money_movement_request", "Requests money movement or finance action", Category.BEC))
    return True


def ind_consumer_domains() -> set[str]:
    from .headers import CONSUMER_DOMAINS

    return CONSUMER_DOMAINS


def _assess_target_value(msg: ReportedMessage, config: Config, findings: list[Finding]) -> bool:
    """The target, not the lure, makes this one an exception."""
    vips = list(msg.recipients_vip)
    for address in [msg.reporter, *msg.raw.get("recipients", [])]:
        if config.is_vip(address) and address not in vips:
            vips.append(address)
    if not vips:
        return False
    findings.append(
        Finding(
            "vip_recipient",
            f"Priority account{'s' if len(vips) > 1 else ''} in scope: {', '.join(sorted(vips))}",
            Category.HIGH_VALUE_TARGET,
        )
    )
    return True


def _assess_interaction(msg: ReportedMessage, findings: list[Finding], unverified: list[str], questions: list[str]) -> tuple[bool, str]:
    """Did the lure work, even partially? Returns (is_exception, worst severity)."""
    kinds = ind.detect_interaction(msg.reporter_note)
    for kind in msg.raw.get("interactions", []):
        findings.append(Finding("telemetry_interaction", str(kind), Category.USER_INTERACTION))
    severity = ""
    for kind in kinds:
        findings.append(Finding(kind.code, kind.detail + " (reporter's own words)", Category.USER_INTERACTION))
        if kind.severity == "compromise":
            severity = "compromise"
        elif kind.severity == "engaged" and severity != "compromise":
            severity = "engaged"
        elif not severity:
            severity = "exposure"
    if msg.raw.get("interactions"):
        severity = severity or "compromise"

    for phrase in ind.detect_uncertainty(msg.reporter_note):
        unverified.append(f'Reporter is unsure ("{phrase}") — confirm directly rather than assuming no interaction')
    if severity == "exposure":
        questions.append("Did the reporter enter credentials or approve an MFA prompt after clicking? That answer moves this to P1.")
    return bool(severity), severity


def _assess_remediation(msg: ReportedMessage, config: Config, findings: list[Finding]) -> bool:
    """Automation proposed something whose blast radius needs a human."""
    hit = False
    d = msg.defender
    if d.awaiting_approval:
        pending = d.actions or "pending actions"
        findings.append(Finding("actions_awaiting_approval", f"Actions awaiting approval in the Action center: {pending}", Category.REMEDIATION_DECISION))
        hit = True
    if msg.recipient_count >= config.large_purge_threshold and (d.verdict_malicious or d.awaiting_approval):
        findings.append(
            Finding(
                "large_purge_scope",
                f"Purge scope is {msg.recipient_count} mailboxes — large enough that scope and timing are a decision, not a default",
                Category.REMEDIATION_DECISION,
            )
        )
        hit = True
    if msg.raw.get("shared_mailbox_or_dl") or msg.raw.get("legal_hold"):
        findings.append(Finding("sensitive_mailbox_scope", "Scope includes a shared mailbox, distribution list, or a mailbox on legal hold", Category.REMEDIATION_DECISION))
        hit = True
    return hit


def _assess_ambiguity(
    msg: ReportedMessage,
    config: Config,
    now: datetime,
    findings: list[Finding],
    contrary: list[str],
    unverified: list[str],
) -> bool:
    """Automation could not, or should not, settle this verdict."""
    hit = False
    d = msg.defender

    age = _age_hours(msg, now)
    if d.air_in_progress and age is not None and age >= config.air_stale_hours:
        findings.append(
            Finding(
                "air_stale",
                f"AIR status is {d.air_status} {age:.1f}h after the report — past the {config.air_stale_hours:g}h window, so it is stuck rather than in progress",
                Category.AMBIGUOUS,
            )
        )
        hit = True
    elif d.air_errored:
        findings.append(Finding("air_errored_exception", f"AIR ended as {d.air_status}; no verdict was produced", Category.AMBIGUOUS))
        hit = True

    if d.verdict_clean and contrary:
        findings.append(
            Finding(
                "disagree_with_air",
                f'AIR verdict "{d.verdict}" conflicts with the evidence ({"; ".join(contrary)}) — recommend disagreeing and resubmitting',
                Category.AMBIGUOUS,
            )
        )
        hit = True

    if d.verdict_malicious and config.is_known_partner(msg.sender_domain) and not _auth_failures(msg):
        findings.append(
            Finding(
                "possible_false_positive",
                f'AIR verdict "{d.verdict}" against {msg.sender_domain}, a domain the org corresponds with legitimately — '
                "confirm before blocking; false positives against real vendors break invoices and relationships",
                Category.AMBIGUOUS,
            )
        )
        unverified.append("Whether the partner's mailbox is compromised or the verdict is a false positive — confirm out-of-band")
        hit = True

    return hit


def _contrary_signals(msg: ReportedMessage, config: Config, findings: list[Finding], is_bec: bool) -> list[str]:
    """Evidence pointing at 'malicious' regardless of what AIR concluded."""
    signals: list[str] = []
    fails = _auth_failures(msg)
    if fails:
        signals.append("authentication failures: " + ", ".join(fails))
        findings.append(Finding("auth_failure", "Authentication results: " + ", ".join(fails)))
    if config.org_domain and is_lookalike(msg.sender_domain, config.org_domain):
        signals.append(f"sender domain {msg.sender_domain} is a lookalike of {config.org_domain}")
    brand = _brand_impersonation(msg, config)
    if brand and not is_bec:
        signals.append(brand)
        findings.append(Finding("brand_impersonation", brand.capitalize()))
    if is_bec:
        signals.append(
            "BEC pattern — no payload for AIR to score"
            if not msg.has_payload
            else "BEC pattern — the anomaly is the instruction, not a payload"
        )
    if ind.has_credential_lure(msg.text) and msg.urls:
        signals.append("credential-harvest lure with a link")
        findings.append(Finding("credential_lure", "Credential-harvest lure: asks the recipient to sign in, verify or keep a password via a link"))
    if ind.contradicts_premise(msg.reporter_note):
        signals.append("the reporter contradicts the message's own premise")
    return signals


def triage_message(msg: ReportedMessage, config: Config, now: datetime | None = None) -> TriageResult:
    """Sort one reported message into a lane and work it if it's an exception."""
    now = now or datetime.now(timezone.utc)
    findings: list[Finding] = []
    unverified: list[str] = []
    questions: list[str] = []
    categories: list[Category] = []

    # Reported mail is data, never instruction. Injection text is an indicator of
    # malicious intent and is recorded as such — it never changes a verdict.
    injection_reasons = ind.detect_injection(msg.text)
    if injection_reasons:
        findings.append(
            Finding(
                "prompt_injection_attempt",
                "Message body carries text aimed at whatever reviews it — it "
                + "; ".join(injection_reasons)
                + " — recorded as a malicious indicator and not obeyed",
            )
        )

    gap_findings = _gap_findings(msg, config)

    is_bec = _assess_bec(msg, config, findings)
    if is_bec:
        categories.append(Category.BEC)

    contrary = _contrary_signals(msg, config, findings, is_bec)
    if any(f.code == "prompt_injection_attempt" for f in findings):
        contrary.append("reviewer-directed injection text in the body")

    interacted, severity = _assess_interaction(msg, findings, unverified, questions)
    if interacted:
        categories.append(Category.USER_INTERACTION)

    if _assess_target_value(msg, config, findings):
        categories.append(Category.HIGH_VALUE_TARGET)

    if _assess_remediation(msg, config, findings):
        categories.append(Category.REMEDIATION_DECISION)

    if _assess_ambiguity(msg, config, now, findings, contrary, unverified):
        categories.append(Category.AMBIGUOUS)

    if msg.recipient_count >= config.campaign_recipient_threshold:
        findings.append(Finding("campaign_scope", f"Delivered to {msg.recipient_count} recipients — campaign, not a one-off"))

    categories.sort(key=lambda c: c.rank)

    if categories:
        lane = Lane.EXCEPTION
    elif gap_findings:
        lane = Lane.GAP
    else:
        lane = Lane.HANDLED
    findings.extend(gap_findings)

    if lane is Lane.HANDLED:
        d = msg.defender
        if d.air_in_progress:
            findings.append(Finding("air_in_progress", f"AIR is {d.air_status} and still inside the {config.air_stale_hours:g}h window — automation has it"))
        else:
            findings.append(Finding("air_closed", f'AIR completed with verdict "{d.verdict}", reporter notified; actions: {d.actions or "none needed"}'))

    priority = _priority(lane, categories, severity, msg, config)
    result = TriageResult(
        message=msg,
        lane=lane,
        categories=categories,
        priority=priority,
        findings=findings,
        unverified=unverified,
        open_questions=questions,
    )
    result.unverified.extend(_unverified_defaults(msg))
    result.actions = recommend_actions(result, config, severity)
    return result


def _priority(lane: Lane, categories: list[Category], severity: str, msg: ReportedMessage, config: Config) -> Priority:
    """Priority is about impact and reversibility, not about how phishy the mail looks."""
    if lane is not Lane.EXCEPTION:
        return Priority.P4
    if severity == "compromise":
        return Priority.P1
    if severity == "engaged" and (Category.BEC in categories or ind.has_finance_intent(msg.text)):
        return Priority.P1
    if severity in {"engaged", "exposure"}:
        return Priority.P2
    if Category.BEC in categories or Category.HIGH_VALUE_TARGET in categories:
        return Priority.P2
    if Category.REMEDIATION_DECISION in categories or msg.recipient_count >= config.campaign_recipient_threshold:
        return Priority.P2
    return Priority.P3


def _unverified_defaults(msg: ReportedMessage) -> list[str]:
    out: list[str] = []
    if not msg.defender.has_submission:
        out.append("AIR status and verdict — not available; check the Defender Submissions page")
    if msg.recipient_count > 1 and not msg.raw.get("recipients"):
        out.append(f"Whether any of the other {msg.recipient_count - 1} recipients interacted — check UrlClickEvents and sign-in logs")
    return out


def recommend_actions(result: TriageResult, config: Config, severity: str = "") -> list[Action]:
    """Build the recommended action list. Ordered by what has to happen first.

    Nothing here is executed. Each action names the decision owner, per
    `skills/phishing-inbox-triage/references/response-actions.md`.
    """
    msg = result.message
    actions: list[Action] = []

    def add(action: str, owner: str, note: str = "") -> None:
        if not any(a.action == action for a in actions):
            actions.append(Action(action, owner, note))

    codes = {f.code for f in result.findings}
    if Category.USER_INTERACTION in result.categories:
        # What the user actually did decides what has to happen first. Credentials
        # and MFA come before mail actions: the attacker already has the session.
        if codes & {"credentials_entered", "mfa_approved"}:
            add("Reset password and revoke all sessions and refresh tokens", "IAM", f"account {msg.reporter}; revoking tokens, not just the password")
            add("Review MFA methods and re-register if an attacker method was added", "IAM")
        if codes & {"attachment_opened", "downloaded_file"}:
            add("Isolate the device and run an EDR investigation for execution after delivery", "SOC / IR")
        if "payment_or_data_actioned" in codes:
            add("Hold or recall the payment and freeze the changed payee record", "Finance / AP", "speed matters more than certainty here")
        if "replied_to_sender" in codes:
            add("Confirm with the reporter exactly what was sent in the reply and whether anything was actioned after it", "SOC analyst")
            add("Warn the impersonated party out-of-band that a thread is running in their name", "SOC analyst")
        if codes & {"clicked_link", "downloaded_file"}:
            add("Check UrlClickEvents and Safe Links telemetry for whether the click was allowed or blocked", "SOC analyst")
            add("Ask the reporter directly whether credentials were entered or an MFA prompt approved", "SOC analyst")
        if severity == "compromise":
            add("Review inbox rules, forwarding, consent grants and delegations", "SOC / IAM", "attackers persist via rules")
            add("Scope the blast radius: sign-in logs and data accessed after delivery", "SOC / IR")
            add("Open an incident", "SOC lead / IR")
        else:
            add("Watch sign-in logs for this account for unfamiliar location, new device or impossible travel", "SOC analyst")

    if Category.BEC in result.categories:
        add("Confirm whether any recipient replied, paid, or changed vendor or payee details", "SOC analyst")
        add("Alert AP / payroll to hold any payment referencing this request", "Finance / AP")
        if config.is_known_partner(msg.sender_domain) or (msg.auth.get("dmarc") == "pass" and ind.is_thread_reply(msg.subject)):
            add(
                "Verify the change out-of-band by calling the vendor on a known number",
                "Finance / AP",
                "never a number from the email",
            )
            add("Notify the vendor that their mailbox may be compromised", "Vendor management", "out-of-band")
            add(
                "Block the sender address only — do not block the domain",
                "SOC analyst",
                f"{msg.sender_domain} is a domain the org corresponds with legitimately",
            )
        else:
            add("Block the sender address in the Tenant Allow/Block List", "SOC analyst")
        add("Soft delete the message from all recipients", "SOC analyst")
        add("Hunt the display name and Reply-To across the tenant for other recipients who did not report", "SOC analyst")

    if Category.HIGH_VALUE_TARGET in result.categories:
        add("Confirm the priority account did not interact before any purge", "SOC analyst")
        add("Hunt the same lure across other priority accounts", "SOC analyst")
        add("Notify the executive's assistant or exec-protection contact", "SOC analyst")

    if Category.REMEDIATION_DECISION in result.categories:
        scope = f"{msg.recipient_count} mailboxes"
        pending = msg.defender.actions or ""
        if "block domain" in pending.lower():
            attacker_controlled = not config.is_known_partner(msg.sender_domain)
            if attacker_controlled:
                add(
                    f"Approve the pending soft delete ({scope}) and the domain block",
                    "SOC analyst; SOC lead for cross-department scope",
                    f"{msg.sender_domain} is attacker-controlled, so the domain block carries no legitimate traffic",
                )
            else:
                add(
                    f"Approve the pending soft delete ({scope}); reject the domain block",
                    "SOC lead",
                    f"the org corresponds with {msg.sender_domain} legitimately",
                )
        else:
            add(f"Decide and approve the pending actions in the Action center (scope: {scope})", "SOC analyst; SOC lead if cross-department")
        add("Block the URL first — lowest collateral, immediate effect", "SOC analyst")
        if not msg.defender.user_notified:
            add("Notify the reporters manually, since auto-notify does not fire while actions are pending", "SOC analyst")

    if Category.AMBIGUOUS in result.categories:
        if msg.defender.air_in_progress or msg.defender.air_errored:
            stuck = "errored" if msg.defender.air_errored else "stalled"
            add(f"Chase the {stuck} AIR investigation ({msg.defender.submission_id or 'no submission id'}) or triage it manually", "SOC analyst")
            add(f"Raise the {stuck} investigation with whoever owns Defender configuration", "Defender admin")
        if msg.defender.verdict_clean:
            add("Reject the AIR verdict and resubmit to Microsoft as phishing so the reporter gets the correct notification", "SOC analyst")
        # Only hold when nothing more decisive has already settled the mail action;
        # recommending a purge and a hold on the same message helps nobody.
        if not any("delete" in a.action.lower() for a in actions):
            add("Hold the message in quarantine rather than purging until the verdict is decided", "SOC analyst")
        if msg.urls:
            add("Block the URL as a holding action while the verdict is open", "SOC analyst")

    if result.lane is Lane.GAP:
        if not msg.defender.has_submission:
            add("Submit the message to Microsoft on the reporter's behalf", "SOC analyst")
        if not msg.reported_by_button and msg.reported_via != "pasted":
            add("Coach the reporter on the Outlook Report button", "SOC analyst", "they did the right thing by reporting — keep it friendly")
        if msg.defender.air_errored:
            add("Raise the AIR error with whoever owns Defender configuration", "Defender admin")
        if any(f.code == "credential_lure" for f in result.findings) and msg.urls:
            add("After submitting, block the URL — the lure is a credential-harvest page", "SOC analyst")

    if (
        result.lane is Lane.EXCEPTION
        and msg.defender.verdict_malicious
        and not msg.defender.awaiting_approval
        and not any("delete" in a.action.lower() for a in actions)
    ):
        add("Soft delete from all recipients", "SOC analyst", "recoverable; hard delete only for malware or confirmed large-scope credential lures")

    return actions


def triage(queue: Queue, config: Config | None = None, now: datetime | None = None) -> list[TriageResult]:
    """Triage a whole queue, ordered for the report: priority first, then arrival."""
    config = config or Config()
    if not config.org_domain and queue.org_domain:
        config.org_domain = queue.org_domain
    if not config.vip_list and queue.vip_list:
        config.vip_list = list(queue.vip_list)
    now = now or _window_end(queue) or datetime.now(timezone.utc)

    results = [triage_message(m, config, now) for m in queue.items]
    lane_order = {Lane.EXCEPTION: 0, Lane.GAP: 1, Lane.HANDLED: 2}
    results.sort(key=lambda r: (lane_order[r.lane], r.priority.value, r.message.received or datetime.max.replace(tzinfo=timezone.utc)))
    return results


def _window_end(queue: Queue) -> datetime | None:
    """Use the export window's end as 'now' so a rerun of the same export is stable."""
    if not queue.window or " to " not in queue.window:
        return None
    try:
        end = queue.window.split(" to ")[-1].strip()
        parsed = datetime.fromisoformat(end.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None
