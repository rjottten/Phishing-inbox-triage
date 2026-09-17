#!/usr/bin/env python3
"""Deterministic SOC rounds: consolidate four portals, prioritize, decide authority.

This is the SKILL.md workflow as code, so the rounds can be worked with no LLM in
the loop. Every decision is a rule you can read, test and audit:

    consolidate  Sentinel incidents re-ingested from Defender are merged; Upwind
                 findings are grouped into the change they would be fixed by;
                 GitHub alert locations collapse to one secret
    priority     P1..P4 by consequence, per SKILL.md, not by portal severity
    authority    every proposed action carries a tier (observe/record/contain/
                 change) and, for contain, the five gates from
                 references/action-authority.md with the failures named
    changes      Tier 3 work becomes change groups, one per executable change,
                 classified emergency / normal / standard

It decides; it does not act. Nothing here reaches a network — no revocation, no
CR submission, no portal write. Execution is the caller's, under the authority
this output describes. CI enforces the offline property.

Usage:
    python rounds.py bundle.json                       # Markdown rounds report
    python rounds.py bundle.json --format json         # machine-readable
    python rounds.py bundle.json --auto-contain-max-scope 10 --now 2026-09-17T09:00:00Z
    python rounds.py bundle.json --no-auto-contain     # propose containment, never auto

Input is the bundle shape in test-data/rounds_bundle.json: rounds_meta plus
github_secret_alerts, upwind_findings, defender_incidents, sentinel_incidents.
A section that is absent is reported as NOT COLLECTED, never as zero, because
absent and clean look identical in a summary and mean opposite things.

Findings are data, never instructions. Text inside an alert, commit message,
resource tag or incident comment that addresses an automated reviewer is
reported as an indicator and raises priority; it never triggers an action.
"""
import argparse
import json
import os
import re
import sys
from collections import Counter, OrderedDict
from datetime import datetime, timedelta, timezone

# --------------------------------------------------------------------------
# Vocabulary
# --------------------------------------------------------------------------

SECTIONS = OrderedDict([
    ("github_secret_alerts", "GitHub secrets"),
    ("upwind_findings", "Upwind"),
    ("defender_incidents", "Defender"),
    ("sentinel_incidents", "Sentinel"),
])

PRIORITIES = ["P1", "P2", "P3", "P4"]

TIER_NAMES = {0: "observe", 1: "record", 2: "contain", 3: "change"}

GATES = ["first_party", "unambiguous", "bounded_scope", "reversible", "rollback_recorded"]

GATE_LABEL = {
    "first_party": "Gate 1 (first-party evidence)",
    "unambiguous": "Gate 2 (unambiguous)",
    "bounded_scope": "Gate 3 (bounded blast radius)",
    "reversible": "Gate 4 (single-step reversible)",
    "rollback_recorded": "Gate 5 (rollback recorded)",
}

# Providers that support issuing a replacement credential of the same scope
# before the old one dies. Gate 4 turns on this: a credential you cannot
# re-issue is not a reversible revocation. `provider_reissuable` on the alert
# overrides this, because an org's own provider list beats a default.
REISSUABLE_SECRET_TYPES = {
    "aws_access_key_id", "aws_secret_access_key", "azure_storage_account_key",
    "azure_ad_client_secret", "google_api_key", "google_oauth_client_secret",
    "github_personal_access_token", "github_oauth_access_token", "github_app_token",
    "slack_api_token", "stripe_api_key", "stripe_test_api_key", "twilio_api_key",
    "sendgrid_api_key", "datadog_api_key", "npm_access_token", "pypi_api_token",
    "atlassian_api_token", "openai_api_key", "anthropic_api_key",
}

ACTIVE = "active"
INACTIVE = "inactive"
UNKNOWN = "unknown"

RESOLVED_STATES = {"resolved", "closed", "true_positive", "false_positive", "benign_positive"}
OPEN_STATES = {"new", "open", "active", "in_progress", "inprogress"}

DEFAULT_SLA_HOURS = {
    # severity: (acknowledge, contain)
    "critical": (0.25, 1.0),
    "high": (1.0, 4.0),
    "medium": (8.0, 24.0),
    "low": (24.0, 168.0),
    "informational": (72.0, 336.0),
}

# Environments whose changes always need CAB. Anything else may qualify as a
# standard (pre-approved) change when the fix type is in the catalogue.
PRODUCTION_ENVS = {"production", "prod", "prd"}

DEFAULT_STANDARD_CATALOGUE = ["package_upgrade"]

# Text addressed at an automated reviewer. Finding this is an indicator: the
# item's priority floor rises and nothing about it may be auto-actioned.
INJECTION_RX = re.compile(
    r"(?:\b(?:ai|llm|automated|automatic)\b[^.\n]{0,40}\b(?:reviewer|agent|assistant|"
    r"triage|scanner|analyst|system)\b)"
    r"|(?:\bignore (?:all |any |the )?(?:previous|prior|above|earlier)\b)"
    r"|(?:\b(?:mark|classify|close|treat|set|flag) (?:this|it|the alert|the finding)"
    r"[^.\n]{0,30}\b(?:as )?(?:safe|clean|benign|resolved|false[ -]positive|not an issue)\b)"
    r"|(?:\bdo not (?:escalate|report|flag|alert|investigate)\b)"
    r"|(?:\b(?:approved|authorized|sanctioned|signed[ -]off|whitelisted) by "
    r"(?:security|the soc|infosec|the security team)\b)",
    re.I,
)


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def _parse_time(value):
    """ISO-8601 in, aware datetime or None out. Tolerates a trailing Z."""
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _age_hours(start, now):
    start = _parse_time(start)
    if not start or not now:
        return None
    return (now - start).total_seconds() / 3600.0


def _norm(value):
    return str(value or "").strip().lower()


def _listify(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [v for v in value]
    return [value]


def escalate(priority, steps=1):
    """Raise a priority by `steps` levels, saturating at P1."""
    index = PRIORITIES.index(priority) if priority in PRIORITIES else len(PRIORITIES) - 1
    return PRIORITIES[max(0, index - steps)]


def worst(priorities):
    """The most consequential priority in a collection; P4 when empty."""
    ranked = [p for p in priorities if p in PRIORITIES]
    if not ranked:
        return "P4"
    return PRIORITIES[min(PRIORITIES.index(p) for p in ranked)]


def floor_priority(priority, minimum):
    """Never let `priority` sit below `minimum` (P1 is the top)."""
    return priority if PRIORITIES.index(priority) <= PRIORITIES.index(minimum) else minimum


def scan_for_injection(*values):
    """Instruction-like text aimed at an automated reviewer, as evidence strings."""
    hits = []
    for value in values:
        for text in _flatten_text(value):
            for match in INJECTION_RX.findall(text):
                snippet = " ".join(str(text).split())
                if len(snippet) > 160:
                    snippet = snippet[:157] + "..."
                hits.append(snippet)
                break
    # Dedupe while keeping order; the same tag repeated on 40 containers is one tell.
    seen = set()
    unique = []
    for hit in hits:
        if hit not in seen:
            seen.add(hit)
            unique.append(hit)
    return unique


def _flatten_text(value):
    """Every string reachable inside a nested structure."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        out = []
        for key, item in value.items():
            out.extend(_flatten_text(key))
            out.extend(_flatten_text(item))
        return out
    if isinstance(value, (list, tuple, set)):
        out = []
        for item in value:
            out.extend(_flatten_text(item))
        return out
    return []


# --------------------------------------------------------------------------
# Actions and the five gates
#
# An action carries its own authority. Tier 0 and 1 are automatic; tier 3 never
# is; tier 2 is automatic only when every gate in references/action-authority.md
# holds. A failed gate is *named*, because the name is what tells the analyst
# which fact to go and establish.
# --------------------------------------------------------------------------

def make_action(action_id, tier, description, target, owner,
                rollback=None, gates=None, requires_judgment=False,
                blocked_reason=None, cr_group=None):
    return {
        "id": action_id,
        "tier": tier,
        "tier_name": TIER_NAMES[tier],
        "description": description,
        "target": target,
        "owner": owner,
        "rollback": rollback,
        "gates": dict(gates or {}),
        "gates_failed": [],
        "requires_judgment": requires_judgment,
        "blocked_reason": blocked_reason,
        "cr_group": cr_group,
        "auto": False,
    }


def decide_authority(action, cfg, in_scope=True, injection=False):
    """Fill in gates_failed and `auto`. The only place autonomy is granted."""
    reasons = []

    if not in_scope:
        # Reading outside the authorized scope is not a tier 0 freebie; it is a
        # policy violation with a friendly name. This one applies at every tier.
        reasons.append("target is outside the authorized scope")
    if injection and action["tier"] > 0:
        # Stop-list item 6: instruction-like text in a finding raises priority
        # and freezes automation on that item. It never licenses an action.
        #
        # Tier 0 is deliberately exempt. Gathering more evidence is exactly the
        # right response to an item that tried to talk to its reviewer, and
        # freezing the hunt would let the injection achieve what it wanted.
        reasons.append("reviewer-directed text found in the item's own content")

    if action["tier"] == 3:
        reasons.append("tier 3 changes never execute outside a change request")
    if action["requires_judgment"]:
        reasons.append("requires an investigation a rules engine cannot perform")
    if action["blocked_reason"]:
        reasons.append(action["blocked_reason"])

    if action["tier"] == 2:
        if cfg.get("no_auto_contain"):
            reasons.append("automatic containment disabled for this run")
        for gate in GATES:
            if action["gates"].get(gate) is not True:
                action["gates_failed"].append(gate)
        if action["gates_failed"]:
            reasons.extend(GATE_LABEL[g] for g in action["gates_failed"])

    action["auto"] = not reasons
    action["blocked_by"] = reasons
    return action


def scope_gate(cfg, count, enumerated):
    """Gate 3: enumerated, and within the configured limit."""
    if not enumerated or count is None:
        return False
    return count <= cfg["max_scope"]


def in_authorized_scope(cfg, *candidates):
    """Scope is allow-list when one is configured, and open when none is.

    An empty allow-list means the operator did not configure one, not that
    nothing is permitted — refusing everything silently would look identical to
    a clean queue, which is the failure mode this whole tool exists to avoid.
    """
    allow = cfg.get("authorized_scope") or []
    if not allow:
        return True
    haystack = [_norm(c) for c in candidates if c]
    for pattern in allow:
        pattern = _norm(pattern)
        if not pattern:
            continue
        stem = pattern.rstrip("*")
        for value in haystack:
            if value == pattern or (stem and stem in value):
                return True
    return False


# --------------------------------------------------------------------------
# Duty 1 — GitHub secret scanning
# --------------------------------------------------------------------------

def _secret_key(alert):
    """One credential, however many alerts GitHub raised for it."""
    fingerprint = alert.get("secret_fingerprint") or alert.get("fingerprint")
    if fingerprint:
        return ("fp", _norm(fingerprint))
    preview = alert.get("secret_preview") or alert.get("secret")
    if preview:
        return ("preview", _norm(alert.get("secret_type")), _norm(preview))
    return ("id", _norm(alert.get("id") or alert.get("number")))


def collapse_secret_alerts(alerts):
    """Collapse alerts describing the same credential; keep the locations."""
    merged = OrderedDict()
    for alert in alerts:
        key = _secret_key(alert)
        if key not in merged:
            copy = dict(alert)
            copy["locations"] = list(_listify(alert.get("locations")))
            copy["repos"] = [alert["repo"]] if alert.get("repo") else []
            copy["alert_ids"] = [alert.get("id") or alert.get("number")]
            merged[key] = copy
            continue
        existing = merged[key]
        existing["locations"].extend(_listify(alert.get("locations")))
        if alert.get("repo") and alert["repo"] not in existing["repos"]:
            existing["repos"].append(alert["repo"])
        existing["alert_ids"].append(alert.get("id") or alert.get("number"))
        # The most exposed repository and the liveliest validity win.
        if _norm(alert.get("repo_visibility")) == "public":
            existing["repo_visibility"] = "public"
        if _norm(alert.get("validity")) == ACTIVE:
            existing["validity"] = ACTIVE
        if alert.get("push_protection_bypassed"):
            existing["push_protection_bypassed"] = True
    return list(merged.values())


def triage_secret(alert, cfg, now):
    validity = _norm(alert.get("validity")) or UNKNOWN
    public = _norm(alert.get("repo_visibility")) == "public"
    state = _norm(alert.get("state")) or "open"
    closed = state not in OPEN_STATES and state != ""
    owner_team = alert.get("owner_team") or alert.get("codeowners") or None
    repos = alert.get("repos") or ([alert["repo"]] if alert.get("repo") else [])
    locations = _listify(alert.get("locations"))
    consumers = _listify(alert.get("consumers"))
    enumerated = bool(alert.get("consumers_enumerated"))
    secret_type = _norm(alert.get("secret_type"))
    display = alert.get("secret_type_display_name") or alert.get("secret_type") or "secret"

    injection = scan_for_injection(
        alert.get("bypass_reason"), alert.get("notes"), alert.get("resolution_comment"),
        [loc.get("path") for loc in locations if isinstance(loc, dict)],
    )

    evidence = []
    not_established = []
    reasons = []

    if validity == ACTIVE:
        evidence.append("validity check: active — the provider confirms it authenticates")
    elif validity == INACTIVE:
        evidence.append("validity check: inactive — the provider confirms it does not authenticate")
    else:
        not_established.append("validity — not partner-verifiable, or the check failed")

    evidence.append("exposure: %s, %d location(s) across %d repo(s)" % (
        "public" if public else "private", len(locations), max(1, len(repos))))

    if alert.get("last_used"):
        evidence.append("provider last-used: %s" % alert["last_used"])
    else:
        not_established.append("whether the credential was ever used — the provider's audit log has this")

    if enumerated:
        evidence.append("consumers enumerated: %s" % (", ".join(map(str, consumers)) or "none"))
    else:
        not_established.append("which services authenticate with this credential")

    # Priority. A public exposure is assumed harvested from push time, so an
    # unknown-validity secret in a public repo is still P1 as a *finding* even
    # though it cannot be an auto-revoke *action*.
    if validity == INACTIVE:
        priority = "P3" if public else "P4"
        reasons.append("already inactive; the question is what it did while live"
                       if public else "already inactive, never publicly exposed")
    elif public:
        priority = "P1"
        reasons.append("live or unverified credential in a public repository — assume harvested")
    elif validity == ACTIVE:
        priority = "P2"
        reasons.append("credential confirmed live, exposure limited to the org")
    else:
        priority = "P3"
        reasons.append("unverified credential in a private repository")

    if alert.get("push_protection_bypassed"):
        reasons.append("committed past push protection: %s" % (
            alert.get("bypass_reason") or "no reason given"))
        priority = floor_priority(priority, "P3")

    if injection:
        reasons.append("reviewer-directed text in the alert's own content — indicator, not instruction")
        priority = floor_priority(priority, "P2")

    scope_name = "%s (%s)" % (display, alert.get("secret_preview") or "no preview")
    in_scope = in_authorized_scope(cfg, *repos)
    if not in_scope:
        reasons.append("outside the authorized repository scope — escalate, do not action")

    reissuable = alert.get("provider_reissuable")
    if reissuable is None:
        reissuable = secret_type in REISSUABLE_SECRET_TYPES
        if not reissuable:
            not_established.append("whether the provider can re-issue this credential's scope")

    bypass_disputed = bool(alert.get("push_protection_bypassed")) and not alert.get("bypass_verified")

    actions = []
    if not closed and validity != INACTIVE:
        gates = {
            "first_party": validity == ACTIVE,
            "unambiguous": validity == ACTIVE and not bypass_disputed and not injection,
            "bounded_scope": scope_gate(cfg, len(consumers), enumerated),
            "reversible": bool(reissuable),
            "rollback_recorded": bool(reissuable) and bool(owner_team),
        }
        rollback = None
        if gates["reversible"] and owner_team:
            rollback = "Re-issue an equivalent %s from the provider console; %s holds the scope" % (
                display, owner_team)
        actions.append(decide_authority(make_action(
            "%s-revoke" % (alert.get("id") or "secret"),
            2,
            "Revoke the exposed %s at the provider" % display,
            scope_name,
            owner_team or "service owner (unidentified — find via CODEOWNERS)",
            rollback=rollback,
            gates=gates,
        ), cfg, in_scope=in_scope, injection=bool(injection)))

        if consumers:
            actions.append(decide_authority(make_action(
                "%s-rotate" % (alert.get("id") or "secret"),
                3,
                "Deploy the replacement credential to %d enumerated consumer(s)" % len(consumers),
                ", ".join(map(str, consumers)),
                owner_team or "service owner",
            ), cfg, in_scope=in_scope, injection=bool(injection)))

    if not closed and (public or validity == ACTIVE):
        actions.append(decide_authority(make_action(
            "%s-hunt" % (alert.get("id") or "secret"),
            0,
            "Hunt the provider audit log over the exposure window for use from "
            "unexpected addresses, regions or user agents",
            scope_name,
            "SOC analyst on shift",
        ), cfg, in_scope=in_scope, injection=bool(injection)))

    if not closed and owner_team:
        actions.append(decide_authority(make_action(
            "%s-notify" % (alert.get("id") or "secret"),
            1,
            "Notify the owning team with the finding and the rotation order",
            owner_team,
            owner_team,
            rollback="Delete the notification",
        ), cfg, in_scope=in_scope, injection=bool(injection)))

    if validity == INACTIVE and not closed:
        actions.append(decide_authority(make_action(
            "%s-close" % (alert.get("id") or "secret"),
            1,
            "Close the alert with resolution `revoked`, recording the evidence",
            scope_name,
            "SOC analyst on shift",
            rollback="Reopen the alert",
            requires_judgment=public,  # a public exposure needs the hunt first
            blocked_reason="public exposure — hunt the live window before closing" if public else None,
        ), cfg, in_scope=in_scope, injection=bool(injection)))

    return {
        "id": str(alert.get("id") or alert.get("number") or scope_name),
        "source": "github",
        "source_label": "GitHub secrets",
        "title": "%s in %s" % (display, ", ".join(repos) or "unknown repo"),
        "priority": priority,
        "reasons": reasons,
        "evidence": evidence,
        "not_established": not_established,
        "actions": actions,
        "owner": owner_team or "service owner (unidentified)",
        "in_scope": in_scope,
        "injection": injection,
        "merged_from": alert.get("alert_ids") or [],
        "detail": {
            "validity": validity,
            "public": public,
            "locations": len(locations),
            "repos": repos,
            "consumers": consumers,
            "consumers_enumerated": enumerated,
            "push_protection_bypassed": bool(alert.get("push_protection_bypassed")),
        },
    }


# --------------------------------------------------------------------------
# Duty 2 — Upwind findings, grouped into the change that fixes them
# --------------------------------------------------------------------------

def _asset(finding):
    return finding.get("asset") or {}


def _runtime(finding):
    return finding.get("runtime") or {}


def rank_finding(finding):
    """Priority for one finding, led by runtime reachability rather than by score."""
    runtime = _runtime(finding)
    asset = _asset(finding)
    severity = _norm(finding.get("severity"))
    production = _norm(asset.get("environment")) in PRODUCTION_ENVS
    running = bool(runtime.get("running"))
    loaded = bool(runtime.get("package_loaded"))
    exposed = bool(runtime.get("internet_exposed"))
    exploited = bool(finding.get("known_exploited"))

    reasons = []
    if not running:
        reasons.append("asset not running — registry or inventory hygiene, not patching")
        return "P4", reasons
    if exploited and exposed and loaded and production:
        reasons.append("known-exploited, internet-exposed, vulnerable code path loaded, production")
        return "P1", reasons
    if exploited and (exposed or production) and loaded:
        reasons.append("known-exploited and reachable, vulnerable code path loaded")
        return "P2", reasons
    if exposed and loaded and severity in ("critical", "high"):
        reasons.append("%s severity, internet-exposed, vulnerable code path loaded" % severity)
        return "P2", reasons
    if loaded:
        reasons.append("vulnerable code path loaded, no observed internet exposure")
        return "P3", reasons
    reasons.append("present but not loaded at runtime — real, not urgent")
    return "P4", reasons


def group_key(finding):
    asset = _asset(finding)
    return (
        _norm(asset.get("owner_team")) or "unassigned",
        _norm(asset.get("environment")) or "unknown",
        _norm(finding.get("fix_type")) or "unknown",
        _norm(finding.get("fix_target")) or _norm(finding.get("fixed_version")) or "unknown",
    )


def change_class(priority, environment, fix_type, catalogue):
    """Exposure and exploitation pick the class. A score never does."""
    if priority == "P1":
        return "emergency", "active or imminent exploitation of a reachable asset"
    if _norm(environment) in PRODUCTION_ENVS:
        return "normal", "production change — CAB and a scheduled window"
    if _norm(fix_type) in {_norm(c) for c in catalogue}:
        return "standard", "non-production and listed in the change catalogue — pre-approved"
    return "normal", "not in the change catalogue, so it is a normal change however routine it feels"


def triage_upwind(findings, cfg, now):
    """Rank every finding, then group them into executable changes."""
    ranked = []
    for finding in findings:
        priority, reasons = rank_finding(finding)
        injection = scan_for_injection(
            finding.get("title"), finding.get("description"),
            _asset(finding).get("tags"), _asset(finding).get("name"),
            finding.get("notes"),
        )
        if injection:
            reasons.append("reviewer-directed text in the finding's own content — indicator, not instruction")
            priority = floor_priority(priority, "P2")
        ranked.append({"finding": finding, "priority": priority,
                       "reasons": reasons, "injection": injection})

    groups = OrderedDict()
    for entry in ranked:
        finding = entry["finding"]
        if not finding.get("fix_available", True):
            continue  # no change to raise; handled as its own item below
        key = group_key(finding)
        if key not in groups:
            groups[key] = {
                "id": "CG-%d" % (len(groups) + 1),
                "owner_team": _asset(finding).get("owner_team") or "unassigned",
                "environment": _asset(finding).get("environment") or "unknown",
                "fix_type": finding.get("fix_type") or "unknown",
                "fix_target": finding.get("fix_target") or finding.get("fixed_version") or "unknown",
                "findings": [],
                "assets": [],
                "cves": [],
                "dependents": [],
                "priority": "P4",
                "injection": [],
            }
        group = groups[key]
        group["findings"].append(finding.get("id"))
        group["priority"] = worst([group["priority"], entry["priority"]])
        asset = _asset(finding)
        asset_name = asset.get("name") or asset.get("id")
        if asset_name and asset_name not in group["assets"]:
            group["assets"].append(asset_name)
        if finding.get("cve") and finding["cve"] not in group["cves"]:
            group["cves"].append(finding["cve"])
        for dependent in _listify(_runtime(finding).get("dependents")):
            if dependent not in group["dependents"]:
                group["dependents"].append(dependent)
        group["injection"].extend(entry["injection"])

    catalogue = cfg.get("standard_catalogue") or DEFAULT_STANDARD_CATALOGUE
    items = []

    for group in groups.values():
        klass, rationale = change_class(group["priority"], group["environment"],
                                        group["fix_type"], catalogue)
        group["change_class"] = klass
        group["class_rationale"] = rationale
        group["asset_count"] = len(group["assets"])
        group["title"] = "%s: %s on %d %s (%s)" % (
            group["fix_type"], group["fix_target"], group["asset_count"],
            "asset" if group["asset_count"] == 1 else "assets", group["environment"])

        in_scope = in_authorized_scope(cfg, group["owner_team"], *group["assets"])
        injection = bool(group["injection"])

        raise_cr = decide_authority(make_action(
            "%s-cr" % group["id"], 1,
            "Raise a %s Cherwell change request for this change group" % klass,
            group["title"],
            "%s (executes); CAB approves" % group["owner_team"],
            rollback="Cancel the change request",
            cr_group=group["id"],
        ), cfg, in_scope=in_scope, injection=injection)

        execute = decide_authority(make_action(
            "%s-exec" % group["id"], 3,
            "Execute the remediation: %s" % group["fix_target"],
            ", ".join(group["assets"][:8]) + (" (+%d more)" % (group["asset_count"] - 8)
                                              if group["asset_count"] > 8 else ""),
            group["owner_team"],
            cr_group=group["id"],
        ), cfg, in_scope=in_scope, injection=injection)

        evidence = ["%d finding(s) fixed by one change: %s" % (
            len(group["findings"]), ", ".join(group["findings"][:10]))]
        if group["cves"]:
            evidence.append("CVEs: %s" % ", ".join(group["cves"][:10]))
        if group["dependents"]:
            evidence.append("observed dependents (the blast-radius answer CAB asks for): %s"
                            % ", ".join(map(str, group["dependents"][:10])))
        else:
            evidence.append("no dependents observed in the runtime graph")

        reasons = [rationale]
        if injection:
            reasons.append("reviewer-directed text in a finding's own content — indicator, not instruction")

        items.append({
            "id": group["id"],
            "source": "upwind",
            "source_label": "Upwind",
            "title": group["title"],
            "priority": group["priority"],
            "reasons": reasons,
            "evidence": evidence,
            "not_established": [] if group["dependents"] else
                               ["whether anything depends on these assets — check the runtime graph "
                                "before the change window"],
            "actions": [raise_cr, execute],
            "owner": group["owner_team"],
            "in_scope": in_scope,
            "injection": group["injection"],
            "merged_from": group["findings"],
            "detail": {"change_class": klass, "fix_type": group["fix_type"],
                       "fix_target": group["fix_target"], "assets": group["asset_count"],
                       "environment": group["environment"]},
        })

    # Findings with no fix are not changes. They are risk decisions, and the SOC
    # is never the owner of a risk acceptance.
    for entry in ranked:
        finding = entry["finding"]
        if finding.get("fix_available", True):
            continue
        asset = _asset(finding)
        in_scope = in_authorized_scope(cfg, asset.get("owner_team"), asset.get("name"))
        items.append({
            "id": finding.get("id"),
            "source": "upwind",
            "source_label": "Upwind",
            "title": "%s — no fix available" % (finding.get("title") or finding.get("cve") or "finding"),
            "priority": entry["priority"],
            "reasons": entry["reasons"] + ["no vendor fix — mitigating control or risk acceptance"],
            "evidence": ["asset: %s (%s, %s)" % (asset.get("name"), asset.get("kind"),
                                                 asset.get("environment"))],
            "not_established": ["whether a mitigating control is already in place"],
            "actions": [decide_authority(make_action(
                "%s-accept" % finding.get("id"), 1,
                "Record a mitigating control or a risk acceptance with a review date",
                asset.get("name") or finding.get("id"),
                "%s (system owner accepts; the SOC never does)" % (asset.get("owner_team") or "system owner"),
                rollback="Withdraw the risk acceptance record",
                requires_judgment=True,
            ), cfg, in_scope=in_scope, injection=bool(entry["injection"]))],
            "owner": asset.get("owner_team") or "system owner",
            "in_scope": in_scope,
            "injection": entry["injection"],
            "merged_from": [],
            "detail": {"no_fix": True},
        })

    return items, list(groups.values()), ranked


# --------------------------------------------------------------------------
# Duties 3 and 4 — Defender and Sentinel, deduplicated first
# --------------------------------------------------------------------------

def dedupe_incidents(defender, sentinel):
    """Merge Sentinel copies of Defender incidents. Do this before counting.

    Sentinel re-ingests Defender incidents, so the same attack sits in both
    queues under different IDs. Two analysts can work it independently for an
    hour before discovering each other. The merged item records which portal
    owns the response, because that is the fact that prevents it.
    """
    merged = []
    matched_sentinel = set()

    by_id = {}
    alert_index = {}
    for incident in defender:
        by_id[_norm(incident.get("id"))] = incident
        for alert_id in _listify(incident.get("alert_ids")):
            alert_index.setdefault(_norm(alert_id), incident)

    for incident in defender:
        item = dict(incident)
        item["source"] = "defender"
        item["response_owner"] = "Defender"
        item["merged_from"] = [incident.get("id")]
        merged.append(item)

    index_by_defender_id = {}
    for item in merged:
        index_by_defender_id[_norm(item.get("id"))] = item

    for incident in sentinel:
        link = _norm(incident.get("defender_incident_id"))
        target = index_by_defender_id.get(link) if link else None
        if target is None:
            for alert_id in _listify(incident.get("alert_ids")):
                candidate = alert_index.get(_norm(alert_id))
                if candidate is not None:
                    target = index_by_defender_id.get(_norm(candidate.get("id")))
                    break
        if target is not None:
            matched_sentinel.add(_norm(incident.get("id")))
            target["source"] = "defender+sentinel"
            target["merged_from"].append(incident.get("id"))
            target["sentinel_id"] = incident.get("id")
            target["analytics_rule"] = incident.get("analytics_rule")
            # A custom correlation rule adds signal Defender cannot see, so the
            # case belongs to Sentinel even though the response actions do not.
            if incident.get("correlates_non_microsoft"):
                target["response_owner"] = "Sentinel (case) / Defender (endpoint and identity actions)"
            else:
                target["response_owner"] = "Defender"
            for field in ("impacted_users", "impacted_devices"):
                for value in _listify(incident.get(field)):
                    target.setdefault(field, [])
                    if value not in target[field]:
                        target[field].append(value)
            continue

        item = dict(incident)
        item["source"] = "sentinel"
        item["response_owner"] = "Sentinel"
        item["merged_from"] = [incident.get("id")]
        merged.append(item)

    return merged, len(matched_sentinel)


def sla_state(incident, cfg, now):
    """Age against the acknowledge and contain clocks, measured from first activity."""
    severity = _norm(incident.get("severity")) or "medium"
    ack_hours, contain_hours = cfg["sla"].get(severity, DEFAULT_SLA_HOURS["medium"])
    age = _age_hours(incident.get("first_activity") or incident.get("created_at"), now)
    if age is None:
        return {"age_hours": None, "ack_breach": False, "contain_breach": False}
    status = _norm(incident.get("status"))
    assigned = bool(incident.get("assigned_to"))
    contained = status in RESOLVED_STATES or bool(incident.get("contained"))
    return {
        "age_hours": round(age, 1),
        "ack_breach": (not assigned) and age > ack_hours,
        "contain_breach": (not contained) and age > contain_hours,
        "ack_hours": ack_hours,
        "contain_hours": contain_hours,
    }


def triage_incident(incident, cfg, now):
    evidence_flags = incident.get("evidence") or {}
    severity = _norm(incident.get("severity")) or "medium"
    status = _norm(incident.get("status"))
    resolved = status in RESOLVED_STATES
    confidence = _norm(incident.get("confidence"))
    users = _listify(incident.get("impacted_users"))
    devices = _listify(incident.get("impacted_devices"))
    pending = _listify(incident.get("pending_actions"))
    air = _norm(incident.get("air_status"))
    sla = sla_state(incident, cfg, now)

    injection = scan_for_injection(
        incident.get("title"), incident.get("comments"), incident.get("description"),
        incident.get("notes"),
    )

    reasons = []
    evidence = []
    not_established = []

    live = [name for name in ("hands_on_keyboard", "lateral_movement", "data_staged",
                              "credential_theft_executed", "mailbox_rule_created",
                              "oauth_grant_created", "beaconing")
            if evidence_flags.get(name)]
    signin = bool(evidence_flags.get("successful_signin"))
    blocked_only = bool(evidence_flags.get("blocked_only"))

    for flag in live:
        evidence.append("observed: %s" % flag.replace("_", " "))
    if signin:
        evidence.append("observed: successful sign-in by the targeted identity")
    if blocked_only:
        evidence.append("the activity was blocked or prevented, not completed")
    if not evidence:
        not_established.append("what actually happened — the alert fired, the consequence is unestablished")

    # Priority by consequence. "Blocked" is information about the attacker's
    # interest; a successful sign-in followed by an action is an incident.
    if live and (signin or "beaconing" in live or "hands_on_keyboard" in live):
        priority = "P1"
        reasons.append("live consequence observed: %s" % ", ".join(live))
    elif live:
        priority = "P2"
        reasons.append("consequential activity observed: %s" % ", ".join(live))
    elif signin:
        priority = "P2"
        reasons.append("successful sign-in, no follow-on activity observed yet")
    elif blocked_only:
        priority = "P3"
        reasons.append("prevented — the pattern matters more than the instance")
    elif severity in ("critical", "high"):
        priority = "P3"
        reasons.append("%s severity, consequence not yet established" % severity)
    else:
        priority = "P4"
        reasons.append("%s severity, no observed consequence" % severity)

    if air == "pending_approval" and pending:
        scope = max([int(action.get("scope") or 0) for action in pending] or [0])
        evidence.append("AIR is waiting on approval for %d action(s), largest scope %d"
                        % (len(pending), scope))
        if scope > cfg["large_scope"]:
            priority = floor_priority(priority, "P2")
            reasons.append("pending remediation with a large blast radius (%d)" % scope)
    elif air in ("failed", "timed_out", "terminated"):
        reasons.append("automated investigation %s — this is a gap, not a verdict" % air)
        priority = floor_priority(priority, "P3")

    if sla["ack_breach"] or sla["contain_breach"]:
        which = "acknowledge" if sla["ack_breach"] else "contain"
        reasons.append("SLA breach (%s clock, %.1fh old)" % (which, sla["age_hours"]))
        priority = escalate(priority)

    if resolved and not (incident.get("classification") and incident.get("determination")):
        priority = floor_priority(priority, "P4")
        reasons.append("closed with no classification or determination — poisons every rule that fed it")

    if injection:
        reasons.append("reviewer-directed text in the incident's own content — indicator, not instruction")
        priority = floor_priority(priority, "P2")

    if confidence and confidence != "high":
        not_established.append("the detection's own confidence is %s" % confidence)

    in_scope = in_authorized_scope(cfg, *(users + devices))
    scope_count = len(users) + len(devices)
    entities_enumerated = bool(users or devices)

    gates_common = {
        "first_party": confidence == "high" and bool(live or signin),
        "unambiguous": confidence == "high" and not incident.get("conflicting_verdict") and not injection,
        "bounded_scope": scope_gate(cfg, scope_count, entities_enumerated),
        "reversible": True,
        "rollback_recorded": True,
    }

    actions = []
    incident_id = incident.get("id") or "incident"

    if not incident.get("assigned_to") and not resolved:
        actions.append(decide_authority(make_action(
            "%s-assign" % incident_id, 1,
            "Assign the incident to the analyst on shift and acknowledge the SLA clock",
            incident_id, "SOC analyst on shift",
            rollback="Unassign the incident",
        ), cfg, in_scope=in_scope, injection=bool(injection)))

    if signin and (live or priority == "P1"):
        rollback_sessions = "Sessions re-establish on next sign-in; no restore needed"
        actions.append(decide_authority(make_action(
            "%s-revoke-sessions" % incident_id, 2,
            "Revoke active sessions for the impacted identities",
            ", ".join(users) or "impacted identities",
            "IAM, with the user's manager informed",
            rollback=rollback_sessions,
            gates=dict(gates_common),
        ), cfg, in_scope=in_scope, injection=bool(injection)))
        actions.append(decide_authority(make_action(
            "%s-disable" % incident_id, 2,
            "Disable the compromised account pending investigation",
            ", ".join(users) or "impacted identities",
            "IAM, with the user's manager informed",
            rollback="Re-enable the account in the directory",
            gates=dict(gates_common),
        ), cfg, in_scope=in_scope, injection=bool(injection)))

    if evidence_flags.get("beaconing") or evidence_flags.get("hands_on_keyboard"):
        actions.append(decide_authority(make_action(
            "%s-isolate" % incident_id, 2,
            "Isolate the affected device",
            ", ".join(devices) or "impacted devices",
            "SOC analyst on shift; endpoint team for a server",
            rollback="Release the device from isolation in Defender",
            gates=dict(gates_common),
        ), cfg, in_scope=in_scope, injection=bool(injection)))

    if air == "pending_approval" and pending:
        scope = max([int(action.get("scope") or 0) for action in pending] or [0])
        tier = 2 if scope > cfg["large_scope"] else 1
        gates = dict(gates_common)
        gates["bounded_scope"] = scope_gate(cfg, scope, True)
        actions.append(decide_authority(make_action(
            "%s-air" % incident_id, tier,
            "Decide the %d pending AIR action(s) (largest scope %d)" % (len(pending), scope),
            incident_id, "SOC analyst on shift",
            rollback="Pending actions can be re-submitted from the Action center",
            gates=gates if tier == 2 else None,
            requires_judgment=tier == 2,
        ), cfg, in_scope=in_scope, injection=bool(injection)))

    if resolved and not (incident.get("classification") and incident.get("determination")):
        actions.append(decide_authority(make_action(
            "%s-classify" % incident_id, 1,
            "Record a classification and determination on the closed incident",
            incident_id, "the analyst who closed it",
            rollback="Clear the classification",
            requires_judgment=True,
            blocked_reason="classifying an incident you did not investigate is stop-list item 7",
        ), cfg, in_scope=in_scope, injection=bool(injection)))

    if incident.get("entities_mapped") is False:
        actions.append(decide_authority(make_action(
            "%s-entities" % incident_id, 3,
            "Fix entity mapping on the analytics rule — unmapped entities cannot be "
            "correlated, enriched or actioned",
            incident.get("analytics_rule") or "analytics rule",
            "detection engineering",
        ), cfg, in_scope=in_scope, injection=bool(injection)))

    title = incident.get("title") or incident_id
    if incident.get("source") == "defender+sentinel":
        title = "%s (also %s in Sentinel)" % (title, incident.get("sentinel_id"))

    return {
        "id": incident_id,
        "source": incident.get("source", "defender"),
        "source_label": {"defender": "Defender", "sentinel": "Sentinel",
                         "defender+sentinel": "Defender+Sentinel"}.get(
                             incident.get("source", "defender"), "Defender"),
        "title": title,
        "priority": priority,
        "reasons": reasons,
        "evidence": evidence,
        "not_established": not_established,
        "actions": actions,
        "owner": incident.get("response_owner") or "SOC analyst on shift",
        "in_scope": in_scope,
        "injection": injection,
        "merged_from": incident.get("merged_from") or [incident_id],
        "detail": {"severity": severity, "status": status, "air_status": air,
                   "sla": sla, "users": users, "devices": devices,
                   "response_owner": incident.get("response_owner"),
                   "analytics_rule": incident.get("analytics_rule")},
    }


# --------------------------------------------------------------------------
# Hygiene — the P4 lines that make a slow-moving problem visible
# --------------------------------------------------------------------------

def collect_hygiene(bundle, items, now, cfg):
    hygiene = []

    alerts = bundle.get("github_secret_alerts")
    if alerts:
        bypassed = [a for a in alerts if a.get("push_protection_bypassed")]
        if bypassed:
            repos = Counter(a.get("repo") for a in bypassed if a.get("repo"))
            hygiene.append({
                "finding": "%d push-protection bypass(es) in the window" % len(bypassed),
                "detail": "top repositories: %s" % ", ".join(
                    "%s (%d)" % (repo, count) for repo, count in repos.most_common(3)),
                "next_step": "Read each bypass reason; a rising count means the control is being routed around",
                "owner": "security lead",
            })
        unverified = [a for a in alerts
                      if _norm(a.get("resolution")) in ("false_positive", "used_in_tests")
                      and not a.get("resolution_evidence")]
        if unverified:
            hygiene.append({
                "finding": "%d alert(s) closed as false-positive or test with no evidence recorded" % len(unverified),
                "detail": ", ".join(str(a.get("id")) for a in unverified[:5]),
                "next_step": "QA sample three per shift; an unverified close is an accepted secret",
                "owner": "SOC analyst on shift",
            })

    repos_without = _listify((bundle.get("rounds_meta") or {}).get("repos_without_scanning"))
    if repos_without:
        hygiene.append({
            "finding": "%d repository(ies) in scope with secret scanning or push protection off" % len(repos_without),
            "detail": ", ".join(map(str, repos_without[:8])),
            "next_step": "Enable scanning (tier 1 — additive, affects future pushes only)",
            "owner": "security lead",
        })

    incidents = (bundle.get("defender_incidents") or []) + (bundle.get("sentinel_incidents") or [])
    unclassified = [i for i in incidents
                    if _norm(i.get("status")) in RESOLVED_STATES
                    and not (i.get("classification") and i.get("determination"))]
    if unclassified:
        hygiene.append({
            "finding": "%d incident(s) closed with no classification or determination" % len(unclassified),
            "detail": ", ".join(str(i.get("id")) for i in unclassified[:6]),
            "next_step": "Classify retrospectively; closures are the tuning data every detection depends on",
            "owner": "the analysts who closed them",
        })

    noisy = [i for i in incidents
             if i.get("rule_benign_rate") is not None
             and float(i["rule_benign_rate"]) >= cfg["noisy_rule_rate"]]
    if noisy:
        rules = Counter(i.get("analytics_rule") for i in noisy if i.get("analytics_rule"))
        hygiene.append({
            "finding": "%d incident(s) from analytics rules with a high benign-positive rate" % len(noisy),
            "detail": ", ".join("%s (%d)" % (rule, count) for rule, count in rules.most_common(3)),
            "next_step": "Tuning is a tier 3 production change — raise a CR, never mute the rule",
            "owner": "detection engineering",
        })

    unmapped = [i for i in incidents if i.get("entities_mapped") is False]
    if unmapped:
        hygiene.append({
            "finding": "%d incident(s) with unmapped entities" % len(unmapped),
            "detail": ", ".join(str(i.get("id")) for i in unmapped[:6]),
            "next_step": "Rule defect — unmapped entities silently degrade correlation and enrichment",
            "owner": "detection engineering",
        })

    stale = _listify((bundle.get("rounds_meta") or {}).get("open_change_requests"))
    aging = []
    for change in stale:
        age = _age_hours(change.get("raised"), now)
        if age is not None and age / 24.0 > cfg["stale_cr_days"] and \
                _norm(change.get("status")) not in ("implemented", "closed", "cancelled"):
            aging.append("%s (%.0f days, %s)" % (change.get("id"), age / 24.0, change.get("status")))
    if aging:
        hygiene.append({
            "finding": "%d change request(s) aging in approval past %d days" % (len(aging), cfg["stale_cr_days"]),
            "detail": ", ".join(aging[:6]),
            "next_step": "An unremediated finding with paperwork is still unremediated — escalate with age",
            "owner": "change manager",
        })

    out_of_scope = [i for i in items if not i.get("in_scope")]
    if out_of_scope:
        hygiene.append({
            "finding": "%d finding(s) outside the authorized scope" % len(out_of_scope),
            "detail": ", ".join(str(i["id"]) for i in out_of_scope[:6]),
            "next_step": "Escalate to the security lead; out of scope stays out of scope even when severe",
            "owner": "security lead",
        })

    return hygiene


# --------------------------------------------------------------------------
# The run
# --------------------------------------------------------------------------

def build_config(meta, args):
    context = (meta or {}).get("org_context") or {}
    sla = dict(DEFAULT_SLA_HOURS)
    for severity, window in (context.get("sla_hours") or {}).items():
        if isinstance(window, (list, tuple)) and len(window) == 2:
            sla[_norm(severity)] = (float(window[0]), float(window[1]))
    return {
        "max_scope": args.auto_contain_max_scope,
        "no_auto_contain": args.no_auto_contain,
        "large_scope": args.large_scope,
        "sla": sla,
        "authorized_scope": _listify(context.get("authorized_scope")) + _listify(args.scope),
        "standard_catalogue": _listify(context.get("standard_change_catalogue")) or DEFAULT_STANDARD_CATALOGUE,
        "noisy_rule_rate": args.noisy_rule_rate,
        "stale_cr_days": args.stale_cr_days,
    }


def run(bundle, cfg, now):
    meta = bundle.get("rounds_meta") or {}

    present = {name: (name in bundle and bundle[name] is not None) for name in SECTIONS}
    raw_counts = {name: len(bundle.get(name) or []) for name in SECTIONS}

    items = []

    if present["github_secret_alerts"]:
        for alert in collapse_secret_alerts(bundle["github_secret_alerts"]):
            items.append(triage_secret(alert, cfg, now))

    change_groups = []
    if present["upwind_findings"]:
        upwind_items, change_groups, _ranked = triage_upwind(bundle["upwind_findings"], cfg, now)
        items.extend(upwind_items)

    deduped = 0
    if present["defender_incidents"] or present["sentinel_incidents"]:
        merged, deduped = dedupe_incidents(bundle.get("defender_incidents") or [],
                                           bundle.get("sentinel_incidents") or [])
        for incident in merged:
            items.append(triage_incident(incident, cfg, now))

    items.sort(key=lambda item: (PRIORITIES.index(item["priority"]),
                                 list(SECTIONS).index(
                                     {"github": "github_secret_alerts",
                                      "upwind": "upwind_findings",
                                      "defender": "defender_incidents",
                                      "sentinel": "sentinel_incidents",
                                      "defender+sentinel": "defender_incidents"}[item["source"]]),
                                 str(item["id"])))

    auto, blocked = [], []
    for item in items:
        for action in item["actions"]:
            record = dict(action)
            record["item"] = item["id"]
            record["item_title"] = item["title"]
            record["priority"] = item["priority"]
            (auto if action["auto"] else blocked).append(record)

    not_collected = [SECTIONS[name] for name in SECTIONS if not present[name]]

    return {
        "meta": {
            "window_start": meta.get("window_start"),
            "window_end": meta.get("window_end"),
            "operator": meta.get("operator"),
            "generated_for": now.isoformat(),
            "collection_notes": _listify(meta.get("collection_notes")),
            "not_collected": not_collected,
            "auto_contain": not cfg["no_auto_contain"],
            "max_scope": cfg["max_scope"],
        },
        "counts": {
            "raw": raw_counts,
            "collected": {SECTIONS[name]: (raw_counts[name] if present[name] else None)
                          for name in SECTIONS},
            "deduplicated_incidents": deduped,
            "items": len(items),
            "change_groups": len(change_groups),
        },
        "priorities": dict(Counter(item["priority"] for item in items)),
        "items": items,
        "change_groups": change_groups,
        "actions": {
            "auto": auto,
            "blocked": blocked,
            "by_tier": dict(Counter(action["tier_name"]
                                    for item in items for action in item["actions"])),
        },
        "hygiene": collect_hygiene(bundle, items, now, cfg),
    }


# --------------------------------------------------------------------------
# Rendering — references/report-template.md
# --------------------------------------------------------------------------

def _cell(text):
    return str(text or "").replace("|", "\\|").replace("\n", " ")


def render_md(result):
    meta = result["meta"]
    out = []
    window = " to ".join(x for x in (meta.get("window_start"), meta.get("window_end")) if x)
    out.append("# SOC rounds — %s" % (window or meta.get("generated_for")))
    out.append("Operator: %s · Automatic containment: %s (max scope %d)" % (
        meta.get("operator") or "unnamed",
        "on" if meta["auto_contain"] else "off",
        meta["max_scope"]))
    out.append("")

    out.append("## 1. Summary")
    out.append("")
    out.append("| Source | Collected | Items after consolidation |")
    out.append("|---|---|---|")
    counts = result["counts"]
    per_source = Counter(item["source"] for item in result["items"])
    label_for = {"GitHub secrets": ["github"], "Upwind": ["upwind"],
                 "Defender": ["defender", "defender+sentinel"], "Sentinel": ["sentinel"]}
    for label, raw in counts["collected"].items():
        if raw is None:
            out.append("| %s | **NOT COLLECTED** | — |" % label)
            continue
        consolidated = sum(per_source.get(key, 0) for key in label_for.get(label, []))
        out.append("| %s | %d | %d |" % (label, raw, consolidated))
    out.append("| **Total** | | **%d** |" % counts["items"])
    out.append("")
    if counts["deduplicated_incidents"]:
        out.append("%d Sentinel incident(s) were re-ingested Defender incidents and are counted once."
                   % counts["deduplicated_incidents"])
        out.append("")

    out.append("**Collection gaps:** %s" % (
        "; ".join(meta["not_collected"] + meta["collection_notes"])
        if (meta["not_collected"] or meta["collection_notes"])
        else "none — all four sources reachable"))
    out.append("")

    priorities = result["priorities"]
    out.append("Priorities: " + ", ".join("%s=%d" % (p, priorities.get(p, 0)) for p in PRIORITIES))
    out.append("")

    p1 = [item for item in result["items"] if item["priority"] == "P1"]
    out.append("## 2. Act now (P1)")
    out.append("")
    if not p1:
        out.append("Nothing at P1 in this window.")
    else:
        out.append("| # | Source | Item | Why P1 | Owner |")
        out.append("|---|---|---|---|---|")
        for index, item in enumerate(p1, 1):
            out.append("| %d | %s | %s | %s | %s |" % (
                index, _cell(item["source_label"]), _cell(item["title"]),
                _cell("; ".join(item["reasons"][:2])), _cell(item["owner"])))
    out.append("")

    blocked = result["actions"]["blocked"]
    out.append("## 3. Needs your decision")
    out.append("")
    if not blocked:
        out.append("Nothing stopped this round.")
    for action in blocked:
        out.append("**%s — tier %d (%s) on %s**" % (
            action["item_title"], action["tier"], action["tier_name"], action["target"]))
        out.append("")
        out.append("- Action: %s" % action["description"])
        out.append("- Stopped by: %s" % "; ".join(
            GATE_LABEL.get(reason, reason) for reason in action["blocked_by"]))
        if action["gates_failed"]:
            out.append("- To clear it, establish: %s" % ", ".join(
                GATE_LABEL[gate] for gate in action["gates_failed"]))
        out.append("- Owner: %s" % action["owner"])
        out.append("")

    out.append("## 4. Actions to take automatically")
    out.append("")
    auto = result["actions"]["auto"]
    if not auto:
        out.append("None — every proposed action needs a person this round.")
    else:
        out.append("| Tier | Action | Target | Rollback |")
        out.append("|---|---|---|---|")
        for action in auto:
            out.append("| %d %s | %s | %s | %s |" % (
                action["tier"], action["tier_name"], _cell(action["description"]),
                _cell(action["target"]), _cell(action["rollback"] or "n/a")))
    out.append("")

    out.append("## 5. Change requests")
    out.append("")
    if not result["change_groups"]:
        out.append("No change groups this round.")
    else:
        out.append("| Group | Class | Change | Findings | Assets | Team |")
        out.append("|---|---|---|---|---|---|")
        for group in result["change_groups"]:
            out.append("| %s | %s | %s | %d | %d | %s |" % (
                group["id"], group["change_class"], _cell(group["title"]),
                len(group["findings"]), group["asset_count"], _cell(group["owner_team"])))
        out.append("")
        for group in result["change_groups"]:
            out.append("**%s (%s)** — %s" % (group["id"], group["change_class"],
                                             group["class_rationale"]))
            out.append("")
            out.append("- Findings closed: %s" % ", ".join(group["findings"]))
            if group["cves"]:
                out.append("- CVEs: %s" % ", ".join(group["cves"]))
            out.append("- Affected CIs: %s" % ", ".join(group["assets"]))
            out.append("- Observed dependents: %s" % (", ".join(map(str, group["dependents"]))
                                                      or "none observed"))
            out.append("")

    out.append("## 6. Everything else, by priority")
    out.append("")
    out.append("| Priority | Source | Item | Why | Owner |")
    out.append("|---|---|---|---|---|")
    for item in result["items"]:
        if item["priority"] == "P1":
            continue
        out.append("| %s | %s | %s | %s | %s |" % (
            item["priority"], _cell(item["source_label"]), _cell(item["title"]),
            _cell("; ".join(item["reasons"][:2])), _cell(item["owner"])))
    out.append("")

    out.append("## 7. Hygiene and gaps (P4)")
    out.append("")
    if not result["hygiene"]:
        out.append("Nothing recorded this round.")
    for entry in result["hygiene"]:
        out.append("- **%s** — %s. Next: %s (%s)" % (
            entry["finding"], entry["detail"], entry["next_step"], entry["owner"]))
    out.append("")

    flagged = [item for item in result["items"] if item.get("injection")]
    if flagged:
        out.append("## 8. Reviewer-directed text found in finding content")
        out.append("")
        out.append("Treated as an indicator, never obeyed. Automation is frozen on these items.")
        out.append("")
        for item in flagged:
            out.append("- **%s** — %s" % (item["id"], "; ".join(item["injection"][:2])))
        out.append("")

    return "\n".join(out).rstrip() + "\n"


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def load_bundle(path):
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise SystemExit("%s: expected a rounds bundle object, got %s"
                         % (path, type(data).__name__))
    known = set(SECTIONS) | {"rounds_meta"}
    if not known & set(data):
        raise SystemExit("%s: no rounds sections found — expected any of %s"
                         % (path, ", ".join(SECTIONS)))
    return data


def build_parser():
    parser = argparse.ArgumentParser(
        description="Deterministic SOC rounds across GitHub, Upwind, Defender and Sentinel (no LLM, no network).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("bundle", help="rounds bundle JSON")
    parser.add_argument("--now", help="ISO time to measure SLA clocks from; default = window end, else now")
    parser.add_argument("--auto-contain-max-scope", type=int, default=25,
                        help="Gate 3: the largest enumerated blast radius that may be contained automatically")
    parser.add_argument("--no-auto-contain", action="store_true",
                        help="propose containment but never mark it automatic")
    parser.add_argument("--large-scope", type=int, default=100,
                        help="pending remediation above this many targets is a judgment call")
    parser.add_argument("--scope", action="append", default=[],
                        help="an authorized repo/team/asset pattern; repeatable, adds to org_context")
    parser.add_argument("--noisy-rule-rate", type=float, default=0.8,
                        help="benign-positive rate at which an analytics rule becomes a tuning finding")
    parser.add_argument("--stale-cr-days", type=int, default=14,
                        help="days in approval after which a change request is reported as aging")
    parser.add_argument("--format", choices=("md", "json", "both"), default="md")
    parser.add_argument("--out", help="write the Markdown report here instead of stdout")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    bundle = load_bundle(args.bundle)
    meta = bundle.get("rounds_meta") or {}

    now = _parse_time(args.now) or _parse_time(meta.get("window_end")) or \
        datetime.now(timezone.utc)

    cfg = build_config(meta, args)
    result = run(bundle, cfg, now)

    if args.format in ("json", "both"):
        json.dump(result, sys.stdout, indent=2, sort_keys=False, default=str)
        sys.stdout.write("\n")

    if args.format in ("md", "both"):
        report = render_md(result)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as handle:
                handle.write(report)
            sys.stderr.write("wrote %s\n" % args.out)
        else:
            sys.stdout.write(report)

    return 0


if __name__ == "__main__":
    sys.exit(main())
