#!/usr/bin/env python3
"""Build (and optionally submit) a Cherwell change request from a change group.

`rounds.py` groups Upwind findings into change groups — one per remediation
action a single team executes together. This turns one of those groups into a
change request a person who has never seen the finding can execute and a CAB
member who is not in security can approve.

That bar is the whole point. A CR that sends the reader back to Upwind has
failed, so every field CAB asks for is filled in before they ask:
why now, what breaks, how you know it worked, how you get back, and what
happens if you do nothing (references/upwind-cr.md).

    python cherwell_cr.py bundle.json --list
    python cherwell_cr.py bundle.json --group CG-1                 # Markdown CR
    python cherwell_cr.py bundle.json --group CG-1 --format payload  # what would be POSTed
    python cherwell_cr.py bundle.json --all --format payload --field-map fields.json
    python cherwell_cr.py bundle.json --group CG-1 --submit        # needs credentials

Drafting is offline and the default. `--submit` is the only outward action, it
requires credentials in the environment, and it refuses rather than half-filing
a change.

**Cherwell business objects are customized per deployment.** The default field
map below is the common out-of-the-box shape, not a promise about your
instance. Verify it against `getbusinessobjecttemplate` for your Change Request
business object, save the result, and pass it with `--field-map`. `--format
payload` exists so you can check the mapping without sending anything.

Credentials (environment):
    CHERWELL_BASE_URL     https://cherwell.example.com
    CHERWELL_CLIENT_ID    the API client key
    CHERWELL_USERNAME     an account authorized to create change requests
    CHERWELL_PASSWORD
"""
import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import rounds  # noqa: E402  the grouping and class rules live there, once


DEFAULT_FIELD_MAP = {
    "title": "Title",
    "description": "Description",
    "justification": "Justification",
    "change_class": "ChangeType",
    "priority": "Priority",
    "impact": "Impact",
    "urgency": "Urgency",
    "risk_level": "RiskLevel",
    "requested_by": "RequestedBy",
    "owned_by_team": "OwnedByTeam",
    "config_items": "ConfigItems",
    "implementation_plan": "ImplementationPlan",
    "validation_plan": "ValidationPlan",
    "backout_plan": "BackoutPlan",
    "scheduled_start": "ScheduledStartDate",
    "scheduled_end": "ScheduledEndDate",
    "security_finding_ref": "SecurityFindingRef",
}

BUS_OB_NAME = "ChangeRequest"

# Implementation, validation and backout, per fix type. Each one has to be
# executable by the owning team without reading the finding, and the backout has
# to be a single step — a restore that needs a data migration is not a backout.
PLANS = {
    "image_rebuild": {
        "implementation": [
            "Rebuild the application image from base {target}.",
            "Push the rebuilt image and record the new digest.",
            "Roll the deployment for: {assets}.",
            "Wait for each replica to pass its readiness probe before proceeding to the next.",
        ],
        "validation": [
            "Confirm the running image digest matches the rebuilt image on every asset listed.",
            "Confirm the fixed package version is present in the running container.",
            "Service health checks green for 15 minutes; error rate and latency within baseline.",
            "Re-scan in Upwind and confirm findings {findings} have cleared.",
        ],
        "backout": [
            "Redeploy the previous image tag ({previous}).",
            "Typical time to restore: under 5 minutes. No data migration involved.",
        ],
    },
    "package_upgrade": {
        "implementation": [
            "Upgrade {target} using the platform's package manager on: {assets}.",
            "Restart the dependent service on each host, one at a time.",
        ],
        "validation": [
            "Assert the installed package version on every host.",
            "Service health checks green for 15 minutes.",
            "Re-scan in Upwind and confirm findings {findings} have cleared.",
        ],
        "backout": [
            "Reinstall and pin the previous package version, then restart the service.",
            "Typical time to restore: under 10 minutes per host.",
        ],
    },
    "config_change": {
        "implementation": [
            "Record the current value of the setting before changing it.",
            "Apply: {target}.",
            "Applies to: {assets}.",
        ],
        "validation": [
            "Read the setting back and confirm the new value.",
            "Confirm legitimate consumers still have the access they need.",
            "Re-scan in Upwind and confirm findings {findings} have cleared.",
        ],
        "backout": [
            "Restore the recorded previous value of the setting.",
            "Typical time to restore: under 5 minutes.",
        ],
    },
    "network_change": {
        "implementation": [
            "Export and attach the current rule set before changing it.",
            "Apply: {target} on {assets}.",
        ],
        "validation": [
            "Confirm the rule is in effect and that expected traffic still flows.",
            "Confirm the previously-exposed path now refuses connections.",
            "Re-scan in Upwind and confirm findings {findings} have cleared.",
        ],
        "backout": [
            "Re-apply the exported rule set.",
            "Typical time to restore: under 10 minutes.",
        ],
    },
    "iam_change": {
        "implementation": [
            "Export the current policy document and attach it to this change.",
            "Apply: {target} for {assets}.",
        ],
        "validation": [
            "Confirm the intended principals retain access and the removed access is gone.",
            "Re-scan in Upwind and confirm findings {findings} have cleared.",
        ],
        "backout": [
            "Re-attach the exported policy document.",
            "Typical time to restore: under 5 minutes.",
        ],
    },
}

GENERIC_PLAN = {
    "implementation": [
        "Record the current state of what is about to change.",
        "Apply: {target} on {assets}.",
    ],
    "validation": [
        "Confirm the change is in effect.",
        "Re-scan in Upwind and confirm findings {findings} have cleared.",
    ],
    "backout": [
        "Restore the recorded previous state.",
        "PLAN NOT TEMPLATED — the executing team must state the restore step and its cost before CAB.",
    ],
}

RISK_BY_CLASS = {"emergency": "High", "normal": "Medium", "standard": "Low"}
IMPACT_BY_COUNT = [(1, "Low"), (10, "Medium")]  # above the last threshold: High


def impact_for(asset_count, environment):
    impact = "High"
    for threshold, label in IMPACT_BY_COUNT:
        if asset_count <= threshold:
            impact = label
            break
    if rounds._norm(environment) in rounds.PRODUCTION_ENVS and impact == "Low":
        impact = "Medium"
    return impact


def window_for(change_class, now, override=None):
    """Emergency goes next available; normal waits for the change window."""
    if override:
        start = rounds._parse_time(override)
        return start, start + timedelta(hours=2)
    if change_class == "emergency":
        start = now + timedelta(hours=2)
        return start, start + timedelta(hours=2)
    if change_class == "standard":
        start = (now + timedelta(days=1)).replace(hour=9, minute=0, second=0, microsecond=0)
        return start, start + timedelta(hours=2)
    # Normal: the next Thursday 22:00 UTC maintenance window.
    days_ahead = (3 - now.weekday()) % 7 or 7
    start = (now + timedelta(days=days_ahead)).replace(hour=22, minute=0, second=0, microsecond=0)
    return start, start + timedelta(hours=4)


def _previous_target(fix_target):
    """'acme/base:1.22 -> 1.24' → 'acme/base:1.22', for the backout line."""
    for separator in ("->", "→", " to "):
        if separator in fix_target:
            return fix_target.split(separator)[0].strip()
    return "the current version"


def build_cr(group, findings_by_id, meta, now, requested_by, window_override=None):
    assets = ", ".join(group["assets"]) or "no assets recorded"
    findings = ", ".join(group["findings"])
    plan = PLANS.get(rounds._norm(group["fix_type"]), GENERIC_PLAN)
    fill = {"target": group["fix_target"], "assets": assets, "findings": findings,
            "previous": _previous_target(group["fix_target"])}

    members = [findings_by_id.get(fid, {}) for fid in group["findings"]]
    exploited = [m for m in members if m.get("known_exploited")]
    exposed = [m for m in members
               if (m.get("runtime") or {}).get("internet_exposed")]
    loaded = [m for m in members if (m.get("runtime") or {}).get("package_loaded")]

    why_now = []
    if exploited:
        why_now.append("%d of these findings are known-exploited in the wild (%s)"
                       % (len(exploited), ", ".join(sorted(
                           {m.get("cve") for m in exploited if m.get("cve")}) or ["no CVE recorded"])))
    if exposed:
        why_now.append("%d affected asset finding(s) are on internet-exposed workloads"
                       % len(exposed))
    if loaded:
        why_now.append("%d have the vulnerable code path observed loaded at runtime, "
                       "not merely present on disk" % len(loaded))
    epss = [m.get("epss") for m in members if isinstance(m.get("epss"), (int, float))]
    if epss:
        why_now.append("highest EPSS among these findings: %.2f" % max(epss))
    if not why_now:
        why_now.append("no runtime exposure or exploitation evidence recorded — "
                       "this is remediation on schedule, not on urgency")

    dependents = group["dependents"]
    what_breaks = ("Observed dependents in the Upwind runtime graph: %s."
                   % ", ".join(map(str, dependents))) if dependents else \
                  ("No dependents observed in the runtime graph. Absence of an observed "
                   "dependent is not proof of no dependent — confirm with the owning team "
                   "before the window.")

    description = [
        "Security remediation raised from SOC rounds on %s." % now.date().isoformat(),
        "",
        "Findings closed by this change: %s" % findings,
    ]
    cves = sorted({m.get("cve") for m in members if m.get("cve")})
    if cves:
        description.append("CVEs: %s" % ", ".join(cves))
    description += [
        "Affected configuration items (%d): %s" % (group["asset_count"], assets),
        "Environment: %s" % group["environment"],
        "Change: %s (%s)" % (group["fix_target"], group["fix_type"]),
        "",
        "What breaks: %s" % what_breaks,
        "",
        "If we do nothing: the findings remain open and unmitigated. Risk acceptance is "
        "the system owner's decision, not the SOC's, and must carry a review date.",
    ]

    justification = [
        "Why now: %s." % "; ".join(why_now),
        "Change class: %s — %s." % (group["change_class"], group["class_rationale"]),
        "Rounds priority: %s." % group["priority"],
    ]

    start, end = window_for(group["change_class"], now, window_override)

    return {
        "group_id": group["id"],
        "business_object": BUS_OB_NAME,
        "change_class": group["change_class"],
        "fields": {
            "title": group["title"],
            "description": "\n".join(description),
            "justification": "\n".join(justification),
            "change_class": group["change_class"],
            "priority": group["priority"],
            "impact": impact_for(group["asset_count"], group["environment"]),
            "urgency": "High" if group["change_class"] == "emergency" else "Medium",
            "risk_level": RISK_BY_CLASS.get(group["change_class"], "Medium"),
            "requested_by": requested_by,
            "owned_by_team": group["owner_team"],
            "config_items": "; ".join(group["assets"]),
            "implementation_plan": "\n".join(
                "%d. %s" % (i, line.format(**fill))
                for i, line in enumerate(plan["implementation"], 1)),
            "validation_plan": "\n".join(
                "%d. %s" % (i, line.format(**fill))
                for i, line in enumerate(plan["validation"], 1)),
            "backout_plan": "\n".join(
                "%d. %s" % (i, line.format(**fill))
                for i, line in enumerate(plan["backout"], 1)),
            "scheduled_start": start.isoformat(),
            "scheduled_end": end.isoformat(),
            "security_finding_ref": findings,
        },
        "cab_required": group["change_class"] in ("emergency", "normal"),
        "templated_backout": rounds._norm(group["fix_type"]) in PLANS,
    }


def to_payload(cr, field_map):
    """The savebo body. `--format payload` prints this so a field map can be checked."""
    fields = []
    for key, value in cr["fields"].items():
        name = field_map.get(key)
        if not name:
            continue
        fields.append({"dirty": True, "name": name, "displayName": name, "value": value})
    return {
        "busObName": cr["business_object"],
        "fields": fields,
        "persist": True,
    }


def render_md(cr):
    fields = cr["fields"]
    out = ["# %s" % fields["title"], ""]
    out.append("**Change class:** %s · **Risk:** %s · **Impact:** %s · **CAB required:** %s"
               % (cr["change_class"], fields["risk_level"], fields["impact"],
                  "yes" if cr["cab_required"] else "no (pre-approved standard change)"))
    out.append("**Owning team:** %s · **Requested by:** %s" %
               (fields["owned_by_team"], fields["requested_by"]))
    out.append("**Window:** %s to %s" % (fields["scheduled_start"], fields["scheduled_end"]))
    out.append("")
    for heading, key in (("Justification", "justification"),
                         ("Description", "description"),
                         ("Affected configuration items", "config_items"),
                         ("Implementation plan", "implementation_plan"),
                         ("Validation plan", "validation_plan"),
                         ("Backout plan", "backout_plan")):
        out.append("## %s" % heading)
        out.append("")
        out.append(fields[key])
        out.append("")
    if not cr["templated_backout"]:
        out.append("> The backout for this fix type is not templated. The executing team "
                   "must state the restore step and its cost before CAB.")
        out.append("")
    out.append("> Raised from SOC rounds. The raiser never approves the change "
               "(references/action-authority.md, stop-list item 4).")
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------
# Submission — the only outward action here
# --------------------------------------------------------------------------

def credentials():
    needed = ("CHERWELL_BASE_URL", "CHERWELL_CLIENT_ID",
              "CHERWELL_USERNAME", "CHERWELL_PASSWORD")
    found = {name: os.environ.get(name) for name in needed}
    missing = [name for name, value in found.items() if not value]
    if missing:
        raise SystemExit(
            "no usable credentials: set %s. Draft with --format md or --format payload "
            "instead; --submit is the only outward action this script takes."
            % ", ".join(missing))
    return found


def submit(cr, field_map, timeout):
    import urllib.parse
    import urllib.request

    creds = credentials()
    base = creds["CHERWELL_BASE_URL"].rstrip("/")

    token_body = urllib.parse.urlencode({
        "grant_type": "password",
        "client_id": creds["CHERWELL_CLIENT_ID"],
        "username": creds["CHERWELL_USERNAME"],
        "password": creds["CHERWELL_PASSWORD"],
    }).encode("utf-8")
    token_request = urllib.request.Request(
        "%s/CherwellAPI/token?auth_mode=Internal&api_key=%s"
        % (base, urllib.parse.quote(creds["CHERWELL_CLIENT_ID"])),
        data=token_body,
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(token_request, timeout=timeout) as response:
        token = json.load(response)["access_token"]

    payload = json.dumps(to_payload(cr, field_map)).encode("utf-8")
    save_request = urllib.request.Request(
        "%s/CherwellAPI/api/V1/savebo" % base,
        data=payload,
        headers={"Authorization": "Bearer %s" % token,
                 "Content-Type": "application/json"})
    with urllib.request.urlopen(save_request, timeout=timeout) as response:
        return json.load(response)


def build_parser():
    parser = argparse.ArgumentParser(
        description="Build a Cherwell change request from a rounds change group.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("bundle", help="rounds bundle JSON")
    parser.add_argument("--group", help="change group id, e.g. CG-1")
    parser.add_argument("--all", action="store_true", help="every change group in the bundle")
    parser.add_argument("--list", action="store_true", help="list the change groups and exit")
    parser.add_argument("--requested-by", help="the analyst raising it; defaults to rounds_meta.operator")
    parser.add_argument("--field-map", help="JSON overriding the default Cherwell field names")
    parser.add_argument("--window-start", help="ISO start for the change window, overriding the default")
    parser.add_argument("--now", help="ISO time to schedule from")
    parser.add_argument("--format", choices=("md", "payload", "json"), default="md")
    parser.add_argument("--submit", action="store_true",
                        help="create the change request in Cherwell (requires credentials)")
    parser.add_argument("--timeout", type=float, default=30.0)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    bundle = rounds.load_bundle(args.bundle)
    meta = bundle.get("rounds_meta") or {}
    now = rounds._parse_time(args.now) or rounds._parse_time(meta.get("window_end")) \
        or datetime.now(timezone.utc)

    findings = bundle.get("upwind_findings")
    if findings is None:
        raise SystemExit("%s has no upwind_findings section — nothing to raise a change for."
                         % args.bundle)

    cfg = {"max_scope": 25, "no_auto_contain": False, "large_scope": 100,
           "sla": rounds.DEFAULT_SLA_HOURS,
           "authorized_scope": rounds._listify((meta.get("org_context") or {}).get("authorized_scope")),
           "standard_catalogue": rounds._listify(
               (meta.get("org_context") or {}).get("standard_change_catalogue"))
               or rounds.DEFAULT_STANDARD_CATALOGUE,
           "noisy_rule_rate": 0.8, "stale_cr_days": 14}
    _items, groups, _ranked = rounds.triage_upwind(findings, cfg, now)

    if args.list:
        for group in groups:
            print("%s  %-9s  %-2d finding(s)  %-2d asset(s)  %-14s  %s"
                  % (group["id"], group["change_class"], len(group["findings"]),
                     group["asset_count"], group["owner_team"], group["title"]))
        return 0

    if not args.group and not args.all:
        raise SystemExit("choose --group <id>, --all, or --list")

    selected = groups if args.all else [g for g in groups if g["id"] == args.group]
    if not selected:
        raise SystemExit("no change group %r in this bundle; --list shows what there is"
                         % args.group)

    field_map = dict(DEFAULT_FIELD_MAP)
    if args.field_map:
        with open(args.field_map, encoding="utf-8") as handle:
            field_map.update(json.load(handle))

    findings_by_id = {f.get("id"): f for f in findings}
    requested_by = args.requested_by or meta.get("operator") or "SOC analyst"

    for group in selected:
        cr = build_cr(group, findings_by_id, meta, now, requested_by, args.window_start)
        if args.submit:
            result = submit(cr, field_map, args.timeout)
            print(json.dumps({"group": group["id"], "result": result}, indent=2))
        elif args.format == "payload":
            print(json.dumps(to_payload(cr, field_map), indent=2))
        elif args.format == "json":
            print(json.dumps(cr, indent=2))
        else:
            print(render_md(cr))
    return 0


if __name__ == "__main__":
    sys.exit(main())
