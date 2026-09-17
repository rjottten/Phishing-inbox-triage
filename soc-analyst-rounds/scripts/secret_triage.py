#!/usr/bin/env python3
"""Collect GitHub secret scanning alerts and normalize them for the rounds bundle.

Reads the org- or repo-level secret scanning API, normalizes each alert into the
`github_secret_alerts` shape `rounds.py` consumes, and optionally triages them
straight away.

    python secret_triage.py --org acme --format bundle --out github.json
    python secret_triage.py --repo acme/payments-api --locations --format md
    python secret_triage.py --from-json raw_alerts.json --format bundle   # no network

**The raw secret value never leaves this script.** GitHub returns it in the
`secret` field; a rounds bundle is a file that gets attached to tickets, pasted
into chat and committed by accident, so what is written out is a fingerprint
(SHA-256, truncated) and a short preview. The fingerprint is what collapses one
credential's many alerts into one item, so nothing is lost by withholding the
value. `tests/test_secret_triage.py` asserts this, because it is the kind of
property that quietly breaks.

Three fields rounds.py wants are not derivable from GitHub, and they are the
ones Gate 3 turns on:

    owner_team            who can re-issue the credential  (--ownership)
    consumers             what authenticates with it       (--consumers)
    consumers_enumerated  whether anyone actually checked

Left absent, Gate 3 fails and the revocation waits for a person. That is the
correct default: revoking a credential whose consumers nobody enumerated is an
unplanned outage you caused while doing security.

Credentials: GITHUB_TOKEN (or GH_TOKEN) with `secret_scanning_alerts:read`.
"""
import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import rounds  # noqa: E402

API_ROOT = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
USER_AGENT = "soc-analyst-rounds/secret_triage"


def fingerprint(secret):
    """A stable id for one credential, with no way back to the value."""
    if not secret:
        return None
    return "fp-" + hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]


def preview(secret):
    """Enough to recognize it in a console, not enough to use it."""
    if not secret:
        return None
    text = str(secret)
    if len(text) <= 10:
        return text[:3] + "..."
    return "%s...%s" % (text[:4], text[-3:])


def normalize_alert(alert, ownership=None, consumers=None, locations=None):
    """One API alert → one bundle item. Drops the secret value, deliberately."""
    ownership = ownership or {}
    consumers = consumers or {}

    repository = alert.get("repository") or {}
    repo = repository.get("full_name") or alert.get("repository_full_name") or alert.get("repo")
    private = repository.get("private")
    if private is None:
        private = alert.get("repo_visibility", "private") != "public"
    visibility = "public" if not private else "private"
    # `publicly_leaked` means GitHub saw it outside the repo too; that is a
    # public exposure however private the repository is.
    if alert.get("publicly_leaked"):
        visibility = "public"

    raw_secret = alert.get("secret")
    fp = alert.get("secret_fingerprint") or fingerprint(raw_secret)
    consumer_entry = consumers.get(fp) if fp else None
    if consumer_entry is None:
        consumer_entry = consumers.get(alert.get("secret_type"))

    normalized = {
        "id": "GHS-%s-%s" % (str(repo).replace("/", "-"), alert.get("number")) if repo
              else "GHS-%s" % alert.get("number"),
        "repo": repo,
        "repo_visibility": visibility,
        "number": alert.get("number"),
        "secret_type": alert.get("secret_type"),
        "secret_type_display_name": alert.get("secret_type_display_name") or alert.get("secret_type"),
        "secret_fingerprint": fp,
        "secret_preview": alert.get("secret_preview") or preview(raw_secret),
        "state": alert.get("state") or "open",
        "validity": alert.get("validity") or "unknown",
        "resolution": alert.get("resolution"),
        "resolution_comment": alert.get("resolution_comment"),
        "created_at": alert.get("created_at"),
        "html_url": alert.get("html_url"),
        "push_protection_bypassed": bool(alert.get("push_protection_bypassed")),
        "bypass_reason": alert.get("push_protection_bypassed_reason"),
        "bypass_verified": False,
        "multi_repo": bool(alert.get("multi_repo")),
        "locations": locations or [],
    }

    team = ownership.get(repo) if repo else None
    if team:
        normalized["owner_team"] = team
    if consumer_entry is not None:
        normalized["consumers"] = list(consumer_entry)
        normalized["consumers_enumerated"] = True

    assert "secret" not in normalized, "the raw secret must never be written out"
    return normalized


# --------------------------------------------------------------------------
# Collection
# --------------------------------------------------------------------------

def _token():
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        raise SystemExit(
            "no usable credentials: set GITHUB_TOKEN (or GH_TOKEN) with "
            "secret_scanning_alerts:read. Use --from-json to normalize an existing "
            "dump without touching the network.")
    return token


def _get(path, params, timeout):
    import urllib.error
    import urllib.parse
    import urllib.request

    token = _token()
    url = "%s%s?%s" % (API_ROOT, path, urllib.parse.urlencode(params))
    collected = []
    while url:
        request = urllib.request.Request(url, headers={
            "Authorization": "Bearer %s" % token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": USER_AGENT,
        })
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                page = json.load(response)
                link = response.headers.get("Link") or ""
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", "replace")[:300]
            raise SystemExit("GitHub API %s on %s: %s" % (error.code, url, detail))
        if isinstance(page, list):
            collected.extend(page)
        else:
            collected.append(page)
        url = None
        for part in link.split(","):
            if 'rel="next"' in part:
                url = part.split(";")[0].strip().strip("<>")
                break
    return collected


def collect(args):
    params = {"per_page": 100, "state": args.state}
    if args.since:
        params["since"] = args.since
    alerts = []
    if args.org:
        alerts.extend(_get("/orgs/%s/secret-scanning/alerts" % args.org, params, args.timeout))
    for repo in args.repo:
        alerts.extend(_get("/repos/%s/secret-scanning/alerts" % repo, params, args.timeout))
    return alerts


def collect_locations(alert, timeout):
    repository = (alert.get("repository") or {}).get("full_name")
    number = alert.get("number")
    if not repository or number is None:
        return []
    raw = _get("/repos/%s/secret-scanning/alerts/%s/locations" % (repository, number),
               {"per_page": 100}, timeout)
    locations = []
    for entry in raw:
        details = entry.get("details") or {}
        locations.append({
            "type": entry.get("type"),
            "path": details.get("path") or details.get("blob_sha"),
            "commit": details.get("commit_sha") or details.get("blob_sha"),
        })
    return locations


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def render_md(normalized, now):
    cfg = {"max_scope": 25, "no_auto_contain": False, "large_scope": 100,
           "sla": rounds.DEFAULT_SLA_HOURS, "authorized_scope": [],
           "standard_catalogue": rounds.DEFAULT_STANDARD_CATALOGUE,
           "noisy_rule_rate": 0.8, "stale_cr_days": 14}
    items = [rounds.triage_secret(alert, cfg, now)
             for alert in rounds.collapse_secret_alerts(normalized)]
    items.sort(key=lambda item: rounds.PRIORITIES.index(item["priority"]))

    out = ["# GitHub secret scanning — %d alert(s), %d credential(s)"
           % (len(normalized), len(items)), ""]
    out.append("| Priority | Credential | Exposure | Validity | Revoke |")
    out.append("|---|---|---|---|---|")
    for item in items:
        revoke = [a for a in item["actions"] if a["id"].endswith("-revoke")]
        if not revoke:
            status = "n/a"
        elif revoke[0]["auto"]:
            status = "automatic — gates pass"
        else:
            status = "blocked: %s" % ", ".join(
                rounds.GATE_LABEL.get(g, g) for g in revoke[0]["gates_failed"]) \
                or "; ".join(revoke[0]["blocked_by"][:1])
        out.append("| %s | %s | %s | %s | %s |" % (
            item["priority"], rounds._cell(item["title"]),
            "public" if item["detail"]["public"] else "private",
            item["detail"]["validity"], rounds._cell(status)))
    out.append("")
    for item in items:
        if item["not_established"]:
            out.append("- **%s** — not established: %s"
                       % (item["id"], "; ".join(item["not_established"])))
    return "\n".join(out) + "\n"


def build_parser():
    parser = argparse.ArgumentParser(
        description="Collect and normalize GitHub secret scanning alerts for a rounds bundle.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    source = parser.add_argument_group("source")
    source.add_argument("--org", help="collect every alert in this organization")
    source.add_argument("--repo", action="append", default=[],
                        help="owner/repo; repeatable")
    source.add_argument("--from-json", help="normalize a saved API dump instead of calling GitHub")
    parser.add_argument("--state", default="open", choices=("open", "resolved"))
    parser.add_argument("--since", help="ISO timestamp; only alerts updated after it")
    parser.add_argument("--locations", action="store_true",
                        help="also fetch each alert's locations (one extra call per alert)")
    parser.add_argument("--ownership", help="JSON mapping repo -> owning team")
    parser.add_argument("--consumers",
                        help="JSON mapping secret fingerprint or type -> list of consuming services")
    parser.add_argument("--format", choices=("bundle", "json", "md"), default="bundle")
    parser.add_argument("--out", help="write here instead of stdout")
    parser.add_argument("--now", help="ISO time for triage in --format md")
    parser.add_argument("--timeout", type=float, default=30.0)
    return parser


def _load_json(path):
    if not path:
        return {}
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def main(argv=None):
    args = build_parser().parse_args(argv)

    if not (args.org or args.repo or args.from_json):
        raise SystemExit("choose --org, --repo, or --from-json")

    ownership = _load_json(args.ownership)
    consumers = _load_json(args.consumers)

    if args.from_json:
        raw = _load_json(args.from_json)
        alerts = raw if isinstance(raw, list) else raw.get("alerts") or []
        fetch_locations = False
    else:
        alerts = collect(args)
        fetch_locations = args.locations

    normalized = []
    for alert in alerts:
        locations = collect_locations(alert, args.timeout) if fetch_locations else \
            alert.get("locations") or []
        normalized.append(normalize_alert(alert, ownership, consumers, locations))

    now = rounds._parse_time(args.now) or datetime.now(timezone.utc)

    if args.format == "md":
        text = render_md(normalized, now)
    elif args.format == "json":
        text = json.dumps(normalized, indent=2) + "\n"
    else:
        bundle = {
            "rounds_meta": {
                "window_end": now.isoformat(),
                "sources": {"github": "ok"},
                "collection_notes": [] if (args.org or args.repo)
                                    else ["github: normalized from a saved dump, not collected live"],
            },
            "github_secret_alerts": normalized,
        }
        text = json.dumps(bundle, indent=2) + "\n"

    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
        sys.stderr.write("wrote %s (%d alert(s))\n" % (args.out, len(normalized)))
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
