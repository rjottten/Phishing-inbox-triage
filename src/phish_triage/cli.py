"""Command line entry points.

    phish-triage run --input export.json --format markdown
    phish-triage run --graph --mailbox phishing@example.com --hours 12
    phish-triage message --headers raw.txt --note "I clicked it"
    phish-triage headers raw.txt --org-domain example.com

`run` never writes to the tenant: every source call is a read, and every response
action lands in the report as a recommendation with a named owner.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from . import headers as headers_mod
from .config import Config
from .models import DefenderState, Lane, Priority, Queue, ReportedMessage
from .report import shift_report, single_message, to_json
from .rules import triage, triage_message
from .sources.json_export import load_queue

EXIT_OK = 0
EXIT_ERROR = 2
#: `--fail-on` uses the exit code as the alerting signal for a scheduled run.
EXIT_THRESHOLD_MET = 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phish-triage", description=__doc__.split("\n")[0])
    parser.add_argument("--version", action="version", version=f"phish-triage {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="triage a queue and write the handover report")
    source = run.add_mutually_exclusive_group(required=True)
    source.add_argument("--input", "-i", help="JSON export of the queue (see docs/data-format.md)")
    source.add_argument("--graph", action="store_true", help="pull live from Microsoft Graph (read-only)")
    run.add_argument("--mailbox", help="shared phishing mailbox address, with --graph")
    run.add_argument("--hours", type=int, default=24, help="look-back window for --graph (default 24)")
    run.add_argument("--no-clicks", action="store_true", help="skip the UrlClickEvents hunting query")
    run.add_argument("--config", "-c", help="tenant config (.toml or .json) — org domain, VIPs, partner domains")
    run.add_argument("--format", "-f", choices=("markdown", "json", "summary"), default="markdown")
    run.add_argument("--out", "-o", help="write to this file instead of stdout")
    run.add_argument(
        "--fail-on",
        choices=("never", "p1", "p2", "exception"),
        default="never",
        help=f"exit {EXIT_THRESHOLD_MET} when the queue contains something at or above this level, for scheduled runs",
    )

    message = sub.add_parser("message", help="triage one message and answer 'is this phishing?'")
    message.add_argument("--headers", help="file of raw headers")
    message.add_argument("--json", dest="json_item", help="file with a single item in export format")
    message.add_argument("--note", default="", help="what the reporter said, in their own words")
    message.add_argument("--body", default="", help="body text or excerpt")
    message.add_argument("--reporter", default="", help="who reported it")
    message.add_argument("--config", "-c", help="tenant config (.toml or .json)")

    head = sub.add_parser("headers", help="parse raw headers to JSON")
    head.add_argument("path", nargs="?", help="file of raw headers; stdin when omitted")
    head.add_argument("--org-domain", default="", help="flag lookalikes of this domain")
    return parser


def _load_config(path: str | None, queue: Queue | None = None) -> Config:
    config = Config.load(path)
    if queue:
        config.org_domain = config.org_domain or queue.org_domain
        config.vip_list = config.vip_list or list(queue.vip_list)
    return config


def _threshold_met(results, fail_on: str) -> bool:
    if fail_on == "never":
        return False
    exceptions = [r for r in results if r.lane is Lane.EXCEPTION]
    if fail_on == "exception":
        return bool(exceptions)
    limit = Priority.P1 if fail_on == "p1" else Priority.P2
    return any(r.priority.value <= limit.value for r in exceptions)


def _cmd_run(args: argparse.Namespace) -> int:
    if args.graph:
        from .sources.graph import GraphError, fetch_queue

        config = _load_config(args.config)
        try:
            queue = fetch_queue(
                mailbox=args.mailbox,
                hours=args.hours,
                org_domain=config.org_domain,
                vip_list=config.vip_list,
                include_clicks=not args.no_clicks,
            )
        except GraphError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR
    else:
        try:
            queue = load_queue(args.input)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: could not read {args.input}: {exc}", file=sys.stderr)
            return EXIT_ERROR
        config = _load_config(args.config, queue)

    results = triage(queue, config)

    if args.format == "json":
        output = to_json(results, queue)
    elif args.format == "summary":
        output = _summary_lines(results)
    else:
        output = shift_report(results, queue)

    if args.out:
        Path(args.out).write_text(output)
        print(f"wrote {args.out} ({len(results)} items)", file=sys.stderr)
    else:
        print(output)

    return EXIT_THRESHOLD_MET if _threshold_met(results, args.fail_on) else EXIT_OK


def _summary_lines(results) -> str:
    lines = []
    for r in results:
        categories = r.category_labels if r.lane is Lane.EXCEPTION else "—"
        lines.append(f"{r.message.id:<12} {r.priority} {r.lane.value:<22} {categories}")
    return "\n".join(lines)


def _cmd_message(args: argparse.Namespace) -> int:
    config = Config.load(args.config)

    if args.json_item:
        try:
            item = json.loads(Path(args.json_item).read_text())
        except (OSError, ValueError) as exc:
            print(f"error: could not read {args.json_item}: {exc}", file=sys.stderr)
            return EXIT_ERROR
        from .sources.json_export import parse_queue

        queue = parse_queue({"items": [item]} if "items" not in item else item)
        results = triage(queue, config)
        print("\n---\n".join(single_message(r) for r in results))
        return EXIT_OK

    if not args.headers:
        print("error: pass --headers or --json", file=sys.stderr)
        return EXIT_ERROR

    try:
        raw = Path(args.headers).read_text(errors="replace")
    except OSError as exc:
        print(f"error: could not read {args.headers}: {exc}", file=sys.stderr)
        return EXIT_ERROR

    parsed = headers_mod.parse(raw, org_domain=config.org_domain)
    body = args.body or _body_after_headers(raw)
    msg = ReportedMessage(
        id=parsed.get("message_id") or "pasted-message",
        reporter=args.reporter,
        received=datetime.now(timezone.utc),
        reported_via="pasted",
        from_name=parsed["from"]["name"],
        from_address=parsed["from"]["address"],
        reply_to=(parsed.get("reply_to") or {}).get("address") if parsed.get("reply_to") else None,
        return_path=parsed.get("return_path"),
        subject=parsed.get("subject") or "",
        body_excerpt=body,
        auth=parsed.get("authentication", {}),
        reporter_note=args.note,
        defender=DefenderState(),
    )
    print(single_message(triage_message(msg, config)))
    return EXIT_OK


def _body_after_headers(raw: str) -> str:
    """Everything after the first blank line is the body. Text only; never rendered."""
    _, _, body = raw.partition("\n\n")
    return " ".join(body.split())[:2000]


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "run":
        return _cmd_run(args)
    if args.command == "message":
        return _cmd_message(args)
    if args.command == "headers":
        return headers_mod.main([p for p in ([args.path] if args.path else []) + (["--org-domain", args.org_domain] if args.org_domain else [])])
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
