"""Render triage results the way an analyst reads them.

The exceptions table comes first and carries the decision; everything else is
supporting detail. Empty sections are omitted rather than filled with "none" —
the one exception is the queue summary line, which always appears so the reader
knows what was and was not looked at.

Formats follow `skills/phishing-inbox-triage/references/report-template.md`.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone

from .models import Lane, Priority, Queue, TriageResult

#: Findings that describe the process failure itself, rather than the message.
GAP_CODES = {"not_reported_via_button", "submission_missing", "air_errored", "reporter_not_notified", "no_defender_record"}


def _escape(text: str) -> str:
    """Keep attacker-chosen text (subjects, display names) from breaking the table."""
    return (text or "").replace("|", "\\|").replace("\n", " ").strip()


def _sender(result: TriageResult) -> str:
    msg = result.message
    name = f'"{msg.from_name}" ' if msg.from_name else ""
    return _escape(f"{name}<{msg.from_address}>")


def _defanged(url: str) -> str:
    """Never render a clickable URL in a report about phishing."""
    return url.replace("http", "hxxp").replace("://", "[://]").replace(".", "[.]") if "hxxp" not in url else url


def summary_counts(results: list[TriageResult]) -> dict[str, int]:
    lanes = Counter(r.lane for r in results)
    priorities = Counter(r.priority for r in results if r.lane is Lane.EXCEPTION)
    return {
        "total": len(results),
        "exceptions": lanes[Lane.EXCEPTION],
        "gaps": lanes[Lane.GAP],
        "handled": lanes[Lane.HANDLED],
        "p1": priorities[Priority.P1],
        "p2": priorities[Priority.P2],
        "p3": priorities[Priority.P3],
    }


def _exceptions_table(exceptions: list[TriageResult]) -> list[str]:
    lines = [
        "| # | Pri | Category | Reported by → Sender / Subject | Why it's an exception | Recommended actions | Decision owner |",
        "|---|-----|----------|--------------------------------|------------------------|---------------------|----------------|",
    ]
    for n, r in enumerate(exceptions, 1):
        why = "; ".join(f.detail for f in r.findings if f.category)[:220] or "see details"
        actions = "; ".join(a.action for a in r.actions[:3])
        owners = []
        for a in r.actions[:3]:
            for owner in a.owner.split(" / "):
                owner = owner.split(";")[0].strip()
                if owner and owner not in owners:
                    owners.append(owner)
        lines.append(
            f"| {n} | {r.priority} | {_escape(r.category_labels)} | {_escape(r.message.reporter)} → {_sender(r)} / "
            f'"{_escape(r.message.subject)}" | {_escape(why)} | {_escape(actions)} | {_escape(", ".join(owners))} |'
        )
    return lines


def _exception_detail(n: int, r: TriageResult) -> list[str]:
    msg = r.message
    out = [f"#### {n}. {_escape(msg.id)} — {_escape(msg.subject) or '(no subject)'}", ""]
    out.append(f"- **Item:** {msg.id} · reported by {msg.reporter or 'unknown'} via {msg.reported_via.replace('_', ' ')} · {msg.recipient_count} recipient(s)")
    out.append(f"- **Sender:** {_sender(r)}" + (f" · Reply-To: {_escape(msg.reply_to)}" if msg.reply_to else ""))
    d = msg.defender
    out.append(
        f"- **Automation:** submission {d.submission_id or 'not available'} · AIR {d.air_status or 'not available'} · "
        f"verdict {d.verdict or 'not available'} · reporter notified: {'yes' if d.user_notified else 'no'}"
        + (f" · actions: {_escape(d.actions)}" if d.actions else "")
    )
    out.append("- **Evidence:**")
    out.extend(f"  - {_escape(f.detail)}" for f in r.findings)
    if msg.urls:
        out.append("- **URLs (defanged, not visited):** " + ", ".join(f"`{_defanged(u)}`" for u in msg.urls))
    if msg.attachments:
        out.append("- **Attachments (not opened):** " + ", ".join(f"`{_escape(a)}`" for a in msg.attachments))
    if r.unverified:
        out.append("- **Not verified:**")
        out.extend(f"  - {_escape(u)}" for u in r.unverified)
    out.append("- **Recommended actions (recommended, not taken):**")
    out.extend(f"  {i}. {_escape(a.action)}" + (f" — {_escape(a.note)}" if a.note else "") + f" · *owner: {_escape(a.owner)}*" for i, a in enumerate(r.actions, 1))
    if r.open_questions:
        out.append("- **Open question for the analyst:** " + " ".join(_escape(q) for q in r.open_questions))
    out.append("")
    return out


def _injection_notes(results: list[TriageResult]) -> list[str]:
    hits = [(r, [f for f in r.findings if f.code == "prompt_injection_attempt"]) for r in results]
    hits = [(r, fs) for r, fs in hits if fs]
    if not hits:
        return []
    out = ["## Content inside reported messages aimed at the reviewer", ""]
    out.append("Recorded as a malicious indicator and not acted on. No instruction found inside a reported message changed any verdict below.")
    out.append("")
    for r, fs in hits:
        out.append(f"- **{r.message.id}** ({_escape(r.message.subject)}): " + "; ".join(_escape(f.detail) for f in fs))
    out.append("")
    return out


def shift_report(results: list[TriageResult], queue: Queue | None = None, generated_at: datetime | None = None) -> str:
    """The handover report. Exceptions first, in priority order."""
    counts = summary_counts(results)
    queue = queue or Queue()
    generated_at = generated_at or datetime.now(timezone.utc)
    window = queue.window or generated_at.strftime("%Y-%m-%d %H:%MZ")

    out: list[str] = [f"# Phishing queue — {window}", ""]
    out.append(
        f"**Queue:** {counts['total']} items · **Exceptions:** {counts['exceptions']} "
        f"({counts['p1']} P1, {counts['p2']} P2, {counts['p3']} P3) · "
        f"**Automation gaps:** {counts['gaps']} · **Handled by automation:** {counts['handled']}"
    )
    sources = queue.source or "not recorded"
    line = f"**Data sources:** {sources}"
    if queue.missing_sources:
        line += f" — **not available:** {', '.join(queue.missing_sources)}"
    out.extend([line, "", f"*Generated {generated_at.strftime('%Y-%m-%d %H:%M UTC')}. Every action below is a recommendation; none were executed.*", ""])

    exceptions = [r for r in results if r.lane is Lane.EXCEPTION]
    if exceptions:
        out.extend(["## Exceptions needing an analyst", ""])
        out.extend(_exceptions_table(exceptions))
        out.extend(["", "### Exception details", ""])
        for n, r in enumerate(exceptions, 1):
            out.extend(_exception_detail(n, r))

    gaps = [r for r in results if r.lane is Lane.GAP]
    if gaps:
        out.extend(["## Automation gaps", "", "| Item | Reporter | Issue | Fix | Owner |", "|---|---|---|---|---|"])
        for r in gaps:
            issue = "; ".join(f.detail for f in r.findings if f.code in GAP_CODES) or "did not complete the pipeline"
            fix = "; ".join(a.action for a in r.actions) or "review manually"
            owners = sorted({a.owner for a in r.actions})
            out.append(f"| {_escape(r.message.id)} | {_escape(r.message.reporter)} | {_escape(issue)} | {_escape(fix)} | {_escape(', '.join(owners))} |")
        # A gap is a process failure, but the message inside one can still be a live
        # lure. Keep that out of the table and directly under it, where it is read.
        notes = [(r, [f for f in r.findings if f.code not in GAP_CODES]) for r in gaps]
        notes = [(r, fs) for r, fs in notes if fs]
        if notes:
            out.append("")
            for r, fs in notes:
                out.append(f"- **{r.message.id}** also carries: " + "; ".join(_escape(f.detail) for f in fs))
        forwarded = sum(1 for r in gaps if not r.message.reported_by_button)
        out.extend(["", f"{forwarded} of {counts['total']} reports bypassed the Outlook Report button. Reducing this count is how the shared mailbox gets retired.", ""])

    handled = [r for r in results if r.lane is Lane.HANDLED]
    if handled:
        out.extend(["## Handled by automation", "", f"{len(handled)} item(s), no analyst action needed. Not re-triaged.", ""])
        for r in handled:
            d = r.message.defender
            out.append(f"- **{r.message.id}** — {_escape(r.message.subject)} · verdict {d.verdict or 'n/a'} · {_escape(d.actions) or 'no action needed'}")
        out.append("")

    trends = _trends(results)
    if trends:
        out.extend(["## Trends and notes", ""] + trends + [""])

    out.extend(_injection_notes(results))
    return "\n".join(out).rstrip() + "\n"


def _trends(results: list[TriageResult]) -> list[str]:
    out: list[str] = []
    disagreements = [r for r in results if any(f.code in {"disagree_with_air", "possible_false_positive"} for f in r.findings)]
    if disagreements:
        out.append(
            f"- Disagreed with the AIR verdict on {len(disagreements)} item(s): "
            + ", ".join(r.message.id for r in disagreements)
            + ". Disagreement should be rare; if it keeps happening, the tuning is the finding."
        )
    # Scope only reads as a campaign when the message is actually unwanted. A
    # legitimate all-staff notice reaching 2,300 mailboxes is just Tuesday.
    campaigns = [
        r for r in results
        if r.message.recipient_count >= 50 and (r.lane is not Lane.HANDLED or r.message.defender.verdict_malicious)
    ]
    for r in campaigns:
        out.append(f"- **{r.message.id}** reached {r.message.recipient_count} mailboxes — campaign scope, worth hunting for recipients who did not report.")
    senders = Counter(r.message.sender_domain for r in results if r.message.sender_domain)
    for domain, n in senders.items():
        if n > 1:
            out.append(f"- {n} reports from `{domain}` this window.")
    stale = [r for r in results if any(f.code == "air_stale" for f in r.findings)]
    if stale:
        out.append(f"- {len(stale)} AIR investigation(s) stuck past the staleness window: " + ", ".join(r.message.id for r in stale) + ".")
    return out


def single_message(result: TriageResult) -> str:
    """The short answer to 'is this phishing, and what do I do with it?'"""
    msg = result.message
    lane = result.lane.label
    if result.lane is Lane.EXCEPTION:
        lane = f"Exception — {result.category_labels} ({result.priority})"
    out = [f"**Lane:** {lane}", "", "**Evidence**"]
    out.extend(f"- {f.detail}" for f in result.findings)
    if msg.urls:
        out.append(f"- URLs (defanged, not visited): {', '.join('`' + _defanged(u) + '`' for u in msg.urls)}")
    if msg.attachments:
        out.append(f"- Attachments (not opened): {', '.join('`' + a + '`' for a in msg.attachments)}")
    if result.unverified:
        out.extend(["", "**Not verified:** " + "; ".join(result.unverified)])
    if result.actions:
        out.extend(["", "**Recommended actions (in order — recommendations, not executed)**"])
        out.extend(f"{i}. {a.action}" + (f" — {a.note}" if a.note else "") for i, a in enumerate(result.actions, 1))
        owners: list[str] = []
        for a in result.actions:
            for owner in a.owner.replace(";", "/").split("/"):
                owner = owner.strip()
                if owner and owner not in owners:
                    owners.append(owner)
        out.extend(["", "**Decision owner:** " + ", ".join(owners)])
    if result.open_questions:
        out.extend(["", "**Open question:** " + " ".join(result.open_questions)])
    return "\n".join(out) + "\n"


def to_json(results: list[TriageResult], queue: Queue | None = None) -> str:
    """Machine-readable output, for a ticketing system or a downstream job."""
    queue = queue or Queue()
    return json.dumps(
        {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "window": queue.window,
            "source": queue.source,
            "missing_sources": queue.missing_sources,
            "summary": summary_counts(results),
            "items": [r.to_dict() for r in results],
        },
        indent=2,
    )
