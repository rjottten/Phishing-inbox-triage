"""Read a queue from a JSON export.

This is the format produced by joining the shared mailbox to the Defender
Submissions page — the one an analyst can produce by hand today, and the one
`graph.py` writes when it pulls live. `test-data/mailbox_export.json` is a
worked example; see `docs/data-format.md` for the field reference.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..models import DefenderState, Queue, ReportedMessage

#: Fields consumed directly; anything else on an item is kept in `raw` so custom
#: exports can carry extra signals (recipients, telemetry hits) without a schema change.
KNOWN_ITEM_FIELDS = {
    "id", "reporter", "received", "reported_via", "from_name", "from_address",
    "reply_to", "return_path", "subject", "body_excerpt", "urls", "attachments",
    "auth", "recipient_count", "recipients_vip", "reporter_note", "defender",
}


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _defender(data: Any) -> DefenderState:
    if not isinstance(data, dict):
        return DefenderState()
    return DefenderState(
        submission_id=data.get("submission_id"),
        air_status=data.get("air_status"),
        verdict=data.get("verdict"),
        user_notified=bool(data.get("user_notified")),
        actions=data.get("actions") or "",
    )


def _message(item: dict[str, Any], index: int) -> ReportedMessage:
    return ReportedMessage(
        id=str(item.get("id") or f"ITEM-{index + 1}"),
        reporter=item.get("reporter") or "",
        received=_parse_dt(item.get("received")),
        reported_via=item.get("reported_via") or "unknown",
        from_name=item.get("from_name") or "",
        from_address=item.get("from_address") or "",
        reply_to=item.get("reply_to"),
        return_path=item.get("return_path"),
        subject=item.get("subject") or "",
        body_excerpt=item.get("body_excerpt") or "",
        urls=list(item.get("urls") or []),
        attachments=list(item.get("attachments") or []),
        auth={k.lower(): str(v).lower() for k, v in (item.get("auth") or {}).items()},
        recipient_count=int(item.get("recipient_count") or 1),
        recipients_vip=list(item.get("recipients_vip") or []),
        reporter_note=item.get("reporter_note") or "",
        defender=_defender(item.get("defender")),
        raw={k: v for k, v in item.items() if k not in KNOWN_ITEM_FIELDS},
    )


def parse_queue(data: dict[str, Any]) -> Queue:
    """Turn a parsed export dict into a `Queue`."""
    if not isinstance(data, dict):
        raise ValueError("export must be a JSON object with an 'items' array")
    items = data.get("items")
    if not isinstance(items, list):
        raise ValueError("export is missing an 'items' array")
    meta = data.get("export_meta") or {}
    return Queue(
        items=[_message(item, i) for i, item in enumerate(items)],
        org_domain=meta.get("org_domain") or "",
        vip_list=list(meta.get("vip_list") or []),
        window=meta.get("window") or "",
        source=meta.get("source") or "JSON export",
        missing_sources=list(meta.get("missing_sources") or []),
    )


def load_queue(path: str | Path) -> Queue:
    """Read a queue from a JSON export file."""
    return parse_queue(json.loads(Path(path).read_text()))
