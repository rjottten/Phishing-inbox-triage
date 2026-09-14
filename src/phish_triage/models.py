"""Core data model for the phishing triage pipeline.

Every source adapter produces `ReportedMessage` objects; the rules engine turns
those into `TriageResult` objects; the report writer renders those. Keeping the
model in the middle means a new source (Graph, Defender export, an mbox dump)
only has to learn how to build `ReportedMessage`.
"""
from __future__ import annotations

import enum
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


class Lane(enum.Enum):
    """The three-way split the skill's operating principle is built on."""

    HANDLED = "handled_by_automation"
    GAP = "automation_gap"
    EXCEPTION = "exception"

    @property
    def label(self) -> str:
        return {
            Lane.HANDLED: "Handled by automation",
            Lane.GAP: "Automation gap",
            Lane.EXCEPTION: "Exception",
        }[self]


class Category(enum.Enum):
    """Exception categories, ordered most to least consequential."""

    USER_INTERACTION = "user_interaction"
    BEC = "bec_impersonation"
    HIGH_VALUE_TARGET = "high_value_target"
    REMEDIATION_DECISION = "remediation_decision"
    AMBIGUOUS = "ambiguous"

    @property
    def label(self) -> str:
        return {
            Category.USER_INTERACTION: "User interaction / compromise",
            Category.BEC: "BEC / impersonation",
            Category.HIGH_VALUE_TARGET: "High-value target",
            Category.REMEDIATION_DECISION: "Remediation decision",
            Category.AMBIGUOUS: "Ambiguous",
        }[self]

    @property
    def rank(self) -> int:
        order = [
            Category.USER_INTERACTION,
            Category.BEC,
            Category.HIGH_VALUE_TARGET,
            Category.REMEDIATION_DECISION,
            Category.AMBIGUOUS,
        ]
        return order.index(self)


class Priority(enum.Enum):
    P1 = 1
    P2 = 2
    P3 = 3
    P4 = 4

    def __str__(self) -> str:
        return self.name


@dataclass
class DefenderState:
    """What Microsoft automation did with this item, as far as we can see."""

    submission_id: str | None = None
    air_status: str | None = None
    verdict: str | None = None
    user_notified: bool = False
    actions: str = ""

    @property
    def has_submission(self) -> bool:
        return bool(self.submission_id)

    @property
    def air_completed(self) -> bool:
        return (self.air_status or "").strip().lower() in {"completed", "complete", "closed"}

    @property
    def air_in_progress(self) -> bool:
        return (self.air_status or "").strip().lower() in {"pending", "running", "queued", "in progress"}

    @property
    def air_errored(self) -> bool:
        return (self.air_status or "").strip().lower() in {"failed", "error", "errored", "terminated"}

    @property
    def awaiting_approval(self) -> bool:
        status = (self.air_status or "").strip().lower()
        return status in {"awaiting approval", "pending approval"} or "PENDING:" in (self.actions or "")

    @property
    def verdict_clean(self) -> bool:
        return (self.verdict or "").strip().lower() in {"clean", "no threats found", "not phishing", "none found"}

    @property
    def verdict_malicious(self) -> bool:
        return (self.verdict or "").strip().lower() in {"phishing", "malware", "high confidence phish", "malicious"}


@dataclass
class ReportedMessage:
    """One item in the user-reported queue, normalized across sources."""

    id: str
    reporter: str = ""
    received: datetime | None = None
    reported_via: str = "unknown"
    from_name: str = ""
    from_address: str = ""
    reply_to: str | None = None
    return_path: str | None = None
    subject: str = ""
    body_excerpt: str = ""
    urls: list[str] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)
    auth: dict[str, str] = field(default_factory=dict)
    recipient_count: int = 1
    recipients_vip: list[str] = field(default_factory=list)
    reporter_note: str = ""
    defender: DefenderState = field(default_factory=DefenderState)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def reported_by_button(self) -> bool:
        return self.reported_via in {"outlook_report_button", "report_button", "user_submission"}

    @property
    def has_payload(self) -> bool:
        return bool(self.urls or self.attachments)

    @property
    def sender_domain(self) -> str:
        return self.from_address.rsplit("@", 1)[-1].lower() if "@" in self.from_address else ""

    @property
    def reply_to_domain(self) -> str:
        if not self.reply_to or "@" not in self.reply_to:
            return ""
        return self.reply_to.rsplit("@", 1)[-1].lower()

    @property
    def text(self) -> str:
        """Everything attacker-controlled, for keyword scanning. Never executed."""
        return f"{self.subject}\n{self.body_excerpt}"


@dataclass
class Finding:
    """One piece of evidence the rules engine produced, with its provenance."""

    code: str
    detail: str
    category: Category | None = None

    def __str__(self) -> str:
        return self.detail


@dataclass
class Action:
    """A recommended — never executed — response action."""

    action: str
    owner: str
    note: str = ""

    def __str__(self) -> str:
        return f"{self.action} ({self.owner})" if not self.note else f"{self.action} — {self.note} ({self.owner})"


@dataclass
class TriageResult:
    message: ReportedMessage
    lane: Lane
    categories: list[Category] = field(default_factory=list)
    priority: Priority = Priority.P4
    findings: list[Finding] = field(default_factory=list)
    unverified: list[str] = field(default_factory=list)
    actions: list[Action] = field(default_factory=list)
    open_questions: list[str] = field(default_factory=list)

    @property
    def is_exception(self) -> bool:
        return self.lane is Lane.EXCEPTION

    @property
    def category_labels(self) -> str:
        return ", ".join(c.label for c in self.categories) if self.categories else "—"

    def evidence(self) -> list[str]:
        return [f.detail for f in self.findings]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.message.id,
            "lane": self.lane.value,
            "priority": self.priority.name,
            "categories": [c.value for c in self.categories],
            "reporter": self.message.reporter,
            "reported_via": self.message.reported_via,
            "from": self.message.from_address,
            "from_name": self.message.from_name,
            "subject": self.message.subject,
            "recipient_count": self.message.recipient_count,
            "recipients_vip": self.message.recipients_vip,
            "defender": {
                "submission_id": self.message.defender.submission_id,
                "air_status": self.message.defender.air_status,
                "verdict": self.message.defender.verdict,
                "user_notified": self.message.defender.user_notified,
                "actions": self.message.defender.actions,
            },
            "findings": [{"code": f.code, "detail": f.detail} for f in self.findings],
            "unverified": self.unverified,
            "recommended_actions": [
                {"action": a.action, "owner": a.owner, "note": a.note} for a in self.actions
            ],
            "open_questions": self.open_questions,
        }


@dataclass
class Queue:
    """A batch of reported messages plus the org context the rules need."""

    items: list[ReportedMessage] = field(default_factory=list)
    org_domain: str = ""
    vip_list: list[str] = field(default_factory=list)
    window: str = ""
    source: str = ""
    missing_sources: list[str] = field(default_factory=list)

    def __iter__(self) -> Iterable[ReportedMessage]:
        return iter(self.items)

    def __len__(self) -> int:
        return len(self.items)
