"""Tenant-specific knobs. Everything here is org context the rules can't guess."""
from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: Display-name brands worth impersonating, mapped to the domains that legitimately
#: send them. A brand match with a domain outside the list is impersonation.
DEFAULT_BRAND_DOMAINS: dict[str, list[str]] = {
    "microsoft": ["microsoft.com", "office.com", "office365.com", "microsoftonline.com", "sharepoint.com", "outlook.com"],
    "office 365": ["microsoft.com", "office.com", "office365.com", "microsoftonline.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "adobe": ["adobe.com"],
    "dropbox": ["dropbox.com", "dropboxmail.com"],
    "linkedin": ["linkedin.com", "linkedinmail.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazonses.com"],
    "paypal": ["paypal.com"],
    "sharepoint": ["sharepoint.com", "microsoft.com", "microsoftonline.com"],
    "zoom": ["zoom.us"],
}


@dataclass
class Config:
    """Org context for the rules engine.

    `org_domain` and `vip_list` matter most: without them the engine can't tell a
    lookalike from a partner, or a VIP from anyone else.
    """

    org_domain: str = ""
    org_domains: list[str] = field(default_factory=list)
    vip_list: list[str] = field(default_factory=list)
    #: Domains the org genuinely corresponds with. Blocking these is a business
    #: incident of its own, so the engine recommends address-level action instead.
    known_partner_domains: list[str] = field(default_factory=list)
    brand_domains: dict[str, list[str]] = field(default_factory=lambda: dict(DEFAULT_BRAND_DOMAINS))
    #: An AIR investigation still running after this many hours is an exception,
    #: not work in progress. Hours, not days (see references/exception-criteria.md).
    air_stale_hours: float = 2.0
    #: Recipient count at which a purge or block stops being routine.
    campaign_recipient_threshold: int = 50
    #: Mailboxes where a purge decision needs a named owner rather than a default.
    large_purge_threshold: int = 50
    #: Canonical field -> the header your CSV export actually uses, for columns the
    #: importer could not place on its own. `phish-triage inspect` names them.
    column_map: dict[str, str] = field(default_factory=dict)
    #: How to record reports from a CSV that carries no source column. A Defender
    #: submissions export only contains reported mail, so the button is the default.
    default_reported_via: str = "outlook_report_button"

    def all_org_domains(self) -> list[str]:
        domains = [d.lower() for d in self.org_domains]
        if self.org_domain and self.org_domain.lower() not in domains:
            domains.insert(0, self.org_domain.lower())
        return domains

    def is_org_domain(self, domain: str) -> bool:
        domain = (domain or "").lower()
        return any(domain == d or domain.endswith("." + d) for d in self.all_org_domains())

    def is_known_partner(self, domain: str) -> bool:
        domain = (domain or "").lower()
        return any(domain == d.lower() or domain.endswith("." + d.lower()) for d in self.known_partner_domains)

    def is_vip(self, address: str) -> bool:
        return (address or "").lower() in {v.lower() for v in self.vip_list}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Config:
        known = {f for f in cls.__dataclass_fields__}
        unknown = set(data) - known
        if unknown:
            raise ValueError(f"unknown config keys: {', '.join(sorted(unknown))}")
        cfg = cls(**{k: v for k, v in data.items() if k in known})
        if "brand_domains" in data:
            merged = dict(DEFAULT_BRAND_DOMAINS)
            merged.update(data["brand_domains"])
            cfg.brand_domains = merged
        return cfg

    @classmethod
    def load(cls, path: str | Path | None) -> Config:
        if not path:
            return cls()
        p = Path(path)
        raw = p.read_bytes()
        data = tomllib.loads(raw.decode()) if p.suffix == ".toml" else json.loads(raw)
        return cls.from_dict(data.get("triage", data) if p.suffix == ".toml" else data)
