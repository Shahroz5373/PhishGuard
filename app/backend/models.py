"""Small data containers shared by all backend modules."""

from __future__ import annotations

from dataclasses import dataclass, field

from .config import RULES

MAX_EVIDENCE_ITEMS = 5
MAX_EVIDENCE_LENGTH = 140


def _clean_evidence(items) -> list[str]:
    """Remove duplicates, shorten long lines and cap the list size."""
    seen: set[str] = set()
    cleaned: list[str] = []
    for item in items or []:
        text = " ".join(str(item).split())
        if not text or text.lower() in seen:
            continue
        seen.add(text.lower())
        if len(text) > MAX_EVIDENCE_LENGTH:
            text = text[: MAX_EVIDENCE_LENGTH - 3] + "..."
        cleaned.append(text)
    if len(cleaned) > MAX_EVIDENCE_ITEMS:
        extra = len(cleaned) - MAX_EVIDENCE_ITEMS
        cleaned = cleaned[:MAX_EVIDENCE_ITEMS] + [f"...and {extra} more"]
    return cleaned


@dataclass
class Indicator:
    """One finding that adds to the risk score, with the evidence behind it."""

    rule_id: str
    category: str
    severity: str
    points: int
    title: str
    detail: str
    evidence: list[str] = field(default_factory=list)

    @classmethod
    def from_rule(cls, rule_id: str, evidence=None, severity: str | None = None, detail: str | None = None):
        rule = RULES[rule_id]
        return cls(
            rule_id=rule_id,
            category=rule.category,
            severity=severity or rule.severity,
            points=rule.points,
            title=rule.title,
            detail=detail or rule.why,
            evidence=_clean_evidence(evidence),
        )

    def to_dict(self) -> dict:
        """Format used by the UI ('reasons' list)."""
        return {
            "title": self.title,
            "detail": self.detail,
            "severity": self.severity,
            "category": self.category,
            "points": self.points,
            "evidence": self.evidence,
        }


@dataclass
class ParsedEmail:
    """Structured version of the raw email text."""

    has_headers: bool = False
    headers: dict = field(default_factory=dict)       # shown in the UI
    sender_name: str = ""
    sender_email: str = ""
    sender_domain: str = ""
    reply_to_email: str = ""
    reply_to_domain: str = ""
    subject: str = ""
    body: str = ""                                    # readable text (HTML removed)
    urls: list[str] = field(default_factory=list)
    links: list[tuple[str, str]] = field(default_factory=list)  # (href, visible text)
    attachments: list[str] = field(default_factory=list)
    auth_results: dict = field(default_factory=dict)  # {"spf": "fail", ...}
    is_html: bool = False


@dataclass
class UrlReport:
    """Analysis result for a single URL."""

    url: str
    host: str = ""
    registered_domain: str = ""
    findings: list[tuple[str, str]] = field(default_factory=list)  # (rule_id, evidence)
    points: int = 0
    risk: str = "Low"
    flagged: bool = False
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "domain": self.registered_domain or self.host,
            "flagged": self.flagged,
            "reason": self.reason,
            "risk": self.risk,
            "points": self.points,
        }
