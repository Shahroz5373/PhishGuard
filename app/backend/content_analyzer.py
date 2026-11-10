"""
Content analysis: looks for social-engineering language in the subject and
body, and for risky attachment names.

Every finding keeps the exact text that triggered it, so the report can show
evidence. Weak words (like "urgent") add only a few points on their own.
"""

from __future__ import annotations

import re

from .config import (
    ARCHIVE_EXT,
    CONTENT_PATTERNS,
    CONTENT_TACTICS,
    DOCUMENT_EXT,
    EXECUTABLE_EXT,
    HTML_EXT,
    MACRO_EXT,
    MULTI_TACTIC_MIN,
)
from .models import Indicator

# Compile once when the module is loaded
_COMPILED = {
    rule_id: [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in patterns]
    for rule_id, patterns in CONTENT_PATTERNS.items()
}


def _find_matches(rule_id: str, text: str) -> list[str]:
    found: list[str] = []
    for pattern in _COMPILED[rule_id]:
        for match in pattern.finditer(text):
            snippet = " ".join(match.group(0).split())
            if snippet:
                found.append(f'"{snippet}"')
    return found


def analyze_content(subject: str, body: str) -> list[Indicator]:
    """Check subject and body for phishing language."""
    text = f"{subject or ''}\n{body or ''}"
    if not text.strip():
        return []

    matches = {rule_id: _find_matches(rule_id, text) for rule_id in _COMPILED}

    # Strong time pressure already covers weak urgency words, so count it once
    if matches["CONTENT_URGENCY_STRONG"]:
        matches["CONTENT_URGENCY_STRONG"] += matches["CONTENT_URGENCY_WEAK"]
        matches["CONTENT_URGENCY_WEAK"] = []

    indicators = [Indicator.from_rule(rule_id, evidence=found) for rule_id, found in matches.items() if found]

    tactics = {CONTENT_TACTICS[i.rule_id] for i in indicators if i.rule_id in CONTENT_TACTICS}
    if len(tactics) >= MULTI_TACTIC_MIN:
        indicators.append(Indicator.from_rule("CONTENT_MULTI_TACTIC", evidence=sorted(tactics)))
    return indicators


def analyze_attachments(filenames: list[str]) -> list[Indicator]:
    """Check attachment file names (the files themselves are never opened)."""
    executable: list[str] = []
    double_ext: list[str] = []
    macro: list[str] = []
    html: list[str] = []
    archive: list[str] = []

    for name in filenames or []:
        parts = name.lower().strip().split(".")
        ext = parts[-1] if len(parts) > 1 else ""
        previous = parts[-2] if len(parts) > 2 else ""

        if ext in EXECUTABLE_EXT:
            if previous in DOCUMENT_EXT:
                double_ext.append(name)
            else:
                executable.append(name)
        elif ext in MACRO_EXT:
            macro.append(name)
        elif ext in HTML_EXT:
            html.append(name)
        elif ext in ARCHIVE_EXT:
            archive.append(name)

    indicators = []
    for rule_id, items in (
        ("ATTACH_EXECUTABLE", executable),
        ("ATTACH_DOUBLE_EXT", double_ext),
        ("ATTACH_MACRO", macro),
        ("ATTACH_HTML", html),
        ("ATTACH_ARCHIVE", archive),
    ):
        if items:
            indicators.append(Indicator.from_rule(rule_id, evidence=items))
    return indicators
