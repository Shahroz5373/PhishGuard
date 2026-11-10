"""
Main detection engine.

The UI only needs this one function:

    from backend.detector import analyze_email
    result = analyze_email(email_text, settings)

Pipeline: sanitize -> parse -> sender checks -> content checks -> attachment
          checks -> URL checks -> risk scoring -> report

Nothing here opens, resolves or downloads a link. Links are only analyzed as text.
"""

from __future__ import annotations

from .config import DEFAULT_SETTINGS, MAX_URLS_ANALYZED
from .content_analyzer import analyze_attachments, analyze_content
from .email_parser import parse_email
from .models import Indicator
from .risk_scoring import calculate_risk
from .security import sanitize_input
from .sender_analyzer import analyze_sender
from .url_analyzer import analyze_urls

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def _summary(score: int, level: str, indicators: list[Indicator]) -> str:
    if not indicators:
        return "No phishing indicators were found."
    areas = sorted({i.category for i in indicators})
    area_text = ", ".join(areas)
    count = len(indicators)
    noun = "indicator" if count == 1 else "indicators"
    return f"Risk score {score}/100 ({level}). {count} {noun} found in: {area_text}."


def analyze_email(email_text: str, settings: dict | None = None) -> dict:
    """
    Analyze a raw email and return a report.

    settings (all optional):
        check_urls     analyze links
        check_headers  analyze sender and headers
    """
    options = {**DEFAULT_SETTINGS, **(settings or {})}

    # The email is untrusted: clean it before anything else touches it
    email_text, notes = sanitize_input(email_text)
    parsed = parse_email(email_text)

    indicators: list[Indicator] = []

    if not (parsed.body or parsed.subject or parsed.urls or parsed.attachments):
        return _empty_report(options)

    # Sender / headers
    if options["check_headers"]:
        if parsed.has_headers:
            indicators += analyze_sender(parsed)
        else:
            notes.append(
                "No email headers were found, so sender checks were skipped. "
                "Paste the full email with headers for a more complete result."
            )

    # Content and attachments
    indicators += analyze_content(parsed.subject, parsed.body)
    indicators += analyze_attachments(parsed.attachments)

    # URLs
    if options["check_urls"]:
        urls = parsed.urls
        if len(urls) > MAX_URLS_ANALYZED:
            notes.append(f"This email has {len(urls)} links. Only the first {MAX_URLS_ANALYZED} were analyzed.")
            urls = urls[:MAX_URLS_ANALYZED]
        url_reports, url_indicators = analyze_urls(urls, parsed.links)
        indicators += url_indicators
        url_list = [report.to_dict() for report in url_reports]
    else:
        url_list = [
            {"url": u, "domain": "", "flagged": False, "reason": "Not analyzed (URL analysis is turned off)", "risk": "Unknown", "points": 0}
            for u in parsed.urls
        ]
        if parsed.urls:
            notes.append("URL analysis is turned off in the settings.")

    assessment = calculate_risk(indicators)
    reasons = sorted(assessment.indicators, key=lambda i: (_SEVERITY_ORDER.get(i.severity, 3), -i.points))

    return {
        "score": assessment.score,
        "verdict": assessment.verdict,
        "risk_level": assessment.level,
        "reasons": [item.to_dict() for item in reasons],
        "urls": url_list,
        "headers": parsed.headers,
        "notes": notes,
        "summary": _summary(assessment.score, assessment.level, assessment.indicators),
        "breakdown": assessment.breakdown,
    }


def _empty_report(options: dict) -> dict:
    return {
        "score": 0,
        "verdict": "Safe",
        "risk_level": "Low",
        "reasons": [],
        "urls": [],
        "headers": {},
        "notes": ["The email is empty, so there was nothing to analyze."],
        "summary": "No phishing indicators were found.",
        "breakdown": {},
    }
