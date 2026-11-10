"""
URL analysis: inspects every link found in the email.

Links are only analyzed as text. They are never opened, resolved or
downloaded, so nothing malicious can be triggered.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from .config import (
    HOST_KEYWORDS,
    PATH_KEYWORDS,
    RULES,
    URL_SHORTENERS,
)
from .domain_utils import (
    MAX_HOST_LENGTH,
    find_brand_impersonation,
    has_punycode,
    is_ip_host,
    is_official_domain,
    normalize_host,
    split_domain,
    tld_is_suspicious,
)
from .models import Indicator, UrlReport

_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE)
_REDIRECT_RE = re.compile(r"[?&][^=&]+=(?:https?(?::|%3a)(?:/|%2f)(?:/|%2f))", re.IGNORECASE)
_LINK_TEXT_RE = re.compile(
    r"(?i)^(?:https?://|www\.)?[a-z0-9\-]+(?:\.[a-z0-9\-]+)+(?::\d+)?(?:[/?#]\S*)?$"
)
_MAX_NORMAL_URL_LENGTH = 150
_MIN_FLAGGED_POINTS = 15


def _parse(url: str):
    """Parse a URL, adding a scheme when it is missing (www.example.com)."""
    has_scheme = bool(_SCHEME_RE.match(url))
    try:
        return urlsplit(url if has_scheme else "http://" + url), has_scheme
    except ValueError:
        return None, has_scheme


def _tokens(text: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", text.lower()) if t}


def analyze_url(url: str) -> UrlReport:
    """Run all URL rules on a single link."""
    report = UrlReport(url=url)
    split, has_scheme = _parse(url)
    if split is None:
        report.findings.append(("URL_LONG", "Link could not be parsed correctly"))
        return _finish(report)

    host = normalize_host(split.hostname or "")
    report.host = host[:MAX_HOST_LENGTH]
    if not host:
        return _finish(report)

    # A hostname longer than DNS allows is not a real address. Flag it and stop,
    # so a giant "domain" can never slow the analysis down.
    if len(host) > MAX_HOST_LENGTH:
        report.findings.append(("URL_LONG", f"Hostname is {len(host)} characters long (the limit is {MAX_HOST_LENGTH})"))
        return _finish(report)

    parts = split_domain(host)
    report.registered_domain = host if is_ip_host(host) else parts.registered
    official = (not is_ip_host(host)) and is_official_domain(parts)

    def add(rule_id: str, evidence: str) -> None:
        report.findings.append((rule_id, evidence))

    # Scheme
    if has_scheme and split.scheme.lower() == "http":
        add("URL_HTTP", "Uses http:// (no encryption)")

    # '@' trick
    if split.username is not None or "@" in split.netloc:
        add("URL_USERINFO_AT", f"Address part before '@' is ignored: {split.netloc}")

    # Non-standard port
    try:
        port = split.port
    except ValueError:
        port = None
    if port not in (None, 80, 443):
        add("URL_NONSTANDARD_PORT", f"Port {port} is used")

    # IP address instead of domain
    if is_ip_host(host):
        add("URL_IP_HOST", f"Host is {host}")
    else:
        if has_punycode(host):
            add("URL_PUNYCODE", f"Domain {host}")

        if parts.registered in URL_SHORTENERS:
            add("URL_SHORTENER", f"{parts.registered} hides the real destination")

        if tld_is_suspicious(parts):
            add("URL_SUSPICIOUS_TLD", f"Ending .{parts.suffix.split('.')[-1]}")

        if not official:
            impersonation = find_brand_impersonation(host)
            if impersonation:
                rule = "URL_BRAND_SUBDOMAIN" if impersonation["kind"] == "brand-in-subdomain" else "URL_LOOKALIKE"
                add(rule, impersonation["detail"])

            if parts.subdomain and len(parts.subdomain.split(".")) >= 3:
                add("URL_EXCESS_SUBDOMAINS", f"{len(parts.subdomain.split('.'))} subdomain levels: {host}")

            host_words = sorted(_tokens(f"{parts.subdomain}.{parts.domain}") & HOST_KEYWORDS)
            if host_words:
                add("URL_KEYWORD_HOST", f"Keywords in domain: {', '.join(host_words)}")

            if host.count("-") >= 3:
                add("URL_MANY_HYPHENS", f"{host.count('-')} hyphens in {host}")

            path_words = sorted(_tokens(f"{split.path} {split.query}") & PATH_KEYWORDS)
            if path_words:
                add("URL_KEYWORD_PATH", f"Keywords in path: {', '.join(path_words)}")

            if _REDIRECT_RE.search(url):
                add("URL_REDIRECT_PARAM", "A parameter contains another web address")

    if len(url) > _MAX_NORMAL_URL_LENGTH:
        add("URL_LONG", f"{len(url)} characters")

    return _finish(report)


def _finish(report: UrlReport) -> UrlReport:
    """Calculate the per-URL score, risk level and a readable reason."""
    report.points = min(100, sum(RULES[rule_id].points for rule_id, _ in report.findings))
    has_high = any(RULES[rule_id].severity == "high" for rule_id, _ in report.findings)

    if has_high or report.points >= 25:
        report.risk = "High"
    elif report.points >= _MIN_FLAGGED_POINTS:
        report.risk = "Medium"
    else:
        report.risk = "Low"
    report.flagged = report.risk in ("High", "Medium")

    titles = [RULES[rule_id].title for rule_id, _ in report.findings]
    if titles:
        prefix = "" if report.flagged else "Minor: "
        report.reason = prefix + "; ".join(titles)
    return report


def _shown_url(text: str) -> str | None:
    """If link text looks like a web address, return it."""
    text = (text or "").strip()
    if text and len(text) <= 200 and _LINK_TEXT_RE.match(text):
        return text
    return None


def _text_mismatch(href: str, text: str) -> str | None:
    """Detect links like <a href="http://evil.xyz">https://www.paypal.com</a>."""
    shown = _shown_url(text)
    if not shown:
        return None
    shown_split, _ = _parse(shown)
    real_split, _ = _parse(href)
    if shown_split is None or real_split is None:
        return None
    shown_host = normalize_host(shown_split.hostname or "")
    real_host = normalize_host(real_split.hostname or "")
    if not shown_host or not real_host:
        return None
    if split_domain(shown_host).registered != split_domain(real_host).registered:
        return f"Text shows '{shown_host}' but the link goes to '{real_host}'"
    return None


def analyze_urls(urls: list[str], links: list[tuple[str, str]] | None = None) -> tuple[list[UrlReport], list[Indicator]]:
    """
    Analyze all URLs of an email.

    Returns (per-URL reports, grouped indicators). Indicators are grouped by
    rule so the same problem found in five links is counted once in the score.
    """
    reports: dict[str, UrlReport] = {url: analyze_url(url) for url in urls}

    # Link text vs real destination (needs HTML anchors)
    for href, text in links or []:
        problem = _text_mismatch(href, text)
        if problem and href in reports:
            report = reports[href]
            if not any(rule == "URL_TEXT_MISMATCH" for rule, _ in report.findings):
                report.findings.append(("URL_TEXT_MISMATCH", problem))
                _finish(report)

    grouped: dict[str, list[str]] = {}
    for report in reports.values():
        for rule_id, evidence in report.findings:
            grouped.setdefault(rule_id, []).append(f"{report.url} -> {evidence}")

    indicators = [Indicator.from_rule(rule_id, evidence=items) for rule_id, items in grouped.items()]
    return list(reports.values()), indicators
