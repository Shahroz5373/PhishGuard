"""
Sender analysis: checks who the email claims to be from versus who really
sent it (display name, domain, Reply-To and SPF / DKIM / DMARC results).
"""

from __future__ import annotations

import re

from .config import BRANDS, FREE_MAIL_DOMAINS, GENERIC_ORG_WORDS
from .domain_utils import (
    brand_in_text,
    find_brand_impersonation,
    has_punycode,
    is_official_domain,
    split_domain,
    tld_is_suspicious,
)
from .models import Indicator, ParsedEmail

_EMAIL_IN_TEXT = re.compile(r"[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})")
_BAD_AUTH = {"fail", "permerror"}
_WEAK_AUTH = {"softfail"}


def analyze_sender(parsed: ParsedEmail) -> list[Indicator]:
    """Return sender-related indicators. Needs email headers to work."""
    if not parsed.sender_email or not parsed.sender_domain:
        return []

    indicators: list[Indicator] = []
    domain = parsed.sender_domain
    parts = split_domain(domain)
    registered = parts.registered
    name = parsed.sender_name

    # 1) Display name contains a different email address ("support@paypal.com" <x@evil.com>)
    shown = _EMAIL_IN_TEXT.search(name)
    if shown:
        shown_registered = split_domain(shown.group(1)).registered
        if shown_registered and shown_registered != registered:
            indicators.append(
                Indicator.from_rule(
                    "SENDER_DISPLAY_EMAIL_SPOOF",
                    evidence=[f'Display name: "{name}"', f"Real sender: {parsed.sender_email}"],
                )
            )

    # 2) Display name claims a known brand but the domain is not that brand's
    brand_claim_found = False
    claimed = brand_in_text(name)
    if claimed:
        on_free_mail = registered in FREE_MAIL_DOMAINS
        for brand in claimed:
            official = is_official_domain(parts) and any(
                registered == d or parts.domain == brand for d in BRANDS[brand]["domains"] + [f"{brand}.{parts.suffix}"]
            )
            if on_free_mail or not official:
                indicators.append(
                    Indicator.from_rule(
                        "SENDER_BRAND_MISMATCH",
                        evidence=[
                            f'Display name: "{name}"',
                            f"Claims to be: {brand}",
                            f"Actual sender domain: {registered}",
                        ],
                    )
                )
                brand_claim_found = True
                break

    # 3) Sender domain imitates a brand (paypa1-support.com)
    impersonation = find_brand_impersonation(domain)
    if impersonation:
        indicators.append(Indicator.from_rule("SENDER_LOOKALIKE_DOMAIN", evidence=[impersonation["detail"]]))

    # 4) Punycode / non-ASCII characters in the domain
    if has_punycode(domain):
        indicators.append(Indicator.from_rule("SENDER_PUNYCODE", evidence=[f"Sender domain: {domain}"]))

    # 5) High-abuse TLD
    if tld_is_suspicious(parts):
        indicators.append(Indicator.from_rule("SENDER_SUSPICIOUS_TLD", evidence=[f"Sender domain: {registered}"]))

    # 6) Official-sounding name from a free mailbox (only if no brand claim already raised)
    if not brand_claim_found and registered in FREE_MAIL_DOMAINS:
        lowered = name.lower()
        words = [w for w in GENERIC_ORG_WORDS if w in lowered]
        if words:
            indicators.append(
                Indicator.from_rule(
                    "SENDER_FREEMAIL_CORPORATE",
                    evidence=[f'Display name: "{name}"', f"Sent from: {parsed.sender_email}"],
                )
            )

    # 7) Reply-To points somewhere else
    if parsed.reply_to_domain:
        reply_registered = split_domain(parsed.reply_to_domain).registered
        if reply_registered and reply_registered != registered:
            indicators.append(
                Indicator.from_rule(
                    "SENDER_REPLY_TO_MISMATCH",
                    evidence=[f"From: {parsed.sender_email}", f"Reply-To: {parsed.reply_to_email}"],
                )
            )

    # 8) SPF / DKIM / DMARC results
    failed = {m: r for m, r in parsed.auth_results.items() if r in _BAD_AUTH}
    weak = {m: r for m, r in parsed.auth_results.items() if r in _WEAK_AUTH}
    if failed or weak:
        shown_results = {**failed, **weak}
        evidence = [f"{m.upper()}: {r}" for m, r in shown_results.items()]
        severity = "high" if failed else "medium"
        indicators.append(Indicator.from_rule("SENDER_AUTH_FAIL", evidence=evidence, severity=severity))

    return indicators
