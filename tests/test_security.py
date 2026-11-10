"""
Security tests: a hostile email must never harm PhishGuard itself.

Run from the project root:   pytest -v
"""

import socket
import time

import pytest

from backend.detector import analyze_email
from backend.security import (
    defang_text,
    defang_url,
    safe_html,
    safe_plain,
    sanitize_input,
)

import samples


# ----------------------------------------------------------------------------
# Links are never opened
# ----------------------------------------------------------------------------
def test_analysis_never_touches_the_network(monkeypatch):
    """Analyzing an email full of malicious links must not open any connection."""

    def blocked(*args, **kwargs):
        raise AssertionError("PhishGuard tried to use the network!")

    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)

    for name in ("PHISHING_PAYPAL", "PHISHING_MICROSOFT", "PHISHING_IP_LINK", "PHISHING_HTML_MISMATCH", "PHISHING_BODY_ONLY"):
        result = analyze_email(getattr(samples, name))
        assert 0 <= result["score"] <= 100


# ----------------------------------------------------------------------------
# Input sanitizing
# ----------------------------------------------------------------------------
def test_sanitize_removes_control_and_hidden_characters():
    clean, notes = sanitize_input("ver\u200bify\x00 your\u202e account\x07")
    assert clean == "verify your account"
    assert notes and "removed" in notes[0]


def test_sanitize_keeps_normal_text_and_newlines():
    text = "Hello\n\tWorld  — ünïcode ✓"
    clean, notes = sanitize_input(text)
    assert clean == text and notes == []


def test_sanitize_accepts_odd_input_types():
    assert sanitize_input(None) == ("", [])
    assert sanitize_input(b"hello")[0] == "hello"
    assert sanitize_input(12345)[0] == "12345"
    assert sanitize_input(b"\xff\xfe broken bytes")[0]  # decoded with replacement, no crash


def test_sanitize_cuts_huge_input_and_says_so():
    clean, notes = sanitize_input("a" * 400_000)
    assert len(clean) == 300_000
    assert any("first" in n for n in notes)


def test_hidden_characters_can_not_hide_a_keyword():
    text = "From: Bank <a@bank-example.com>\nSubject: Hi\n\nPlease ver\u200bify your acc\u200bount now"
    result = analyze_email(text)
    assert any("account details" in r["title"].lower() or "click" in r["title"].lower() for r in result["reasons"])
    assert any("hidden" in n for n in result["notes"])


# ----------------------------------------------------------------------------
# Defanging
# ----------------------------------------------------------------------------
def test_defang_url():
    assert defang_url("http://evil.com/login") == "hxxp://evil[.]com/login"
    assert defang_url("https://a.b.c/x.php") == "hxxps://a[.]b[.]c/x[.]php"
    assert defang_url("www.evil.com") == "www[.]evil[.]com"
    assert defang_url(None) == ""


def test_defang_also_covers_a_link_hidden_inside_a_link():
    out = defang_url("http://good.com/r?next=http://evil.com/x&b=https%3A%2F%2Fevil2.com")
    assert "http://" not in out and "https%3A" not in out.replace("hxxps%3A", "")
    assert out.count("hxxp") == 3


def test_defang_text_only_touches_links():
    text = "Go to http://evil.com/a now. Contact support@paypal.com or visit www.evil.net."
    out = defang_text(text)
    assert "http://evil.com" not in out and "hxxp://evil[.]com/a" in out
    assert "www.evil.net" not in out
    assert "support@paypal.com" in out  # a plain email address is not a link


def test_defang_text_keeps_a_bare_scheme_readable():
    assert defang_text("Uses http:// (no encryption)") == "Uses http:// (no encryption)"


# ----------------------------------------------------------------------------
# Safe display (what goes on the page)
# ----------------------------------------------------------------------------
@pytest.mark.parametrize(
    "payload",
    [
        "<script>alert(1)</script>",
        '<img src=x onerror="alert(1)">',
        "<iframe src='http://evil.com'></iframe>",
        "javascript:alert(1)",
        '"><svg/onload=alert(1)>',
    ],
)
def test_html_payloads_are_escaped(payload):
    out = safe_html(payload)
    assert "<" not in out and ">" not in out
    assert '"' not in out and "'" not in out


def test_markdown_payloads_are_neutralized():
    out = safe_html("[Click me](http://evil.com) ![pixel](http://track.evil.com/p.png) **bold** `code` $x$ :red[hi]")
    for bad in ("[", "]", "*", "`", "$", ":"):
        assert bad not in out
    assert "http://" not in out and "evil.com" not in out.replace("[.]", "").replace("&#91;.&#93;", "") or "hxxp" in out


def test_links_are_defanged_in_display_text():
    out = safe_html("Subject: see http://evil.com/login now")
    assert "http://" not in out
    assert "hxxp" in out


def test_display_text_is_one_line_and_length_limited():
    out = safe_html("line1\n\n\nline2\r\n<b>x</b>" + "A" * 5000)
    assert "\n" not in out and "\r" not in out
    assert len(out) < 2200


def test_safe_helpers_handle_none_and_numbers():
    assert safe_html(None) == ""
    assert safe_html(42) == "42"
    assert safe_plain(None) == ""


def test_report_strings_are_defanged():
    result = analyze_email(samples.PHISHING_PAYPAL)
    flagged = [u for u in result["urls"] if u["flagged"]][0]
    assert "http://" not in safe_plain(flagged["url"])


# ----------------------------------------------------------------------------
# Hostile input must not crash or hang the analyzer
# ----------------------------------------------------------------------------
HOSTILE_INPUTS = {
    "huge url": "http://" + "a" * 250_000 + ".com/" + "b" * 40_000,
    "many dots": "http://" + "a." * 100_000 + "com",
    "many subdomains": "From: x <a@" + "b." * 5_000 + "com>\n\nhttp://" + "c." * 20_000 + "xyz",
    "many @ signs": "http://" + "u@" * 50_000 + "evil.com",
    "many hyphens": "http://" + "a-" * 50_000 + "b.com",
    "many percent": "http://evil.com/?r=" + "%2f" * 80_000,
    "repeated scheme": "http://" * 30_000,
    "deep html": "<div>" * 20_000 + "<a href='http://evil.com'>http://good.com</a>",
    "unclosed html": "<a href='http://evil.com'" * 10_000,
    "null bytes": "\x00" * 100_000 + "http://evil.com",
    "bidi tricks": "http://\u202eevil.com\u202c/" * 5_000,
    "mixed binary": bytes(range(256)).decode("latin-1") * 2_000,
    "long header": "From: " + "x" * 200_000,
    "giant sender label": "From: PayPal <a@" + "p" * 200_000 + ".com>\n\nhello",
    "many headers": "Received: a\n" * 20_000 + "\nBody",
}


@pytest.mark.parametrize("name", list(HOSTILE_INPUTS))
def test_hostile_input_finishes_quickly_and_safely(name):
    start = time.perf_counter()
    result = analyze_email(HOSTILE_INPUTS[name])
    elapsed = time.perf_counter() - start
    assert 0 <= result["score"] <= 100
    assert result["verdict"] in ("Safe", "Suspicious", "Phishing")
    assert elapsed < 10, f"{name} took {elapsed:.1f}s"
