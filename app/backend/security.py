"""
Security layer: keeps hostile emails from harming PhishGuard itself.

An email that is being analyzed is, by definition, untrusted. It can contain
malicious links, hidden characters, HTML, Markdown or giant payloads. PhishGuard
protects itself in three ways:

1. INPUT  - `sanitize_input` cleans the raw text before anything parses it
            (control characters, invisible "trick" characters, size limit).
2. OUTPUT - `safe_html` makes any email-derived text harmless before it is put
            on the page (HTML, Markdown, math and emoji syntax can not run).
3. LINKS  - `defang_url` / `defang_text` rewrite web addresses to a harmless
            form (hxxp://evil[.]com) so nobody, and nothing, can follow them.

The analyzers never open, resolve or download a link. They only treat links as
text, and this file makes sure that text stays text when it is displayed.

This module only uses the standard library, so it is easy to test.
"""

from __future__ import annotations

import html
import re

from .config import MAX_INPUT_CHARS

# ----------------------------------------------------------------------------
# Character classes
# ----------------------------------------------------------------------------
# Control characters (except tab, newline and carriage return). Never needed in
# a real email, sometimes used to confuse parsers.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")

# Invisible characters: zero-width spaces/joiners, soft hyphen, BOM and the
# "bidirectional" overrides that can make text or a link read backwards.
# Attackers use them to split keywords ("ver\u200bify") and to disguise links.
_HIDDEN_RE = re.compile("[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")

# A web address inside free text (same idea as the parser, but standalone).
_URLISH_RE = re.compile(r"""(?i)\b(?:https?://|www\.)[^\s<>"'`]+""")

# Characters that have a special meaning in Streamlit's Markdown renderer.
# They are turned into HTML entities, which look the same on screen but can
# no longer start a link, image, emphasis, code span, math block or :emoji:.
_MARKDOWN_ENTITIES = {
    ord("*"): "&#42;",
    ord("_"): "&#95;",
    ord("`"): "&#96;",
    ord("["): "&#91;",
    ord("]"): "&#93;",
    ord("~"): "&#126;",
    ord("\\"): "&#92;",
    ord("|"): "&#124;",
    ord("$"): "&#36;",
    ord(":"): "&#58;",
}

MAX_DISPLAY_LENGTH = 2_000  # one displayed value is never longer than this


# ----------------------------------------------------------------------------
# 1) Input
# ----------------------------------------------------------------------------
def sanitize_input(raw) -> tuple[str, list[str]]:
    """
    Clean untrusted email text before analysis.

    Returns (clean_text, notes). `notes` are short messages for the report,
    for example when the text was cut or hidden characters were removed.
    Accepts str, bytes or None and never raises.
    """
    notes: list[str] = []

    if raw is None:
        return "", notes
    if isinstance(raw, (bytes, bytearray)):
        raw = bytes(raw).decode("utf-8", errors="replace")
    elif not isinstance(raw, str):
        raw = str(raw)

    if len(raw) > MAX_INPUT_CHARS:
        raw = raw[:MAX_INPUT_CHARS]
        notes.append(f"The email is very long, so only the first {MAX_INPUT_CHARS:,} characters were analyzed.")

    text, hidden = _HIDDEN_RE.subn("", raw)
    text, control = _CONTROL_RE.subn("", text)

    removed = hidden + control
    if removed:
        noun = "character was" if removed == 1 else "characters were"
        notes.append(
            f"{removed} hidden or control {noun} removed before analysis "
            "(attackers use them to hide words and disguise links)."
        )
    return text, notes


# ----------------------------------------------------------------------------
# 3) Links
# ----------------------------------------------------------------------------
def defang_url(url) -> str:
    """
    Make one web address harmless: https://evil.com/a -> hxxps://evil[.]com/a

    The result can still be read, but it is no longer a working link, so it
    can't be clicked, auto-linked by the page or opened by mistake.
    """
    text = "" if url is None else str(url)
    # Every scheme, also one hidden inside the link (?next=http://other.com)
    text = re.sub(r"(?i)(?<![a-z0-9])http(s?)(?=://|%3a)", r"hxxp\1", text)
    return text.replace(".", "[.]")


def defang_text(text) -> str:
    """Defang every web address found inside a longer piece of text."""
    return _URLISH_RE.sub(lambda match: defang_url(match.group(0)), "" if text is None else str(text))


# ----------------------------------------------------------------------------
# 2) Output
# ----------------------------------------------------------------------------
def _clean_for_display(value, max_length: int) -> str:
    text = "" if value is None else str(value)
    text = text[:max_length]
    text = _HIDDEN_RE.sub("", text)
    text = _CONTROL_RE.sub("", text)
    return " ".join(text.split())  # one line: no newlines that could break the layout


def safe_plain(value, max_length: int = MAX_DISPLAY_LENGTH) -> str:
    """Plain-text version for the downloadable report: one line, links defanged."""
    return defang_text(_clean_for_display(value, max_length))


def safe_html(value, max_length: int = MAX_DISPLAY_LENGTH) -> str:
    """
    Turn any email-derived value into text that is safe to place inside HTML.

    Steps: cut to length -> remove hidden/control characters -> single line ->
    defang links -> escape HTML -> neutralize Markdown, math and :emoji: syntax.
    """
    text = safe_plain(value, max_length)
    text = html.escape(text, quote=True)
    return text.translate(_MARKDOWN_ENTITIES)
