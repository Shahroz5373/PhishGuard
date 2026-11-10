"""
Email parser: turns raw pasted text or the contents of an .eml file into
structured data (sender, subject, body, URLs, attachments, auth results).

It never opens a link and never downloads anything.
"""

from __future__ import annotations

import email
import re
from email import policy
from email.utils import parseaddr
from html.parser import HTMLParser

from .config import MAX_INPUT_CHARS
from .domain_utils import normalize_host
from .models import ParsedEmail

# Header names we accept as "this text starts with email headers"
_KNOWN_HEADERS = {
    "from", "to", "cc", "bcc", "subject", "date", "reply-to", "return-path",
    "received", "message-id", "mime-version", "content-type", "sender",
    "authentication-results", "received-spf", "dkim-signature", "delivered-to",
}

_URL_RE = re.compile(r"""(?i)\b((?:https?://|www\.)[^\s<>"'`]+)""")
_TRAILING_PUNCTUATION = ".,;:!?)]}>'\""
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_AUTH_RE = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror|policy)\b",
    re.IGNORECASE,
)
_SPF_HEADER_RE = re.compile(r"\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b", re.IGNORECASE)
_HTML_HINT_RE = re.compile(r"<\s*(html|body|a\s|div|p|table|br)\b", re.IGNORECASE)

_DISPLAY_HEADERS = ["From", "Reply-To", "Return-Path", "To", "Subject", "Date", "Message-ID"]
_MAX_HEADER_VALUE = 300


# ----------------------------------------------------------------------------
# HTML handling
# ----------------------------------------------------------------------------
class _HTMLExtractor(HTMLParser):
    """Collects visible text, <a> links (href + text) and form actions."""

    _SKIP_TAGS = {"script", "style", "head", "title"}
    _BREAK_TAGS = {"p", "br", "div", "tr", "li", "h1", "h2", "h3", "h4", "table"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text_parts: list[str] = []
        self.links: list[tuple[str, str]] = []
        self.form_actions: list[str] = []
        self._skip_depth = 0
        self._href: str | None = None
        self._anchor_text: list[str] = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in self._SKIP_TAGS:
            self._skip_depth += 1
        if tag in self._BREAK_TAGS:
            self.text_parts.append("\n")
        if tag == "a":
            self._href = attrs.get("href") or ""
            self._anchor_text = []
        if tag == "form" and attrs.get("action"):
            self.form_actions.append(attrs["action"])

    def handle_endtag(self, tag):
        if tag in self._SKIP_TAGS and self._skip_depth:
            self._skip_depth -= 1
        if tag in self._BREAK_TAGS:
            self.text_parts.append("\n")
        if tag == "a" and self._href is not None:
            self.links.append((self._href.strip(), "".join(self._anchor_text).strip()))
            self._href = None

    def handle_data(self, data):
        if self._skip_depth:
            return
        self.text_parts.append(data)
        if self._href is not None:
            self._anchor_text.append(data)


def html_to_text(html_source: str) -> tuple[str, list[tuple[str, str]], list[str]]:
    """Returns (visible text, links, form actions)."""
    parser = _HTMLExtractor()
    try:
        parser.feed(html_source)
        parser.close()
    except Exception:
        pass  # broken HTML is common in phishing, use what we collected
    text = "".join(parser.text_parts)
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    text = re.sub(r"\n\s*\n+", "\n\n", text).strip()
    return text, parser.links, parser.form_actions


# ----------------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------------
def extract_urls(text: str) -> list[str]:
    """Find http(s):// and www. links in plain text."""
    urls = []
    for match in _URL_RE.finditer(text or ""):
        url = match.group(1).rstrip(_TRAILING_PUNCTUATION)
        if url:
            urls.append(url)
    return urls


def _unique(items) -> list:
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _is_web_link(url: str) -> bool:
    return bool(re.match(r"(?i)^(https?://|www\.)", (url or "").strip()))


def _looks_like_headers(text: str) -> bool:
    first_line = text.split("\n", 1)[0]
    match = re.match(r"^([A-Za-z][A-Za-z0-9\-]*):", first_line)
    if not match:
        return False
    name = match.group(1).lower()
    return name in _KNOWN_HEADERS or name.startswith("x-")


def _header(msg, name: str) -> str:
    try:
        value = msg.get(name)
        return str(value).strip() if value else ""
    except Exception:
        return ""


def _address(header_value: str) -> tuple[str, str, str]:
    """Returns (display name, email address, domain) from a From/Reply-To value."""
    name, address = parseaddr(header_value or "")
    if not address:
        found = _EMAIL_RE.search(header_value or "")
        address = found.group(0) if found else ""
    address = address.strip().strip("<>").lower()
    domain = normalize_host(address.rpartition("@")[2]) if "@" in address else ""
    return name.strip(), address, domain


def _part_text(part) -> str:
    try:
        return str(part.get_content())
    except Exception:
        payload = part.get_payload(decode=True)
        if payload is None:
            return str(part.get_payload() or "")
        return payload.decode("utf-8", errors="replace")


def _parse_auth(msg) -> dict:
    """Read SPF / DKIM / DMARC results if the headers include them."""
    results: dict[str, str] = {}
    try:
        for value in msg.get_all("Authentication-Results") or []:
            for mechanism, result in _AUTH_RE.findall(str(value)):
                results.setdefault(mechanism.lower(), result.lower())
        for value in msg.get_all("Received-SPF") or []:
            match = _SPF_HEADER_RE.match(str(value))
            if match:
                results.setdefault("spf", match.group(1).lower())
    except Exception:
        pass
    return results


# ----------------------------------------------------------------------------
# Parsing
# ----------------------------------------------------------------------------
def _parse_plain(text: str) -> ParsedEmail:
    """Used when the text has no headers (only the message body was pasted)."""
    is_html = bool(_HTML_HINT_RE.search(text))
    links: list[tuple[str, str]] = []
    forms: list[str] = []
    body = text.strip()
    if is_html:
        body, links, forms = html_to_text(text)

    urls = extract_urls(body) + [href for href, _ in links if _is_web_link(href)] + [f for f in forms if _is_web_link(f)]
    return ParsedEmail(
        has_headers=False,
        body=body,
        urls=_unique(urls),
        links=[(h, t) for h, t in links if _is_web_link(h)],
        is_html=is_html,
    )


def _parse_structured(text: str) -> ParsedEmail:
    """Used when the text starts with email headers (also handles .eml / MIME)."""
    msg = email.message_from_string(text, policy=policy.default)

    sender_name, sender_email, sender_domain = _address(_header(msg, "From"))
    _, reply_to_email, reply_to_domain = _address(_header(msg, "Reply-To"))

    plain_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename:
            attachments.append(str(filename))
            continue
        content_type = part.get_content_type()
        if content_type == "text/plain":
            plain_parts.append(_part_text(part))
        elif content_type == "text/html":
            html_parts.append(_part_text(part))

    plain_text = "\n".join(plain_parts).strip()
    html_text, links, forms = html_to_text("\n".join(html_parts)) if html_parts else ("", [], [])
    body = plain_text or html_text

    urls = (
        extract_urls(plain_text)
        + extract_urls(html_text)
        + [href for href, _ in links if _is_web_link(href)]
        + [f for f in forms if _is_web_link(f)]
    )

    auth_results = _parse_auth(msg)
    headers = {}
    for name in _DISPLAY_HEADERS:
        value = _header(msg, name)
        if value:
            headers[name] = value[:_MAX_HEADER_VALUE]
    for mechanism in ("spf", "dkim", "dmarc"):
        if mechanism in auth_results:
            headers[mechanism.upper()] = auth_results[mechanism]

    return ParsedEmail(
        has_headers=True,
        headers=headers,
        sender_name=sender_name,
        sender_email=sender_email,
        sender_domain=sender_domain,
        reply_to_email=reply_to_email,
        reply_to_domain=reply_to_domain,
        subject=_header(msg, "Subject"),
        body=body,
        urls=_unique(urls),
        links=[(h, t) for h, t in links if _is_web_link(h)],
        attachments=attachments,
        auth_results=auth_results,
        is_html=bool(html_parts),
    )


def parse_email(raw_text: str) -> ParsedEmail:
    """
    Main entry point.

    Accepts raw pasted text or the text of an .eml file. If the text does not
    start with email headers, it is treated as a message body only.
    """
    text = (raw_text or "")[:MAX_INPUT_CHARS].replace("\r\n", "\n").replace("\r", "\n")
    text = text.lstrip("\ufeff \t\n")
    if not text.strip():
        return ParsedEmail()

    if _looks_like_headers(text):
        try:
            return _parse_structured(text)
        except Exception:
            pass  # fall back to treating it as plain text
    return _parse_plain(text)
