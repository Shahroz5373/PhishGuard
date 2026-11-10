"""
Helpers for working with domain names.

Used by both the sender analyzer and the URL analyzer, so the look-alike
and brand-impersonation logic exists in only one place.

Nothing here touches the network. tldextract is used with its bundled
public-suffix snapshot, so no request is ever made.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from .config import BRANDS, HOST_KEYWORDS, SUSPICIOUS_TLDS

# ---- tldextract (offline), with a simple fallback if it is not installed ----
try:
    import tldextract

    try:
        _EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
    except TypeError:
        _EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())
except Exception:  # pragma: no cover - only used when tldextract is missing
    _EXTRACTOR = None

# Used only by the fallback splitter
_TWO_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.in", "net.in",
    "com.pk", "net.pk", "org.pk", "gov.pk", "edu.pk", "com.br", "co.jp", "co.za",
    "com.tr", "com.sa", "com.ae", "com.bd", "com.eg", "co.nz", "com.sg",
}


@dataclass(frozen=True)
class DomainParts:
    subdomain: str
    domain: str       # the main label, e.g. "paypal"
    suffix: str       # e.g. "com" or "co.uk"

    @property
    def registered(self) -> str:
        """The domain a person can actually own, e.g. paypal.com"""
        if self.domain and self.suffix:
            return f"{self.domain}.{self.suffix}"
        return self.domain


# DNS never allows a hostname longer than 253 characters (or a label over 63).
# Anything longer is not a real host, and comparing it against every brand name
# would be slow, so it is skipped. This stops "giant domain" denial-of-service tricks.
MAX_HOST_LENGTH = 253


def normalize_host(host: str) -> str:
    return (host or "").strip().lower().rstrip(".")


def split_domain(host: str) -> DomainParts:
    """Split a hostname into subdomain, main label and suffix."""
    host = normalize_host(host)
    if not host:
        return DomainParts("", "", "")

    if _EXTRACTOR is not None:
        try:
            result = _EXTRACTOR(host)
            return DomainParts(result.subdomain, result.domain, result.suffix)
        except Exception:
            pass  # fall through to the simple splitter

    labels = host.split(".")
    if len(labels) == 1:
        return DomainParts("", labels[0], "")
    suffix_len = 2 if ".".join(labels[-2:]) in _TWO_PART_SUFFIXES and len(labels) >= 3 else 1
    suffix = ".".join(labels[-suffix_len:])
    domain = labels[-suffix_len - 1]
    subdomain = ".".join(labels[: -suffix_len - 1])
    return DomainParts(subdomain, domain, suffix)


def is_ip_host(host: str) -> bool:
    """True for normal IPs and for common obfuscated forms (decimal / hex)."""
    host = normalize_host(host)
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return bool(re.fullmatch(r"\d{8,10}", host) or re.fullmatch(r"0x[0-9a-f]{6,8}", host))


def has_punycode(host: str) -> bool:
    host = normalize_host(host)
    return any(label.startswith("xn--") for label in host.split(".")) or any(ord(c) > 127 for c in host)


def tld_is_suspicious(parts: DomainParts) -> bool:
    return bool(parts.suffix) and parts.suffix.split(".")[-1] in SUSPICIOUS_TLDS


# ----------------------------------------------------------------------------
# Brand knowledge
# ----------------------------------------------------------------------------
_OFFICIAL_DOMAINS: set[str] = {d for brand in BRANDS.values() for d in brand["domains"]}


def is_official_domain(parts: DomainParts) -> bool:
    """
    True if the domain belongs to a known brand.

    Either it is on the brand's official list, or its main label is exactly the
    brand name with a normal ending (amazon.co.uk, google.com.pk). A high-abuse
    ending such as amazon.xyz is NOT treated as official.
    """
    if parts.registered in _OFFICIAL_DOMAINS:
        return True
    if parts.domain in BRANDS and not tld_is_suspicious(parts):
        return True
    return False


def brand_in_text(text: str) -> list[str]:
    """Return brand keys whose name appears as a whole word in the text."""
    lowered = (text or "").lower()
    found = []
    for key, brand in BRANDS.items():
        for name in brand["names"]:
            if re.search(rf"(?<![a-z0-9]){re.escape(name)}(?![a-z0-9])", lowered):
                found.append(key)
                break
    return found


# ----------------------------------------------------------------------------
# Look-alike detection
# ----------------------------------------------------------------------------
_LEET = str.maketrans({"0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def leet_variants(label: str) -> set[str]:
    """
    Undo common character swaps (paypa1 -> paypal, g00gle -> google).
    The digit 1 can stand for 'l' or 'i', so both versions are returned.
    """
    label = label.lower()
    base = label.translate(_LEET).replace("rn", "m").replace("vv", "w")
    return {base.replace("1", "l"), base.replace("1", "i")}


def levenshtein(a: str, b: str) -> int:
    """Number of single-character edits needed to turn a into b."""
    if a == b:
        return 0
    if not a or not b:
        return max(len(a), len(b))
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def _brand_names(key: str) -> set[str]:
    names = {key}
    for name in BRANDS[key]["names"]:
        names.add(name.replace(" ", ""))
    return names


def _split_tokens(text: str) -> list[str]:
    return [t for t in re.split(r"[-_.]", text) if t]


def _match_label(label: str, name: str) -> str | None:
    """Compare one domain label with one brand name. Returns the kind of match."""
    tokens = _split_tokens(label)
    long_name = len(name) >= 6

    # 1) Character-swap tricks: paypa1, micr0soft, rn -> m
    for variant in leet_variants(label):
        if variant == label:
            continue
        v_tokens = _split_tokens(variant)
        if variant == name or name in v_tokens or (long_name and name in variant):
            return "lookalike"

    # 2) Typos: paypall, gooogle (only for longer names to avoid false alarms).
    #    One edit changes the length by at most 1, so other lengths are skipped
    #    without running the (slow) comparison.
    if long_name:
        for token in tokens:
            if token != name and abs(len(token) - len(name)) <= 1 and levenshtein(token, name) == 1:
                return "lookalike"

    # 3) Brand name placed inside an unrelated domain: paypal-support
    if label == name or name in tokens:
        return "brand-in-domain"
    # Joined without a hyphen (paypalverify). Only counted when the rest of the
    # label contains a scam-style keyword, so names like "amazonas" are not flagged.
    if long_name and name in label:
        rest = label.replace(name, "")
        if any(word in rest for word in HOST_KEYWORDS):
            return "brand-in-domain"
    return None


def find_brand_impersonation(host: str) -> dict | None:
    """
    Check whether a hostname imitates a known brand.

    Returns {"brand", "kind", "detail"} or None. kind is one of
    "lookalike", "brand-in-domain" or "brand-in-subdomain".
    """
    if len(normalize_host(host)) > MAX_HOST_LENGTH:
        return None  # not a valid hostname, see MAX_HOST_LENGTH

    parts = split_domain(host)
    if not parts.domain or is_official_domain(parts):
        return None

    for key in BRANDS:
        for name in _brand_names(key):
            kind = _match_label(parts.domain, name)
            if kind == "lookalike":
                return {
                    "brand": key,
                    "kind": kind,
                    "detail": f"'{parts.registered}' looks like '{key}' (character swap or typo) but is not an official {key} domain.",
                }
            if kind == "brand-in-domain":
                return {
                    "brand": key,
                    "kind": kind,
                    "detail": f"'{parts.registered}' contains the brand name '{key}' but is not an official {key} domain.",
                }

    sub_tokens = _split_tokens(parts.subdomain)
    for key in BRANDS:
        for name in _brand_names(key):
            if name in sub_tokens or (len(name) >= 6 and any(name in t for t in sub_tokens)):
                return {
                    "brand": key,
                    "kind": "brand-in-subdomain",
                    "detail": f"'{normalize_host(host)}' shows '{key}' at the front, but the real domain is '{parts.registered}'.",
                }
    return None
