"""
Tests for the PhishGuard backend.

Run from the project root:   pytest -v
"""

from backend.content_analyzer import analyze_attachments, analyze_content
from backend.detector import analyze_email
from backend.domain_utils import find_brand_impersonation, is_ip_host, levenshtein, split_domain
from backend.email_parser import parse_email
from backend.risk_scoring import calculate_risk, level_for_score
from backend.models import Indicator
from backend.url_analyzer import analyze_url

import samples


def rule_ids(result):
    """Titles are stable enough to check, but ids are clearer: rebuild from titles."""
    return {r["title"] for r in result["reasons"]}


# ----------------------------------------------------------------------------
# Parser
# ----------------------------------------------------------------------------
def test_parser_extracts_fields():
    parsed = parse_email(samples.PHISHING_PAYPAL)
    assert parsed.has_headers
    assert parsed.sender_name == "PayPal Security"
    assert parsed.sender_email == "security@paypa1-support.com"
    assert parsed.sender_domain == "paypa1-support.com"
    assert parsed.subject.startswith("URGENT")
    assert parsed.urls == ["http://paypa1-support.com/verify-login"]


def test_parser_body_only_text():
    parsed = parse_email(samples.PHISHING_BODY_ONLY)
    assert not parsed.has_headers
    assert parsed.urls == ["http://bit.ly/3xYz12"]


def test_parser_html_links_and_attachments():
    parsed = parse_email(samples.PHISHING_HTML_MISMATCH)
    assert parsed.is_html
    assert ("http://hbl-secure.xyz/login", "https://www.hbl.com") in parsed.links
    parsed = parse_email(samples.PHISHING_EXE_ATTACHMENT)
    assert parsed.attachments == ["invoice.pdf.exe"]


def test_parser_auth_results():
    parsed = parse_email(samples.PHISHING_AUTH_FAIL)
    assert parsed.auth_results["spf"] == "fail"
    assert parsed.auth_results["dmarc"] == "fail"


def test_parser_handles_empty_and_garbage():
    assert parse_email("").body == ""
    assert parse_email(None).body == ""
    assert parse_email("\x00\x01 ???").has_headers is False


# ----------------------------------------------------------------------------
# Domain helpers
# ----------------------------------------------------------------------------
def test_domain_split():
    parts = split_domain("accounts.google.com")
    assert parts.registered == "google.com"
    assert split_domain("mail.ucp.edu.pk").registered == "ucp.edu.pk"


def test_levenshtein_and_ip():
    assert levenshtein("paypal", "paypall") == 1
    assert is_ip_host("192.168.1.1") and is_ip_host("3232235777")
    assert not is_ip_host("example.com")


def test_brand_impersonation_detection():
    assert find_brand_impersonation("paypa1-support.com")["kind"] == "lookalike"
    assert find_brand_impersonation("gooogle.com")["kind"] == "lookalike"
    assert find_brand_impersonation("google.com.security-check.example")["kind"] == "brand-in-subdomain"
    assert find_brand_impersonation("paypal-support.com")["kind"] == "brand-in-domain"
    assert find_brand_impersonation("amazon.xyz") is not None


def test_official_domains_are_not_flagged():
    for host in ["accounts.google.com", "www.paypal.com", "amazon.co.uk", "mail.hbl.com", "ucp.edu.pk", "amazonas.org"]:
        assert find_brand_impersonation(host) is None, host


# ----------------------------------------------------------------------------
# URL analyzer
# ----------------------------------------------------------------------------
def findings(url):
    return {rule for rule, _ in analyze_url(url).findings}


def test_url_ip_address():
    assert "URL_IP_HOST" in findings("http://192.168.1.1/login")


def test_url_userinfo_trick():
    assert "URL_USERINFO_AT" in findings("https://trusted.com@evil.example/login")


def test_url_punycode_and_shortener_and_port():
    assert "URL_PUNYCODE" in findings("https://xn--pypal-4ve.com/login")
    assert "URL_SHORTENER" in findings("https://bit.ly/abc123")
    assert "URL_NONSTANDARD_PORT" in findings("https://example.com:8443/login")


def test_url_excessive_subdomains_and_keywords():
    result = findings("https://a.b.c.d.example.com/")
    assert "URL_EXCESS_SUBDOMAINS" in result
    assert "URL_KEYWORD_HOST" in findings("https://secure-login.example.xyz/")


def test_url_http_alone_is_not_flagged():
    report = analyze_url("http://techweekly.org/issues/42")
    assert {r for r, _ in report.findings} == {"URL_HTTP"}
    assert not report.flagged


def test_url_https_is_not_proof_of_safety():
    report = analyze_url("https://paypa1-secure.xyz/login")
    assert report.flagged and report.risk == "High"


def test_url_official_domain_is_clean():
    report = analyze_url("https://accounts.google.com/AccountChooser")
    assert report.findings == [] and not report.flagged


def test_url_without_scheme():
    report = analyze_url("www.paypa1-login.com/verify")
    assert report.flagged


# ----------------------------------------------------------------------------
# Content analyzer
# ----------------------------------------------------------------------------
def test_content_detects_categories():
    ids = {i.rule_id for i in analyze_content("URGENT", "Your account will be suspended. Verify your password within 24 hours. Click here.")}
    assert {"CONTENT_THREAT", "CONTENT_URGENCY_STRONG", "CONTENT_ACTION"} <= ids


def test_content_weak_word_alone_is_low():
    result = analyze_content("", "Please reply immediately when you can.")
    assert [i.rule_id for i in result] == ["CONTENT_URGENCY_WEAK"]
    assert result[0].severity == "low" and result[0].points <= 5


def test_content_keeps_evidence():
    result = analyze_content("", "Verify your identity within 24 hours.")
    evidence = " ".join(" ".join(i.evidence) for i in result).lower()
    assert "verify your identity" in evidence and "within 24 hours" in evidence


def test_content_clean_text_has_no_findings():
    assert analyze_content("Lunch", "Are we still meeting for lunch tomorrow at one?") == []


def test_attachments():
    ids = {i.rule_id for i in analyze_attachments(["invoice.pdf.exe", "setup.exe", "report.xlsm", "a.html", "photos.zip", "notes.pdf"])}
    assert ids == {"ATTACH_DOUBLE_EXT", "ATTACH_EXECUTABLE", "ATTACH_MACRO", "ATTACH_HTML", "ATTACH_ARCHIVE"}
    assert analyze_attachments(["notes.pdf", "photo.jpg"]) == []


# ----------------------------------------------------------------------------
# Risk scoring
# ----------------------------------------------------------------------------
def test_score_is_capped_at_100():
    many = [Indicator.from_rule(r) for r in ["SENDER_LOOKALIKE_DOMAIN", "SENDER_BRAND_MISMATCH", "URL_IP_HOST", "URL_LOOKALIKE", "CONTENT_CREDENTIAL", "CONTENT_THREAT", "ATTACH_EXECUTABLE"]]
    assert calculate_risk(many).score <= 100


def test_category_cap_limits_one_area():
    only_urls = [Indicator.from_rule(r) for r in ["URL_IP_HOST", "URL_LOOKALIKE", "URL_PUNYCODE", "URL_USERINFO_AT"]]
    assert calculate_risk(only_urls).breakdown["URL"] == 40


def test_verdict_thresholds_are_fixed():
    assert level_for_score(0) == "Low"
    assert level_for_score(29) == "Low"
    assert level_for_score(30) == "Medium"
    assert level_for_score(59) == "Medium"
    assert level_for_score(60) == "High"
    assert level_for_score(100) == "High"


def test_verdict_follows_the_score():
    weak = [Indicator.from_rule("CONTENT_THREAT"), Indicator.from_rule("CONTENT_ACTION")]  # 25 points
    assert calculate_risk(weak).verdict == "Safe"
    strong = [Indicator.from_rule("SENDER_LOOKALIKE_DOMAIN"), Indicator.from_rule("URL_IP_HOST")]  # 55 + bonus
    assert calculate_risk(strong).verdict in ("Suspicious", "Phishing")


# ----------------------------------------------------------------------------
# End to end
# ----------------------------------------------------------------------------
def test_phishing_emails_are_detected():
    for name in ["PHISHING_PAYPAL", "PHISHING_MICROSOFT", "PHISHING_IP_LINK", "PHISHING_HTML_MISMATCH", "PHISHING_EXE_ATTACHMENT", "PHISHING_AUTH_FAIL", "PHISHING_BODY_ONLY"]:
        result = analyze_email(getattr(samples, name))
        assert result["verdict"] in ("Suspicious", "Phishing"), (name, result["score"])


def test_obvious_phishing_is_high():
    for name in ["PHISHING_PAYPAL", "PHISHING_MICROSOFT", "PHISHING_IP_LINK", "PHISHING_HTML_MISMATCH"]:
        assert analyze_email(getattr(samples, name))["verdict"] == "Phishing", name


def test_legitimate_emails_are_safe():
    for name in ["LEGIT_PERSONAL", "LEGIT_AMAZON", "LEGIT_GITHUB", "LEGIT_NEWSLETTER", "LEGIT_GOOGLE_ACCOUNT"]:
        result = analyze_email(getattr(samples, name))
        assert result["verdict"] == "Safe", (name, result["score"], [r["title"] for r in result["reasons"]])


def test_html_text_mismatch_is_reported():
    result = analyze_email(samples.PHISHING_HTML_MISMATCH)
    assert "Link text shows a different site than the real destination" in rule_ids(result)


def test_report_has_what_the_ui_needs():
    result = analyze_email(samples.PHISHING_PAYPAL)
    for key in ("score", "verdict", "risk_level", "reasons", "urls", "headers", "notes", "summary"):
        assert key in result
    assert 0 <= result["score"] <= 100
    reason = result["reasons"][0]
    for key in ("title", "detail", "severity", "category", "evidence"):
        assert key in reason
    assert result["urls"][0]["flagged"] is True
    assert result["headers"]["From"].startswith("PayPal")


def test_settings_are_respected():
    full = analyze_email(samples.PHISHING_PAYPAL)
    no_urls = analyze_email(samples.PHISHING_PAYPAL, {"check_urls": False})
    no_headers = analyze_email(samples.PHISHING_PAYPAL, {"check_headers": False})
    assert not any(r["category"] == "URL" for r in no_urls["reasons"])
    assert not any(r["category"] == "Sender" for r in no_headers["reasons"])
    assert full["score"] >= no_urls["score"]


def test_body_only_email_notes_missing_headers():
    result = analyze_email(samples.PHISHING_BODY_ONLY)
    assert any("headers" in note.lower() for note in result["notes"])


def test_empty_input_is_safe_and_does_not_crash():
    for text in ["", "   \n  ", None]:
        result = analyze_email(text)
        assert result["score"] == 0 and result["verdict"] == "Safe"


def test_huge_input_does_not_crash():
    result = analyze_email("Hello there " * 200_000)
    assert 0 <= result["score"] <= 100


def test_many_urls_are_capped_and_noted():
    text = "\n".join(f"http://a{i}.example.com/page" for i in range(500))
    result = analyze_email(text)
    assert len(result["urls"]) == 200
    assert any("500 links" in note for note in result["notes"])
