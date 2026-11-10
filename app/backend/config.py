"""
Central place for every detection rule, weight and word list.

To tune the detector (change points, add a brand, add a phrase) you only
edit this file. The analyzer modules contain the logic, not the numbers.
"""

from __future__ import annotations

from dataclasses import dataclass


# ----------------------------------------------------------------------------
# Rules: one entry per thing the detector can report
# ----------------------------------------------------------------------------
@dataclass(frozen=True)
class Rule:
    category: str   # Sender | URL | Content | Attachment | Correlation
    severity: str   # high | medium | low (used for colors in the UI)
    points: int     # contribution to the risk score
    title: str      # short name shown in the report
    why: str        # plain-English explanation of why this matters


RULES: dict[str, Rule] = {
    # ---------------- Sender ----------------
    "SENDER_BRAND_MISMATCH": Rule(
        "Sender", "high", 25,
        "Sender name claims a known brand",
        "The display name mentions a well-known company, but the email was not sent from that company's real domain.",
    ),
    "SENDER_LOOKALIKE_DOMAIN": Rule(
        "Sender", "high", 30,
        "Sender domain imitates a known brand",
        "The sender's domain is built to look like a real company (swapped characters, typos or the brand name inside a fake domain).",
    ),
    "SENDER_DISPLAY_EMAIL_SPOOF": Rule(
        "Sender", "high", 20,
        "Display name shows a different email address",
        "The visible name contains an email address that does not match the real sender address, a common spoofing trick.",
    ),
    "SENDER_FREEMAIL_CORPORATE": Rule(
        "Sender", "medium", 12,
        "Official-sounding name sent from a free email service",
        "Real companies send security and billing emails from their own domain, not from free mailbox providers.",
    ),
    "SENDER_REPLY_TO_MISMATCH": Rule(
        "Sender", "medium", 15,
        "Reply-To goes to a different domain",
        "Replies would go to a different domain than the sender, which attackers use to capture answers.",
    ),
    "SENDER_AUTH_FAIL": Rule(
        "Sender", "high", 20,
        "Email authentication failed",
        "SPF, DKIM or DMARC checks failed, which means the sender may not be who they claim to be.",
    ),
    "SENDER_PUNYCODE": Rule(
        "Sender", "high", 20,
        "Sender domain uses lookalike characters (punycode)",
        "The domain uses special Unicode characters that can look identical to normal letters.",
    ),
    "SENDER_SUSPICIOUS_TLD": Rule(
        "Sender", "low", 5,
        "Sender domain uses a high-abuse TLD",
        "Some domain endings are cheap and heavily used for spam and phishing. This alone is a weak signal.",
    ),
    # ---------------- URL ----------------
    "URL_IP_HOST": Rule(
        "URL", "high", 25,
        "Link uses an IP address instead of a domain",
        "Legitimate companies almost never ask you to log in through a raw IP address.",
    ),
    "URL_USERINFO_AT": Rule(
        "URL", "high", 25,
        "Link contains '@' to hide the real destination",
        "Everything before the '@' is ignored by the browser, so the link can look trusted while going somewhere else.",
    ),
    "URL_LOOKALIKE": Rule(
        "URL", "high", 25,
        "Link domain imitates a known brand",
        "The link's domain uses a brand name or a look-alike spelling, but it is not the brand's real domain.",
    ),
    "URL_BRAND_SUBDOMAIN": Rule(
        "URL", "high", 25,
        "Brand name placed in the subdomain",
        "Attackers put a trusted name at the front of the address (paypal.com.evil.example) so it looks real. The real domain is the part at the end.",
    ),
    "URL_PUNYCODE": Rule(
        "URL", "high", 20,
        "Link uses lookalike characters (punycode)",
        "The domain contains Unicode characters that can imitate normal letters (homograph attack).",
    ),
    "URL_TEXT_MISMATCH": Rule(
        "URL", "high", 25,
        "Link text shows a different site than the real destination",
        "The visible text of the link names one website but the link actually opens another.",
    ),
    "URL_SHORTENER": Rule(
        "URL", "medium", 10,
        "Link uses a URL shortener",
        "Shortened links hide the real destination. PhishGuard does not open links, so the target is unknown.",
    ),
    "URL_EXCESS_SUBDOMAINS": Rule(
        "URL", "medium", 10,
        "Link has an unusually long chain of subdomains",
        "Long subdomain chains are used to push the real domain out of sight.",
    ),
    "URL_KEYWORD_HOST": Rule(
        "URL", "medium", 10,
        "Sensitive keywords inside the domain name",
        "Words like login, verify or secure inside a domain name are common in phishing sites.",
    ),
    "URL_REDIRECT_PARAM": Rule(
        "URL", "medium", 8,
        "Link contains another URL (redirect pattern)",
        "Redirect parameters can send you to a different site than the one shown first.",
    ),
    "URL_NONSTANDARD_PORT": Rule(
        "URL", "medium", 8,
        "Link uses an unusual port",
        "Normal websites use the standard web ports. Unusual ports are common on throwaway attacker servers.",
    ),
    "URL_HTTP": Rule(
        "URL", "low", 10,
        "Link does not use HTTPS",
        "The connection is not encrypted. Note that HTTPS alone does not prove a site is safe, phishing sites use it too.",
    ),
    "URL_SUSPICIOUS_TLD": Rule(
        "URL", "low", 8,
        "Link uses a high-abuse TLD",
        "Some domain endings are cheap and heavily abused. This alone is a weak signal.",
    ),
    "URL_KEYWORD_PATH": Rule(
        "URL", "low", 3,
        "Sensitive keywords in the link path",
        "Words such as login or verify in the path are normal on real sites too, so this is a weak signal.",
    ),
    "URL_MANY_HYPHENS": Rule(
        "URL", "low", 4,
        "Domain contains many hyphens",
        "Long hyphenated domains (secure-login-verify-account) are typical of throwaway phishing domains.",
    ),
    "URL_LONG": Rule(
        "URL", "low", 3,
        "Very long link",
        "Very long links can hide the real destination in the middle.",
    ),
    # ---------------- Content ----------------
    "CONTENT_URGENCY_WEAK": Rule(
        "Content", "low", 5,
        "Urgent wording",
        "Words that push you to act quickly. They also appear in normal emails, so this is a weak signal.",
    ),
    "CONTENT_URGENCY_STRONG": Rule(
        "Content", "medium", 10,
        "Time pressure",
        "Deadlines such as 'within 24 hours' are used to stop you from thinking or verifying.",
    ),
    "CONTENT_THREAT": Rule(
        "Content", "medium", 15,
        "Threat or fear language",
        "The email threatens suspension, closure or legal trouble to scare you into acting.",
    ),
    "CONTENT_CREDENTIAL": Rule(
        "Content", "high", 20,
        "Asks you to verify or enter account details",
        "Legitimate companies rarely ask you to confirm passwords or identity through an email link.",
    ),
    "CONTENT_SENSITIVE_DATA": Rule(
        "Content", "high", 20,
        "Asks you to send sensitive data",
        "The email asks for a code, PIN, card number or ID number. No real service asks for these over email.",
    ),
    "CONTENT_FINANCIAL": Rule(
        "Content", "medium", 10,
        "Financial lure or payment scare",
        "Prizes, refunds or failed payments are classic bait to make you click or pay.",
    ),
    "CONTENT_ACTION": Rule(
        "Content", "medium", 10,
        "Pushes you to click or open something",
        "Phrases like 'click here' or 'verify now' try to move you to a link before you think.",
    ),
    "CONTENT_GENERIC_GREETING": Rule(
        "Content", "low", 5,
        "Generic greeting",
        "Mass phishing often uses 'Dear customer' because the attacker does not know your name.",
    ),
    "CONTENT_MULTI_TACTIC": Rule(
        "Content", "medium", 10,
        "Several social-engineering tactics combined",
        "Urgency, threats and requests used together are far more typical of phishing than of normal mail.",
    ),
    # ---------------- Attachment ----------------
    "ATTACH_EXECUTABLE": Rule(
        "Attachment", "high", 30,
        "Executable or script attachment",
        "Programs and scripts attached to an email can install malware when opened.",
    ),
    "ATTACH_DOUBLE_EXT": Rule(
        "Attachment", "high", 25,
        "Attachment hides its real file type",
        "A name like invoice.pdf.exe pretends to be a document but is actually a program.",
    ),
    "ATTACH_MACRO": Rule(
        "Attachment", "medium", 15,
        "Office document with macros",
        "Macro-enabled documents are a common way to deliver malware.",
    ),
    "ATTACH_HTML": Rule(
        "Attachment", "medium", 12,
        "HTML attachment",
        "HTML files attached to emails are often fake login pages that run on your own computer.",
    ),
    "ATTACH_ARCHIVE": Rule(
        "Attachment", "low", 5,
        "Compressed or disk-image attachment",
        "Archives are used to hide malicious files from scanners. Common in normal mail too, so this is a weak signal.",
    ),
    # ---------------- Correlation ----------------
    "CORR_TWO_SIGNALS": Rule(
        "Correlation", "medium", 10,
        "Warning signs from two different areas",
        "Independent problems (for example sender and link) in the same email make a false alarm less likely.",
    ),
    "CORR_THREE_SIGNALS": Rule(
        "Correlation", "high", 15,
        "Warning signs from three or more areas",
        "Problems in the sender, the content and the links at the same time strongly suggest an attack.",
    ),
}

# Maximum points one category can add, so a single area cannot dominate
CATEGORY_CAPS: dict[str, int] = {
    "Sender": 40,
    "URL": 40,
    "Content": 35,
    "Attachment": 30,
    "Correlation": 15,
}

# An indicator counts as a "strong signal" for correlation when it is high severity
# or worth at least this many points
STRONG_SIGNAL_POINTS = 15

# Score where each verdict starts (one fixed setting, no user-adjustable sensitivity)
SUSPICIOUS_AT = 30   # score >= 30 -> "Suspicious"
PHISHING_AT = 60     # score >= 60 -> "Phishing"

VERDICTS = {"Low": "Safe", "Medium": "Suspicious", "High": "Phishing"}

DEFAULT_SETTINGS = {
    "check_urls": True,
    "check_headers": True,
}

MAX_INPUT_CHARS = 300_000  # protects the app from huge pastes
MAX_UPLOAD_BYTES = 1_000_000  # largest .eml / .txt file the UI accepts (1 MB)
MAX_URLS_ANALYZED = 200    # emails with thousands of links would be slow to analyze


# ----------------------------------------------------------------------------
# Domain related lists
# ----------------------------------------------------------------------------
FREE_MAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "outlook.com",
    "hotmail.com", "live.com", "msn.com", "aol.com", "icloud.com", "me.com",
    "proton.me", "protonmail.com", "mail.com", "gmx.com", "gmx.net",
    "yandex.com", "yandex.ru", "zoho.com", "rediffmail.com", "qq.com",
    "163.com", "126.com",
}

# Endings that are cheap and heavily abused (weak signal on their own)
SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "zip", "mov", "gq", "tk", "ml", "cf", "ga", "icu",
    "cyou", "rest", "buzz", "monster", "sbs", "cfd", "work", "support", "loan",
    "country", "stream", "download", "bid", "win",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "ow.ly",
    "rebrand.ly", "buff.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "s.id",
}

# Words that are suspicious inside a domain name
HOST_KEYWORDS = {
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "update", "confirm", "banking", "password", "wallet", "billing",
    "recover", "unlock", "authenticate", "validate", "webmail", "helpdesk",
    "support",
}

# Words that are only a weak signal inside a link path
PATH_KEYWORDS = {
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "password", "banking", "wallet", "validate", "recover", "unlock",
}

# Words in a display name that sound official
GENERIC_ORG_WORDS = [
    "security", "support", "billing", "service", "helpdesk", "help desk",
    "admin", "account", "accounts", "team", "notification", "alert",
    "verification", "no-reply", "noreply", "official",
]


# ----------------------------------------------------------------------------
# Known brands (commonly impersonated)
#   key      -> main name used in look-alike domain checks
#   names    -> words to look for in an email display name
#   domains  -> the brand's real registered domains
# ----------------------------------------------------------------------------
BRANDS: dict[str, dict] = {
    "paypal": {"names": ["paypal"], "domains": ["paypal.com", "paypal.me"]},
    "microsoft": {
        "names": ["microsoft", "office 365", "office365", "outlook", "onedrive", "sharepoint", "xbox"],
        "domains": [
            "microsoft.com", "office.com", "office365.com", "outlook.com", "live.com",
            "microsoftonline.com", "msn.com", "hotmail.com", "windows.com", "skype.com",
            "xbox.com", "sharepoint.com", "onedrive.com", "bing.com", "azure.com",
            "microsoft365.com",
        ],
    },
    "google": {
        "names": ["google", "gmail", "youtube"],
        "domains": ["google.com", "gmail.com", "googlemail.com", "youtube.com", "withgoogle.com"],
    },
    "apple": {"names": ["apple", "icloud", "itunes", "app store"], "domains": ["apple.com", "icloud.com", "me.com"]},
    "amazon": {
        "names": ["amazon", "aws"],
        "domains": ["amazon.com", "amazonaws.com", "amazonses.com", "aws.com"],
    },
    "facebook": {
        "names": ["facebook", "messenger"],
        "domains": ["facebook.com", "fb.com", "facebookmail.com", "meta.com", "messenger.com"],
    },
    "instagram": {"names": ["instagram"], "domains": ["instagram.com"]},
    "whatsapp": {"names": ["whatsapp"], "domains": ["whatsapp.com", "whatsapp.net"]},
    "netflix": {"names": ["netflix"], "domains": ["netflix.com", "nflxso.net"]},
    "linkedin": {"names": ["linkedin"], "domains": ["linkedin.com", "licdn.com"]},
    "github": {"names": ["github"], "domains": ["github.com", "githubusercontent.com", "github.io"]},
    "upwork": {"names": ["upwork"], "domains": ["upwork.com"]},
    "dropbox": {"names": ["dropbox"], "domains": ["dropbox.com", "dropboxmail.com"]},
    "docusign": {"names": ["docusign"], "domains": ["docusign.com", "docusign.net"]},
    "adobe": {"names": ["adobe"], "domains": ["adobe.com"]},
    "dhl": {"names": ["dhl"], "domains": ["dhl.com", "dhl.de"]},
    "fedex": {"names": ["fedex"], "domains": ["fedex.com"]},
    "ups": {"names": ["ups"], "domains": ["ups.com"]},
    "usps": {"names": ["usps"], "domains": ["usps.com"]},
    "binance": {"names": ["binance"], "domains": ["binance.com"]},
    "coinbase": {"names": ["coinbase"], "domains": ["coinbase.com"]},
    # Pakistan (commonly targeted locally)
    "jazzcash": {"names": ["jazzcash", "jazz cash"], "domains": ["jazzcash.com.pk"]},
    "easypaisa": {"names": ["easypaisa", "easy paisa"], "domains": ["easypaisa.com.pk", "telenor.com.pk"]},
    "hbl": {"names": ["hbl"], "domains": ["hbl.com"]},
    "ubl": {"names": ["ubl"], "domains": ["ubl.com.pk"]},
    "meezan": {"names": ["meezan"], "domains": ["meezanbank.com"]},
    "nadra": {"names": ["nadra"], "domains": ["nadra.gov.pk"]},
}


# ----------------------------------------------------------------------------
# Email content patterns (all case-insensitive)
# ----------------------------------------------------------------------------
CONTENT_PATTERNS: dict[str, list[str]] = {
    "CONTENT_URGENCY_WEAK": [
        r"\burgent(?:ly)?\b",
        r"\bimmediate(?:ly)?\b",
        r"\basap\b",
        r"\bright away\b",
        r"\bact now\b",
        r"\bwithout delay\b",
        r"\bimportant notice\b",
    ],
    "CONTENT_URGENCY_STRONG": [
        r"\bwithin (?:the next )?\d+\s*(?:hours?|hrs?|minutes?|mins?|days?)\b",
        r"\b(?:expires?|expiring|expiry)\s+(?:today|tonight|soon|in\s+\d+)",
        r"\bfinal (?:notice|warning|reminder)\b",
        r"\blast (?:chance|warning)\b",
        r"\b(?:verify|confirm|update)\s+(?:immediately|within)\b",
        r"\b(?:respond|reply|act)\s+within\b",
        r"\bbefore it(?:'|’)?s too late\b",
    ],
    "CONTENT_THREAT": [
        r"\b(?:account|access|card|service|mailbox|profile|wallet)\s+(?:has been|have been|will be|is being|is|was|may be|could be|might be|are)\s+(?:temporarily\s+|permanently\s+)?(?:suspended|blocked|locked|limited|disabled|terminated|closed|deactivated|restricted|deleted)\b",
        r"\b(?:permanently|temporarily)\s+(?:suspended|blocked|locked|disabled|closed|deleted)\b",
        r"\b(?:unauthori[sz]ed|unusual|suspicious)\s+(?:login|sign-?in|access|activity|transaction|attempt)s?\b",
        r"\blegal action\b",
        r"\b(?:avoid|prevent)\s+(?:account\s+)?(?:suspension|closure|termination|penalt(?:y|ies)|deactivation)\b",
        r"\bwill be (?:reported|terminated|deleted|cancelled|canceled)\b",
    ],
    "CONTENT_CREDENTIAL": [
        r"\b(?:verify|confirm|update|validate|re-?enter|provide|enter|submit)\s+(?:your|the)\s+(?:account\s+)?(?:password|credentials|login|log-?in details|identity|account (?:details|information)|personal (?:details|information)|billing (?:details|information)|payment (?:details|information|method)|card (?:number|details|information)|bank (?:details|information))\b",
        r"\b(?:verify|confirm|validate|reactivate|restore|unlock)\s+your\s+account\b",
        r"\b(?:log ?in|sign ?in)\s+(?:to|and)\s+(?:verify|confirm|secure|restore|unlock|validate|update)\b",
        r"\b(?:reset|change)\s+your\s+password\s+(?:now|immediately|here)\b",
    ],
    "CONTENT_SENSITIVE_DATA": [
        r"\b(?:share|send|provide|enter|reply with|give|submit|confirm)\s+(?:us\s+|me\s+)?(?:your\s+)?(?:otp|one[- ]time (?:password|passcode|code)|pin(?: code)?|cvv|cvc|security code|social security number|ssn|cnic|card number|credit card (?:number|details)|bank account number|passport number)\b",
    ],
    "CONTENT_FINANCIAL": [
        r"\byou(?:['’]ve| have)?\s+(?:been selected|won|are a winner)\b",
        r"\b(?:lottery|jackpot|unclaimed (?:funds|prize|package))\b",
        r"\bclaim your (?:prize|reward|refund|gift|winnings|funds)\b",
        r"\bpayment (?:has |was )?(?:failed|declined|unsuccessful|rejected)\b",
        r"\b(?:gift cards?|wire transfer|western union|bitcoin)\b",
        r"\b(?:refund|reimbursement)\s+(?:of|for|is)\b",
        r"\binheritance\b",
        r"\b(?:overdue|outstanding)\s+(?:invoice|payment|balance)\b",
    ],
    "CONTENT_ACTION": [
        r"\bclick (?:here|the link|below|on the link|the button|this link)\b",
        r"\b(?:follow|use|open|visit) (?:this|the|the following) link\b",
        r"\b(?:verify|confirm|log ?in|sign ?in|update|secure|restore|unlock|validate)\s+(?:your account\s+|it\s+)?(?:now|immediately|today)\b",
        r"\b(?:open|download|view) the attach(?:ed|ment)\b",
        r"\benable (?:macros|content|editing)\b",
        r"\bscan (?:the|this) qr code\b",
    ],
    "CONTENT_GENERIC_GREETING": [
        r"^\s*(?:dear|hello|hi)\s+(?:valued\s+)?(?:customer|user|member|client|account\s*holder|sir\s*/\s*madam|sir or madam|friend|email user|beneficiary)\b",
    ],
}

# Which "tactic" each content rule represents (used for the multi-tactic bonus)
CONTENT_TACTICS: dict[str, str] = {
    "CONTENT_URGENCY_WEAK": "urgency",
    "CONTENT_URGENCY_STRONG": "urgency",
    "CONTENT_THREAT": "threat",
    "CONTENT_CREDENTIAL": "credential request",
    "CONTENT_SENSITIVE_DATA": "credential request",
    "CONTENT_FINANCIAL": "financial lure",
    "CONTENT_ACTION": "action pressure",
}
MULTI_TACTIC_MIN = 3


# ----------------------------------------------------------------------------
# Attachment extensions
# ----------------------------------------------------------------------------
EXECUTABLE_EXT = {
    "exe", "scr", "bat", "cmd", "com", "pif", "js", "jse", "vbs", "vbe", "wsf",
    "jar", "msi", "ps1", "hta", "lnk", "reg", "dll",
}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xlsb"}
HTML_EXT = {"html", "htm", "shtml", "svg"}
ARCHIVE_EXT = {"zip", "rar", "7z", "iso", "img", "gz", "tar"}
DOCUMENT_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "txt", "zip"}
