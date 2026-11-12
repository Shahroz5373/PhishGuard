# PhishGuard Workflow

This file explains **how PhishGuard works inside**: what every file does, why it exists, and how the files talk to each other. Read it top to bottom once, then use it as a map.

---

## 1. The idea in one minute

You paste an email (or upload an `.eml` file). PhishGuard:

1. **cleans** the text (it is untrusted),
2. **parses** it into sender, subject, body, links and attachments,
3. runs **four groups of checks** (sender, content, attachments, URLs),
4. turns the findings into **one risk score (0-100)** and a verdict (`Safe`, `Suspicious`, `Phishing`),
5. shows the result with **evidence** for every finding.

**The golden rule:** PhishGuard never opens, resolves or downloads a link or attachment. Links are only read as *text*. That is what makes it safe to analyze real phishing emails.

---

## 2. Folder map

```
PhishGuard/
├── app/
│   ├── main.py                  # entry point: connects UI and backend
│   ├── ui/
│   │   ├── __init__.py          # empty, makes "ui" a package
│   │   └── ui.py                # everything the user sees (Streamlit)
│   └── backend/
│       ├── __init__.py          # public exports of the backend
│       ├── config.py            # ALL rules, points, brands, word lists, limits
│       ├── models.py            # small data containers (Indicator, ParsedEmail, UrlReport)
│       ├── security.py          # protects the tool from hostile emails
│       ├── email_parser.py      # raw text / .eml  ->  structured data
│       ├── domain_utils.py      # domain helpers + look-alike detection
│       ├── sender_analyzer.py   # checks who really sent the email
│       ├── url_analyzer.py      # checks every link
│       ├── content_analyzer.py  # checks wording + attachment names
│       ├── risk_scoring.py      # indicators -> score + verdict
│       └── detector.py          # the one function the UI calls: analyze_email()
├── tests/
│   ├── samples.py               # sample emails (phishing + legitimate)
│   ├── test_detector.py         # tests for detection logic
│   └── test_security.py         # tests for the safety layer
├── .streamlit/config.toml       # Streamlit server settings (upload limit, XSRF)
├── pytest.ini                   # tells pytest where code and tests are
├── requirements.txt             # packages to RUN the app
├── requirements-dev.txt         # packages to RUN + TEST the app
├── LICENSE
├── readme.md
└── workflow.md                  # this file
```

**Design rule:** the UI knows *nothing* about detection, and the backend knows *nothing* about Streamlit. The only bridge is one function, `analyze_email(text, settings)`, which returns a plain Python dictionary. Because of this, the backend can be tested without opening a browser.

---

## 3. What happens when you click "Analyze"

```
 you paste text
      │
      ▼
 ui.py  render_input()         reads the text box / uploaded file
      │  (button is always clickable; empty input shows a warning)
      ▼
 main.py  run_analysis()       calls the backend, catches any crash
      │
      ▼
 detector.py  analyze_email()
      │
      ├─ 1. security.sanitize_input()      remove hidden/control chars, cut huge text
      ├─ 2. email_parser.parse_email()     text -> ParsedEmail
      ├─ 3. sender_analyzer.analyze_sender()      (if "Analyze headers" is on)
      ├─ 4. content_analyzer.analyze_content()    subject + body wording
      ├─ 5. content_analyzer.analyze_attachments() attachment file names
      ├─ 6. url_analyzer.analyze_urls()           (if "Analyze URLs" is on)
      ├─ 7. risk_scoring.calculate_risk()         indicators -> score + verdict
      └─ 8. build the report dictionary
      │
      ▼
 main.py   saves the result, ui.record_scan() updates session stats
      │
      ▼
 ui.py  render_results()       gauge, verdict, indicators, URLs, headers, actions
        (every email-derived text goes through security.safe_html first)
```

The report dictionary has these keys: `score`, `verdict`, `risk_level`, `reasons`, `urls`, `headers`, `notes`, `summary`, `breakdown`.

---

## 4. The app files

### `app/main.py` - the entry point
**Why:** one small place that wires the UI to the backend.
**How:** `main()` sets up the page, draws the sidebar and input, and when *Analyze* is clicked it calls `run_analysis()`. That function runs `analyze_email()` inside a spinner. If anything crashes, a **generic** error is shown and the details go only to the server log; the email text is never echoed back into the page. The sidebar session numbers are drawn **last**, so they always include the scan that just finished.
**Run it:** `streamlit run app/main.py`

### `app/ui/ui.py` - everything visual
**Why:** keeps all Streamlit and CSS code in one file.
**How (main parts):**
- `CSS` - the theme (cards, gauge, severity bar, pills). It uses the app's own primary color so it follows light/dark mode.
- `setup_page()`, `render_header()`, `render_empty_state()`, `render_footer()` - page frame.
- `render_sidebar()` - the two toggles (*Analyze URLs*, *Analyze headers*) and a placeholder for session stats. `render_session()` fills that placeholder at the end of the run.
- `render_input()` - the paste tab, the upload tab (1 MB limit) and the *Analyze* button. The button is never disabled: Streamlit only saves typed text when the box loses focus, so a disabled button looked "stuck" after pasting.
- `record_scan()` - counts the scan, saves it to history, resets the "What to do" checklist.
- `render_results()` - gauge, verdict banner, metrics, severity bar and four tabs (Indicators, URLs, Headers, What to do).
- `_build_report()` - the downloadable `.txt` report.
- `_e()` - **the safety gate**: every value that comes from the email passes through it before being displayed (see section 7).

### `app/ui/__init__.py`
Empty file. It only makes `ui` a Python package so `from ui.ui import ...` works.

---

## 5. The backend files

### `backend/__init__.py`
**Why:** defines the backend's public face. **How:** re-exports `analyze_email` and the safe-display helpers so other code can write `from backend import analyze_email`.

### `backend/config.py` - the single place for all numbers and lists
**Why:** to tune the detector you should only edit one file, not hunt through logic. The analyzer modules contain *logic*; this file contains *knowledge*.
**What is inside:**
- `RULES` - 40 rules. Each is a `Rule(category, severity, points, title, why)`: 8 Sender, 16 URL, 9 Content, 5 Attachment, 2 Correlation.
- `CATEGORY_CAPS` - the most points one category can add (Sender 40, URL 40, Content 35, Attachment 30, Correlation 15).
- `SUSPICIOUS_AT = 30`, `PHISHING_AT = 60` - the score where each verdict starts.
- `DEFAULT_SETTINGS` - `check_urls`, `check_headers`.
- Limits: `MAX_INPUT_CHARS` (300,000), `MAX_URLS_ANALYZED` (200), `MAX_UPLOAD_BYTES` (1 MB).
- Word lists: `FREE_MAIL_DOMAINS`, `SUSPICIOUS_TLDS`, `URL_SHORTENERS`, `HOST_KEYWORDS`, `PATH_KEYWORDS`, `GENERIC_ORG_WORDS`.
- `BRANDS` - 27 commonly impersonated brands (PayPal, Microsoft, banks in Pakistan, ...) with their real domains.
- `CONTENT_PATTERNS` - the regular expressions for suspicious wording; `CONTENT_TACTICS` maps them to tactics (urgency, threat, ...).
- Attachment extension sets (executable, macro, HTML, archive, document).

### `backend/models.py` - data containers
**Why:** so every module shares the same shapes instead of passing loose dictionaries around.
**What:**
- `Indicator` - one finding (rule id, category, severity, points, title, detail, evidence). `Indicator.from_rule("URL_IP_HOST", evidence=[...])` builds one from `RULES`. Evidence is cleaned (duplicates removed, long lines cut, max 5 items). `to_dict()` is the format the UI reads.
- `ParsedEmail` - the email after parsing (sender, subject, body, urls, links, attachments, auth results).
- `UrlReport` - the result for one URL (points, risk, flagged, reason).

### `backend/security.py` - protects PhishGuard from the email
**Why:** the email you analyze is hostile by definition. See section 7 for the full threat list.
**How:**
- `sanitize_input()` - removes control characters and invisible tricks (zero-width spaces, bidi overrides), cuts text over the size limit, and returns notes for the report.
- `defang_url()` / `defang_text()` - rewrite links to a harmless form: `https://evil.com` becomes `hxxps://evil[.]com`.
- `safe_html()` - makes any text safe for the page: one line, length limited, links defanged, HTML escaped, Markdown / math / `:emoji:` characters neutralized.
- `safe_plain()` - same cleaning without HTML escaping, used for the `.txt` report.
Uses only the standard library, so it is easy to test.

### `backend/email_parser.py` - raw text to structure
**Why:** detectors need clean fields, not a blob of text.
**How:** `parse_email()` first checks if the text starts with real email headers.
- **With headers** (or an `.eml` file): `_parse_structured()` uses Python's `email` package to read From, Reply-To, Subject, plain and HTML parts, attachment names and SPF/DKIM/DMARC results.
- **Without headers** (only the body was pasted): `_parse_plain()` treats everything as the body and notes that sender checks are skipped.
- `_HTMLExtractor` turns HTML into visible text and collects every `<a href>` with its visible text (needed to catch "text says paypal.com, link goes elsewhere") plus form actions.
- `extract_urls()` finds `http(s)://` and `www.` links in text and removes trailing punctuation.
It never opens a link and never downloads anything.

### `backend/domain_utils.py` - domain knowledge in one place
**Why:** both the sender check and the URL check need the same look-alike logic, so it lives once here.
**How:**
- `split_domain()` - splits a host into subdomain / main label / suffix using `tldextract` (offline, no network request); falls back to a small built-in splitter if the package is missing.
- `is_ip_host()` - normal IPs plus decimal/hex tricks (`http://3232235777`).
- `has_punycode()` - `xn--` or non-ASCII characters (homograph attacks).
- `is_official_domain()` - is this really a known brand's domain? (`amazon.co.uk` yes, `amazon.xyz` no).
- `find_brand_impersonation()` - detects `paypa1.com` (character swaps via `leet_variants`), `paypall.com` (one-letter typo via `levenshtein`), `paypal-support.com` (brand inside a fake domain) and `paypal.com.evil.xyz` (brand in the subdomain).
- `MAX_HOST_LENGTH = 253` - a hostname longer than DNS allows is skipped, so a giant fake domain can't freeze the tool.

### `backend/sender_analyzer.py` - who really sent this?
**Why:** the sender is where most phishing lies. **How:** `analyze_sender()` needs headers and runs 8 checks: display name contains a different email address; display name claims a brand but the domain is not the brand's; sender domain is a look-alike; punycode in the domain; high-abuse TLD; official-sounding name on a free mailbox (Gmail, Outlook...); Reply-To goes to a different domain; SPF / DKIM / DMARC failed.

### `backend/url_analyzer.py` - every link, as text only
**Why:** links are the most dangerous part of a phishing email.
**How:** `analyze_url()` parses one URL and applies the URL rules (http only, `@` trick, odd port, IP host, punycode, shortener, bad TLD, brand in subdomain / look-alike, too many subdomains or hyphens, scam keywords in host or path, redirect parameter, very long link). Each URL gets points and a risk level (Low / Medium / High; Medium and High are "flagged"). `analyze_urls()` additionally compares **link text vs real destination** for HTML anchors, then groups findings by rule so the same problem in five links is scored once.

### `backend/content_analyzer.py` - wording and attachment names
**Why:** phishing uses social engineering: pressure, fear, greed.
**How:**
- `analyze_content()` runs the compiled regexes from `CONTENT_PATTERNS` over subject + body (urgency, threats, credential requests, sensitive data requests, financial lures, "click here", generic greeting). Weak words like "urgent" add few points. If 3+ different tactics appear together, a multi-tactic bonus is added. Every finding keeps the exact matched text as evidence.
- `analyze_attachments()` checks file **names only** (never opens files): executables, double extensions (`invoice.pdf.exe`), macro documents, HTML files, archives.

### `backend/risk_scoring.py` - findings to one score
**Why:** the user needs one understandable number, and the number must be explainable.
**How:** `calculate_risk()`:
1. keeps one indicator per rule,
2. adds a **correlation bonus** if strong signals come from 2 (or 3+) different areas, because independent evidence is more reliable,
3. adds points per category but never above that category's cap, so one weak area can't decide alone,
4. limits the total to 100,
5. `level_for_score()` converts it: below 30 `Safe`, 30-59 `Suspicious`, 60+ `Phishing`.
The numbers are heuristic starting points, not scientifically validated probabilities.

### `backend/detector.py` - the conductor
**Why:** the UI needs exactly one function. **How:** `analyze_email(email_text, settings)` runs the pipeline in section 3 and builds the report. Features: it respects the two toggles, caps the analyzed URLs at 200 (and tells you), adds a note when headers are missing, and returns a safe empty report for empty input.

---

## 6. The tests

### `pytest.ini` - how pytest finds your code
```ini
[pytest]
pythonpath = app tests
testpaths = tests
```
- `pythonpath = app tests` adds the `app/` and `tests/` folders to Python's import path while tests run. This is why tests can write `from backend.detector import analyze_email` (exactly like `main.py` does) and `import samples`, without installing the project as a package.
- `testpaths = tests` makes plain `pytest` look only inside `tests/`, so it never wanders into the app code.
- `pythonpath` as an ini option needs pytest 7+, which is why `requirements-dev.txt` says `pytest>=7.0`.

### `tests/samples.py` - test data
Realistic emails kept out of the test logic so the tests stay readable. Phishing samples: PayPal look-alike, Microsoft subdomain trick, IP-address link, HTML text-vs-link mismatch, `invoice.pdf.exe` attachment, failed SPF/DKIM/DMARC, body-only with shortener. Legitimate samples: personal mail, real Amazon, GitHub, newsletter, real Google alert. The legitimate ones guard against **false alarms**.

### `tests/test_detector.py` - does the detection work? (36 tests)
Grouped from small to big: **parser** (fields, body-only, HTML links, auth results, garbage) -> **domain helpers** (split, look-alikes, official domains not flagged) -> **URL rules** (IP, `@`, punycode, shortener, "https is not proof of safety") -> **content** and **attachments** -> **risk scoring** (cap at 100, category caps, fixed thresholds) -> **end to end** (phishing is detected, legitimate mail is Safe, report has every key the UI needs, toggles are respected, empty and huge input don't crash, 500 links are capped at 200).

### `tests/test_security.py` - can a hostile email hurt the tool? (17 tests)
- analyzing malicious links **never uses the network** (socket calls are blocked during the test; any attempt fails the test),
- control and hidden characters are removed and can't hide a keyword,
- links are defanged, including a link hidden inside a link,
- HTML and Markdown payloads (`<script>`, `<img onerror>`, `[x](http://...)`, `$math$`, `:emoji:`) are neutralized,
- 15 hostile inputs (giant URLs, 100,000 dots, deep HTML, null bytes, bidi tricks, ...) must finish quickly and return a valid result.

### How to run
```bash
pip install -r requirements-dev.txt
pytest -v            # run everything
pytest -k security   # only tests with "security" in the name
pytest tests/test_security.py::test_defang_url   # one test
```
How a test run flows: pytest reads `pytest.ini` -> adds `app/` and `tests/` to the path -> collects every `test_*.py` in `tests/` -> runs each `test_*` function -> a failed `assert` marks it red.

### Adding a new detection rule (example)
1. Add a `Rule(...)` to `RULES` in `config.py` (and patterns/word lists if needed).
2. Add the logic in the matching analyzer (`url_analyzer.py`, `sender_analyzer.py`, ...) using `Indicator.from_rule("YOUR_RULE", evidence=[...])`.
3. Add a sample to `tests/samples.py` and a test in `tests/test_detector.py`.
4. Run `pytest -v`. Also run it after every change to check you did not create false alarms on the legitimate samples.

---

## 7. Security design: "the email must not harm the tool"

| Threat inside the email | What protects PhishGuard | Where |
|---|---|---|
| Link that tracks you or serves malware when opened | Links are **never opened, resolved or downloaded**. `tldextract` runs offline. A test blocks the network and proves it. | whole backend, `test_security.py` |
| Link that gets clicked by accident in the results | All links are **defanged** (`hxxp://evil[.]com`), also links hidden inside links and inside evidence text | `security.py` |
| HTML / script injection into the page (XSS) | Every email-derived value goes through `safe_html()` (HTML escaped) | `ui._e()` |
| Markdown injection: fake links, tracking images `![](http://...)`, math, `:emoji:` | Special characters are turned into entities so they can't start Markdown syntax | `security.py` |
| Newlines or blank lines that break the page layout | Values are collapsed to one line and length limited | `security.py` |
| Invisible characters to hide keywords or fake a link direction | Removed before analysis; a note tells the user | `sanitize_input()` |
| Huge paste, huge file | 300,000 character limit; 1 MB upload limit (UI check + Streamlit server setting) | `config.py`, `ui.py`, `.streamlit/config.toml` |
| Giant "domain" or other input meant to freeze the tool (denial of service) | Hostnames over 253 characters are skipped; slow comparisons are length-filtered; 15 hostile inputs are tested for speed | `domain_utils.py`, `url_analyzer.py` |
| Crash that echoes the attacker's text into an error box | Generic error message; details only in the server log | `main.py` |
| Unsafe text in the downloaded report | Report values are cleaned and links defanged | `ui._build_report()` |

PhishGuard is a heuristic detector. It can miss attacks and can flag safe mail, so the footer reminds users to verify suspicious emails themselves.

---

## 8. Other files

- **`requirements.txt`** - packages needed to run: `streamlit` (the UI) and `tldextract` (domain splitting).
- **`requirements-dev.txt`** - includes `requirements.txt` plus `pytest`.
- **`.streamlit/config.toml`** - Streamlit server settings: 1 MB upload limit, XSRF protection on, usage statistics off. Streamlit reads it when you start the app from the project root.
- **`LICENSE`** - the license that tells others how they may use the code.
- **`readme.md`** - the project front page for GitHub (to be written next).
