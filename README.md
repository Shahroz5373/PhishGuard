# 🛡️ PhishGuard
### Email Phishing Detection & Safe Analysis Tool

PhishGuard is a Python + Streamlit project that helps users inspect suspicious emails without opening dangerous links or attachments. Paste an email or upload an `.eml` file, run the analysis, and review a risk score, verdict, and evidence-backed findings.

> **Safety first:** PhishGuard analyzes links and attachment names as text. It does **not** open, resolve, or download links—or open attachments.

---


## 🎬 Project Demo

<p align="center">
  <img src="assets/PhishGuard_Demo.gif" alt="PhishGuard Demo" width="800">
</p>

---

## ✨ Features

- **Email input:** Paste raw email text or upload an `.eml` file (up to 1 MB).
- **Sender analysis:** Checks display-name mismatches, brand impersonation, look-alike domains, punycode, suspicious TLDs, Reply-To mismatches, and SPF/DKIM/DMARC results when headers are available.
- **URL analysis:** Inspects URL structure for IP-based hosts, URL shorteners, unusual ports, `@` tricks, punycode, suspicious keywords, redirect parameters, and brand look-alikes.
- **Content analysis:** Detects social-engineering signals such as urgency, threats, credential requests, and financial lures.
- **Attachment-name checks:** Flags risky extensions, double extensions (for example, `invoice.pdf.exe`), macro-enabled documents, HTML files, and archives—by filename only.
- **Explainable risk score:** Combines findings into a score from **0–100**, with a verdict and supporting evidence.
- **Correlation bonus & category caps:** Multiple independent signal categories can increase risk; category caps help prevent one category from dominating.
- **Defanged indicators:** Links are displayed in a safer, non-clickable form.
- **Defensive input handling:** Sanitization, size limits, safe rendering, and generic error messages help protect the app from hostile input.
- **Test suite:** Automated parser, detection, end-to-end, and security tests.

## 🧭 How It Works

```text
Paste email / upload .eml
          │
          ▼
   Input sanitization
          │
          ▼
     Email parser
          │
          ├── Sender/header checks (optional)
          ├── Content & social-engineering checks
          ├── Attachment filename checks
          └── URL checks (optional)
          │
          ▼
  Indicators + evidence
          │
          ▼
  Risk scoring (0–100)
          │
          ▼
 Safe / Suspicious / Phishing
          │
          ▼
 Results dashboard + report
```

### Verdict thresholds

| Score | Verdict |
|---:|---|
| `0–29` | 🟢 Safe |
| `30–59` | 🟠 Suspicious |
| `60–100` | 🔴 Phishing |

**Important:** These are heuristic thresholds—not probabilities or a guarantee that an email is safe. Always verify suspicious messages through a trusted channel.

## 🖥️ Tech Stack

- **Python** — detection logic and backend
- **Streamlit** — interactive web UI
- **tldextract** — offline domain parsing
- **pytest** — automated testing

## 📁 Project Structure

```text
PhishGuard/
├── app/
│   ├── main.py
│   ├── ui/
│   │   ├── __init__.py
│   │   └── ui.py
│   └── backend/
│       ├── __init__.py
│       ├── config.py
│       ├── models.py
│       ├── security.py
│       ├── email_parser.py
│       ├── domain_utils.py
│       ├── sender_analyzer.py
│       ├── url_analyzer.py
│       ├── content_analyzer.py
│       ├── risk_scoring.py
│       └── detector.py
├── tests/
│   ├── samples.py
│   ├── test_detector.py
│   └── test_security.py
├── .streamlit/config.toml
├── requirements.txt
├── requirements-dev.txt
├── pytest.ini
├── LICENSE
├── readme.md
└── workflow.md
```

## 🚀 Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/PhishGuard.git
cd PhishGuard
```

### 2. Create and activate a virtual environment

**Linux / macOS**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows**
```powershell
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install dependencies

Run the app:
```bash
pip install -r requirements.txt
```

Install development dependencies (includes pytest):
```bash
pip install -r requirements-dev.txt
```

### 4. Launch PhishGuard

Run from the project root:

```bash
streamlit run app/main.py
```

Your browser should open the local Streamlit app.

## 🧪 Run Tests

```bash
pytest -v
```

Run security-focused tests:
```bash
pytest -k security
```

Run one test:
```bash
pytest tests/test_security.py::test_defang_url
```

The project includes **53 tests** (36 detection tests + 17 security tests), covering parsing, detection rules, risk scoring, end-to-end behavior, safe rendering, and hostile-input handling.

## 🔐 Security Design

PhishGuard is designed to analyze hostile email content without interacting with its payloads.

| Risk | Mitigation |
|---|---|
| Malicious or tracking URL | Never opened, resolved, or downloaded |
| Accidental link click | URLs are defanged in results |
| HTML/script injection | Email-derived display values are escaped |
| Markdown/link injection | Unsafe Markdown constructs are neutralized |
| Hidden/control characters | Input is sanitized before analysis |
| Oversized input | 300,000-character limit; 1 MB upload limit |
| Resource-exhaustion attempts | URL and hostname limits; hostile-input tests |
| Error-message data leakage | Generic UI errors; details stay in server logs |

## ⚙️ Analysis Options

The sidebar provides options to:

- **Analyze URLs** — enable or disable URL checks.
- **Analyze headers** — enable or disable sender/header checks.

When an email has no headers, PhishGuard analyzes the body and notes that sender checks are unavailable.

## 📌 Limitations

- Detection is **rule-based and heuristic**, not machine learning.
- A low score does not prove an email is legitimate.
- False positives and false negatives are possible.
- SPF/DKIM/DMARC checks depend on authentication results present in the email headers; PhishGuard does not independently authenticate the sender.
- Attachments are assessed by their names/extensions only—not their contents.
- PhishGuard does not visit URLs or verify whether a website is currently malicious.

## 🗺️ Development Workflow

For the complete module-by-module explanation, pipeline details, rule design, and guidance for adding new detection rules, see **[`workflow.md`](workflow.md)**.

## 👨‍💻 Author

**Shahroz Javid**  
Cybersecurity learner | Python | Linux | Security projects

- GitHub: [@Shahroz5373](https://github.com/Shahroz5373)
- LinkedIn: [Muhammad Shahroz](https://linkedin.com/in/muhammad-shahroz-70982a448)

## 📄 License

This project is distributed under the license in [`LICENSE`](LICENSE).

---

<p align="center">
  <b>Analyze safely. Understand the evidence. Stay alert. 🛡️</b>
</p>
