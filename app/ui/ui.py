import re
from datetime import datetime

import streamlit as st

from backend.config import MAX_UPLOAD_BYTES
from backend.security import safe_html, safe_plain

# ----------------------------------------------------------------------------
# Theme helpers
# ----------------------------------------------------------------------------
VERDICT_META = {
    "Phishing": {"icon": "🚨", "color": "#ef4444", "bg": "rgba(239,68,68,0.10)"},
    "Suspicious": {"icon": "⚠️", "color": "#f59e0b", "bg": "rgba(245,158,11,0.10)"},
    "Safe": {"icon": "✅", "color": "#22c55e", "bg": "rgba(34,197,94,0.10)"},
}

SEVERITY_META = {
    "high": {"label": "HIGH", "color": "#ef4444"},
    "medium": {"label": "MEDIUM", "color": "#f59e0b"},
    "low": {"label": "LOW", "color": "#eab308"},
}

CSS = """
<style>
.block-container {padding-top: 1.5rem; max-width: 1150px;}
#MainMenu, footer {visibility: hidden;}

/* ---------- Hero (follows the app theme, no hardcoded colors) ---------- */
.hero {
    padding: 1.5rem 1.8rem;
    border-radius: 16px;
    margin-bottom: 1.2rem;
    border: 1px solid rgba(128,128,128,0.25);
    border-left: 6px solid var(--pg-primary);
    background: linear-gradient(
        135deg,
        color-mix(in srgb, var(--pg-primary) 14%, transparent),
        rgba(128,128,128,0.05)
    );
}
.hero-title {font-size: 2.1rem; font-weight: 800; line-height: 1.2;}
.hero-sub {margin: 0.35rem 0 0.9rem 0; opacity: 0.75; font-size: 1rem;}
.chip {
    display: inline-block; padding: 0.2rem 0.7rem; margin: 0 0.4rem 0.3rem 0;
    border-radius: 999px; font-size: 0.78rem; font-weight: 600;
    border: 1px solid color-mix(in srgb, var(--pg-primary) 45%, transparent);
    background: color-mix(in srgb, var(--pg-primary) 10%, transparent);
}

/* ---------- Generic cards ---------- */
.card {
    padding: 0.9rem 1.2rem; border-radius: 14px; margin-bottom: 0.7rem;
    border: 1px solid rgba(128,128,128,0.25);
    background: rgba(128,128,128,0.06);
    transition: transform 0.15s ease, box-shadow 0.15s ease;
}
.card:hover {transform: translateY(-1px); box-shadow: 0 4px 14px rgba(0,0,0,0.12);}
.card-title {font-weight: 700; font-size: 1rem; margin-bottom: 0.2rem;}
.card-text {opacity: 0.8; font-size: 0.93rem;}

.badge {
    display: inline-block; padding: 0.1rem 0.55rem; border-radius: 6px;
    font-size: 0.68rem; font-weight: 800; letter-spacing: 0.05em; color: #fff;
    margin-right: 0.5rem; vertical-align: middle;
}

/* ---------- Verdict + gauge ---------- */
.verdict-banner {padding: 1.1rem 1.3rem; border-radius: 14px; margin-bottom: 0.7rem;}
.verdict-title {font-size: 1.5rem; font-weight: 800;}
.verdict-sub {opacity: 0.85; margin-top: 0.2rem;}

.gauge-wrap {display: flex; justify-content: center; padding: 0.3rem 0;}
.gauge {position: relative; width: 170px; height: 170px;}
.gauge-ring {
    position: absolute; inset: 0; border-radius: 50%;
    -webkit-mask: radial-gradient(farthest-side, transparent 72%, #000 73%);
            mask: radial-gradient(farthest-side, transparent 72%, #000 73%);
}
.gauge-center {
    position: absolute; inset: 0; display: flex; flex-direction: column;
    align-items: center; justify-content: center;
}
.gauge-score {font-size: 2.6rem; font-weight: 800; line-height: 1;}
.gauge-label {font-size: 0.72rem; opacity: 0.6; margin-top: 0.25rem; letter-spacing: 0.08em;}

/* ---------- Metrics ---------- */
.metric-card {
    padding: 0.9rem 1rem; border-radius: 14px; text-align: center;
    border: 1px solid rgba(128,128,128,0.25);
    background: rgba(128,128,128,0.06);
}
.metric-value {font-size: 1.7rem; font-weight: 800;}
.metric-label {font-size: 0.75rem; opacity: 0.65; text-transform: uppercase; letter-spacing: 0.06em;}

/* ---------- Severity bar ---------- */
.sev-bar {display: flex; height: 10px; border-radius: 999px; overflow: hidden; background: rgba(128,128,128,0.2);}
.sev-legend {font-size: 0.8rem; opacity: 0.75; margin-top: 0.35rem;}
.dot {display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin: 0 4px 0 10px;}

/* ---------- Email summary pills ---------- */
.pill {
    display: inline-block; max-width: 100%; padding: 0.3rem 0.8rem; margin: 0 0.5rem 0.5rem 0;
    border-radius: 10px; font-size: 0.85rem;
    border: 1px solid rgba(128,128,128,0.25); background: rgba(128,128,128,0.06);
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap; vertical-align: top;
}
.pill b {opacity: 0.6; font-weight: 700; margin-right: 0.35rem;}

/* ---------- URLs / headers ---------- */
.url-row {padding: 0.8rem 1rem; border-radius: 12px; margin-bottom: 0.6rem; border: 1px solid rgba(128,128,128,0.25);}
.url-flagged {border-left: 5px solid #ef4444; background: rgba(239,68,68,0.08);}
.url-ok {border-left: 5px solid #22c55e; background: rgba(34,197,94,0.07);}
.url-text {font-family: monospace; font-size: 0.88rem; word-break: break-all; margin-top: 0.2rem;}

.header-row {display: flex; gap: 1rem; padding: 0.55rem 0.9rem; border-bottom: 1px solid rgba(128,128,128,0.2);}
.header-key {min-width: 110px; font-weight: 700; opacity: 0.75;}
.header-val {font-family: monospace; word-break: break-all;}

/* ---------- Empty state ---------- */
.empty {
    text-align: center; padding: 2rem 1rem; border-radius: 16px;
    border: 2px dashed rgba(128,128,128,0.3); margin-top: 0.8rem;
}
.empty-icon {font-size: 2.4rem;}
.empty-title {font-weight: 700; font-size: 1.15rem; margin: 0.3rem 0;}
.steps {display: flex; gap: 0.8rem; justify-content: center; flex-wrap: wrap; margin-top: 1rem;}
.step {
    flex: 1; min-width: 160px; max-width: 240px; padding: 0.8rem; border-radius: 12px;
    background: rgba(128,128,128,0.06); border: 1px solid rgba(128,128,128,0.2);
}
.step-num {
    display: inline-flex; width: 26px; height: 26px; border-radius: 50%;
    align-items: center; justify-content: center; font-weight: 800; font-size: 0.85rem;
    background: var(--pg-primary); color: #fff; margin-bottom: 0.4rem;
}

.cat-tag {
    display: inline-block; padding: 0.05rem 0.5rem; margin-left: 0.5rem; border-radius: 999px;
    font-size: 0.68rem; font-weight: 700; opacity: 0.8; vertical-align: middle;
    border: 1px solid rgba(128,128,128,0.4);
}
.evidence {
    margin-top: 0.5rem; padding: 0.5rem 0.7rem; border-radius: 8px;
    background: rgba(128,128,128,0.10); font-family: monospace; font-size: 0.82rem;
    word-break: break-all; line-height: 1.5;
}
.evidence-label {font-family: inherit; font-weight: 700; opacity: 0.6; font-size: 0.72rem; letter-spacing: 0.05em;}

.small-muted {opacity: 0.6; font-size: 0.85rem;}
.footer {text-align: center; opacity: 0.5; font-size: 0.82rem; margin-top: 2.5rem; padding-bottom: 1rem;}

/* ---------- Small polish on Streamlit widgets ---------- */
div[data-testid="stTextArea"] textarea {font-family: monospace; font-size: 0.9rem;}
button[kind="primary"], button[kind="secondary"] {transition: transform 0.12s ease;}
button[kind="primary"]:hover, button[kind="secondary"]:hover {transform: translateY(-1px);}
</style>
"""


def _e(value):
    """
    Make ANY email-derived text safe before it is shown on the page.

    Every value that comes from the analyzed email (subject, links, evidence,
    file names...) must go through this. It escapes HTML, neutralizes Markdown
    and defangs links (hxxp://evil[.]com), see backend/security.py.
    """
    return safe_html(value)


def _primary_color():
    """Use the app's own primary color so the UI always matches the theme."""
    try:
        color = st.get_option("theme.primaryColor")
    except Exception:
        color = None
    if isinstance(color, str) and re.fullmatch(r"#[0-9a-fA-F]{3,8}", color):
        return color
    return "#ff4b4b"  # Streamlit default


# ----------------------------------------------------------------------------
# Page setup + header + footer
# ----------------------------------------------------------------------------
def setup_page():
    st.set_page_config(
        page_title="PhishGuard | Phishing Email Detector",
        page_icon="🛡️",
        layout="wide",
    )
    st.markdown(f"<style>:root {{ --pg-primary: {_primary_color()}; }}</style>", unsafe_allow_html=True)
    st.markdown(CSS, unsafe_allow_html=True)
    if "scans" not in st.session_state:
        st.session_state.scans = 0
    if "history" not in st.session_state:
        st.session_state.history = []


def render_header():
    st.markdown(
        """
        <div class="hero">
            <div class="hero-title">🛡️ PhishGuard</div>
            <div class="hero-sub">Paste an email or upload an .eml file and find out if it is a phishing attempt in seconds.</div>
            <span class="chip">🔍 Content analysis</span>
            <span class="chip">🔗 Link inspection</span>
            <span class="chip">📨 Header check</span>
            <span class="chip">📊 Risk score</span>
            <span class="chip">🔒 Links are never opened</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_empty_state():
    st.markdown(
        """
        <div class="empty">
            <div class="empty-icon">📭</div>
            <div class="empty-title">No analysis yet</div>
            <div class="small-muted">Your results will appear here after you analyze an email.</div>
            <div class="steps">
                <div class="step"><div class="step-num">1</div><div><b>Add an email</b><br>
                    <span class="small-muted">Paste it or upload a file</span></div></div>
                <div class="step"><div class="step-num">2</div><div><b>Click Analyze</b><br>
                    <span class="small-muted">We scan text, links and headers</span></div></div>
                <div class="step"><div class="step-num">3</div><div><b>Review results</b><br>
                    <span class="small-muted">Get a score and next steps</span></div></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_footer():
    st.markdown(
        "<div class='footer'>PhishGuard · Cybersecurity Project · "
        "Results are automated and not 100% accurate, always verify suspicious emails.</div>",
        unsafe_allow_html=True,
    )


# ----------------------------------------------------------------------------
# Sidebar
# ----------------------------------------------------------------------------
def render_sidebar():
    """Draws the settings. Returns (settings, session_slot)."""
    with st.sidebar:
        st.markdown("## ⚙️ Settings")
        check_urls = st.toggle(
            "🔗 Analyze URLs", value=True,
            help="Inspect every link in the email. Links are only read as text, never opened.",
        )
        check_headers = st.toggle(
            "📨 Analyze headers", value=True,
            help="Check the sender, Reply-To and SPF / DKIM / DMARC results (needs the email headers).",
        )
        st.caption("🔒 Links and attachments are never opened or downloaded.")

        st.divider()
        # Filled at the end of the run (render_session) so the numbers always
        # include the scan that just finished.
        session_slot = st.container()

        st.divider()
        with st.expander("🧠 Common phishing signs"):
            st.markdown(
                "- Urgent or threatening language\n"
                "- Sender domain looks slightly wrong\n"
                "- Links that don't match the sender\n"
                "- Requests for passwords or card details\n"
                "- Unexpected attachments\n"
                "- Generic greetings like 'Dear customer'"
            )
        st.caption("PhishGuard · Cybersecurity Project")

    settings = {
        "check_urls": check_urls,
        "check_headers": check_headers,
    }
    return settings, session_slot


def render_session(slot):
    """Session stats in the sidebar. Call it after the analysis has run."""
    history = st.session_state.get("history", [])
    threats = sum(1 for h in history if h["verdict"] != "Safe")
    with slot:
        st.markdown("## 📈 Session")
        c1, c2 = st.columns(2)
        c1.metric("Scans", st.session_state.get("scans", 0))
        c2.metric("Threats", threats)

        if history:
            st.markdown("**Recent scans**")
            for h in reversed(history[-5:]):
                meta = VERDICT_META.get(h["verdict"], VERDICT_META["Safe"])
                st.markdown(
                    f"<div class='small-muted'>{meta['icon']} {_e(h['verdict'])} "
                    f"({_e(h['score'])}) · {_e(h['time'])}</div>",
                    unsafe_allow_html=True,
                )
            if st.button("Clear history", use_container_width=True, key="clear_history"):
                st.session_state.history = []
                st.session_state.scans = 0
                st.rerun()


# ----------------------------------------------------------------------------
# Input
# ----------------------------------------------------------------------------
def _clear_text():
    st.session_state.email_text = ""


def render_input():
    """Returns (email_text, analyze_clicked)."""
    if "email_text" not in st.session_state:
        st.session_state.email_text = ""

    tab_paste, tab_upload = st.tabs(["📋 Paste email", "📎 Upload file"])

    with tab_paste:
        st.button("🗑️ Clear", on_click=_clear_text)

        st.text_area(
            "Email content",
            key="email_text",
            height=280,
            placeholder="Paste the full email here, including headers if you have them...",
            label_visibility="collapsed",
        )
        text = st.session_state.email_text
        st.markdown(
            f"<div class='small-muted'>{len(text)} characters · {len(text.split())} words</div>",
            unsafe_allow_html=True,
        )

    uploaded = None
    with tab_upload:
        uploaded = st.file_uploader(
            "Drop an .eml or .txt file", type=["eml", "txt"], label_visibility="collapsed"
        )
        if uploaded is not None and uploaded.size > MAX_UPLOAD_BYTES:
            st.error(f"This file is too large ({uploaded.size / 1_000_000:.1f} MB). The limit is {MAX_UPLOAD_BYTES // 1_000_000} MB.")
            uploaded = None
        if uploaded is not None:
            st.success(f"Loaded: {_e(uploaded.name)} ({uploaded.size} bytes)")
            if st.session_state.email_text.strip():
                st.info("Text is already pasted in the other tab, so that text will be analyzed. "
                        "Click Clear there to analyze this file instead.")

    email_text = st.session_state.email_text
    if uploaded is not None and not email_text.strip():
        email_text = uploaded.getvalue().decode("utf-8", errors="replace")

    # The button is always clickable. Streamlit only saves what you type once
    # you leave the box, so a disabled button looked "stuck" after pasting.
    # Clicking the button leaves the box and sends the text in the same click.
    clicked = st.button("🔍 Analyze email", type="primary", use_container_width=True)
    return email_text, clicked


def record_scan(result):
    """Count a finished scan and reset the checklist for the new result."""
    st.session_state.scans = st.session_state.get("scans", 0) + 1
    history = st.session_state.setdefault("history", [])
    history.append(
        {
            "verdict": result.get("verdict", "Safe"),
            "score": result.get("score", 0),
            "time": datetime.now().strftime("%H:%M"),
        }
    )
    del history[:-50]  # keep the list small
    for key in [k for k in st.session_state if str(k).startswith("act_")]:
        del st.session_state[key]  # untick the "What to do" boxes


# ----------------------------------------------------------------------------
# Results
# ----------------------------------------------------------------------------
def _score_color(score):
    if score >= 70:
        return "#ef4444"
    if score >= 40:
        return "#f59e0b"
    return "#22c55e"


def _gauge_html(score):
    score = min(max(int(score), 0), 100)
    color = _score_color(score)
    return f"""
    <div class="gauge-wrap">
        <div class="gauge">
            <div class="gauge-ring"
                 style="background: conic-gradient({color} {score * 3.6}deg, rgba(128,128,128,0.22) 0deg);"></div>
            <div class="gauge-center">
                <div class="gauge-score" style="color:{color}">{score}</div>
                <div class="gauge-label">RISK / 100</div>
            </div>
        </div>
    </div>
    """


def _evidence_html(evidence):
    if not evidence:
        return ""
    lines = "".join(f"<div>• {_e(item)}</div>" for item in evidence)
    return f"<div class='evidence'><div class='evidence-label'>EVIDENCE</div>{lines}</div>"


def _metric_html(value, label, color=None):
    style = f"color:{color}" if color else ""
    return (
        f"<div class='metric-card'><div class='metric-value' style='{style}'>{_e(value)}</div>"
        f"<div class='metric-label'>{_e(label)}</div></div>"
    )


def _severity_bar_html(reasons):
    counts = {"high": 0, "medium": 0, "low": 0}
    for r in reasons:
        sev = r.get("severity", "low")
        counts[sev if sev in counts else "low"] += 1
    total = sum(counts.values())
    if total == 0:
        return ""
    segments = "".join(
        f"<div style='width:{counts[k] / total * 100:.1f}%; background:{SEVERITY_META[k]['color']}'></div>"
        for k in ("high", "medium", "low")
        if counts[k]
    )
    legend = "".join(
        f"<span class='dot' style='background:{SEVERITY_META[k]['color']}'></span>"
        f"{counts[k]} {SEVERITY_META[k]['label'].lower()}"
        for k in ("high", "medium", "low")
    )
    return f"<div class='sev-bar'>{segments}</div><div class='sev-legend'>{legend}</div>"


def _build_report(result):
    """Plain-text report. Everything from the email is cleaned and links are defanged."""
    lines = [
        "PHISHGUARD REPORT",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "Links are defanged (hxxp, [.]) so they can not be clicked by accident.",
        "=" * 40,
        f"Verdict: {safe_plain(result.get('verdict'))}",
        f"Risk score: {safe_plain(result.get('score'))}/100",
        f"Summary: {safe_plain(result.get('summary', ''))}",
        "",
        "INDICATORS",
    ]
    for r in result.get("reasons", []):
        lines.append(f"- [{safe_plain(r.get('severity', 'low')).upper()}] {safe_plain(r.get('title'))}: {safe_plain(r.get('detail'))}")
        for item in r.get("evidence", []):
            lines.append(f"    * {safe_plain(item)}")
    lines += ["", "URLS"]
    for u in result.get("urls", []):
        flag = "FLAGGED" if u.get("flagged") else "OK"
        lines.append(f"- [{flag}] {safe_plain(u.get('url'))} {safe_plain(u.get('reason', ''))}")
    lines += ["", "HEADERS"]
    for k, v in result.get("headers", {}).items():
        lines.append(f"- {safe_plain(k)}: {safe_plain(v)}")
    return "\n".join(lines)


def render_results(result):
    """
    Expected result format (the backend should return this):
    {
        "score": int (0-100),
        "verdict": "Phishing" | "Suspicious" | "Safe",
        "reasons": [{"title": str, "detail": str, "severity": "high"|"medium"|"low"}],
        "urls": [{"url": str, "domain": str, "flagged": bool, "reason": str}],
        "headers": {"From": str, "Subject": str, ...},
        # optional: "summary": str, "notes": [str], reasons[i]["category"/"evidence"]
    }
    """
    score = result.get("score", 0)
    verdict = result.get("verdict", "Safe")
    meta = VERDICT_META.get(verdict, VERDICT_META["Safe"])
    reasons = result.get("reasons", [])
    urls = result.get("urls", [])
    headers = result.get("headers", {})

    advice = {
        "Phishing": "Do not click any links, open attachments or reply. Report it and delete it.",
        "Suspicious": "Be careful. Verify the sender through another channel before doing anything.",
        "Safe": "No strong phishing signs found, but always stay alert.",
    }.get(verdict, "")

    st.divider()
    st.markdown("### 📊 Analysis results")

    # Gauge + verdict
    col_gauge, col_verdict = st.columns([1, 2], vertical_alignment="center")
    with col_gauge:
        st.markdown(_gauge_html(score), unsafe_allow_html=True)
    with col_verdict:
        st.markdown(
            f"""
            <div class="verdict-banner" style="background:{meta['bg']}; border:1px solid {meta['color']};">
                <div class="verdict-title" style="color:{meta['color']}">{meta['icon']} {_e(verdict)}</div>
                <div class="verdict-sub">{_e(advice)}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        pills = "".join(
            f"<span class='pill'><b>{_e(k)}</b>{_e(headers[k])}</span>"
            for k in ("From", "Subject")
            if headers.get(k)
        )
        if pills:
            st.markdown(pills, unsafe_allow_html=True)
        if result.get("summary"):
            st.caption(_e(result["summary"]))
        for note in result.get("notes", []):
            st.caption(f"ℹ️ {_e(note)}")

    # Metrics
    flagged_urls = sum(1 for u in urls if u.get("flagged"))
    high = sum(1 for r in reasons if r.get("severity") == "high")
    m1, m2, m3, m4 = st.columns(4)
    m1.markdown(_metric_html(len(reasons), "Indicators"), unsafe_allow_html=True)
    m2.markdown(
        _metric_html(high, "High severity", "#ef4444" if high else None), unsafe_allow_html=True
    )
    m3.markdown(_metric_html(len(urls), "URLs found"), unsafe_allow_html=True)
    m4.markdown(
        _metric_html(flagged_urls, "URLs flagged", "#ef4444" if flagged_urls else None),
        unsafe_allow_html=True,
    )

    bar = _severity_bar_html(reasons)
    if bar:
        st.markdown("<div style='margin-top:0.9rem'></div>" + bar, unsafe_allow_html=True)

    st.write("")
    tab_reasons, tab_urls, tab_headers, tab_actions = st.tabs(
        [
            f"🔎 Indicators ({len(reasons)})",
            f"🔗 URLs ({len(urls)})",
            "📨 Headers",
            "🛠️ What to do",
        ]
    )

    with tab_reasons:
        if not reasons:
            st.info("No suspicious indicators found.")
        order = {"high": 0, "medium": 1, "low": 2}
        for r in sorted(reasons, key=lambda x: order.get(x.get("severity", "low"), 3)):
            sev = SEVERITY_META.get(r.get("severity", "low"), SEVERITY_META["low"])
            st.markdown(
                f"""
                <div class="card" style="border-left:5px solid {sev['color']};">
                    <div class="card-title">
                        <span class="badge" style="background:{sev['color']}">{sev['label']}</span>{_e(r.get('title'))}<span class="cat-tag">{_e(r.get('category', ''))}</span>
                    </div>
                    <div class="card-text">{_e(r.get('detail'))}</div>
                    {_evidence_html(r.get('evidence'))}
                </div>
                """,
                unsafe_allow_html=True,
            )

    with tab_urls:
        if not urls:
            st.info("No URLs found in this email.")
        for u in urls:
            flagged = u.get("flagged")
            cls = "url-flagged" if flagged else "url-ok"
            tag = "🚩 FLAGGED" if flagged else "✅ OK"
            reason = u.get("reason", "")
            st.markdown(
                f"""
                <div class="url-row {cls}">
                    <div><b>{tag}</b> · <span class="small-muted">{_e(u.get('domain'))}</span></div>
                    <div class="url-text">{_e(u.get('url'))}</div>
                    {f"<div class='card-text'>{_e(reason)}</div>" if reason else ""}
                </div>
                """,
                unsafe_allow_html=True,
            )
        if urls:
            st.caption(
                "Links are defanged on purpose (hxxp, [.]) and are never opened, "
                "so you can't click them by accident."
            )

    with tab_headers:
        if not headers:
            st.info("No headers found.")
        for k, v in headers.items():
            st.markdown(
                f"<div class='header-row'><div class='header-key'>{_e(k)}</div>"
                f"<div class='header-val'>{_e(v)}</div></div>",
                unsafe_allow_html=True,
            )

    with tab_actions:
        if verdict == "Safe":
            st.success("This email looks fine. Still, never share passwords over email.")
        else:
            left, right = st.columns(2)
            with left:
                st.markdown("**If you haven't interacted with it**")
                st.checkbox("Don't click any links or open attachments", value=True, disabled=True)
                st.checkbox("Report it as phishing in your email app", key="act_report")
                st.checkbox("Delete the email", key="act_delete")
            with right:
                st.markdown("**If you already clicked or entered details**")
                st.checkbox("Change that account's password right away", key="act_pass")
                st.checkbox("Turn on two-factor authentication", key="act_2fa")
                st.checkbox("Check your account for unknown activity", key="act_check")
                st.checkbox("Contact your bank or IT team if money or work data is involved", key="act_bank")

    st.write("")
    st.download_button(
        "⬇️ Download report (.txt)",
        data=_build_report(result),
        file_name="phishguard_report.txt",
        mime="text/plain",
        use_container_width=True,
    )
