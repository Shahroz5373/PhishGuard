import logging

import streamlit as st

from backend.detector import analyze_email
from ui.ui import (
    setup_page,
    render_header,
    render_sidebar,
    render_session,
    render_input,
    render_results,
    render_empty_state,
    render_footer,
    record_scan,
)

logger = logging.getLogger("phishguard")


def run_analysis(email_text, settings):
    """Analyze the email and store the result. The UI must never crash on a weird email."""
    with st.spinner("Analyzing email..."):
        try:
            result = analyze_email(email_text, settings)
        except Exception:
            # Details go to the server log only. The email text is never echoed
            # back into the page (it is untrusted).
            logger.exception("Analysis failed")
            st.session_state.pop("result", None)
            st.error("Something went wrong while analyzing this email. Try again or use a different email.")
            return
    st.session_state.result = result
    record_scan(result)


def main():
    setup_page()
    render_header()
    settings, session_slot = render_sidebar()
    email_text, clicked = render_input()

    if clicked:
        if email_text.strip():
            run_analysis(email_text, settings)
        else:
            st.warning("Paste an email (or upload a file) first, then click Analyze.")

    if "result" in st.session_state:
        render_results(st.session_state.result)
    else:
        render_empty_state()

    render_session(session_slot)  # last, so the numbers include this scan
    render_footer()


if __name__ == "__main__":
    main()
