"""PhishGuard backend. The UI needs `analyze_email` and the safe-display helpers."""

from .detector import analyze_email
from .security import defang_text, defang_url, safe_html, safe_plain, sanitize_input

__all__ = [
    "analyze_email",
    "sanitize_input",
    "safe_html",
    "safe_plain",
    "defang_url",
    "defang_text",
]
