"""
Risk scoring: combines all indicators into one explainable score (0-100).

How the score is built:
1. Each indicator carries points (defined in config.py).
2. Points are added per category, and each category has a cap, so one area
   (for example many weak URL signals) cannot decide everything alone.
3. If strong signals come from several areas at once (sender + link + wording),
   a correlation bonus is added, because independent evidence is more reliable.
4. The total is limited to 100 and converted to a level using the fixed
   thresholds in config.py (SUSPICIOUS_AT and PHISHING_AT).

These numbers are heuristic starting points, not scientifically validated
probabilities.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .config import CATEGORY_CAPS, PHISHING_AT, STRONG_SIGNAL_POINTS, SUSPICIOUS_AT, VERDICTS
from .models import Indicator

_CORRELATION_AREAS = ("Sender", "URL", "Content", "Attachment")


@dataclass
class RiskAssessment:
    score: int
    level: str                      # Low | Medium | High
    verdict: str                    # Safe | Suspicious | Phishing
    indicators: list[Indicator]     # includes the correlation indicator if any
    breakdown: dict[str, int] = field(default_factory=dict)  # points per category


def _strong_areas(indicators: list[Indicator]) -> list[str]:
    areas = set()
    for item in indicators:
        if item.category in _CORRELATION_AREAS and (item.severity == "high" or item.points >= STRONG_SIGNAL_POINTS):
            areas.add(item.category)
    return sorted(areas)


def level_for_score(score: int) -> str:
    """Convert a 0-100 score into Low / Medium / High."""
    if score >= PHISHING_AT:
        return "High"
    if score >= SUSPICIOUS_AT:
        return "Medium"
    return "Low"


def calculate_risk(indicators: list[Indicator]) -> RiskAssessment:
    """Calculate the final score from a list of indicators."""
    # One indicator per rule
    unique: dict[str, Indicator] = {}
    for item in indicators:
        unique.setdefault(item.rule_id, item)
    final = list(unique.values())

    # Correlation bonus
    areas = _strong_areas(final)
    if len(areas) >= 3:
        final.append(Indicator.from_rule("CORR_THREE_SIGNALS", evidence=areas))
    elif len(areas) == 2:
        final.append(Indicator.from_rule("CORR_TWO_SIGNALS", evidence=areas))

    # Points per category, limited by the category cap
    totals: dict[str, int] = {}
    for item in final:
        totals[item.category] = totals.get(item.category, 0) + item.points
    breakdown = {category: min(points, CATEGORY_CAPS.get(category, 100)) for category, points in totals.items()}

    score = min(100, sum(breakdown.values()))
    level = level_for_score(score)
    return RiskAssessment(score=score, level=level, verdict=VERDICTS[level], indicators=final, breakdown=breakdown)
