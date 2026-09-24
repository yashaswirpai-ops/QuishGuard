import os
from typing import Any, Dict

from dotenv import load_dotenv

# Load variables from a local .env file when present. The key is available for
# future reputation lookups; the current deterministic analyzer does not call
# VirusTotal.
load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

_SIGNAL_NAMES = (
    "threat_intelligence",
    "domain_age",
    "suspicious_redirects",
    "brand_mismatch",
    "credential_indicators",
)
_SIGNAL_POINTS = 25


def analyze_url_risk(url: str) -> Dict[str, Any]:
    """Score a URL using simple deterministic indicators.

    Each triggered signal receives 25 points and the total is capped at 100.
    The signal breakdown contains per-signal points.
    """
    breakdown = {name: 0 for name in _SIGNAL_NAMES}
    normalized_url = str(url).strip().lower()

    if any(term in normalized_url for term in ("login", "secure", "auth")):
        breakdown["credential_indicators"] += _SIGNAL_POINTS
        breakdown["suspicious_redirects"] += _SIGNAL_POINTS

    if (
        any(term in normalized_url for term in ("free", "wifi"))
        or not normalized_url.startswith("https://")
    ):
        breakdown["domain_age"] += _SIGNAL_POINTS
        breakdown["threat_intelligence"] += _SIGNAL_POINTS

    score = min(sum(breakdown.values()), 100)
    if score >= 70:
        level = "HIGH RISK 🔴"
    elif score >= 40:
        level = "MEDIUM RISK 🟡"
    else:
        level = "LOW RISK 🟢"

    return {
        "url": url,
        "score": score,
        "level": level,
        "breakdown": breakdown,
    }

