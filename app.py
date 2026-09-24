import streamlit as st

from backend.extractor import extract_qr_from_bytes
from backend.threat_intel import analyze_url_risk


st.set_page_config(page_title="QuishGuard", page_icon="🛡️", layout="wide")

st.title("🛡️ QuishGuard")
st.caption("Scan QR codes in documents and images, then review the risk of their URLs.")

uploaded_file = st.file_uploader(
    "Upload a file to scan",
    type=["pdf", "png", "jpg", "jpeg"],
    help="Supported formats: PDF, PNG, JPG, and JPEG.",
)


def _get_result_value(result, *keys, default=None):
    """Read a field from a mapping-like threat analysis result."""
    if isinstance(result, dict):
        for key in keys:
            if key in result:
                return result[key]
    return default


def _format_signals(signals):
    """Format the analyzer's risk signals for a transparent breakdown."""
    if signals is None:
        return "No signal breakdown was returned by the threat analyzer."
    if isinstance(signals, dict):
        if not signals:
            return "No risk signals were reported."
        return "\n".join(f"- **{name}:** {points}" for name, points in signals.items())
    if isinstance(signals, (list, tuple)):
        if not signals:
            return "No risk signals were reported."
        lines = []
        for signal in signals:
            if isinstance(signal, dict):
                name = signal.get("name", signal.get("signal", "Risk signal"))
                points = signal.get("points", signal.get("score", ""))
                detail = signal.get("details", signal.get("description", ""))
                line = f"- **{name}:** {points}"
                if detail:
                    line += f" — {detail}"
                lines.append(line)
            else:
                lines.append(f"- {signal}")
        return "\n".join(lines)
    return str(signals)


def _risk_level(result, verdict, score):
    """Resolve a normalized severity from analyzer output."""
    explicit = _get_result_value(result, "risk_level", "level", "severity")
    label = str(explicit or verdict).strip().lower()
    if any(word in label for word in ("high", "critical", "malicious", "danger")):
        return "high"
    if any(word in label for word in ("medium", "moderate", "suspicious", "caution")):
        return "medium"
    if any(word in label for word in ("low", "safe", "benign")):
        return "low"

    # Fallback for analyzers that return only a 0–100 score.
    try:
        numeric_score = float(score)
    except (TypeError, ValueError):
        return "medium"
    if numeric_score >= 70:
        return "high"
    if numeric_score >= 35:
        return "medium"
    return "low"


if uploaded_file is not None:
    with st.spinner("Extracting QR code URLs…"):
        extracted_urls = extract_qr_from_bytes(uploaded_file.getvalue(), uploaded_file.name)

    if not extracted_urls:
        st.info("No URL QR codes were found in this file.")
    else:
        st.subheader("Extracted URLs and risk analysis")
        for index, url in enumerate(extracted_urls, start=1):
            st.markdown(f"**URL {index}**")
            st.code(url, language=None)

            try:
                analysis = analyze_url_risk(url)
                score = _get_result_value(analysis, "score", "risk_score", "total_score", default="N/A")
                verdict = _get_result_value(analysis, "verdict", "risk", "classification", default="Unknown")
                signals = _get_result_value(
                    analysis,
                    "signals",
                    "risk_signals",
                    "breakdown",
                    "signal_points",
                )

                score_col, verdict_col = st.columns(2)
                score_col.metric("Risk score", score)
                verdict_col.metric("Verdict", str(verdict))

                with st.expander("Risk signal points", expanded=True):
                    st.markdown(_format_signals(signals))

                level = _risk_level(analysis, verdict, score)
                if level == "high":
                    st.error("🚨 HIGH RISK — DO NOT OPEN THIS LINK. Do not scan it again, visit it, or enter any personal information.")
                elif level == "medium":
                    st.warning("⚠️ MEDIUM RISK — Use caution. Do not open this link unless you can independently verify the destination.")
                else:
                    st.success("✅ LOW RISK — No significant risk was detected. Still verify the destination before opening.")
            except Exception as exc:
                st.error(f"Could not analyze this URL: {exc}")

            if index < len(extracted_urls):
                st.divider()
