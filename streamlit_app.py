import streamlit as st
from backend.extractor import extract_qr_from_bytes
from backend.threat_intel import analyze_url_risk

# Page Configuration
st.set_page_config(
    page_title="QuishGuard | QR Phishing Defense",
    page_icon="🛡️",
    layout="centered"
)

# App Header & Overview
st.title("🛡️ QuishGuard")
st.subheader("Multi-Stage Defense Against QR-Based Phishing")

st.markdown(
    "Upload a PDF document, physical poster image, or screenshot containing a QR code. "
    "QuishGuard intercepts the artifact, extracts the hidden URL, analyzes its destination path, "
    "and calculates a deterministic security risk score before you scan."
)

st.divider()

# File Uploader Widget
uploaded_file = st.file_uploader(
    "📁 Drop your QR-containing document or image here", 
    type=["pdf", "png", "jpg", "jpeg"]
)

if uploaded_file is not None:
    # Read file bytes into memory
    file_bytes = uploaded_file.read()
    filename = uploaded_file.name

    # Step 1: Extract QR Code and URL
    with st.spinner("🔍 Scanning document matrix and decoding hidden QR payloads..."):
        extracted_urls = extract_qr_from_bytes(file_bytes, filename)

    if not extracted_urls:
        st.warning("⚠️ No valid QR codes detected in the uploaded file. Please try another sample image or document.")
    else:
        st.success(f"✅ Successfully decoded {len(extracted_urls)} QR code(s) from the artifact!")
        
        for idx, url in enumerate(extracted_urls):
            st.markdown(f"### 🔗 Extracted URL #{idx + 1}")
            st.code(url, language="text")
            
            # Step 2: Run Threat Intelligence & Risk Scoring
            with st.spinner(f"🛡️ Evaluating domain reputation, redirect chain, and indicators for URL #{idx + 1}..."):
                analysis = analyze_url_risk(url)
            
            # Display Score Metrics
            col1, col2 = st.columns(2)
            with col1:
                st.metric(label="Calculated Risk Score", value=f"{analysis['score']} / 100")
            with col2:
                st.metric(label="Threat Verdict", value=analysis['level'])
                
            st.markdown("#### 🔍 Threat Signals Breakdown")
            
            # List out individual scoring components transparently
            for signal, weight in analysis['breakdown'].items():
                formatted_signal = signal.replace('_', ' ').title()
                if weight > 0:
                    st.markdown(f"- ⚠️ **{formatted_signal}**: `+{weight} pts`")
                else:
                    st.markdown(f"- ✅ **{formatted_signal}**: `0 pts`")

            st.markdown("---")

            # Step 3: Defensive Response Banner (The Final Action)
            if analysis['score'] >= 70:
                st.error("🚨 **CRITICAL RISK DETECTED:** High probability of a quishing/credential-harvesting attack. **DO NOT OPEN THIS LINK.**")
            elif analysis['score'] >= 40:
                st.warning("⚠️ **MEDIUM RISK:** Suspicious redirection patterns or domain anomalies identified. **Proceed with extreme caution.**")
            else:
                st.success("✅ **LOW RISK:** Link appears verified and safe based on current security telemetry.")
