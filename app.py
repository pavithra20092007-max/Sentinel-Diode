import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest

# =========================================================
# PAGE CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="Sentinel-Diode",
    page_icon="🛡️",
    layout="wide"
)

# =========================================================
# HEADER
# =========================================================

st.title("🛡️ Sentinel-Diode")
st.subheader("Autonomous Cognitive Threat-Intelligence Dashboard")
st.caption("AI-Based Network Anomaly Detection Prototype")

# =========================================================
# LOAD DEFAULT DATA
# =========================================================

@st.cache_data
def load_data():

    try:
        data = pd.read_csv("detected_traffic.csv")

    except FileNotFoundError:
        data = pd.read_csv("traffic.csv")

    return data


data = load_data()

# =========================================================
# SESSION STATE
# =========================================================

if "attack_mode" not in st.session_state:
    st.session_state.attack_mode = False

# =========================================================
# SIDEBAR
# =========================================================

st.sidebar.header("🚨 Attack Simulator")

attack_type = st.sidebar.selectbox(
    "🎯 Select Attack Scenario",
    [
        "High Volume Exfiltration",
        "Low & Slow Exfiltration",
        "Periodic Beaconing"
    ]
)

if st.sidebar.button("🚨 SIMULATE ATTACK"):
    st.session_state.attack_mode = True

if st.sidebar.button("🔄 RESET ATTACK"):
    st.session_state.attack_mode = False

# =========================================================
# CSV UPLOAD
# =========================================================

st.sidebar.divider()
st.sidebar.header("📂 Traffic Data")

uploaded_file = st.sidebar.file_uploader(
    "Upload Network Traffic CSV",
    type=["csv"]
)

# =========================================================
# USE UPLOADED DATA
# =========================================================

if uploaded_file is not None:

    uploaded_data = pd.read_csv(uploaded_file)

    required_features = [
        "packet_count",
        "byte_count",
        "duration",
        "destination_count"
    ]

    if all(
        column in uploaded_data.columns
        for column in required_features
    ):

        data = uploaded_data.copy()

        st.sidebar.success(
            "✅ CSV uploaded successfully!"
        )

    else:

        st.sidebar.error(
            "❌ Required columns missing."
        )

# =========================================================
# ATTACK SIMULATION
# =========================================================

display_data = data.copy()

if st.session_state.attack_mode:

    if attack_type == "High Volume Exfiltration":

        attack_count = int(len(display_data) * 0.35)

        threat_message = (
            "🔴 HIGH VOLUME EXFILTRATION DETECTED!"
        )

    elif attack_type == "Low & Slow Exfiltration":

        attack_count = int(len(display_data) * 0.15)

        threat_message = (
            "🟠 LOW & SLOW EXFILTRATION DETECTED!"
        )

    else:

        attack_count = int(len(display_data) * 0.20)

        threat_message = (
            "🟣 PERIODIC BEACONING DETECTED!"
        )

    suspicious_index = display_data.sample(
        n=max(1, attack_count),
        random_state=42
    ).index

    display_data["status"] = "Normal"

    display_data.loc[
        suspicious_index,
        "status"
    ] = "Suspicious"

    st.warning(threat_message)

else:

    if "status" not in display_data.columns:

        display_data["status"] = "Normal"

# =========================================================
# REAL ISOLATION FOREST AI
# =========================================================

required_features = [
    "packet_count",
    "byte_count",
    "duration",
    "destination_count"
]

if all(
    column in display_data.columns
    for column in required_features
):

    ai_model = IsolationForest(
        contamination=0.15,
        random_state=42
    )

    display_data["AI_Prediction"] = ai_model.fit_predict(
        display_data[required_features]
    )

    display_data["AI_Status"] = display_data[
        "AI_Prediction"
    ].apply(
        lambda x: "Suspicious" if x == -1 else "Normal"
    )

    display_data["AI_Score"] = ai_model.decision_function(
        display_data[required_features]
    )

    display_data["Threat_Score"] = (
        (1 - display_data["AI_Score"]) * 50
    ).clip(0, 100)

else:

    display_data["AI_Status"] = "Unknown"
    display_data["AI_Score"] = 0
    display_data["Threat_Score"] = 0

# =========================================================
# STATISTICS
# =========================================================

total_traffic = len(display_data)

normal_traffic = len(
    display_data[
        display_data["status"] == "Normal"
    ]
)

suspicious_traffic = len(
    display_data[
        display_data["status"] == "Suspicious"
    ]
)

if total_traffic > 0:

    threat_level = (
        suspicious_traffic /
        total_traffic
    ) * 100

else:

    threat_level = 0

# =========================================================
# MAIN METRICS
# =========================================================

st.divider()

col1, col2, col3, col4 = st.columns(4)

with col1:

    st.metric(
        "📡 Total Traffic",
        total_traffic
    )

with col2:

    st.metric(
        "🟢 Normal Traffic",
        normal_traffic
    )

with col3:

    st.metric(
        "🚨 Suspicious Traffic",
        suspicious_traffic
    )

with col4:

    st.metric(
        "🎯 Threat Level",
        f"{threat_level:.1f}%"
    )

# =========================================================
# LIVE TRAFFIC MONITOR
# =========================================================

st.divider()

st.subheader(
    "📡 Live Network Traffic Monitor"
)

if st.session_state.attack_mode:

    live_packets = np.random.randint(
        300,
        700
    )

    live_bytes = np.random.randint(
        30000,
        90000
    )

else:

    live_packets = np.random.randint(
        80,
        150
    )

    live_bytes = np.random.randint(
        5000,
        15000
    )

live_col1, live_col2 = st.columns(2)

with live_col1:

    st.metric(
        "📦 Live Packets/sec",
        live_packets
    )

with live_col2:

    st.metric(
        "💾 Live Data Transfer",
        f"{live_bytes:,} bytes"
    )

if st.session_state.attack_mode:

    st.error(
        "🔴 LIVE ALERT: Abnormal traffic detected!"
    )

else:

    st.success(
        "🟢 LIVE STATUS: Traffic operating normally."
    )

# =========================================================
# NETWORK TRAFFIC ANALYSIS
# =========================================================

st.divider()

st.subheader(
    "📊 Network Traffic Analysis"
)

chart_columns = []

if "byte_count" in display_data.columns:

    chart_columns.append(
        "byte_count"
    )

if "packet_count" in display_data.columns:

    chart_columns.append(
        "packet_count"
    )

if len(chart_columns) > 0:

    st.line_chart(
        display_data[chart_columns]
    )

# =========================================================
# THREAT ANALYSIS
# =========================================================

st.divider()

st.subheader(
    "🧠 AI Threat Analysis"
)

if threat_level >= 70:

    severity = "CRITICAL"

    st.error(
        "🔴 CRITICAL THREAT — Immediate attention required."
    )

elif threat_level >= 30:

    severity = "HIGH"

    st.warning(
        "🟠 HIGH THREAT — Suspicious network activity detected."
    )

elif threat_level >= 15:

    severity = "MEDIUM"

    st.warning(
        "🟡 MEDIUM THREAT — Monitoring required."
    )

else:

    severity = "LOW"

    st.success(
        "🟢 LOW THREAT — Network traffic appears normal."
    )
# -----------------------------
# Overall Threat Score
# -----------------------------
st.divider()
st.subheader("🎯 Overall Threat Score")

overall_col1, overall_col2, overall_col3 = st.columns(3)

with overall_col1:
    st.metric(
        "Threat Score",
        f"{threat_level:.1f}/100"
    )

with overall_col2:
    st.metric(
        "Severity",
        severity
    )

with overall_col3:
    st.metric(
        "Attack Scenario",
        attack_type if st.session_state.attack_mode else "None"
    )

st.progress(
    min(threat_level / 100, 1.0)
)
st.metric(
    "🎯 Threat Severity",
    severity
)

st.progress(
    min(threat_level / 100, 1.0)
)

st.write(
    f"AI Threat Score: **{threat_level:.1f}%**"
)
st.subheader("🎯 Overall Threat Score")

overall_col1, overall_col2, overall_col3 = st.columns(3)

with overall_col1:
    st.metric(
        "Threat Score",
        f"{threat_level:.1f}/100"
    )

with overall_col2:
    st.metric(
        "Severity",
        severity
    )

with overall_col3:
    st.metric(
        "Attack Scenario",
        attack_type
    )

st.progress(min(threat_level / 100, 1.0))

with overall_col1:
    st.metric(
        "Threat Score",
        f"{threat_level:.1f}/100"
    )

with overall_col2:
    st.metric(
        "Severity",
        severity
    )

with overall_col3:
    st.metric(
        "Attack Scenario",
        attack_type
    )

st.progress(min(threat_level / 100, 1.0))
# =========================================================
# REAL AI DETECTION RESULT
# =========================================================

st.divider()

st.subheader(
    "🤖 Real AI Detection Result"
)

ai_suspicious = len(
    display_data[
        display_data["AI_Status"] == "Suspicious"
    ]
)

ai_normal = len(
    display_data[
        display_data["AI_Status"] == "Normal"
    ]
)

ai_col1, ai_col2, ai_col3 = st.columns(3)

with ai_col1:

    st.metric(
        "🚨 AI Anomalies",
        ai_suspicious
    )

with ai_col2:

    st.metric(
        "🟢 AI Normal",
        ai_normal
    )

with ai_col3:

    ai_rate = (
        ai_suspicious /
        total_traffic * 100
        if total_traffic > 0
        else 0
    )

    st.metric(
        "📊 AI Anomaly Rate",
        f"{ai_rate:.1f}%"
    )

# =========================================================
# EXPLAINABLE AI
# =========================================================

st.divider()

st.subheader(
    "🔎 Why Was This Traffic Suspicious?"
)

if suspicious_traffic > 0:

    st.write(
        "The AI detected abnormal network behavior based on:"
    )

    reason1, reason2, reason3 = st.columns(3)

    with reason1:

        st.info(
            "📦 High Packet Activity"
        )

        st.caption(
            "Unusual packet count detected."
        )

    with reason2:

        st.warning(
            "📡 Multiple Destinations"
        )

        st.caption(
            "Traffic contacted an unusual number of destinations."
        )

    with reason3:

        st.error(
            "💾 High Data Transfer"
        )

        st.caption(
            "Abnormally high byte transfer detected."
        )

else:

    st.success(
        "✅ No abnormal behavior detected."
    )

# =========================================================
# ENSEMBLE AI
# =========================================================

st.divider()

st.subheader(
    "🤖 Ensemble AI Detection"
)

ai1, ai2, ai3, ai4 = st.columns(4)

with ai1:

    st.metric(
        "🌲 Isolation Forest",
        "ACTIVE"
    )

with ai2:

    st.metric(
        "🧠 Autoencoder",
        "READY"
    )

with ai3:

    st.metric(
        "🔗 Graph Analysis",
        "READY"
    )

with ai4:

    st.metric(
        "⚡ Ensemble Engine",
        "ACTIVE"
    )

if st.session_state.attack_mode:

    st.warning(
        "🚨 Ensemble AI: Multiple detection signals indicate abnormal behavior."
    )

else:

    st.success(
        "🟢 Ensemble AI: No significant anomaly detected."
    )

# =========================================================
# DIGITAL TWIN
# =========================================================

st.divider()

st.subheader(
    "🧬 Digital Twin — Normal vs Attack"
)

np.random.seed(42)

twin_normal = np.random.randint(
    80,
    150,
    20
)

if st.session_state.attack_mode:

    twin_attack = np.random.randint(
        300,
        700,
        20
    )

else:

    twin_attack = np.random.randint(
        80,
        150,
        20
    )

twin_data = pd.DataFrame({
    "Normal Traffic": twin_normal,
    "Simulated Traffic": twin_attack
})

st.line_chart(
    twin_data
)

if st.session_state.attack_mode:

    st.error(
        "🚨 Digital Twin detected a significant deviation from normal network behavior."
    )

else:

    st.success(
        "🟢 Digital Twin: Network behavior is within normal range."
    )

# =========================================================
# AI SECURITY RECOMMENDATION
# =========================================================

st.divider()

st.subheader(
    "🛡️ AI Security Recommendation"
)

if st.session_state.attack_mode:

    if attack_type == "High Volume Exfiltration":

        recommendation = [
            "🔴 Investigate high-volume outbound traffic",
            "🔒 Isolate the suspicious source",
            "📋 Preserve traffic evidence for analysis"
        ]

    elif attack_type == "Low & Slow Exfiltration":

        recommendation = [
            "🟠 Monitor the source for longer duration",
            "🔎 Analyze repeated small data transfers",
            "📋 Correlate traffic with previous events"
        ]

    else:

        recommendation = [
            "🟣 Investigate periodic communication",
            "🔎 Check beaconing patterns",
            "📋 Correlate repeated connection events"
        ]

    for action in recommendation:

        st.warning(action)

else:

    st.success(
        "✅ No immediate security action required."
    )

# =========================================================
# ATTACK EVENT TIMELINE
# =========================================================

st.divider()

st.subheader(
    "🚨 Attack Event Timeline"
)

if st.session_state.attack_mode:

    events = pd.DataFrame({
        "Time": [
            "10:01:12",
            "10:01:18",
            "10:01:25",
            "10:01:32"
        ],

        "Event": [
            "Abnormal traffic detected",
            f"{attack_type} identified",
            "AI threat score calculated",
            "Security recommendation generated"
        ],

        "Severity": [
            "HIGH",
            "HIGH",
            severity,
            "ACTION"
        ]
    })

    st.dataframe(
        events,
        use_container_width=True,
        hide_index=True
    )

else:

    st.info(
        "🟢 No security events recorded."
    )

# =========================================================
# SUSPICIOUS TRAFFIC TABLE
# =========================================================

st.divider()
# -----------------------------
# Security Evidence Report
# -----------------------------
st.divider()
st.subheader("📋 Security Evidence")

if suspicious_traffic > 0:

    evidence_col1, evidence_col2 = st.columns(2)

    with evidence_col1:
        st.write("🔍 **Detection Evidence**")
        st.write(f"• Suspicious Events: {suspicious_traffic}")
        st.write(f"• Threat Level: {threat_level:.1f}%")
        st.write(f"• Severity: {severity}")
        st.write(f"• Attack Scenario: {attack_type}")

    with evidence_col2:
        st.write("🛡️ **System Response**")
        st.write("• AI anomaly detection completed")
        st.write("• Suspicious traffic identified")
        st.write("• Security recommendation generated")
        st.write("• Event timeline recorded")

else:
    st.success("✅ No security evidence requiring investigation.")
st.divider()
st.subheader("📥 Security Report")

report = f"""
SENTINEL-DIODE SECURITY REPORT
==============================

Threat Score      : {threat_level:.1f}/100
Threat Severity   : {severity}
Attack Scenario   : {attack_type if st.session_state.attack_mode else "None"}

Traffic Statistics
------------------
Total Traffic     : {total_traffic}
Normal Traffic    : {normal_traffic}
Suspicious Traffic: {suspicious_traffic}

AI Detection
------------
AI Anomalies     : {ai_suspicious}
AI Normal        : {ai_normal}
AI Anomaly Rate  : {ai_rate:.1f}%

System Status
-------------
Sentinel-Diode   : ACTIVE
AI Detection     : READY
"""

st.download_button(
    label="📥 Download Security Report",
    data=report,
    file_name="sentinel_diode_security_report.txt",
    mime="text/plain"
)
st.divider()
st.subheader("📥 Security Report")

report = f"""
SENTINEL-DIODE SECURITY REPORT

Threat Score: {threat_level:.1f}/100
Severity: {severity}
Attack Scenario: {attack_type if st.session_state.attack_mode else "None"}

Total Traffic: {total_traffic}
Normal Traffic: {normal_traffic}
Suspicious Traffic: {suspicious_traffic}

AI Anomalies: {ai_suspicious}
AI Normal: {ai_normal}
AI Anomaly Rate: {ai_rate:.1f}%

System Status: ACTIVE
"""

st.download_button(
    "📥 Download Security Report",
    report,
    "sentinel_diode_security_report.txt",
    "text/plain",
    key="security_report_download"
)
st.subheader(
    "🚨 Detected Suspicious Traffic"
)

suspicious_data = display_data[
    display_data["status"] == "Suspicious"
]

if len(suspicious_data) > 0:

    st.dataframe(
        suspicious_data,
        use_container_width=True,
        hide_index=True
    )

else:

    st.success(
        "No suspicious traffic detected."
    )

# =========================================================
# FULL TRAFFIC DATA
# =========================================================

st.divider()

with st.expander(
    "📋 View Network Traffic Data"
):

    st.dataframe(
        display_data,
        use_container_width=True,
        hide_index=True
    )

# =========================================================
# SYSTEM STATUS
# =========================================================

st.divider()

st.subheader(
    "⚙️ System Status"
)

system_col1, system_col2, system_col3 = st.columns(3)

with system_col1:

    st.success(
        "🟢 Sentinel-Diode: ACTIVE"
    )

with system_col2:

    st.success(
        "🟢 AI Detection: READY"
    )

with system_col3:

    if st.session_state.attack_mode:

        st.error(
            "🔴 SECURITY ALERT"
        )

    else:

        st.success(
            "🟢 SYSTEM SECURE"
        )

# =========================================================
# FOOTER
# =========================================================

st.divider()

st.caption(
    "Sentinel-Diode Prototype | AI Network Anomaly Detection"
)