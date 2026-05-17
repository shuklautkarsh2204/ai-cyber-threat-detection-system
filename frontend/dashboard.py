import streamlit as st
import pandas as pd
from streamlit_autorefresh import st_autorefresh

# =========================
# Page Config
# =========================

st.set_page_config(
    page_title="AI Cyber Threat Detection System",
    page_icon="🛡️",
    layout="wide"
)

# =========================
# Auto Refresh
# =========================

st_autorefresh(
    interval=5000,
    key="refresh"
)

# =========================
# Load Dataset
# =========================

df = pd.read_csv("datasets/network_traffic.csv")

# Clean columns
df.columns = df.columns.str.strip()

df["threat"] = (
    df["threat"]
    .astype(str)
    .str.strip()
    .str.capitalize()
)

df["protocol"] = (
    df["protocol"]
    .astype(str)
    .str.strip()
    .str.upper()
)

# =========================
# Sidebar
# =========================

st.sidebar.title("Dashboard Controls")

protocol_filter = st.sidebar.multiselect(
    "Select Protocol",
    options=df["protocol"].unique(),
    default=df["protocol"].unique()
)

filtered_df = df[
    df["protocol"].isin(protocol_filter)
]

# =========================
# Metrics
# =========================

total_packets = len(filtered_df)

suspicious_packets = (
    filtered_df["threat"] == "Suspicious"
).sum()

normal_packets = (
    filtered_df["threat"] == "Normal"
).sum()

threat_percentage = (
    (suspicious_packets / total_packets) * 100
    if total_packets > 0
    else 0
)

# =========================
# Title
# =========================

st.title("🛡️ AI Cyber Threat Detection System")

st.markdown("---")

# =========================
# Top Metrics
# =========================

col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Total Packets",
    total_packets
)

col2.metric(
    "Suspicious Packets",
    suspicious_packets
)

col3.metric(
    "Normal Packets",
    normal_packets
)

col4.metric(
    "Threat %",
    f"{threat_percentage:.2f}%"
)

st.markdown("---")

# =========================
# Charts Section
# =========================

chart1, chart2 = st.columns(2)

# Threat Distribution
with chart1:

    st.subheader("Threat Distribution")

    st.bar_chart(
        filtered_df["threat"].value_counts()
    )

# Protocol Distribution
with chart2:

    st.subheader("Protocol Distribution")

    st.bar_chart(
        filtered_df["protocol"].value_counts()
    )

st.markdown("---")

# =========================
# Packet Size Analysis
# =========================

st.subheader("Packet Size Analysis")

st.line_chart(
    filtered_df["packet_size"]
)

st.markdown("---")

# =========================
# Recent Suspicious Alerts
# =========================

st.subheader("🚨 Recent Suspicious Alerts")

suspicious_df = filtered_df[
    filtered_df["threat"] == "Suspicious"
]

st.dataframe(
    suspicious_df.tail(20),
    use_container_width=True
)

st.markdown("---")

# =========================
# Top Source IPs
# =========================

st.subheader("Top Source IPs")

if "src_ip" in filtered_df.columns:

    top_ips = (
        filtered_df["src_ip"]
        .value_counts()
        .head(10)
    )

    st.bar_chart(top_ips)

st.markdown("---")

# =========================
# Full Dataset
# =========================

st.subheader("Complete Network Traffic Data")

st.dataframe(
    filtered_df,
    use_container_width=True
)