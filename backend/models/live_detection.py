import joblib
import pandas as pd
from datetime import datetime

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

# Load trained model
model = joblib.load("backend/models/anomaly_model.pkl")

print("Model loaded successfully!")
print("Starting live AI threat detection...\n")


def process_packet(packet):

    if packet.haslayer(IP):

        # =========================
        # Packet Information
        # =========================

        timestamp = datetime.now()

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        packet_size = len(packet)

        protocol = "OTHER"

        src_port = None
        dst_port = None

        # =========================
        # Protocol Detection
        # =========================

        if packet.haslayer(TCP):

            protocol = "TCP"

            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        elif packet.haslayer(UDP):

            protocol = "UDP"

            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # =========================
        # Protocol Encoding
        # =========================

        protocol_map = {
            "OTHER": 0,
            "TCP": 1,
            "UDP": 2
        }

        protocol_encoded = protocol_map[protocol]

        # =========================
        # Create Features
        # =========================

        features = pd.DataFrame([{
            "protocol": protocol_encoded,
            "packet_size": packet_size
        }])

        # =========================
        # Predict Threat
        # =========================

        prediction = model.predict(features)

        threat = (
            "Suspicious"
            if prediction[0] == -1
            else "Normal"
        )

        # =========================
        # Packet Dictionary
        # =========================

        packet_info = {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "packet_size": packet_size,
            "src_port": src_port,
            "dst_port": dst_port,
            "threat": threat
        }

        # =========================
        # Print Output
        # =========================

        print(packet_info)

        # =========================
        # Append To CSV
        # =========================

        live_df = pd.DataFrame([packet_info])

        live_df.to_csv(
            "datasets/network_traffic.csv",
            mode="a",
            header=False,
            index=False
        )


# =========================
# Start Sniffing
# =========================

sniff(
    prn=process_packet,
    store=False
)