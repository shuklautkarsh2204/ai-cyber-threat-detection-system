from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime
import pandas as pd

# Store packet data
packet_data = []

# Track packet frequency from IPs
ip_count = {}

# Common suspicious ports
suspicious_ports = [21, 22, 23, 3389]


def process_packet(packet):

    if packet.haslayer(IP):

        # Basic packet information
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_size = len(packet)
        timestamp = datetime.now()

        src_port = None
        dst_port = None
        protocol = "OTHER"

        # Detect protocol and ports
        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # Default threat status
        threat = "Normal"

        # -----------------------------
        # Rule 1: Large Packet Detection
        # -----------------------------
        if packet_size > 1000:
            threat = "Suspicious"
            print("WARNING: Large packet detected")

        # -----------------------------
        # Rule 2: Suspicious Port Access
        # -----------------------------
        if dst_port in suspicious_ports:
            threat = "Suspicious"
            print(f"WARNING: Suspicious port access on port {dst_port}")

        # -----------------------------
        # Rule 3: Possible Flooding
        # -----------------------------
        if src_ip not in ip_count:
            ip_count[src_ip] = 0

        ip_count[src_ip] += 1

        if ip_count[src_ip] > 20:
            threat = "Suspicious"
            print(f"WARNING: Possible flooding from IP {src_ip}")

        # Store packet information
        packet_info = {
            "timestamp": str(timestamp),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "packet_size": packet_size,
            "src_port": src_port,
            "dst_port": dst_port,
            "threat": threat
        }

        packet_data.append(packet_info)

        # Print packet information
        print(packet_info)


# Start sniffing
print("Starting packet capture...")

sniff(
    prn=process_packet,
    store=False,
    count=100
)

# Save data to CSV
df = pd.DataFrame(packet_data)

df.to_csv("network_traffic.csv", index=False)

print("Packet capture completed!")
print("CSV file saved successfully!")