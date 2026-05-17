import pandas as pd

df = pd.read_csv("datasets/network_traffic.csv")
print(df.info())
print(df.describe())
print(df["threat"].value_counts()) ## counting threats
print(df["src_ip"].value_counts().head()) ## top 5 source IPs
print(df["protocol"].value_counts()) ## protocol distributions
large_packets = df[df["packet_size"] > 1000]
print(large_packets.shape[0]) ## count of large packets