import pandas as pd 
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import joblib

print("Starting model training...")

df = pd.read_csv("datasets/network_traffic.csv")

encoder = LabelEncoder()  ## tcp -> 0 , udp -> 1
df['protocol'] = encoder.fit_transform(df['protocol'])

features = df[[
    "protocol","packet_size"
]]

model = IsolationForest(
    n_estimators = 100,
    contamination=0.1,
    random_state=42
)

model.fit(features)

joblib.dump(model , "backend/models/anomaly_model.pkl")

print("model trained and saved successfully")