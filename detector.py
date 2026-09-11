import pandas as pd
from sklearn.ensemble import IsolationForest

# Load traffic data
data = pd.read_csv("traffic.csv")

# Features used by AI
features = [
    "packet_count",
    "byte_count",
    "duration",
    "destination_count"
]

# Create AI model
model = IsolationForest(
    contamination=0.15,
    random_state=42
)

# Detect anomalies
data["prediction"] = model.fit_predict(data[features])

# Convert prediction into status
data["status"] = data["prediction"].apply(
    lambda x: "Suspicious" if x == -1 else "Normal"
)

# Calculate threat score
data["anomaly_score"] = model.decision_function(
    data[features]
)

# Convert into 0-100 threat score
data["threat_score"] = (
    (1 - data["anomaly_score"]) * 50
).clip(0, 100)

# Save results
data.to_csv("detected_traffic.csv", index=False)

print("✅ AI detection completed!")
print()
print(data[
    [
        "packet_count",
        "byte_count",
        "status",
        "threat_score"
    ]
].head(20))