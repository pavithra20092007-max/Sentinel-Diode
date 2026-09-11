import pandas as pd
import numpy as np

np.random.seed(42)

# Normal network traffic
normal_data = pd.DataFrame({
    "packet_count": np.random.randint(80, 150, 100),
    "byte_count": np.random.randint(5000, 15000, 100),
    "duration": np.random.uniform(1, 5, 100),
    "destination_count": np.random.randint(1, 5, 100)
})

# Suspicious network traffic
suspicious_data = pd.DataFrame({
    "packet_count": np.random.randint(300, 600, 20),
    "byte_count": np.random.randint(30000, 80000, 20),
    "duration": np.random.uniform(0.1, 1, 20),
    "destination_count": np.random.randint(8, 20, 20)
})

# Combine both
data = pd.concat(
    [normal_data, suspicious_data],
    ignore_index=True
)

# Save data
data.to_csv("traffic.csv", index=False)

print("✅ Traffic data generated successfully!")
print(data.head())