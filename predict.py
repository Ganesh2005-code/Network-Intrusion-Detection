import joblib
import pandas as pd

# Load trained model and scaler
model = joblib.load("models/random_forest_model.pkl")
scaler = joblib.load("models/scaler.pkl")

# Load processed dataset
df = pd.read_csv("dataset/processed_dataset.csv")

# Take one sample (remove label column)
sample = df.drop("label", axis=1).iloc[[0]]

print("Sample Data:")
print(sample)

# Scale the sample
sample_scaled = scaler.transform(sample)

# Predict
prediction = model.predict(sample_scaled)

if prediction[0] == 0:
    print("\nPrediction: Attack")
else:
    print("\nPrediction: Normal")