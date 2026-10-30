import pandas as pd
import joblib
import matplotlib.pyplot as plt

from sklearn.metrics import roc_curve, auc

# Load dataset
df = pd.read_csv("dataset/processed_dataset.csv")

# Features and labels
X = df.drop("label", axis=1)
y = df["label"]

# Load scaler and model
scaler = joblib.load("models/scaler.pkl")
model = joblib.load("models/random_forest_model.pkl")

# Scale features
X = scaler.transform(X)

# Predict probabilities
y_score = model.predict_proba(X)[:, 1]

# ROC
fpr, tpr, _ = roc_curve(y, y_score)
roc_auc = auc(fpr, tpr)

# Plot
plt.figure(figsize=(7,6))
plt.plot(fpr, tpr,
         color="blue",
         linewidth=3,
         label=f"ROC Curve (AUC = {roc_auc:.3f})")

plt.plot([0,1],[0,1],
         linestyle="--",
         color="red")

plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title("ROC Curve - Random Forest")
plt.legend(loc="lower right")
plt.grid(True)

plt.savefig("static/roc_curve.png", dpi=300)

plt.show()

print("ROC Curve Saved Successfully!")
print("AUC =", roc_auc)