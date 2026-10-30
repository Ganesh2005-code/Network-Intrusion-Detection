import pandas as pd
import joblib
import matplotlib.pyplot as plt

from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay

# Load dataset
df = pd.read_csv("dataset/processed_dataset.csv")

X = df.drop("label", axis=1)
y = df["label"]

# Load model and scaler
model = joblib.load("models/random_forest_model.pkl")
scaler = joblib.load("models/scaler.pkl")

X = scaler.transform(X)

# Predictions
y_pred = model.predict(X)

# Confusion Matrix
cm = confusion_matrix(y, y_pred)

disp = ConfusionMatrixDisplay(
    confusion_matrix=cm,
    display_labels=["Attack","Normal"]
)

fig, ax = plt.subplots(figsize=(6,6))

disp.plot(
    cmap="Blues",
    values_format="d",
    ax=ax
)

plt.title("Confusion Matrix")

plt.savefig("static/confusion_matrix.png", dpi=300)

plt.show()

print("Confusion Matrix Saved Successfully!")