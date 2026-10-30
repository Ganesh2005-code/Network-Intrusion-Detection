import pandas as pd
import matplotlib.pyplot as plt

# Load processed dataset
df = pd.read_csv("dataset/processed_dataset.csv")

print(df.head())

# Label distribution
print(df["label"].value_counts())

# Create bar chart
df["label"].value_counts().plot(kind="bar")

plt.title("Normal vs Attack")
plt.xlabel("Class")
plt.ylabel("Count")

plt.show()