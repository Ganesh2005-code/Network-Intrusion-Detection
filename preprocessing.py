import pandas as pd
from sklearn.preprocessing import LabelEncoder

# NSL-KDD column names
columns = [
'duration','protocol_type','service','flag','src_bytes','dst_bytes',
'land','wrong_fragment','urgent','hot','num_failed_logins',
'logged_in','num_compromised','root_shell','su_attempted',
'num_root','num_file_creations','num_shells','num_access_files',
'num_outbound_cmds','is_host_login','is_guest_login',
'count','srv_count','serror_rate','srv_serror_rate',
'rerror_rate','srv_rerror_rate','same_srv_rate',
'diff_srv_rate','srv_diff_host_rate','dst_host_count',
'dst_host_srv_count','dst_host_same_srv_rate',
'dst_host_diff_srv_rate','dst_host_same_src_port_rate',
'dst_host_srv_diff_host_rate','dst_host_serror_rate',
'dst_host_srv_serror_rate','dst_host_rerror_rate',
'dst_host_srv_rerror_rate','label','difficulty'
]

# Load dataset
df = pd.read_csv(
    "dataset/KDDTrain+.txt",
    names=columns
)

print("Dataset Loaded Successfully!\n")
print(df.head())

print("\nDataset Shape:")
print(df.shape)

print("\nMissing Values:")
print(df.isnull().sum())

# Show attack types
print("\nAttack Types:")
print(df["label"].value_counts())

# Convert labels into binary classes
df["label"] = df["label"].apply(
    lambda x: "Normal" if x == "normal" else "Attack"
)

print("\nBinary Labels:")
print(df["label"].value_counts())

# Drop difficulty column
df.drop("difficulty", axis=1, inplace=True)

print("\nDataset Shape After Dropping Difficulty:")
print(df.shape)

# Encode categorical features
encoder = LabelEncoder()

# Encode categorical features
from sklearn.preprocessing import LabelEncoder
import joblib
import os

# Create models directory if it does not exist
os.makedirs("models", exist_ok=True)

# Protocol encoder
protocol_encoder = LabelEncoder()
df["protocol_type"] = protocol_encoder.fit_transform(
    df["protocol_type"]
)

# Service encoder
service_encoder = LabelEncoder()
df["service"] = service_encoder.fit_transform(
    df["service"]
)

# Flag encoder
flag_encoder = LabelEncoder()
df["flag"] = flag_encoder.fit_transform(
    df["flag"]
)

# Label encoder
label_encoder = LabelEncoder()
df["label"] = label_encoder.fit_transform(
    df["label"]
)

# Save encoders
joblib.dump(
    protocol_encoder,
    "models/protocol_encoder.pkl"
)

joblib.dump(
    service_encoder,
    "models/service_encoder.pkl"
)

joblib.dump(
    flag_encoder,
    "models/flag_encoder.pkl"
)

joblib.dump(
    label_encoder,
    "models/label_encoder.pkl"
)

print("\nEncoders saved successfully!")

print("\nProcessed Dataset:")
print(df.head())

# Save processed dataset
df.to_csv("dataset/processed_dataset.csv", index=False)

print("\nProcessed dataset saved successfully!")