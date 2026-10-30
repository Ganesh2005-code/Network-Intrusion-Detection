import joblib
import pandas as pd

from scapy.all import sniff, IP

from feature_extractor import process_packet, build_features, flows


# ============================================================
# LOAD MODEL
# ============================================================

model = joblib.load(
    "models/random_forest_model.pkl"
)

scaler = joblib.load(
    "models/scaler.pkl"
)


# ============================================================
# LOAD ENCODERS
# ============================================================

protocol_encoder = joblib.load(
    "models/protocol_encoder.pkl"
)

service_encoder = joblib.load(
    "models/service_encoder.pkl"
)

flag_encoder = joblib.load(
    "models/flag_encoder.pkl"
)


# ============================================================
# EXPECTED 41 FEATURES
# ============================================================

expected_columns = [

    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate"
]


# ============================================================
# PACKET COUNTER
# ============================================================

packet_number = 0


# ============================================================
# HANDLE PACKET
# ============================================================

def handle_packet(packet):

    global packet_number

    packet_number += 1

    print()
    print("-" * 60)

    print(
        f"Packet #{packet_number} captured"
    )

    # --------------------------------------------------------
    # Check IP
    # --------------------------------------------------------

    if IP not in packet:

        print("Not an IP packet - skipped")

        return


    # --------------------------------------------------------
    # Extract packet information
    # --------------------------------------------------------

    packet_info = process_packet(packet)

    if packet_info is None:

        print("Could not extract packet information")

        return


    print(
        "Source IP:",
        packet_info["source_ip"]
    )

    print(
        "Destination IP:",
        packet_info["destination_ip"]
    )

    print(
        "Protocol:",
        packet_info["protocol"]
    )

    print(
        "Service:",
        packet_info["service"]
    )

    print(
        "Flag:",
        packet_info["flag"]
    )

    print(
        "Packet Size:",
        packet_info["packet_size"]
    )


    # --------------------------------------------------------
    # Find flow
    # --------------------------------------------------------

    flow_key = (

        packet_info["source_ip"],

        packet_info["destination_ip"],

        packet_info["protocol"],

        packet_info["service"]

    )


    if flow_key not in flows:

        print("Flow not found")

        return


    flow = flows[flow_key]


    # --------------------------------------------------------
    # Build features
    # --------------------------------------------------------

    features = build_features(flow)


    feature_df = pd.DataFrame(
        [features]
    )


    # --------------------------------------------------------
    # Check columns
    # --------------------------------------------------------

    feature_df = feature_df[
        expected_columns
    ]


    print()
    print(
        "Features extracted:",
        feature_df.shape[1]
    )


    # ========================================================
    # ENCODE CATEGORICAL FEATURES
    # ========================================================

    try:

        feature_df["protocol_type"] = (
            protocol_encoder.transform(
                feature_df["protocol_type"]
            )
        )

        feature_df["service"] = (
            service_encoder.transform(
                feature_df["service"]
            )
        )

        feature_df["flag"] = (
            flag_encoder.transform(
                feature_df["flag"]
            )
        )


    except ValueError as e:

        print()
        print("ENCODER ERROR:")
        print(e)

        print()
        print(
            "This live packet contains a category "
            "that was not present during training."
        )

        return


    # --------------------------------------------------------
    # Show encoded values
    # --------------------------------------------------------

    print()
    print("Encoded categorical features:")

    print(
        "protocol_type:",
        feature_df["protocol_type"].iloc[0]
    )

    print(
        "service:",
        feature_df["service"].iloc[0]
    )

    print(
        "flag:",
        feature_df["flag"].iloc[0]
    )


    # ========================================================
    # SCALE FEATURES
    # ========================================================

    try:

        print()
        print(
            "Sending features to scaler..."
        )

        scaled_features = scaler.transform(
            feature_df
        )

        print(
            "Scaling successful."
        )


    except Exception as e:

        print()
        print("SCALER ERROR:")
        print(e)

        return


    # ========================================================
    # MACHINE LEARNING PREDICTION
    # ========================================================

    try:

        prediction = model.predict(
            scaled_features
        )


        # ----------------------------------------------------
        # Probability
        # ----------------------------------------------------

        if hasattr(model, "predict_proba"):

            probability = model.predict_proba(
                scaled_features
            )

            confidence = round(
                max(probability[0]) * 100,
                2
            )

        else:

            confidence = None


        # ----------------------------------------------------
        # Result
        # ----------------------------------------------------

        print()
        print("=" * 60)

        if prediction[0] == 1:

            print(
                "Prediction: NORMAL TRAFFIC"
            )

        else:

            print(
                "Prediction: ATTACK DETECTED"
            )


        if confidence is not None:

            print(
                "Confidence:",
                confidence,
                "%"
            )


        print("=" * 60)


    except Exception as e:

        print()
        print("MODEL ERROR:")
        print(e)


# ============================================================
# START CAPTURE
# ============================================================

print("=" * 60)

print(
    "LIVE PACKET → MACHINE LEARNING TEST"
)

print("=" * 60)

print()

print(
    "Capturing 10 IP packets..."
)

print(
    "Please generate network traffic."
)

print(
    "Open a website or refresh a browser page."
)

print()


sniff(
    filter="ip",
    count=10,
    prn=handle_packet,
    store=False
)


print()

print("=" * 60)

print(
    "Live ML test completed."
)

print("=" * 60)