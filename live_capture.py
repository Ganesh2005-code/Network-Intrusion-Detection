import os
import joblib
import pandas as pd
import threading
import time

from scapy.all import sniff, IP

from feature_extractor import process_packet, build_features


# ============================================================
# Base directory
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ============================================================
# Continuous monitoring
# ============================================================

monitoring = False

monitor_thread = None

live_results = []

results_lock = threading.Lock()
# ============================================================
# Load ML components
# ============================================================

model = joblib.load(
    os.path.join(BASE_DIR, "models", "random_forest_model.pkl")
)

scaler = joblib.load(
    os.path.join(BASE_DIR, "models", "scaler.pkl")
)

protocol_encoder = joblib.load(
    os.path.join(BASE_DIR, "models", "protocol_encoder.pkl")
)

service_encoder = joblib.load(
    os.path.join(BASE_DIR, "models", "service_encoder.pkl")
)

flag_encoder = joblib.load(
    os.path.join(BASE_DIR, "models", "flag_encoder.pkl")
)


# ============================================================
# Feature order
# ============================================================

FEATURE_COLUMNS = [
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
# Encode live categorical features
# ============================================================

def encode_features(features):

    features["protocol_type"] = protocol_encoder.transform(
        [features["protocol_type"]]
    )[0]

    features["service"] = service_encoder.transform(
        [features["service"]]
    )[0]

    features["flag"] = flag_encoder.transform(
        [features["flag"]]
    )[0]

    return features


# ============================================================
# Analyze one packet
# ============================================================

def analyze_packet(packet):

    try:

        if IP not in packet:
            return None

        packet_info = process_packet(packet)

        if packet_info is None:
            return None

        # Get flow
        from feature_extractor import flows

        flow_key = (
            packet_info["source_ip"],
            packet_info["destination_ip"],
            packet_info["protocol"],
            packet_info["service"]
        )

        flow = flows[flow_key]

        # Build 41 NSL-KDD features
        features = build_features(flow)

        # Encode categorical features
        features = encode_features(features)

        # DataFrame
        input_df = pd.DataFrame(
            [features],
            columns=FEATURE_COLUMNS
        )

        # Scale
        scaled_features = scaler.transform(input_df)

        # Prediction
        prediction = model.predict(scaled_features)[0]

        # Confidence
        if hasattr(model, "predict_proba"):

            probabilities = model.predict_proba(
                scaled_features
            )[0]

            confidence = round(
                max(probabilities) * 100,
                2
            )

        else:

            confidence = 0.0

        # Prediction label
        if prediction == 1:

            result = "NORMAL"

        else:

            result = "ATTACK"

        return {

            "source_ip": packet_info["source_ip"],

            "destination_ip": packet_info["destination_ip"],

            "protocol": packet_info["protocol"].upper(),

            "service": packet_info["service"],

            "flag": packet_info["flag"],

            "packet_size": packet_info["packet_size"],

            "prediction": result,

            "confidence": confidence,

            "time": packet_info["time"]

        }

    except Exception as e:

        print("Live packet error:", e)

        return None


# ============================================================
# Capture packets
# ============================================================

def capture_packets(count=10):

    results = []

    print()
    print("=" * 60)
    print("LIVE NETWORK PACKET CAPTURE")
    print("=" * 60)
    print()
    print(f"Capturing {count} packets...")
    print("Generate network traffic by opening a website.")
    print()

    packets = sniff(
        filter="ip",
        count=count
    )

    for packet in packets:

        result = analyze_packet(packet)

        if result:

            results.append(result)

    return results

# ============================================================
# Continuous Live Monitoring
# ============================================================

def continuous_monitor():

    global monitoring
    global live_results

    print()
    print("=" * 60)
    print("CONTINUOUS LIVE MONITORING STARTED")
    print("=" * 60)
    print()

    while monitoring:

        try:

            # Capture one IP packet
            packets = sniff(
                filter="ip",
                count=1,
                timeout=2
            )

            if not packets:
                continue

            packet = packets[0]

            # Analyze packet using existing ML pipeline
            result = analyze_packet(packet)

            if result:

                with results_lock:

                    live_results.append(result)

                    # Keep only latest 100 packets
                    if len(live_results) > 100:

                        live_results.pop(0)

                print(
                    "Packet:",
                    result["source_ip"],
                    "→",
                    result["destination_ip"],
                    "|",
                    result["prediction"],
                    "|",
                    result["confidence"],
                    "%"
                )

        except Exception as e:

            print(
                "Continuous monitoring error:",
                e
            )

            time.sleep(1)

    print()
    print("=" * 60)
    print("CONTINUOUS LIVE MONITORING STOPPED")
    print("=" * 60)


# ============================================================
# Start Monitoring
# ============================================================

def start_monitoring():

    global monitoring
    global monitor_thread
    global live_results

    if monitoring:

        return False

    with results_lock:

        live_results.clear()

    monitoring = True

    monitor_thread = threading.Thread(
        target=continuous_monitor,
        daemon=True
    )

    monitor_thread.start()

    return True


# ============================================================
# Stop Monitoring
# ============================================================

def stop_monitoring():

    global monitoring

    monitoring = False

    return True


# ============================================================
# Get Live Results
# ============================================================

def get_live_results():

    with results_lock:

        return list(live_results)
    # ============================================================
# Monitoring Status
# ============================================================

def is_monitoring():

    return monitoring
# ============================================================
# Test
# ============================================================

if __name__ == "__main__":

    results = capture_packets(10)

    print()

    print("=" * 60)
    print("LIVE ML RESULTS")
    print("=" * 60)

    for i, result in enumerate(results, 1):

        print()
        print(f"Packet #{i}")

        print(
            "Source:",
            result["source_ip"]
        )

        print(
            "Destination:",
            result["destination_ip"]
        )

        print(
            "Protocol:",
            result["protocol"]
        )

        print(
            "Service:",
            result["service"]
        )

        print(
            "Prediction:",
            result["prediction"]
        )

        print(
            "Confidence:",
            result["confidence"],
            "%"
        )

    print()
    print("=" * 60)