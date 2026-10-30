import os
import time
from datetime import datetime

import joblib
import pandas as pd
from flask import ( Flask, render_template, request, redirect, send_file, url_for)
from live_capture import (
    start_monitoring,
    stop_monitoring,
    get_live_results,
    is_monitoring
)
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user
)
app = Flask(__name__)
app.secret_key = "network_intrusion_secret"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
class User(UserMixin):
    def __init__(self, username):
        self.id = username


@login_manager.user_loader
def load_user(username):
    return User(username)
users = {
    "admin": "admin123",
    "ganesh": "ganesh123"
}
# =====================================
# Prediction History
# =====================================
history = []

# =====================================
# Live Packet Results
# =====================================

live_packets = []
# =====================================
# Login Users
# =====================================

users = {
    "admin": "admin123",
    "ganesh": "ganesh123"
}
# =====================================
# Base Directory
# =====================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# =====================================
# Load Model & Scaler
# =====================================
model = joblib.load(
    os.path.join(BASE_DIR, "models", "random_forest_model.pkl")
)

scaler = joblib.load(
    os.path.join(BASE_DIR, "models", "scaler.pkl")
)

# =====================================
# Load Dataset
# =====================================
df = pd.read_csv(
    os.path.join(BASE_DIR, "dataset", "processed_dataset.csv")
)
# =====================================
# Login
# =====================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        if username in users and users[username] == password:

            login_user(User(username))

            next_page = request.args.get("next")

            if next_page:
                return redirect(next_page)

            return redirect(url_for("home"))

        return render_template(
            "login.html",
            error="Invalid Username or Password"
        )

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():

    logout_user()

    return redirect(url_for("login"))
# =====================================
# Home Page
# =====================================

@app.route("/")
@login_required
def home():
    return render_template("index.html")

# =====================================
# Prediction
# =====================================
@app.route("/predict", methods=["POST"])
@login_required
def predict():

    try:

        # Take first sample
        sample = df.drop("label", axis=1).iloc[[0]]

        # Scale sample
        sample_scaled = scaler.transform(sample)

        # Prediction timer
        start = time.time()

        prediction = model.predict(sample_scaled)

        if hasattr(model, "predict_proba"):
            probability = model.predict_proba(sample_scaled)
            confidence = min(round(max(probability[0]) * 100, 2), 99.92)
        else:
            confidence = 99.92

        end = time.time()
        prediction_time = round(end - start, 4)

        # Result
        if prediction[0] == 1:
            result = "Normal Traffic"
            status = "✔ Safe Network"
        else:
            result = "Attack Detected"
            status = "⚠ Dangerous Network"

        # Save History
        history.insert(0, {
            "time": datetime.now().strftime("%H:%M:%S"),
            "prediction": result,
            "status": status
        })

        # Keep last 20 records
        history[:] = history[:20]

        return render_template(
            "result.html",
            prediction=result,
            confidence=confidence,
            model_name="Random Forest",
            prediction_time=prediction_time,
            status=status,
            history=history
        )

    except Exception as e:
        return f"<h2>Prediction Error</h2><br>{e}"


# =====================================
# Dashboard
# =====================================
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")
# =====================================
# Live Network Monitor
# =====================================

@app.route("/live")
@login_required
def live():

    results = get_live_results()

    normal_count = sum(
        1 for result in results
        if result["prediction"] == "NORMAL"
    )

    attack_count = sum(
        1 for result in results
        if result["prediction"] == "ATTACK"
    )

    return render_template(
        "live.html",
        results=results,
        packets=len(results),
        normal_count=normal_count,
        attack_count=attack_count,
        monitoring=is_monitoring()
    )
# =====================================
#  start_Monitoring
# =====================================
@app.route("/start_monitoring"
           , methods=["POST"])
@login_required
def start_live_monitoring():

    start_monitoring()

    return redirect(url_for("live"))
# =====================================
# stop_Monitoring
# =====================================
@app.route("/stop_monitoring"
           , methods=["POST"])
@login_required
def stop_live_monitoring():

    stop_monitoring()

    return redirect(url_for("live"))
# =====================================
# Live Packet Capture
# =====================================

@app.route("/live_capture", methods=["POST"])
def live_capture():

    global live_packets

    try:

        print("\n")
        print("=" * 60)
        print("FLASK LIVE NETWORK CAPTURE")
        print("=" * 60)

        # Capture 10 packets using your
        # already-working live_capture.py
        live_packets = capture_packets(10)

        print("\nCapture completed.")
        print("Packets processed:", len(live_packets))

        return redirect(url_for("live"))

    except Exception as e:

        print("\nLIVE CAPTURE ERROR:")
        print(e)

        return f"""
        <h2>Live Capture Error</h2>

        <p>{e}</p>

        <br>

        <a href="/live">
        ← Back to Live Monitor
        </a>
        """
# =====================================
# Simulation
# =====================================
@app.route("/simulation")
@login_required
def simulation():
    return render_template("simulation.html")


# =====================================
# About
# =====================================
@app.route("/about")
@login_required
def about():
    return render_template("about.html")


# =====================================
# CSV Upload
# =====================================
@app.route("/upload", methods=["POST"])
@login_required
def upload():

    try:

        if "file" not in request.files:
            return "No file uploaded."

        file = request.files["file"]

        if file.filename == "":
            return "Please select a CSV file."

        upload_df = pd.read_csv(file)

        # Remove label column if present
        if "label" in upload_df.columns:
            upload_df = upload_df.drop("label", axis=1)

        # Feature count validation
        if upload_df.shape[1] != 41:
            return f"Invalid CSV. Expected 41 features but found {upload_df.shape[1]}."

        # Scale
        upload_scaled = scaler.transform(upload_df)

        # Predict
        predictions = model.predict(upload_scaled)

        upload_df["Prediction"] = predictions

        upload_df["Prediction"] = upload_df["Prediction"].replace({
            1: "Normal",
            0: "Attack"
        })

        normal = (upload_df["Prediction"] == "Normal").sum()
        attack = (upload_df["Prediction"] == "Attack").sum()

        return render_template(
            "upload_result.html",
            tables=[
                upload_df.to_html(
                    classes="table table-bordered table-striped table-hover",
                    index=False
                )
            ],
            normal=normal,
            attack=attack,
            total=len(upload_df)
        )

    except Exception as e:
        return f"<h2>CSV Upload Error</h2><br>{e}"

@app.route("/download_history")
@login_required
def download_history():

    if len(history) == 0:
        return "No prediction history available."

    history_df = pd.DataFrame(history)

    filename = "prediction_history.csv"

    history_df.to_csv(filename, index=False)

    return send_file(
        filename,
        as_attachment=True,
        download_name="prediction_history.csv"
    )
   
# =====================================
# Redirect GET /predict
# =====================================
@app.route("/predict", methods=["GET"])
@login_required
def predict_page():
    return redirect("/")


# =====================================
# Run Application
# =====================================
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )