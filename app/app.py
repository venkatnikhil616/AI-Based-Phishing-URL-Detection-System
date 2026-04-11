from flask import Flask, render_template, request
import pickle
import os
import sys
import numpy as np

# fix import path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from features.feature_extraction import extract_features
from utils.url_cleaner import normalize_url, is_valid_url, is_url_reachable
from utils.helpers import interpret_result, confidence_score
from utils.url_checker import check_virustotal, check_google_safe_browsing

app = Flask(__name__)

# ---------------------------
# LOAD MODEL COMPONENTS
# ---------------------------

MODEL_PATH = os.path.join("models", "model.pkl")
SCALER_PATH = os.path.join("models", "scaler.pkl")
VECTORIZER_PATH = os.path.join("models", "vectorizer.pkl")

with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

with open(SCALER_PATH, "rb") as f:
    scaler = pickle.load(f)

with open(VECTORIZER_PATH, "rb") as f:
    vectorizer = pickle.load(f)


# ---------------------------
# ROUTES
# ---------------------------

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    user_input = request.form.get("url")

    if not user_input:
        return render_template("index.html", prediction_text="Please enter a URL")

    # ---------------------------
    # NORMALIZE + VALIDATE
    # ---------------------------
    url = normalize_url(user_input)

    if not is_valid_url(url):
        return render_template("index.html", prediction_text="Please enter a valid URL")

    # ---------------------------
    # LIVE / DEAD CHECK
    # ---------------------------
    is_live = is_url_reachable(url)
    status = "🟢 Live" if is_live else "🔴 Dead"

    # ---------------------------
    # FEATURE PROCESSING
    # ---------------------------
    manual_features = extract_features(url)
    url_vector = vectorizer.transform([url]).toarray()[0]

    combined_features = np.hstack((manual_features, url_vector))
    features = combined_features.reshape(1, -1)

    features_scaled = scaler.transform(features)

    # ---------------------------
    # ML PREDICTION
    # ---------------------------
    prediction = model.predict(features_scaled)[0]
    result = interpret_result(prediction)

    conf = confidence_score(model, features_scaled)

    # ---------------------------
    # EXTERNAL API CHECKS
    # ---------------------------
    vt_result = check_virustotal(url)
    google_result = check_google_safe_browsing(url)

    # ---------------------------
    # FINAL OUTPUT
    # ---------------------------
    if conf:
        output = f"""
{result} ({conf}% confidence)

Status: {status}
VirusTotal: {vt_result}
Google Safe Browsing: {google_result}
"""
    else:
        output = f"""
{result}

Status: {status}
VirusTotal: {vt_result}
Google Safe Browsing: {google_result}
"""

    return render_template("index.html", prediction_text=output)


# ---------------------------
# RUN APP
# ---------------------------

if __name__ == "__main__":
    app.run(debug=True)
