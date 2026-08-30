import os
import sys
import pickle

import numpy as np
from flask import Flask, render_template, request, jsonify

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
APP_DIR = os.path.dirname(__file__)

if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from features.feature_extraction import extract_features
from utils.url_cleaner import normalize_url, is_valid_url, is_url_reachable
from utils.helpers import interpret_result, confidence_score
from utils.url_checker import check_virustotal, check_google_safe_browsing

app = Flask(
    __name__,
    template_folder=os.path.join(APP_DIR, "templates"),
    static_folder=os.path.join(APP_DIR, "static")
)

MODEL_DIR = os.path.join(BASE_DIR, "models")
MODEL_PATH = os.path.join(MODEL_DIR, "model.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")
VECTORIZER_PATH = os.path.join(MODEL_DIR, "vectorizer.pkl")

def load_pickle_file(file_path, component_name):
    if not os.path.isfile(file_path):
        raise FileNotFoundError(
            f"{component_name} not found at: {file_path}. "
            "Make sure the trained .pkl files are included in the repository."
        )

    try:
        with open(file_path, "rb") as file:
            return pickle.load(file)
    except Exception as exc:
        raise RuntimeError(
            f"Failed to load {component_name}: {exc}"
        ) from exc

model = load_pickle_file(MODEL_PATH, "ML model")
scaler = load_pickle_file(SCALER_PATH, "feature scaler")
vectorizer = load_pickle_file(VECTORIZER_PATH, "TF-IDF vectorizer")

@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")

@app.route("/predict", methods=["POST"])
def predict():
    is_json_request = (
        request.is_json
        or request.headers.get("Accept", "").find("application/json") != -1
        or request.content_type == "application/json"
    )

    if request.is_json:
        data = request.get_json(silent=True) or {}
        user_input = str(data.get("url", "")).strip()
    else:
        user_input = request.form.get("url", "").strip()

    if not user_input:
        if is_json_request:
            return jsonify({
                "success": False,
                "error": "Please enter a URL."
            }), 400
        return render_template("index.html", prediction_text="Please enter a URL.")

    try:
        url = normalize_url(user_input)
    except Exception as exc:
        app.logger.error("URL normalization failed: %s", exc, exc_info=True)
        if is_json_request:
            return jsonify({
                "success": False,
                "error": "Unable to process the URL format."
            }), 400
        return render_template("index.html", prediction_text="Unable to process the URL.")

    if not is_valid_url(url):
        if is_json_request:
            return jsonify({
                "success": False,
                "error": "Please enter a valid URL."
            }), 400
        return render_template("index.html", prediction_text="Please enter a valid URL.")

    try:
        is_live = is_url_reachable(url)
        status = "🟢 Live" if is_live else "🔴 Dead"
    except Exception as exc:
        app.logger.warning("URL reachability check failed: %s", exc)
        status = "⚠️ Unable to determine"

    try:
        manual_features = extract_features(url)
        url_vector = vectorizer.transform([url]).toarray()[0]
        combined_features = np.hstack((manual_features, url_vector))
        features = combined_features.reshape(1, -1)
        features_scaled = scaler.transform(features)
    except Exception as exc:
        app.logger.error("Feature processing failed: %s", exc, exc_info=True)
        if is_json_request:
            return jsonify({
                "success": False,
                "error": "Unable to extract features from this URL."
            }), 500
        return render_template("index.html", prediction_text="Unable to process this URL. Please try another URL.")

    try:
        prediction = model.predict(features_scaled)[0]
        result = interpret_result(prediction)
        conf = confidence_score(model, features_scaled)
    except Exception as exc:
        app.logger.error("Model prediction failed: %s", exc, exc_info=True)
        if is_json_request:
            return jsonify({
                "success": False,
                "error": "The URL could not be analyzed by the prediction model."
            }), 500
        return render_template("index.html", prediction_text="The URL could not be analyzed by the prediction model.")

    try:
        vt_result = check_virustotal(url)
    except Exception as exc:
        app.logger.warning("VirusTotal check failed: %s", exc)
        vt_result = "Unavailable"

    try:
        google_result = check_google_safe_browsing(url)
    except Exception as exc:
        app.logger.warning("Google Safe Browsing check failed: %s", exc)
        google_result = "Unavailable"

    is_phishing = bool(prediction == 1)
    confidence_val = float(conf) if conf is not None else 85.0

    if is_json_request:
        return jsonify({
            "success": True,
            "url": url,
            "is_phishing": is_phishing,
            "result": result,
            "confidence": confidence_val,
            "status": status,
            "virustotal": vt_result,
            "google_safe_browsing": google_result
        })

    if conf:
        output = (
            f"{result} ({conf}% confidence)\n\n"
            f"Status: {status}\n"
            f"VirusTotal: {vt_result}\n"
            f"Google Safe Browsing: {google_result}"
        )
    else:
        output = (
            f"{result}\n\n"
            f"Status: {status}\n"
            f"VirusTotal: {vt_result}\n"
            f"Google Safe Browsing: {google_result}"
        )

    return render_template("index.html", prediction_text=output)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
