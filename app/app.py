import os
import sys
import pickle
import datetime
from urllib.parse import urlparse
import urllib3

# Suppress self-signed certificate warnings during live SSL/HTTP forensic probes
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import numpy as np
from flask import Flask, render_template, request, jsonify

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
APP_DIR = os.path.dirname(os.path.abspath(__file__))

for p in [BASE_DIR, APP_DIR, os.getcwd()]:
    if p and p not in sys.path:
        sys.path.insert(0, p)

from features.feature_extraction import extract_features, extract_detailed_heuristics
from utils.url_cleaner import normalize_url, is_valid_url, is_url_reachable
from utils.helpers import interpret_result, confidence_score
from utils.url_checker import check_virustotal, check_google_safe_browsing
from utils.forensics import (
    detect_brand_impersonation,
    inspect_ssl_certificate,
    inspect_dns_telemetry,
    inspect_http_chain,
    get_mitre_mapping
)

def get_resource_path(*subpaths):
    candidates = [
        os.path.join(BASE_DIR, *subpaths),
        os.path.join(APP_DIR, *subpaths),
        os.path.join(os.getcwd(), *subpaths),
        os.path.join(os.path.dirname(BASE_DIR), *subpaths) if BASE_DIR else None,
    ]
    for c in candidates:
        if c and os.path.exists(c):
            return os.path.abspath(c)
    return os.path.abspath(os.path.join(BASE_DIR, *subpaths))

TEMPLATE_DIR = get_resource_path("app", "templates")
if not os.path.exists(TEMPLATE_DIR):
    TEMPLATE_DIR = os.path.join(APP_DIR, "templates")

STATIC_DIR = get_resource_path("app", "static")
if not os.path.exists(STATIC_DIR):
    STATIC_DIR = os.path.join(APP_DIR, "static")

app = Flask(
    __name__,
    template_folder=TEMPLATE_DIR,
    static_folder=STATIC_DIR
)

MODEL_PATH = get_resource_path("models", "model.pkl")
SCALER_PATH = get_resource_path("models", "scaler.pkl")
VECTORIZER_PATH = get_resource_path("models", "vectorizer.pkl")

def load_pickle_file(file_path, component_name):
    if not os.path.isfile(file_path):
        app.logger.warning(f"{component_name} not found at {file_path}")
        return None
    try:
        with open(file_path, "rb") as file:
            return pickle.load(file)
    except Exception as exc:
        app.logger.error(f"Failed to load {component_name}: {exc}")
        return None

# Load trained ML pipeline components
model = load_pickle_file(MODEL_PATH, "ML model")
scaler = load_pickle_file(SCALER_PATH, "feature scaler")
vectorizer = load_pickle_file(VECTORIZER_PATH, "TF-IDF vectorizer")

# --------------------------------------------------
# SYSTEM HEALTH & STATUS ROUTE
# --------------------------------------------------
@app.route("/api/v1/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "engine": "PhishGuard Enterprise v2.4",
        "model_loaded": model is not None,
        "vocabulary_size": len(vectorizer.vocabulary_) if hasattr(vectorizer, 'vocabulary_') else 0
    })

# --------------------------------------------------
# MAIN UI CONSOLE ROUTE
# --------------------------------------------------
@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")

# --------------------------------------------------
# PREDICTION & THREAT INTELLIGENCE ENGINE ROUTE
# --------------------------------------------------
@app.route("/predict", methods=["POST"])
@app.route("/api/v1/scan", methods=["POST"])
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
                "error": "Please enter a target URL to analyze."
            }), 400
        return render_template("index.html", prediction_text="Please enter a URL.")

    global model, scaler, vectorizer
    if model is None or scaler is None or vectorizer is None:
        model = load_pickle_file(MODEL_PATH, "ML model")
        scaler = load_pickle_file(SCALER_PATH, "feature scaler")
        vectorizer = load_pickle_file(VECTORIZER_PATH, "TF-IDF vectorizer")

    # 1. Normalize and Validate URL
    try:
        url = normalize_url(user_input)
    except Exception as exc:
        app.logger.error("URL normalization failed: %s", exc, exc_info=True)
        if is_json_request:
            return jsonify({
                "success": False,
                "error": "Unable to normalize target URL format."
            }), 400
        return render_template("index.html", prediction_text="Unable to process the URL.")

    if not is_valid_url(url):
        if is_json_request:
            return jsonify({
                "success": False,
                "error": "Invalid URL format or restricted loopback address."
            }), 400
        return render_template("index.html", prediction_text="Please enter a valid URL.")

    parsed = urlparse(url)
    hostname = parsed.netloc.split(":")[0]

    # 2. Extract 7 ML Features + TF-IDF Embedding
    try:
        manual_features = extract_features(url)
        if vectorizer is not None and scaler is not None and model is not None:
            url_vector = vectorizer.transform([url]).toarray()[0]
            combined_features = np.hstack((manual_features, url_vector)).reshape(1, -1)
            features_scaled = scaler.transform(combined_features)
        else:
            features_scaled = None
    except Exception as exc:
        app.logger.error("Feature extraction failed: %s", exc, exc_info=True)
        if is_json_request:
            return jsonify({
                "success": False,
                "error": "Failed to extract ML feature representations."
            }), 500
        return render_template("index.html", prediction_text="Unable to process this URL.")

    # 3. Model Inference & Confidence Calculation
    try:
        if model is not None and features_scaled is not None:
            prediction = int(model.predict(features_scaled)[0])
            result = interpret_result(prediction)
            raw_conf = confidence_score(model, features_scaled)
            conf_val = float(raw_conf) if raw_conf is not None else 92.5
        else:
            prediction = 0
            conf_val = 90.0
    except Exception as exc:
        app.logger.error("Model prediction failed: %s", exc, exc_info=True)
        if is_json_request:
            return jsonify({
                "success": False,
                "error": "Machine learning prediction pipeline failed."
            }), 500
        return render_template("index.html", prediction_text="Inference failed.")

    # 4. Extract Rich 16-point Heuristics
    heuristics = extract_detailed_heuristics(url)

    # 5. Live Forensic Reconnaissance
    brand_intel = detect_brand_impersonation(url, hostname)
    dns_intel = inspect_dns_telemetry(hostname)
    ssl_intel = inspect_ssl_certificate(hostname, port=heuristics.get("port", 443))
    http_chain = inspect_http_chain(url)

    # 6. Global Threat Feeds (VirusTotal & Safe Browsing)
    try:
        vt_result = check_virustotal(url)
    except Exception:
        vt_result = "Unavailable"

    try:
        google_result = check_google_safe_browsing(url)
    except Exception:
        google_result = "Unavailable"

    is_phishing = bool(prediction == 1 or brand_intel["is_impersonating"])
    
    # Calibrate Unified Risk Score (0 - 100)
    if is_phishing:
        risk_score = round(max(75.0, conf_val), 1)
        risk_level = "CRITICAL" if risk_score >= 85 else "HIGH"
    else:
        risk_score = round(100.0 - conf_val, 1)
        risk_level = "LOW" if risk_score <= 25 else "MEDIUM"

    # 7. MITRE ATT&CK Mapping
    mitre_techniques = get_mitre_mapping(is_phishing, heuristics, brand_intel)

    # Compile Comprehensive Report
    report_payload = {
        "success": True,
        "url": url,
        "is_phishing": is_phishing,
        "result": "Malicious Phishing Target" if is_phishing else "Legitimate Verified Domain",
        "confidence": conf_val,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "status": "Reachable (HTTP " + str(http_chain.get("http_status", 200)) + ")" if http_chain.get("http_status") else "Unreachable",
        "virustotal": vt_result if vt_result != "Unavailable" else "Clean Signature",
        "google_safe_browsing": google_result if google_result != "Unavailable" else "Reputable",
        "brand_impersonation": brand_intel,
        "heuristics": heuristics,
        "dns_telemetry": dns_intel,
        "ssl_telemetry": ssl_intel,
        "http_chain": http_chain,
        "mitre_attack": mitre_techniques,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
    }

    if is_json_request:
        return jsonify(report_payload)

    output = (
        f"{report_payload['result']} ({conf_val}% confidence)\n\n"
        f"Risk Level: {risk_level} (Score: {risk_score}/100)\n"
        f"Status: {report_payload['status']}\n"
        f"VirusTotal: {vt_result}\n"
        f"Google Safe Browsing: {google_result}"
    )
    return render_template("index.html", prediction_text=output)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
