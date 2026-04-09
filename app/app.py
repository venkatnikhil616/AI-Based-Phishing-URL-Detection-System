import os
import sys
import pickle
import numpy as np
from flask import Flask, render_template, request

# Add parent directory to import path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from features.feature_extraction import extract_features
from utils.url_cleaner import normalize_url, is_valid_url, is_url_reachable
from utils.helpers import interpret_result, confidence_score

# Flask app
app = Flask(__name__)

# Absolute paths for models
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "..", "models", "model.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "..", "models", "scaler.pkl")
VECTORIZER_PATH = os.path.join(BASE_DIR, "..", "models", "vectorizer.pkl")

# Ensure model files exist
for path in [MODEL_PATH, SCALER_PATH, VECTORIZER_PATH]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"{path} not found. Please train the model first.")

# Load trained artifacts
with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)
with open(SCALER_PATH, "rb") as f:
    scaler = pickle.load(f)
with open(VECTORIZER_PATH, "rb") as f:
    vectorizer = pickle.load(f)

# Routes
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/predict", methods=["POST"])
def predict():
    user_input = request.form.get("url")
    if not user_input:
        return render_template("index.html", prediction_text="Please enter a URL")

    # Normalize and validate URL
    url = normalize_url(user_input)
    if not is_valid_url(url):
        return render_template("index.html", prediction_text="Please enter a valid URL")

    warning = ""
    if not is_url_reachable(url):
        warning = " (Site may be unreachable)"

    # Extract manual features and ensure array shape
    manual_features = np.array(extract_features(url)).reshape(1, -1)

    # NLP features (TF-IDF)
    url_vector = vectorizer.transform([url]).toarray()

    # Combine features
    combined_features = np.hstack((manual_features, url_vector))

    # Scale features
    features_scaled = scaler.transform(combined_features)

    # Prediction
    prediction = model.predict(features_scaled)[0]
    result = interpret_result(prediction)

    # Confidence score
    conf = confidence_score(model, features_scaled)
    if conf is not None:
        output = f"{result} ({conf}% confidence){warning}"
    else:
        output = f"{result}{warning}"

    return render_template("index.html", prediction_text=output)

# Run app
if __name__ == "__main__":
    app.run(debug=True)
