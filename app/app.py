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

app = Flask(__name__)
MODEL_PATH = os.path.join("models", "model.pkl")
SCALER_PATH = os.path.join("models", "scaler.pkl")
VECTORIZER_PATH = os.path.join("models", "vectorizer.pkl")
with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)
with open(SCALER_PATH, "rb") as f:
    scaler = pickle.load(f)
with open(VECTORIZER_PATH, "rb") as f:
    vectorizer = pickle.load(f)
@app.route("/")
def home():
    return render_template("index.html")
@app.route("/predict", methods=["POST"])
def predict():
    user_input = request.form.get("url")
    if not user_input:
        return render_template("index.html", prediction_text="Please enter a URL")
    # normalize URL
    url = normalize_url(user_input)
    # validate URL format
    if not is_valid_url(url):
        return render_template("index.html", prediction_text="Please enter a valid URL")
    warning = ""
    if not is_url_reachable(url):
        warning = " (Site may be unreachable)"
    # manual features
    manual_features = extract_features(url)
    # NLP features (TF-IDF)
    url_vector = vectorizer.transform([url]).toarray()[0]
    # combine features
    combined_features = np.hstack((manual_features, url_vector))
    # reshape for model
    features = combined_features.reshape(1, -1)
    # scale features
    features_scaled = scaler.transform(features)
    prediction = model.predict(features_scaled)[0]
    result = interpret_result(prediction)
    # confidence score
    conf = confidence_score(model, features_scaled)
    if conf:
        output = f"{result} ({conf}% confidence){warning}"
    else:
        output = f"{result}{warning}"
    return render_template("index.html", prediction_text=output)
if __name__ == "__main__":
    app.run(debug=True)
