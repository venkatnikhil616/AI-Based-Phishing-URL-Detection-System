import os
import sys
import pickle

import numpy as np
from flask import Flask, render_template, request


# --------------------------------------------------
# PROJECT ROOT PATH
# --------------------------------------------------

BASE_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        ".."
    )
)

# Make project root available for imports
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


# --------------------------------------------------
# PROJECT IMPORTS
# --------------------------------------------------

from features.feature_extraction import extract_features
from utils.url_cleaner import (
    normalize_url,
    is_valid_url,
    is_url_reachable
)
from utils.helpers import (
    interpret_result,
    confidence_score
)
from utils.url_checker import (
    check_virustotal,
    check_google_safe_browsing
)


# --------------------------------------------------
# FLASK APPLICATION
# --------------------------------------------------

APP_DIR = os.path.dirname(__file__)

app = Flask(
    __name__,
    template_folder=os.path.join(
        APP_DIR,
        "templates"
    ),
    static_folder=os.path.join(
        APP_DIR,
        "static"
    )
)


# --------------------------------------------------
# MODEL PATHS
# --------------------------------------------------

MODEL_DIR = os.path.join(
    BASE_DIR,
    "models"
)

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "model.pkl"
)

SCALER_PATH = os.path.join(
    MODEL_DIR,
    "scaler.pkl"
)

VECTORIZER_PATH = os.path.join(
    MODEL_DIR,
    "vectorizer.pkl"
)


# --------------------------------------------------
# LOAD PICKLE FILE
# --------------------------------------------------

def load_pickle_file(
    file_path,
    component_name
):
    """
    Load a serialized ML component from disk.
    """

    if not os.path.isfile(file_path):
        raise FileNotFoundError(
            f"{component_name} not found: "
            f"{file_path}. "
            "Run models/train_model.py first."
        )

    try:
        with open(
            file_path,
            "rb"
        ) as file:
            return pickle.load(file)

    except Exception as exc:
        raise RuntimeError(
            f"Failed to load {component_name}: {exc}"
        ) from exc


# --------------------------------------------------
# LOAD MODEL COMPONENTS
# --------------------------------------------------

model = load_pickle_file(
    MODEL_PATH,
    "ML model"
)

scaler = load_pickle_file(
    SCALER_PATH,
    "feature scaler"
)

vectorizer = load_pickle_file(
    VECTORIZER_PATH,
    "TF-IDF vectorizer"
)


# --------------------------------------------------
# HOME ROUTE
# --------------------------------------------------

@app.route(
    "/",
    methods=["GET"]
)
def home():

    return render_template(
        "index.html"
    )


# --------------------------------------------------
# PREDICTION ROUTE
# --------------------------------------------------

@app.route(
    "/predict",
    methods=["POST"]
)
def predict():

    user_input = request.form.get(
        "url",
        ""
    ).strip()

    # --------------------------------------------------
    # INPUT VALIDATION
    # --------------------------------------------------

    if not user_input:

        return render_template(
            "index.html",
            prediction_text=(
                "Please enter a URL."
            )
        )

    url = normalize_url(
        user_input
    )

    if not is_valid_url(url):

        return render_template(
            "index.html",
            prediction_text=(
                "Please enter a valid URL."
            )
        )

    # --------------------------------------------------
    # URL REACHABILITY
    # --------------------------------------------------

    try:

        is_live = is_url_reachable(
            url
        )

        status = (
            "🟢 Live"
            if is_live
            else "🔴 Dead"
        )

    except Exception as exc:

        app.logger.warning(
            "URL reachability check failed: %s",
            exc
        )

        status = (
            "⚠️ Unable to determine"
        )

    # --------------------------------------------------
    # FEATURE EXTRACTION
    # --------------------------------------------------

    try:

        manual_features = extract_features(
            url
        )

        url_vector = vectorizer.transform(
            [url]
        ).toarray()[0]

        combined_features = np.hstack(
            (
                manual_features,
                url_vector
            )
        )

        features = combined_features.reshape(
            1,
            -1
        )

        features_scaled = scaler.transform(
            features
        )

    except Exception as exc:

        app.logger.error(
            "Feature processing failed: %s",
            exc,
            exc_info=True
        )

        return render_template(
            "index.html",
            prediction_text=(
                "Unable to process this URL. "
                "Please try another URL."
            )
        )

    # --------------------------------------------------
    # MACHINE LEARNING PREDICTION
    # --------------------------------------------------

    try:

        prediction = model.predict(
            features_scaled
        )[0]

        result = interpret_result(
            prediction
        )

        conf = confidence_score(
            model,
            features_scaled
        )

    except Exception as exc:

        app.logger.error(
            "Model prediction failed: %s",
            exc,
            exc_info=True
        )

        return render_template(
            "index.html",
            prediction_text=(
                "The URL could not be analyzed "
                "by the prediction model."
            )
        )

    # --------------------------------------------------
    # VIRUSTOTAL
    # --------------------------------------------------

    try:

        vt_result = check_virustotal(
            url
        )

    except Exception as exc:

        app.logger.warning(
            "VirusTotal check failed: %s",
            exc
        )

        vt_result = "Unavailable"

    # --------------------------------------------------
    # GOOGLE SAFE BROWSING
    # --------------------------------------------------

    try:

        google_result = (
            check_google_safe_browsing(
                url
            )
        )

    except Exception as exc:

        app.logger.warning(
            "Google Safe Browsing check failed: %s",
            exc
        )

        google_result = "Unavailable"

    # --------------------------------------------------
    # RESULT
    # --------------------------------------------------

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

    return render_template(
        "index.html",
        prediction_text=output
    )


# --------------------------------------------------
# LOCAL DEVELOPMENT
# --------------------------------------------------

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            5000
        )
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )
