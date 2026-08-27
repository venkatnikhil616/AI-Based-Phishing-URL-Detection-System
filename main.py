import os                                       import pickle

import numpy as np

from features.feature_extraction import extract_features
from utils.url_cleaner import normalize_url, is_valid_url
from utils.helpers import interpret_result, confidence_score


# --------------------------------------------------
# PROJECT PATHS
# --------------------------------------------------
                                                BASE_DIR = os.path.abspath(
    os.path.dirname(__file__)
)

MODEL_PATH = os.path.join(                          BASE_DIR,
    "models",
    "model.pkl"
)
                                                SCALER_PATH = os.path.join(
    BASE_DIR,
    "models",                                       "scaler.pkl"
)

VECTORIZER_PATH = os.path.join(
    BASE_DIR,
    "models",                                       "vectorizer.pkl"
)


# --------------------------------------------------
# LOAD MODEL COMPONENTS
# --------------------------------------------------

def load_model():
    """
    Load the trained model, scaler, and TF-IDF vectorizer.
    """

    required_files = {
        "model": MODEL_PATH,
        "scaler": SCALER_PATH,
        "vectorizer": VECTORIZER_PATH,
    }

    for component, path in required_files.items():
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"{component.capitalize()} file not found: {path}\n"
                "Run 'python -m models.train_model' first."
            )

    with open(MODEL_PATH, "rb") as file:
        model = pickle.load(file)

    with open(SCALER_PATH, "rb") as file:
        scaler = pickle.load(file)

    with open(VECTORIZER_PATH, "rb") as file:
        vectorizer = pickle.load(file)

    return model, scaler, vectorizer


# --------------------------------------------------
# PREDICT URL
# --------------------------------------------------

def predict_url(model, scaler, vectorizer, url):
    """
    Normalize, validate, extract features, and classify a URL.

    Uses the exact same feature pipeline as the Flask
    web application.
    """

    # --------------------------------------------------
    # NORMALIZE INPUT
    # --------------------------------------------------

    url = normalize_url(url)

    if not is_valid_url(url):
        return "Invalid URL format"

    # --------------------------------------------------
    # EXTRACT MANUAL FEATURES
    # --------------------------------------------------

    manual_features = extract_features(url)

    # --------------------------------------------------
    # EXTRACT TF-IDF FEATURES
    # --------------------------------------------------

    url_vector = vectorizer.transform(
        [url]
    ).toarray()[0]

    # --------------------------------------------------
    # COMBINE FEATURES
    # --------------------------------------------------

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

    # --------------------------------------------------
    # SCALE FEATURES
    # --------------------------------------------------

    features_scaled = scaler.transform(
        features
    )

    # --------------------------------------------------
    # MODEL PREDICTION
    # --------------------------------------------------

    prediction = model.predict(
        features_scaled
    )[0]

    result = interpret_result(
        prediction
    )

    # --------------------------------------------------
    # CONFIDENCE
    # --------------------------------------------------

    conf = confidence_score(
        model,
        features_scaled
    )

    if conf:
        return f"{result} ({conf}% confidence)"

    return result


# --------------------------------------------------
# CLI APPLICATION
# --------------------------------------------------

def main():
    """
    Run the command-line phishing URL detector.
    """

    print(
        "\n=== Phishing URL Detection System ===\n"
    )

    try:
        model, scaler, vectorizer = load_model()

    except Exception as exc:
        print(
            f"Unable to load model components: {exc}"
        )
        return

    while True:

        try:
            url = input(
                "Enter URL (or type 'exit' to quit): "
            ).strip()

        except (KeyboardInterrupt, EOFError):
            print("\nExiting...")
            break

        if url.lower() == "exit":
            print("Exiting...")
            break

        if not url:
            print(
                "Please enter a URL.\n"
            )
            continue

        try:
            result = predict_url(
                model,
                scaler,
                vectorizer,
                url
            )

            print(
                f"Result: {result}\n"
            )

        except Exception as exc:
            print(
                f"Unable to process URL: {exc}\n"
            )


# --------------------------------------------------
# SCRIPT ENTRY POINT
# --------------------------------------------------

if __name__ == "__main__":
    main()
