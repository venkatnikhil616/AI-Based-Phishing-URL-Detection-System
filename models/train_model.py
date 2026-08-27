import os
import pickle

import numpy as np
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from features.feature_extraction import extract_features
                                                
# --------------------------------------------------
# PROJECT PATHS
# --------------------------------------------------

BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

DATA_DIR = os.path.join(BASE_DIR, "data")
MODEL_DIR = os.path.join(BASE_DIR, "models")

DATA_PATH = os.path.join(
    DATA_DIR,
    "raw_urls.csv"
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
# MODEL TRAINING
# --------------------------------------------------

def train_model():

    # --------------------------------------------------
    # LOAD DATASET
    # --------------------------------------------------

    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(
            f"Training dataset not found: {DATA_PATH}"
        )

    print(f"Loading dataset from: {DATA_PATH}")

    df = pd.read_csv(DATA_PATH)

    # Drop rows where URL or label is missing
    df = df.dropna(
        subset=["url", "label"]
    )

    if df.empty:
        raise ValueError(
            "The training dataset contains no valid rows."
        )

    urls = df["url"].astype(str)
    labels = df["label"]

    # --------------------------------------------------
    # LABEL VALIDATION
    # --------------------------------------------------

    if labels.dtype == object:
        try:
            labels = labels.astype(int)
        except ValueError as exc:
            raise ValueError(
                "The 'label' column must contain integer "
                "classification labels."
            ) from exc

    if labels.nunique() < 2:
        raise ValueError(
            "The dataset must contain at least two classes."
        )

    # --------------------------------------------------
    # MANUAL URL FEATURES
    # --------------------------------------------------

    print("Extracting manual URL features...")

    manual_features = [
        extract_features(url)
        for url in urls
    ]

    manual_features = np.asarray(
        manual_features,
        dtype=float
    )

    # --------------------------------------------------
    # TF-IDF FEATURES
    # --------------------------------------------------

    print("Generating TF-IDF features...")

    vectorizer = TfidfVectorizer()

    url_vectors = vectorizer.fit_transform(
        urls
    ).toarray()

    # --------------------------------------------------
    # COMBINE FEATURES
    # --------------------------------------------------

    combined_features = np.hstack(
        (
            manual_features,
            url_vectors
        )
    )

    print(
        f"Combined feature shape: "
        f"{combined_features.shape}"
    )

    # --------------------------------------------------
    # TRAIN / TEST SPLIT
    # --------------------------------------------------

    X_train, X_test, y_train, y_test = train_test_split(
        combined_features,
        labels,
        test_size=0.2,
        random_state=42,
        stratify=labels
    )

    # --------------------------------------------------
    # FEATURE SCALING
    # --------------------------------------------------

    scaler = StandardScaler()

    X_train = scaler.fit_transform(
        X_train
    )

    X_test = scaler.transform(
        X_test
    )

    # --------------------------------------------------
    # TRAIN LOGISTIC REGRESSION MODEL
    # --------------------------------------------------

    print("Training Logistic Regression model...")

    model = LogisticRegression(
        max_iter=1000,
        class_weight="balanced"
    )

    model.fit(
        X_train,
        y_train
    )

    # --------------------------------------------------
    # MODEL EVALUATION
    # --------------------------------------------------

    y_pred = model.predict(
        X_test
    )

    accuracy = accuracy_score(
        y_test,
        y_pred
    )

    print("\n=== MODEL PERFORMANCE ===")
    print(f"Accuracy: {accuracy:.4f}")

    print("\n=== CLASSIFICATION REPORT ===")
    print(
        classification_report(
            y_test,
            y_pred
        )
    )

    # --------------------------------------------------
    # SAVE MODEL ARTIFACTS
    # --------------------------------------------------

    os.makedirs(
        MODEL_DIR,
        exist_ok=True
    )

    with open(
        MODEL_PATH,
        "wb"
    ) as file:
        pickle.dump(
            model,
            file
        )

    with open(
        SCALER_PATH,
        "wb"
    ) as file:
        pickle.dump(
            scaler,
            file
        )

    with open(
        VECTORIZER_PATH,
        "wb"
    ) as file:
        pickle.dump(
            vectorizer,
            file
        )

    print("\n=== MODEL ARTIFACTS ===")
    print(f"Model:      {MODEL_PATH}")
    print(f"Scaler:     {SCALER_PATH}")
    print(f"Vectorizer: {VECTORIZER_PATH}")
    print("\nModel, scaler, and vectorizer saved successfully!")


# --------------------------------------------------
# SCRIPT ENTRY POINT
# --------------------------------------------------

if __name__ == "__main__":
    train_model()
