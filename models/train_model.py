import pandas as pd
import numpy as np
import pickle
import os

from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, classification_report
from features.feature_extraction import extract_features

def train_model():
    df = pd.read_csv("data/raw_urls.csv")

    # Drop rows where label or url is missing
    df = df.dropna(subset=["url", "label"])

    urls = df["url"]
    labels = df["label"]

    # If labels are not integers, convert them
    if labels.dtype == object:
        labels = labels.astype(int)

    manual_features = [extract_features(url) for url in urls]
    manual_features = np.array(manual_features)

    vectorizer = TfidfVectorizer()
    url_vectors = vectorizer.fit_transform(urls).toarray()

    combined_features = np.hstack((manual_features, url_vectors))

    X_train, X_test, y_train, y_test = train_test_split(
        combined_features, labels, test_size=0.2, random_state=42
    )

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    model = LogisticRegression(max_iter=1000, class_weight='balanced')
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    print("\n=== MODEL PERFORMANCE ===")
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print("\nClassification Report:\n")
    print(classification_report(y_test, y_pred))

    os.makedirs("models", exist_ok=True)
    with open("models/model.pkl", "wb") as f:
        pickle.dump(model, f)
    with open("models/scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)
    with open("models/vectorizer.pkl", "wb") as f:
        pickle.dump(vectorizer, f)

    print("\nModel, scaler, and vectorizer saved successfully!")

if __name__ == "__main__":
    train_model()
