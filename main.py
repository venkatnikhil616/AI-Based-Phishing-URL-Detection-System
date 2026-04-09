import pickle
import os
from features.feature_extraction import extract_features
from utils.url_cleaner import normalize_url, is_valid_url
from utils.helpers import format_features, interpret_result, confidence_score

def load_model():
    model_path = os.path.join("models", "model.pkl")
    scaler_path = os.path.join("models", "scaler.pkl")
    with open(model_path, "rb") as f:
        model = pickle.load(f)
    with open(scaler_path, "rb") as f:
        scaler = pickle.load(f)
    return model, scaler
def predict_url(model, scaler, url):
    # normalize input
    url = normalize_url(url)
    if not is_valid_url(url):
        return "Invalid URL format"
    # extract features
    features = extract_features(url)
    features = format_features(features)
    # scale
    features_scaled = scaler.transform(features)
    # predict
    prediction = model.predict(features_scaled)[0]
    result = interpret_result(prediction)
    # confidence
    conf = confidence_score(model, features_scaled)
    if conf:
        return f"{result} ({conf}% confidence)"
    else:
        return result
def main():
    print("\n=== Phishing URL Detection System ===\n")
    model, scaler = load_model()
    while True:
        url = input("Enter URL (or type 'exit' to quit): ")
        if url.lower() == "exit":
            print("Exiting...")
            break
        result = predict_url(model, scaler, url)
        print(f"Result: {result}\n")
if __name__ == "__main__":
    main()
