def format_features(features):
    try:
        import numpy as np
        return np.asarray(
            features,
            dtype=float
        ).reshape(1, -1)
    except Exception:
        return [features]


def interpret_result(prediction):
    try:
        prediction = int(prediction)
    except (TypeError, ValueError):
        return "Unknown"

    if prediction == 1:
        return "Phishing"

    return "Legitimate"


def confidence_score(model, features):
    try:
        probabilities = model.predict_proba(features)[0]

        if len(probabilities) == 0:
            return None

        confidence = max(probabilities) * 100

        return round(float(confidence), 2)

    except (
        AttributeError,
        ValueError,
        TypeError,
        IndexError
    ):
        return None


def print_separator():
    print("-" * 50)
