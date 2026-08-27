import numpy as np


# --------------------------------------------------
# FEATURE FORMATTING
# --------------------------------------------------

def format_features(features):
    """
    Convert a feature collection into a 2D NumPy array
    suitable for scikit-learn model input.

    Args:
        features: List or array of numerical features.
                                                    Returns:
        numpy.ndarray: Features reshaped to (1, n_features).
    """
                                                    return np.asarray(
        features,
        dtype=float
    ).reshape(1, -1)                            

# --------------------------------------------------
# RESULT INTERPRETATION
# --------------------------------------------------

def interpret_result(prediction):
    """
    Convert the model's numerical prediction into
    a human-readable classification.

    Expected labels:
        1 -> Phishing
        0 -> Legitimate

    Returns:
        str: Classification result.
    """

    try:
        prediction = int(prediction)
    except (TypeError, ValueError):
        return "Unknown"

    if prediction == 1:
        return "Phishing"

    return "Legitimate"


# --------------------------------------------------
# CONFIDENCE SCORE
# --------------------------------------------------

def confidence_score(model, features):
    """
    Calculate the model's prediction confidence.

    Uses predict_proba() when supported by the model.

    Returns:
        float: Confidence percentage rounded to 2 decimals.
        None: If probability prediction is unavailable.
    """

    try:
        probabilities = model.predict_proba(
            features
        )[0]

        if len(probabilities) == 0:
            return None

        confidence = max(probabilities) * 100

        return round(
            float(confidence),
            2
        )

    except (
        AttributeError,
        ValueError,
        TypeError,
        IndexError
    ):
        return None


# --------------------------------------------------
# CONSOLE UTILITY
# --------------------------------------------------

def print_separator():
    """
    Print a separator for CLI output readability.
    """

    print("-" * 50)
