import numpy as np

def format_features(features):
    """
    Convert feature list into 2D array for model input
    """
    return np.array(features).reshape(1, -1)

def interpret_result(prediction):
    """
    Convert numeric prediction to readable output
    """
    if prediction == 1:
        return "Phishing"
    else:
        return "Legitimate"

def confidence_score(model, features):
    """
    Get confidence score from model (if supported)
    """
    try:
        prob = model.predict_proba(features)[0]
        return round(max(prob) * 100, 2)
    except:
        return None
def print_separator():
    """
    Simple console separator for readability
    """
    print("-" * 50)
