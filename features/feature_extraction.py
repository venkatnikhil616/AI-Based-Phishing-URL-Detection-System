import re
from urllib.parse import urlparse


# --------------------------------------------------
# COMMON PHISHING KEYWORDS
# --------------------------------------------------

SUSPICIOUS_WORDS = [
    "login",                                        "verify",
    "secure",
    "account",
    "update",                                       "bank",
    "paypal",
    "free",
    "gift",
    "win",                                          "bonus",
]

                                                # --------------------------------------------------
# IP ADDRESS DETECTION
# --------------------------------------------------

def has_ip_address(url):
    """
    Check whether the URL contains an IPv4 address.

    Returns:
        int: 1 if an IPv4 address is detected, otherwise 0.
    """

    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    match = re.search(
        pattern,
        url
    )

    return 1 if match else 0


# --------------------------------------------------
# SUSPICIOUS KEYWORD DETECTION
# --------------------------------------------------

def has_suspicious_words(url):
    """
    Check whether the URL contains known
    phishing-related keywords.

    Returns:
        int: 1 if a suspicious keyword is found,
             otherwise 0.
    """

    url_lower = url.lower()

    return int(
        any(
            word in url_lower
            for word in SUSPICIOUS_WORDS
        )
    )


# --------------------------------------------------
# URL FEATURE EXTRACTION
# --------------------------------------------------

def extract_features(url):
    """
    Extract manual numerical features from a URL.

    The feature order MUST remain unchanged because
    the trained ML model expects this exact ordering.

    Feature order:
        1. URL length
        2. Dot count
        3. HTTPS flag
        4. @ symbol flag
        5. Hyphen flag
        6. IP address flag
        7. Suspicious keyword flag

    Returns:
        list: Seven numerical URL features.
    """

    if not isinstance(url, str):
        raise TypeError(
            "URL must be provided as a string."
        )

    url = url.strip()

    if not url:
        raise ValueError(
            "URL cannot be empty."
        )

    # Ensure the URL has a scheme so urlparse()
    # correctly identifies the network location.
    if not re.match(
        r"^https?://",
        url,
        re.IGNORECASE
    ):
        url = "http://" + url

    parsed = urlparse(url)

    url_length = len(url)

    dot_count = url.count(".")

    has_https = int(
        parsed.scheme.lower() == "https"
    )

    has_at = int(
        "@" in url
    )

    has_hyphen = int(
        "-" in parsed.netloc
    )

    ip_flag = has_ip_address(
        url
    )

    suspicious_flag = has_suspicious_words(
        url
    )

    return [
        url_length,
        dot_count,
        has_https,
        has_at,
        has_hyphen,
        ip_flag,
        suspicious_flag,
    ]
