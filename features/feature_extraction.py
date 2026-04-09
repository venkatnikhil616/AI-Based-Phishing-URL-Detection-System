import re
from urllib.parse import urlparse

# common phishing keywords
SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "account", "update",
    "bank", "paypal", "free", "gift", "win", "bonus"
]


def has_ip_address(url):
    """
    Check if URL contains an IP address
    """
    pattern = r'(\d{1,3}\.){3}\d{1,3}'
    return 1 if re.search(pattern, url) else 0


def has_suspicious_words(url):
    """
    Check for phishing-related keywords
    """
    url = url.lower()
    for word in SUSPICIOUS_WORDS:
        if word in url:
            return 1
    return 0


def extract_features(url):
    """
    Extract manual features from URL
    Returns features in fixed order
    """
    # ensure scheme
    if not url.startswith("http"):
        url = "http://" + url

    parsed = urlparse(url)

    url_length = len(url)
    dot_count = url.count(".")
    has_https = 1 if parsed.scheme == "https" else 0
    has_at = 1 if "@" in url else 0
    has_hyphen = 1 if "-" in parsed.netloc else 0
    ip_flag = has_ip_address(url)
    suspicious_flag = has_suspicious_words(url)

    return [
        url_length,
        dot_count,
        has_https,
        has_at,
        has_hyphen,
        ip_flag,
        suspicious_flag
    ]
