import re
import math
from urllib.parse import urlparse

# --------------------------------------------------
# COMMON PHISHING KEYWORDS DICTIONARY
# --------------------------------------------------
SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "verification", "secure", "account",
    "update", "banking", "paypal", "free", "gift", "win", "bonus",
    "wallet", "auth", "support", "recover", "password", "billing",
    "invoice", "oauth", "token", "challenge", "confirm", "security",
    "service", "portal", "webscr", "ebayisapi"
]

HIGH_RISK_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "club", "work",
    "click", "loan", "buzz", "fit", "surf", "rest", "cam", "icu"
}

# --------------------------------------------------
# HEURISTIC UTILITIES
# --------------------------------------------------
def has_ip_address(url: str) -> int:
    """Check whether the URL contains an IPv4 address."""
    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    return 1 if re.search(pattern, url) else 0

def has_suspicious_words(url: str) -> int:
    """Check whether the URL contains known phishing-related keywords."""
    url_lower = url.lower()
    return int(any(word in url_lower for word in SUSPICIOUS_WORDS))

def calculate_entropy(text: str) -> float:
    """Compute character Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)

# --------------------------------------------------
# CORE ML MODEL FEATURE EXTRACTION (7 Features)
# --------------------------------------------------
def extract_features(url: str):
    """
    Extract standard numerical features for the Scikit-Learn Model.
    Must maintain exact ordering:
      1. URL length
      2. Dot count
      3. HTTPS flag
      4. @ symbol flag
      5. Hyphen flag
      6. IP address flag
      7. Suspicious keyword flag
    """
    if not isinstance(url, str):
        raise TypeError("URL must be provided as a string.")

    url = url.strip()
    if not url:
        raise ValueError("URL cannot be empty.")

    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url

    parsed = urlparse(url)

    url_length = len(url)
    dot_count = url.count(".")
    has_https = int(parsed.scheme.lower() == "https")
    has_at = int("@" in url)
    has_hyphen = int("-" in parsed.netloc)
    ip_flag = has_ip_address(url)
    suspicious_flag = has_suspicious_words(url)

    return [
        url_length,
        dot_count,
        has_https,
        has_at,
        has_hyphen,
        ip_flag,
        suspicious_flag,
    ]

# --------------------------------------------------
# COMPREHENSIVE ENTERPRISE HEURISTIC TELEMETRY
# --------------------------------------------------
def extract_detailed_heuristics(url: str) -> dict:
    """
    Extract comprehensive 16-point heuristic threat signals
    for Enterprise SOC telemetry reporting and forensic UI.
    """
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.netloc.split(":")[0].lower()
    path = parsed.pathname if hasattr(parsed, 'pathname') else parsed.path

    # Calculations
    url_len = len(url)
    domain_len = len(hostname)
    dot_count = url.count(".")
    subdomain_count = max(0, len(hostname.split(".")) - 2) if not has_ip_address(hostname) else 0
    is_https = parsed.scheme.lower() == "https"
    has_at = "@" in url
    has_hyphen = "-" in hostname
    is_ip = bool(has_ip_address(url))
    has_double_slash = "//" in path
    
    # Entropy & Ratios
    entropy = calculate_entropy(hostname)
    digit_count = sum(c.isdigit() for c in url)
    digit_ratio = round(digit_count / max(1, url_len), 3)
    
    # Keyword matches
    found_keywords = [w for w in SUSPICIOUS_WORDS if w in url.lower()]
    
    # TLD
    parts = hostname.split(".")
    tld = parts[-1] if len(parts) > 1 else "none"
    is_high_risk_tld = tld in HIGH_RISK_TLDS
    has_punycode = "xn--" in hostname
    has_port = bool(parsed.port and parsed.port not in (80, 443))

    return {
        "url_length": url_len,
        "domain_length": domain_len,
        "dot_count": dot_count,
        "subdomain_count": subdomain_count,
        "is_https": is_https,
        "has_at_symbol": has_at,
        "has_hyphen": has_hyphen,
        "is_ip_address": is_ip,
        "has_double_slash_redirect": has_double_slash,
        "shannon_entropy": entropy,
        "digit_ratio": digit_ratio,
        "matched_keywords": found_keywords,
        "keyword_count": len(found_keywords),
        "tld": tld,
        "is_high_risk_tld": is_high_risk_tld,
        "has_punycode": has_punycode,
        "has_custom_port": has_port,
        "port": parsed.port if parsed.port else (443 if is_https else 80)
    }
