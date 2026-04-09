import re
import requests
from urllib.parse import urlparse

def clean_url(url):
    """
    Basic cleaning and normalization
    """
    if not isinstance(url, str):
        return ""

    url = url.strip()

    # add scheme if missing
    if not url.startswith("http"):
        url = "http://" + url

    # remove spaces
    url = url.replace(" ", "")

    return url

def remove_www(url):
    """
    Remove 'www.' from URL
    """
    parsed = urlparse(url)
    netloc = parsed.netloc.replace("www.", "")
    return f"{parsed.scheme}://{netloc}{parsed.path}"

def normalize_url(url):
    """
    Full normalization pipeline
    """
    url = clean_url(url)
    url = remove_www(url)
    return url

def is_valid_url(url):
    """
    Strict URL format validation
    """
    pattern = re.compile(
        r'^(https?:\/\/)'
        r'(([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|'
        r'(\d{1,3}\.){3}\d{1,3})'
        r'(:\d+)?(\/.*)?$'
    )
    return True if pattern.match(url) else False

def is_url_reachable(url):
    """
    Robust check if URL exists on the internet
    """
    try:
        headers = {
            "User-Agent": "Mozilla/5.0"
        }

        # Try HEAD request first (faster & less blocked)
        response = requests.head(
            url,
            headers=headers,
            timeout=5,
            allow_redirects=True
        )

        if response.status_code < 400:
            return True

        # Fallback to GET request
        response = requests.get(
            url,
            headers=headers,
            timeout=5,
            allow_redirects=True
        )

        return True if response.status_code < 400 else False

    except requests.exceptions.RequestException:
        return False
