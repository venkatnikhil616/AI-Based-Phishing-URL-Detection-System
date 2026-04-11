import requests
import base64

# ADD YOUR API KEYS HERE

VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
GOOGLE_API_KEY = "YOUR_GOOGLE_API_KEY"

# VIRUSTOTAL CHECK
def check_virustotal(url):
    """                                                               Check URL using VirusTotal API
    Returns: Safe / Malicious / Unknown / Error
    """
    try:
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }
                                                                          # Encode URL (required by VT API)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        response = requests.get(vt_url, headers=headers, timeout=5)

        if response.status_code != 200:
            return "Unknown"

        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious > 0 or suspicious > 0:
            return "Malicious"
        else:
            return "Safe"

    except Exception:
        return "Error"


# ===========================
# GOOGLE SAFE BROWSING CHECK
# ===========================
def check_google_safe_browsing(url):
    """
    Check URL using Google Safe Browsing API
    Returns: Safe / Unsafe / Error
    """
    try:
        body = {
            "client": {
                "clientId": "phishing-detector",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": url}
                ]
            }
        }

        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"

        response = requests.post(api_url, json=body, timeout=5)

        if response.status_code != 200:
            return "Unknown"

        data = response.json()

        if "matches" in data:
            return "Unsafe"
        else:
            return "Safe"

    except Exception:
        return "Error"
