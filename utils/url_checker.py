import base64
import os
import requests


# --------------------------------------------------
# VIRUSTOTAL CHECK
# --------------------------------------------------

def check_virustotal(url):
    """
    Check a URL using the VirusTotal API.

    If no API key is configured, the external
    VirusTotal check is skipped.

    Returns:
        Safe
        Malicious
        Unknown
        Unavailable
    """

    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not api_key:
        return "Unavailable"

    try:
        headers = {
            "x-apikey": api_key
        }

        url_id = (
            base64.urlsafe_b64encode(
                url.encode("utf-8")
            )
            .decode("utf-8")
            .rstrip("=")
        )

        vt_url = (
            "https://www.virustotal.com/api/v3/urls/"
            f"{url_id}"
        )

        response = requests.get(
            vt_url,
            headers=headers,
            timeout=5
        )

        if response.status_code != 200:
            return "Unknown"

        data = response.json()

        stats = (
            data
            .get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious > 0 or suspicious > 0:
            return "Malicious"

        return "Safe"

    except requests.exceptions.Timeout:
        return "Unknown"

    except requests.exceptions.RequestException:
        return "Unknown"

    except (ValueError, KeyError, TypeError):
        return "Unknown"

    except Exception:
        return "Unknown"


# --------------------------------------------------
# GOOGLE SAFE BROWSING CHECK
# --------------------------------------------------

def check_google_safe_browsing(url):
    """
    Check a URL using Google Safe Browsing API.

    If no API key is configured, the external
    Google Safe Browsing check is skipped.

    Returns:
        Safe
        Unsafe
        Unknown
        Unavailable
    """

    api_key = os.getenv("GOOGLE_API_KEY")

    if not api_key:
        return "Unavailable"

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
                "platformTypes": [
                    "ANY_PLATFORM"
                ],
                "threatEntryTypes": [
                    "URL"
                ],
                "threatEntries": [
                    {
                        "url": url
                    }
                ]
            }
        }

        api_url = (
            "https://safebrowsing.googleapis.com/"
            "v4/threatMatches:find"
            f"?key={api_key}"
        )

        response = requests.post(
            api_url,
            json=body,
            timeout=5
        )

        if response.status_code != 200:
            return "Unknown"

        data = response.json()

        if data.get("matches"):
            return "Unsafe"

        return "Safe"

    except requests.exceptions.Timeout:
        return "Unknown"

    except requests.exceptions.RequestException:
        return "Unknown"

    except (ValueError, KeyError, TypeError):
        return "Unknown"

    except Exception:
        return "Unknown"
