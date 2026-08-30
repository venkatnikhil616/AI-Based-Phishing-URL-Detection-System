import re
import ssl
import socket
import datetime
import math
from urllib.parse import urlparse
import requests

# --------------------------------------------------
# TARGETED BRANDS REPOSITORY
# --------------------------------------------------
TRACKED_BRANDS = {
    "paypal": ["paypal", "paypa1", "pay-pal", "paypal-security"],
    "google": ["google", "g00gle", "google-security", "gmail"],
    "microsoft": ["microsoft", "micro-soft", "office365", "outlook", "live-login", "azure"],
    "apple": ["apple", "apple-id", "icloud-find", "icloud-security", "appleid"],
    "amazon": ["amazon", "amaz0n", "amazon-security", "prime-update"],
    "netflix": ["netflix", "netf1ix", "netflix-billing"],
    "facebook": ["facebook", "faceb00k", "fb-security", "meta-verify"],
    "instagram": ["instagram", "insta-verify", "ig-badge"],
    "chase": ["chase", "chase-online", "jpmorgan"],
    "wellsfargo": ["wellsfargo", "wells-fargo"],
    "bankofamerica": ["bankofamerica", "bofa", "bank-of-america"],
    "binance": ["binance", "binance-verify"],
    "coinbase": ["coinbase", "c0inbase", "coinbase-support"],
    "dhl": ["dhl", "dhl-tracking", "dhl-delivery"],
    "usps": ["usps", "usps-tracking", "usps-redelivery"],
    "fedex": ["fedex", "fedex-delivery"]
}

HIGH_RISK_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "club", "work", 
    "click", "loan", "buzz", "fit", "surf", "rest", "cam", "icu"
}

# --------------------------------------------------
# ENTROPY & SHANNON CALCULATOR
# --------------------------------------------------
def calculate_shannon_entropy(text: str) -> float:
    """Compute Shannon entropy of a string (higher = more random/DGA)."""
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
# BRAND IMPERSONATION DETECTOR
# --------------------------------------------------
def detect_brand_impersonation(url: str, hostname: str) -> dict:
    """Analyze domain & URL for brand spoofing and deceptive subdomains."""
    hostname_lower = hostname.lower()
    url_lower = url.lower()
    
    matched_brand = None
    is_spoofed = False
    evidence = []

    # Check if host contains brand keywords but is not the authentic domain
    for brand, variations in TRACKED_BRANDS.items():
        for variant in variations:
            if variant in hostname_lower or variant in url_lower:
                matched_brand = brand.capitalize()
                
                # Check if it's the genuine top-level brand domain
                authentic_domain = f"{brand}.com"
                if not hostname_lower.endswith(authentic_domain) and not hostname_lower == authentic_domain:
                    is_spoofed = True
                    evidence.append(f"Contains '{variant}' marker outside official {authentic_domain} domain")
                    break

    # Homoglyph / Punycode check
    if "xn--" in hostname_lower:
        is_spoofed = True
        evidence.append("Punycode (xn--) Internationalized Domain Name detected (possible homoglyph spoof)")

    # High-Risk TLD Check
    parts = hostname_lower.split(".")
    if len(parts) >= 2:
        tld = parts[-1]
        if tld in HIGH_RISK_TLDS:
            evidence.append(f"Hosted on high-abuse top-level domain (.{tld})")

    return {
        "is_impersonating": is_spoofed,
        "targeted_brand": matched_brand if is_spoofed else ("Verified " + matched_brand if matched_brand else None),
        "evidence": evidence
    }

# --------------------------------------------------
# LIVE TLS / SSL CERTIFICATE INSPECTION
# --------------------------------------------------
def inspect_ssl_certificate(hostname: str, port: int = 443, timeout: float = 3.0) -> dict:
    """Perform live TLS handshake to inspect certificate validity and issuer."""
    # Skip if hostname is an IP or invalid
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
        return {
            "status": "Insecure",
            "issuer": "N/A (Raw IP Host)",
            "valid_days_remaining": 0,
            "protocol": "None",
            "is_trusted": False
        }

    try:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                # Extract Issuer
                issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                issuer_cn = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown CA"

                # Expiry check
                not_after = cert.get("notAfter")
                days_left = 0
                if not_after:
                    expiry_dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = max(0, (expiry_dt - datetime.datetime.utcnow()).days)

                return {
                    "status": "Valid TLS",
                    "issuer": issuer_cn,
                    "valid_days_remaining": days_left,
                    "protocol": version or "TLSv1.3",
                    "cipher": cipher[0] if cipher else "AES-GCM",
                    "is_trusted": True
                }

    except ssl.SSLCertVerificationError as e:
        return {
            "status": "Untrusted / Invalid Certificate",
            "issuer": "Self-Signed or Expired CA",
            "valid_days_remaining": 0,
            "protocol": "TLS Alert",
            "is_trusted": False,
            "error": str(e.verify_message if hasattr(e, "verify_message") else e)
        }
    except Exception:
        return {
            "status": "No HTTPS Service",
            "issuer": "Unencrypted (Port 80 HTTP)",
            "valid_days_remaining": 0,
            "protocol": "Cleartext",
            "is_trusted": False
        }

# --------------------------------------------------
# DNS & NETWORK RECONNAISSANCE
# --------------------------------------------------
def inspect_dns_telemetry(hostname: str) -> dict:
    """Resolve A-records, reverse PTR, and ASN routing info."""
    clean_host = hostname.split(":")[0]
    try:
        addr_info = socket.getaddrinfo(clean_host, None, socket.AF_INET)
        ips = list(set([item[4][0] for item in addr_info]))
        
        # Check reverse DNS for first IP
        ptr = "None"
        if ips:
            try:
                ptr_res = socket.gethostbyaddr(ips[0])
                ptr = ptr_res[0]
            except Exception:
                ptr = "No PTR Record"

        return {
            "resolved_ips": ips[:4],
            "primary_ip": ips[0] if ips else "Unresolved",
            "reverse_dns": ptr,
            "is_resolved": len(ips) > 0
        }
    except Exception:
        return {
            "resolved_ips": [],
            "primary_ip": "NXDOMAIN / Unresolved",
            "reverse_dns": "N/A",
            "is_resolved": False
        }

# --------------------------------------------------
# REDIRECTION CHAIN & HTTP HEADERS PROBE
# --------------------------------------------------
def inspect_http_chain(url: str, timeout: float = 3.5) -> dict:
    """Trace HTTP redirect hops and inspect response headers."""
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishGuard-Scanner/2.4"
        }
        res = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=False)
        
        hops = []
        for r in res.history:
            hops.append({
                "status_code": r.status_code,
                "url": r.url
            })
        hops.append({
            "status_code": res.status_code,
            "url": res.url
        })

        server_header = res.headers.get("Server", "Undisclosed")
        hsts = "strict-transport-security" in res.headers
        csp = "content-security-policy" in res.headers

        return {
            "final_url": res.url,
            "redirect_count": len(res.history),
            "redirect_chain": hops,
            "http_status": res.status_code,
            "server": server_header,
            "has_hsts": hsts,
            "has_csp": csp
        }
    except Exception as exc:
        return {
            "final_url": url,
            "redirect_count": 0,
            "redirect_chain": [{"status_code": 0, "url": url}],
            "http_status": 0,
            "server": "Unavailable",
            "has_hsts": False,
            "has_csp": False
        }

# --------------------------------------------------
# MITRE ATT&CK MAPPING
# --------------------------------------------------
def get_mitre_mapping(is_phishing: bool, heuristics: dict, brand_intel: dict) -> list:
    """Map detected threat vectors to MITRE ATT&CK Enterprise Matrix techniques."""
    if not is_phishing:
        return []

    techniques = [
        {
            "id": "T1566.002",
            "name": "Phishing: Spearphishing Link",
            "tactic": "Initial Access",
            "description": "Adversary sends a malicious link to target users to harvest credentials or deliver payloads."
        }
    ]

    if brand_intel.get("is_impersonating"):
        techniques.append({
            "id": "T1583.001",
            "name": "Acquire Infrastructure: Domains",
            "tactic": "Resource Development",
            "description": "Adversary registers typosquatting or homoglyph domains mimicking legitimate organizations."
        })

    if heuristics.get("is_ip_address"):
        techniques.append({
            "id": "T1566.001",
            "name": "Phishing: Direct IP Host",
            "tactic": "Defense Evasion",
            "description": "Direct numeric IP addressing utilized to bypass standard DNS reputation filters."
        })

    if heuristics.get("has_at_symbol"):
        techniques.append({
            "id": "T1027",
            "name": "Obfuscated Files or Information: Redirection Delimiter",
            "tactic": "Defense Evasion",
            "description": "@ symbol used to mask actual destination host within URL authority."
        })

    return techniques
