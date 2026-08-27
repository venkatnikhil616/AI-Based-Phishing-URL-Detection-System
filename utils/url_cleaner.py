import ipaddress
import re
import socket
from urllib.parse import urlparse

import requests


# --------------------------------------------------
# URL CLEANING
# --------------------------------------------------

def clean_url(url):
    """
    Basic cleaning and normalization.

    Returns:
        str: Cleaned URL or an empty string for invalid input.
    """

    if not isinstance(url, str):
        return ""

    url = url.strip()

    if not url:
        return ""

    # Remove whitespace characters.
    url = re.sub(r"\s+", "", url)

    # Add a default scheme if one is missing.
    if not re.match(
        r"^https?://",
        url,
        re.IGNORECASE
    ):
        url = "http://" + url

    return url


# --------------------------------------------------
# REMOVE WWW
# --------------------------------------------------

def remove_www(url):
    """
    Remove the 'www.' prefix from the hostname.

    Returns:
        str: Normalized URL.
    """

    parsed = urlparse(url)

    hostname = parsed.hostname

    if not hostname:
        return url

    hostname = re.sub(
        r"^www\.",
        "",
        hostname,
        flags=re.IGNORECASE
    )

    # Preserve port if one exists.
    netloc = hostname

    if parsed.port:
        netloc = f"{hostname}:{parsed.port}"

    normalized = parsed._replace(
        netloc=netloc
    )

    return normalized.geturl()


# --------------------------------------------------
# URL NORMALIZATION
# --------------------------------------------------

def normalize_url(url):
    """
    Run the complete URL normalization pipeline.

    Returns:
        str: Normalized URL.
    """

    url = clean_url(url)

    if not url:
        return ""

    return remove_www(url)


# --------------------------------------------------
# URL VALIDATION
# --------------------------------------------------

def is_valid_url(url):
    """
    Validate HTTP/HTTPS URLs.

    Supports:
        - Domain names
        - IPv4 addresses
        - Optional ports
        - Paths
        - Query strings
        - Fragments

    Returns:
        bool: True if the URL has a valid structure.
    """

    if not isinstance(url, str):
        return False

    try:
        parsed = urlparse(url)
    except ValueError:
        return False

    # Only allow HTTP and HTTPS.
    if parsed.scheme.lower() not in {
        "http",
        "https"
    }:
        return False

    if not parsed.hostname:
        return False

    hostname = parsed.hostname

    # Reject whitespace.
    if re.search(r"\s", hostname):
        return False

    # Validate IPv4 addresses.
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass

    # Validate domain names.
    if len(hostname) > 253:
        return False

    domain_pattern = re.compile(
        r"^(?=.{1,253}$)"
        r"(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}"
        r"[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}$"
    )

    return bool(
        domain_pattern.match(hostname)
    )


# --------------------------------------------------
# PRIVATE / INTERNAL IP PROTECTION
# --------------------------------------------------

def is_private_or_reserved_host(hostname):
    """
    Determine whether a hostname resolves to a private,
    loopback, link-local, reserved, multicast, or otherwise
    non-public IP address.

    This protection helps prevent SSRF attacks when the
    application makes server-side HTTP requests.
    """

    if not hostname:
        return True

    hostname = hostname.strip().lower()

    # Explicitly block localhost names.
    blocked_hostnames = {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
    }

    if hostname in blocked_hostnames:
        return True

    # Remove IPv6 brackets if present.
    hostname = hostname.strip("[]")

    # If hostname itself is an IP address, inspect it.
    try:
        ip = ipaddress.ip_address(hostname)

        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        )

    except ValueError:
        pass

    # Resolve the hostname and inspect every returned address.
    try:
        addresses = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM
        )

        for address_info in addresses:
            ip_address = address_info[4][0]

            try:
                ip = ipaddress.ip_address(
                    ip_address
                )

                if (
                    ip.is_private
                    or ip.is_loopback
                    or ip.is_link_local
                    or ip.is_reserved
                    or ip.is_multicast
                    or ip.is_unspecified
                ):
                    return True

            except ValueError:
                continue

    except socket.gaierror:
        # DNS resolution failure is handled later by requests.
        return False

    return False


# --------------------------------------------------
# URL REACHABILITY CHECK
# --------------------------------------------------

def is_url_reachable(url):
    """
    Check whether a public HTTP/HTTPS URL is reachable.

    Security:
        Prevents server-side requests to private,
        loopback, link-local, reserved, and internal
        network addresses.

    Returns:
        bool: True when a successful HTTP response is received.
    """

    if not is_valid_url(url):
        return False

    try:
        parsed = urlparse(url)

        hostname = parsed.hostname

        if is_private_or_reserved_host(hostname):
            return False

        headers = {
            "User-Agent": (
                "Mozilla/5.0 "
                "(Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 "
                "(KHTML, like Gecko) "
                "Chrome/120.0 Safari/537.36"
            )
        }

        # --------------------------------------------------
        # HEAD REQUEST
        # --------------------------------------------------

        try:
            response = requests.head(
                url,
                headers=headers,
                timeout=5,
                allow_redirects=True
            )

            if response.status_code < 400:
                return True

        except requests.exceptions.RequestException:
            pass

        # --------------------------------------------------
        # GET FALLBACK
        # --------------------------------------------------

        response = requests.get(
            url,
            headers=headers,
            timeout=5,
            allow_redirects=True,
            stream=True
        )

        return response.status_code < 400

    except requests.exceptions.RequestException:
        return False

    except Exception:
        return False
