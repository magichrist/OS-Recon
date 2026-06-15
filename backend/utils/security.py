import ipaddress
import socket
from urllib.parse import urlparse


def is_safe_url(url: str) -> bool:
    try:
        parsed_url = urlparse(url)
        # standard web protocols only
        if parsed_url.scheme not in ["http", "https"]:
            return False

        hostname = parsed_url.hostname
        if not hostname:
            return False

        # catches 'localhost' and '127.0.0.1' and similar domains to avoid local network calls
        ip_string = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(ip_string)

        # block private, loopback, local, and reserved ranges
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_unspecified
        ) or ip_string == "169.254.169.254":
            return False

        return True
    except (ValueError, socket.gaierror, TypeError):
        return False
