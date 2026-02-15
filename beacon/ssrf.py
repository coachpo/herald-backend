import ipaddress
import socket
from urllib.parse import urlparse

from django.conf import settings


def _is_blocked_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if addr.is_loopback or addr.is_link_local:
        return True
    if getattr(settings, "BARK_BLOCK_PRIVATE_NETWORKS", True) and addr.is_private:
        return True
    return False


def assert_ssrf_safe(url: str):
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("invalid_url_scheme")
    if not parsed.hostname:
        raise ValueError("invalid_url_host")

    host = parsed.hostname
    if host in {"localhost"}:
        raise ValueError("blocked_host")

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise ValueError("unresolvable_host") from e

    for info in infos:
        ip = info[4][0]
        if _is_blocked_ip(ip):
            raise ValueError("blocked_ip")
