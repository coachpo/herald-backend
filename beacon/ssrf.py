import ipaddress
import socket
from urllib.parse import urlparse

from django.conf import settings


def _is_blocked_ip(ip: str, *, block_private_networks: bool) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if addr.is_loopback or addr.is_link_local:
        return True
    if block_private_networks and addr.is_private:
        return True
    return False


def assert_host_ssrf_safe(host: str, *, block_private_networks: bool):
    if host in {"localhost"}:
        raise ValueError("blocked_host")

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise ValueError("unresolvable_host") from e

    for info in infos:
        ip = str(info[4][0])
        if _is_blocked_ip(ip, block_private_networks=block_private_networks):
            raise ValueError("blocked_ip")


def assert_ssrf_safe(url: str, *, block_private_networks: bool | None = None):
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("invalid_url_scheme")
    if not parsed.hostname:
        raise ValueError("invalid_url_host")

    val = block_private_networks
    if val is None:
        val = bool(getattr(settings, "BARK_BLOCK_PRIVATE_NETWORKS", True))

    assert_host_ssrf_safe(parsed.hostname, block_private_networks=val)
