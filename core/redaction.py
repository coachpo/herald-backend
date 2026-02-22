import re
from collections.abc import Mapping


_EXACT_REDACT = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrftoken",
    "x-csrf-token",
}

_NAME_PATTERNS = [
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"password", re.IGNORECASE),
    re.compile(r"auth", re.IGNORECASE),
    re.compile(r"key", re.IGNORECASE),
]


def redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in headers.items():
        name = str(k)
        val = str(v)
        lower = name.lower()
        redact = lower in _EXACT_REDACT or any(p.search(name) for p in _NAME_PATTERNS)
        out[name] = "[REDACTED]" if redact else val
    return out
