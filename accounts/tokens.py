import hashlib
import hmac
import secrets

from django.conf import settings


def generate_secret_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def hash_token(raw_token: str) -> str:
    cfg = getattr(settings, "TOKEN_HASH_KEY", "")
    key = (cfg or settings.SECRET_KEY).encode("utf-8")
    msg = raw_token.encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()
