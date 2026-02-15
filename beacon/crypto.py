import base64
import hashlib
from functools import lru_cache

from cryptography.fernet import Fernet
from django.conf import settings


@lru_cache(maxsize=1)
def _fernet() -> Fernet:
    key = getattr(settings, "CHANNEL_CONFIG_ENCRYPTION_KEY", "")
    if key:
        return Fernet(key.encode("utf-8"))

    derived = hashlib.sha256(settings.SECRET_KEY.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(derived))


def encrypt_json_bytes(plaintext: bytes) -> str:
    return _fernet().encrypt(plaintext).decode("utf-8")


def decrypt_json_bytes(ciphertext: str) -> bytes:
    return _fernet().decrypt(ciphertext.encode("utf-8"))
