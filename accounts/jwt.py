import time

import jwt
from django.conf import settings
from rest_framework import authentication
from rest_framework.exceptions import AuthenticationFailed

from .models import User


def issue_access_token(user: User) -> str:
    now = int(time.time())
    exp = now + int(getattr(settings, "JWT_ACCESS_TTL_SECONDS", 900))
    payload = {
        "sub": str(user.id),
        "email": user.email,
        "iat": now,
        "exp": exp,
    }
    return jwt.encode(payload, settings.JWT_SIGNING_KEY, algorithm="HS256")


class JWTAuthentication(authentication.BaseAuthentication):
    def authenticate_header(self, request):
        return "Bearer"

    def authenticate(self, request):
        auth = request.META.get("HTTP_AUTHORIZATION") or ""
        if not auth:
            return None
        parts = auth.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise AuthenticationFailed("invalid_authorization")

        token = parts[1]
        try:
            payload = jwt.decode(token, settings.JWT_SIGNING_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError as e:
            raise AuthenticationFailed("token_expired") from e
        except jwt.PyJWTError as e:
            raise AuthenticationFailed("invalid_token") from e

        sub = payload.get("sub")
        if not sub:
            raise AuthenticationFailed("invalid_token")

        try:
            user = User.objects.get(id=sub)
        except User.DoesNotExist as e:
            raise AuthenticationFailed("invalid_user") from e
        if not user.is_active:
            raise AuthenticationFailed("inactive_user")

        return (user, payload)
