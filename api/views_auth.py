from __future__ import annotations

import logging
import time

from django.db import IntegrityError
from django.db.utils import OperationalError
from django.http import HttpRequest
from django.utils import timezone
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.flows import create_email_verification, create_password_reset
from accounts.jwt import issue_access_token
from accounts.emails import EmailSendError, send_account_deleted_email
from accounts.models import EmailVerificationToken, PasswordResetToken, User
from accounts.sessions import (
    create_refresh_token,
    revoke_all_refresh_tokens,
    revoke_refresh_token,
    rotate_refresh_token,
)
from accounts.tokens import hash_token

from beacon.models import IngestEndpoint

from .errors import api_error
from .ratelimit import allow_rate
from .serializers import (
    DeleteAccountRequestSerializer,
    ChangeEmailRequestSerializer,
    ChangePasswordRequestSerializer,
    ForgotPasswordRequestSerializer,
    LoginRequestSerializer,
    ResetPasswordRequestSerializer,
    SignupRequestSerializer,
    UserSerializer,
    VerifyEmailRequestSerializer,
)


logger = logging.getLogger(__name__)


def _client_ip(req: HttpRequest) -> str | None:
    return req.META.get("REMOTE_ADDR")


def _user_agent(req: HttpRequest) -> str | None:
    return req.META.get("HTTP_USER_AGENT")


def _set_refresh_cookie(resp: Response, raw_refresh: str):
    from django.conf import settings

    resp.set_cookie(
        settings.JWT_REFRESH_COOKIE_NAME,
        raw_refresh,
        max_age=int(settings.JWT_REFRESH_TTL_SECONDS),
        httponly=True,
        secure=bool(settings.JWT_REFRESH_COOKIE_SECURE),
        samesite=settings.JWT_REFRESH_COOKIE_SAMESITE,
        path="/api/auth/refresh",
    )


def _clear_refresh_cookie(resp: Response):
    from django.conf import settings

    resp.delete_cookie(
        settings.JWT_REFRESH_COOKIE_NAME,
        path="/api/auth/refresh",
    )


class SignupView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        ip = _client_ip(request._request) or ""
        if ip and not allow_rate(key=f"su:{ip}", limit=10, window_seconds=3600):
            return api_error(code="rate_limited", message="try later", status=400)

        ser = SignupRequestSerializer(data=request.data)
        if not ser.is_valid():
            return api_error(
                code="validation_error",
                message="invalid request",
                status=400,
                details=ser.errors,
            )

        try:
            user = User.objects.create_user(
                email=ser.validated_data["email"],
                password=ser.validated_data["password"],
            )
        except IntegrityError:
            return api_error(
                code="email_taken", message="email already in use", status=400
            )

        try:
            create_email_verification(user=user)
        except EmailSendError:
            logger.exception(
                "signup_verification_email_failed", extra={"user_id": str(user.id)}
            )
        return Response({"user": UserSerializer(user).data}, status=201)


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        ser = LoginRequestSerializer(data=request.data)
        if not ser.is_valid():
            return api_error(
                code="validation_error",
                message="invalid request",
                status=400,
                details=ser.errors,
            )

        email = ser.validated_data["email"].strip().lower()
        password = ser.validated_data["password"]
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return api_error(
                code="invalid_credentials", message="invalid credentials", status=401
            )

        if not user.is_active or not user.check_password(password):
            return api_error(
                code="invalid_credentials", message="invalid credentials", status=401
            )

        access = issue_access_token(user)
        raw_refresh, _ = create_refresh_token(
            user=user,
            ip=_client_ip(request._request),
            user_agent=_user_agent(request._request),
        )
        resp = Response(
            {"access_token": access, "user": UserSerializer(user).data}, status=200
        )
        _set_refresh_cookie(resp, raw_refresh)
        return resp


class RefreshView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        from django.conf import settings

        raw = request.COOKIES.get(settings.JWT_REFRESH_COOKIE_NAME)
        if not raw:
            return api_error(
                code="not_authenticated", message="missing refresh token", status=401
            )

        token_hash = hash_token(raw)
        try:
            # SQLite can throw transient "database is locked" under concurrent
            # refresh + worker writes. Small retries avoid returning 500s.
            for attempt in range(3):
                try:
                    new_raw, rt = rotate_refresh_token(
                        token_hash=token_hash,
                        ip=_client_ip(request._request),
                        user_agent=_user_agent(request._request),
                    )
                    break
                except OperationalError as e:
                    if "database is locked" in str(e).lower() and attempt < 2:
                        time.sleep(0.05 * (2**attempt))
                        continue
                    raise
        except ValueError:
            resp = api_error(
                code="not_authenticated", message="invalid refresh token", status=401
            )
            _clear_refresh_cookie(resp)
            return resp
        except OperationalError as e:
            logger.exception("refresh_db_locked", extra={"err": str(e)})
            return api_error(
                code="temporarily_unavailable", message="try again", status=503
            )

        access = issue_access_token(rt.user)
        resp = Response(
            {"access_token": access, "user": UserSerializer(rt.user).data}, status=200
        )
        _set_refresh_cookie(resp, new_raw)
        return resp


class LogoutView(APIView):
    def post(self, request):
        from django.conf import settings

        raw = request.COOKIES.get(settings.JWT_REFRESH_COOKIE_NAME)
        if raw:
            revoke_refresh_token(token_hash=hash_token(raw), reason="logout")

        resp = Response(status=204)
        _clear_refresh_cookie(resp)
        return resp


class MeView(APIView):
    def get(self, request):
        return Response({"user": UserSerializer(request.user).data}, status=200)


class ResendVerificationView(APIView):
    def post(self, request):
        user: User = request.user
        if user.email_verified_at is not None:
            return Response(status=204)

        key = f"rv:{user.id}"
        if not allow_rate(key=key, limit=3, window_seconds=3600):
            return Response(status=204)

        try:
            create_email_verification(user=user)
        except EmailSendError:
            logger.exception(
                "resend_verification_email_failed",
                extra={"user_id": str(user.id)},
            )
        return Response(status=204)


class VerifyEmailView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        ser = VerifyEmailRequestSerializer(data=request.data)
        if not ser.is_valid():
            return api_error(
                code="validation_error",
                message="invalid request",
                status=400,
                details=ser.errors,
            )

        token_hash = hash_token(ser.validated_data["token"])
        now = timezone.now()
        try:
            tok = EmailVerificationToken.objects.select_related("user").get(
                token_hash=token_hash
            )
        except EmailVerificationToken.DoesNotExist:
            return api_error(
                code="invalid_token", message="invalid or expired token", status=400
            )

        if tok.used_at is not None or tok.expires_at <= now:
            return api_error(
                code="invalid_token", message="invalid or expired token", status=400
            )

        user = tok.user
        user.email_verified_at = now
        user.save(update_fields=["email_verified_at"])
        tok.used_at = now
        tok.save(update_fields=["used_at"])
        return Response(status=204)


class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        ser = ForgotPasswordRequestSerializer(data=request.data)
        if not ser.is_valid():
            return api_error(
                code="validation_error",
                message="invalid request",
                status=400,
                details=ser.errors,
            )

        email = ser.validated_data["email"].strip().lower()
        ip = _client_ip(request._request) or ""
        if not allow_rate(key=f"fp:{ip}", limit=10, window_seconds=3600):
            return Response(status=204)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(status=204)
        if not user.is_active:
            return Response(status=204)

        try:
            create_password_reset(user=user)
        except EmailSendError:
            logger.exception(
                "forgot_password_email_failed",
                extra={"user_id": str(user.id)},
            )
        return Response(status=204)


class ResetPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        ser = ResetPasswordRequestSerializer(data=request.data)
        if not ser.is_valid():
            return api_error(
                code="validation_error",
                message="invalid request",
                status=400,
                details=ser.errors,
            )

        token_hash = hash_token(ser.validated_data["token"])
        now = timezone.now()
        try:
            tok = PasswordResetToken.objects.select_related("user").get(
                token_hash=token_hash
            )
        except PasswordResetToken.DoesNotExist:
            return api_error(
                code="invalid_token", message="invalid or expired token", status=400
            )

        if tok.used_at is not None or tok.expires_at <= now:
            return api_error(
                code="invalid_token", message="invalid or expired token", status=400
            )

        user = tok.user
        user.set_password(ser.validated_data["new_password"])
        user.save(update_fields=["password"])
        tok.used_at = now
        tok.save(update_fields=["used_at"])
        revoke_all_refresh_tokens(user=user, reason="password_reset")
        return Response(status=204)


class ChangeEmailView(APIView):
    def post(self, request):
        ser = ChangeEmailRequestSerializer(data=request.data)
        if not ser.is_valid():
            return api_error(
                code="validation_error",
                message="invalid request",
                status=400,
                details=ser.errors,
            )

        user: User = request.user
        user.email = ser.validated_data["new_email"].strip().lower()
        user.email_verified_at = None
        try:
            user.save(update_fields=["email", "email_verified_at"])
        except IntegrityError:
            return api_error(
                code="email_taken", message="email already in use", status=400
            )

        try:
            create_email_verification(user=user)
        except EmailSendError:
            logger.exception(
                "change_email_verification_email_failed",
                extra={"user_id": str(user.id)},
            )
        return Response({"user": UserSerializer(user).data}, status=200)


class ChangePasswordView(APIView):
    def post(self, request):
        ser = ChangePasswordRequestSerializer(data=request.data)
        if not ser.is_valid():
            return api_error(
                code="validation_error",
                message="invalid request",
                status=400,
                details=ser.errors,
            )

        user: User = request.user
        if not user.check_password(ser.validated_data["old_password"]):
            return api_error(
                code="invalid_credentials", message="invalid credentials", status=401
            )

        user.set_password(ser.validated_data["new_password"])
        user.save(update_fields=["password"])
        revoke_all_refresh_tokens(user=user, reason="password_changed")
        return Response(status=204)


class DeleteAccountView(APIView):
    def post(self, request):
        ser = DeleteAccountRequestSerializer(data=request.data)
        if not ser.is_valid():
            return api_error(
                code="validation_error",
                message="invalid request",
                status=400,
                details=ser.errors,
            )

        user: User = request.user
        if not user.check_password(ser.validated_data["password"]):
            return api_error(
                code="invalid_credentials", message="invalid credentials", status=401
            )

        email = user.email
        now = timezone.now()

        revoke_all_refresh_tokens(user=user, reason="account_deleted")
        IngestEndpoint.objects.filter(user=user, revoked_at__isnull=True).update(
            revoked_at=now
        )

        user.delete()

        resp = Response(status=204)
        _clear_refresh_cookie(resp)

        try:
            send_account_deleted_email(email=email, deleted_at=now)
        except EmailSendError:
            logger.exception("account_deleted_email_failed", extra={"email": email})

        return resp
