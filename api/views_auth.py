from __future__ import annotations

import logging
import time
from typing import Any, cast

from django.conf import settings
from django.db import IntegrityError
from django.db.utils import OperationalError
from django.http import HttpRequest
from django.utils import timezone
from rest_framework import serializers
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


class RefreshRequestSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()


class LogoutRequestSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(required=False, allow_blank=True)


logger = logging.getLogger(__name__)


_UserModel = cast(Any, User)
_EmailVerificationTokenModel = cast(Any, EmailVerificationToken)
_PasswordResetTokenModel = cast(Any, PasswordResetToken)
_IngestEndpointModel = cast(Any, IngestEndpoint)


def _client_ip(req: HttpRequest) -> str | None:
    return req.META.get("REMOTE_ADDR")


def _user_agent(req: HttpRequest) -> str | None:
    return req.META.get("HTTP_USER_AGENT")


class SignupView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        if not getattr(settings, "ALLOW_USER_SIGNUP", True):
            return api_error(
                code="signup_disabled", message="signup disabled", status=403
            )

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
            data = cast(dict[str, Any], ser.validated_data)
            user = _UserModel.objects.create_user(
                email=data.get("email"),
                password=data.get("password"),
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
    authentication_classes: list = []

    def post(self, request):
        ser = LoginRequestSerializer(data=request.data)
        if not ser.is_valid():
            return api_error(
                code="validation_error",
                message="invalid request",
                status=400,
                details=ser.errors,
            )

        data = cast(dict[str, Any], ser.validated_data)
        email = str(data.get("email") or "").strip().lower()
        password = str(data.get("password") or "")
        try:
            user = _UserModel.objects.get(email=email)
        except _UserModel.DoesNotExist:
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
            {
                "access_token": access,
                "refresh_token": raw_refresh,
                "user": UserSerializer(user).data,
            },
            status=200,
        )
        resp["Cache-Control"] = "no-store"
        return resp


class RefreshView(APIView):
    permission_classes = [AllowAny]
    authentication_classes: list = []

    def post(self, request):
        ser = RefreshRequestSerializer(data=request.data)
        if not ser.is_valid():
            return api_error(
                code="validation_error",
                message="invalid request",
                status=400,
                details=ser.errors,
            )

        data = cast(dict[str, Any], ser.validated_data)
        raw = str(data.get("refresh_token") or "").strip()
        if not raw:
            return api_error(
                code="not_authenticated", message="missing refresh token", status=401
            )

        token_hash = hash_token(raw)
        try:
            # SQLite can throw transient "database is locked" under concurrent
            # refresh + worker writes. Small retries avoid returning 500s.
            new_raw: str | None = None
            rt = None
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
            return api_error(
                code="not_authenticated", message="invalid refresh token", status=401
            )
        except OperationalError as e:
            logger.exception("refresh_db_locked", extra={"err": str(e)})
            return api_error(
                code="temporarily_unavailable", message="try again", status=503
            )

        if not rt or not new_raw:
            return api_error(
                code="temporarily_unavailable", message="try again", status=503
            )

        rt_user = cast(Any, rt).user
        access = issue_access_token(rt_user)
        resp = Response(
            {
                "access_token": access,
                "refresh_token": new_raw,
                "user": UserSerializer(rt_user).data,
            },
            status=200,
        )
        resp["Cache-Control"] = "no-store"
        return resp


class LogoutView(APIView):
    permission_classes = [AllowAny]
    authentication_classes: list = []

    def post(self, request):
        ser = LogoutRequestSerializer(data=request.data)
        if not ser.is_valid():
            return api_error(
                code="validation_error",
                message="invalid request",
                status=400,
                details=ser.errors,
            )

        data = cast(dict[str, Any], ser.validated_data)
        raw = str(data.get("refresh_token") or "").strip()
        if raw:
            revoke_refresh_token(token_hash=hash_token(raw), reason="logout")
        return Response(status=204)


class MeView(APIView):
    def get(self, request):
        return Response({"user": UserSerializer(request.user).data}, status=200)


class ResendVerificationView(APIView):
    def post(self, request):
        user: User = request.user
        if user.email_verified_at is not None:
            return Response(status=204)

        ip = _client_ip(request._request) or ""
        if ip and not allow_rate(key=f"rv:ip:{ip}", limit=10, window_seconds=3600):
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

        data = cast(dict[str, Any], ser.validated_data)
        token_hash = hash_token(str(data.get("token") or ""))
        now = timezone.now()
        try:
            tok = _EmailVerificationTokenModel.objects.select_related("user").get(
                token_hash=token_hash
            )
        except _EmailVerificationTokenModel.DoesNotExist:
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

        data = cast(dict[str, Any], ser.validated_data)
        email = str(data.get("email") or "").strip().lower()
        ip = _client_ip(request._request) or ""
        if ip and not allow_rate(key=f"fp:{ip}", limit=10, window_seconds=3600):
            return Response(status=204)
        if email and not allow_rate(key=f"fp:e:{email}", limit=5, window_seconds=3600):
            return Response(status=204)

        try:
            user = _UserModel.objects.get(email=email)
        except _UserModel.DoesNotExist:
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

        data = cast(dict[str, Any], ser.validated_data)
        token_hash = hash_token(str(data.get("token") or ""))
        now = timezone.now()
        try:
            tok = _PasswordResetTokenModel.objects.select_related("user").get(
                token_hash=token_hash
            )
        except _PasswordResetTokenModel.DoesNotExist:
            return api_error(
                code="invalid_token", message="invalid or expired token", status=400
            )

        if tok.used_at is not None or tok.expires_at <= now:
            return api_error(
                code="invalid_token", message="invalid or expired token", status=400
            )

        user = tok.user
        user.set_password(str(data.get("new_password") or ""))
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
        data = cast(dict[str, Any], ser.validated_data)
        user.email = str(data.get("new_email") or "").strip().lower()
        setattr(user, "email_verified_at", None)
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
        data = cast(dict[str, Any], ser.validated_data)
        if not user.check_password(str(data.get("old_password") or "")):
            return api_error(
                code="invalid_credentials", message="invalid credentials", status=401
            )

        user.set_password(str(data.get("new_password") or ""))
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
        data = cast(dict[str, Any], ser.validated_data)
        if not user.check_password(str(data.get("password") or "")):
            return api_error(
                code="invalid_credentials", message="invalid credentials", status=401
            )

        email = str(getattr(user, "email", ""))
        now = timezone.now()

        revoke_all_refresh_tokens(user=user, reason="account_deleted")
        _IngestEndpointModel.objects.filter(user=user, revoked_at__isnull=True).update(
            revoked_at=now
        )

        user.delete()

        try:
            send_account_deleted_email(email=email, deleted_at=now)
        except EmailSendError:
            logger.exception("account_deleted_email_failed", extra={"email": email})

        return Response(status=204)
