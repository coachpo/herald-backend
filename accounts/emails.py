from django.conf import settings
from django.core.mail import send_mail

from .models import User


class EmailSendError(RuntimeError):
    pass


def _from_email() -> str:
    val = getattr(settings, "DEFAULT_FROM_EMAIL", "")
    if val:
        return val
    val = getattr(settings, "EMAIL_HOST_USER", "")
    return val or "no-reply@localhost"


def send_verification_email(*, user: User, token: str):
    url = f"{settings.APP_BASE_URL.rstrip('/')}/verify-email?token={token}"
    try:
        send_mail(
            subject="Verify your email",
            message=f"Verify your email: {url}",
            from_email=_from_email(),
            recipient_list=[user.email],
            fail_silently=False,
        )
    except Exception as e:
        raise EmailSendError("verification_email_failed") from e


def send_password_reset_email(*, user: User, token: str):
    url = f"{settings.APP_BASE_URL.rstrip('/')}/reset-password?token={token}"
    try:
        send_mail(
            subject="Reset your password",
            message=f"Reset your password: {url}",
            from_email=_from_email(),
            recipient_list=[user.email],
            fail_silently=False,
        )
    except Exception as e:
        raise EmailSendError("password_reset_email_failed") from e


def send_account_deleted_email(*, email: str, deleted_at):
    try:
        send_mail(
            subject="Account deleted",
            message=f"Your account was deleted at {deleted_at.isoformat()}.",
            from_email=_from_email(),
            recipient_list=[email],
            fail_silently=False,
        )
    except Exception as e:
        raise EmailSendError("account_deleted_email_failed") from e
