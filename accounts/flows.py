from datetime import timedelta

from django.utils import timezone

from .emails import send_password_reset_email, send_verification_email
from .models import EmailVerificationToken, PasswordResetToken, User
from .tokens import generate_secret_token, hash_token


def create_email_verification(*, user: User) -> str:
    raw = generate_secret_token(32)
    EmailVerificationToken.objects.create(
        user=user,
        token_hash=hash_token(raw),
        expires_at=timezone.now() + timedelta(hours=24),
    )
    send_verification_email(user=user, token=raw)
    return raw


def create_password_reset(*, user: User) -> str:
    raw = generate_secret_token(32)
    PasswordResetToken.objects.create(
        user=user,
        token_hash=hash_token(raw),
        expires_at=timezone.now() + timedelta(hours=1),
    )
    send_password_reset_email(user=user, token=raw)
    return raw
