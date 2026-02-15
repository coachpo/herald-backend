from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .models import RefreshToken, User
from .tokens import generate_secret_token, hash_token


def _refresh_expiry() -> timezone.datetime:
    ttl = int(getattr(settings, "JWT_REFRESH_TTL_SECONDS", 2592000))
    return timezone.now() + timedelta(seconds=ttl)


def create_refresh_token(
    *, user: User, ip: str | None, user_agent: str | None
) -> tuple[str, RefreshToken]:
    raw = generate_secret_token(32)
    rt = RefreshToken.objects.create(
        user=user,
        token_hash=hash_token(raw),
        expires_at=_refresh_expiry(),
        ip=ip,
        user_agent=user_agent,
    )
    return raw, rt


@transaction.atomic
def rotate_refresh_token(
    *, token_hash: str, ip: str | None, user_agent: str | None
) -> tuple[str, RefreshToken]:
    now = timezone.now()
    try:
        current = RefreshToken.objects.select_for_update().get(token_hash=token_hash)
    except RefreshToken.DoesNotExist as e:
        raise ValueError("invalid_refresh") from e

    if current.revoked_at is not None:
        RefreshToken.objects.filter(
            family_id=current.family_id, revoked_at__isnull=True
        ).update(
            revoked_at=now,
            revoked_reason="family_compromised",
        )
        raise ValueError("refresh_reused")

    if current.expires_at <= now:
        current.revoked_at = now
        current.revoked_reason = "expired"
        current.save(update_fields=["revoked_at", "revoked_reason", "updated_at"])
        raise ValueError("refresh_expired")

    raw, new_rt = create_refresh_token(user=current.user, ip=ip, user_agent=user_agent)
    new_rt.family_id = current.family_id
    new_rt.save(update_fields=["family_id", "updated_at"])

    current.revoked_at = now
    current.revoked_reason = "rotated"
    current.replaced_by = new_rt
    current.last_used_at = now
    current.save(
        update_fields=[
            "revoked_at",
            "revoked_reason",
            "replaced_by",
            "last_used_at",
            "updated_at",
        ]
    )

    return raw, new_rt


def revoke_refresh_token(*, token_hash: str, reason: str):
    now = timezone.now()
    RefreshToken.objects.filter(token_hash=token_hash, revoked_at__isnull=True).update(
        revoked_at=now,
        revoked_reason=reason,
    )


def revoke_all_refresh_tokens(*, user: User, reason: str):
    now = timezone.now()
    RefreshToken.objects.filter(user=user, revoked_at__isnull=True).update(
        revoked_at=now,
        revoked_reason=reason,
    )
