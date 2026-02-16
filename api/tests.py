from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient
from unittest.mock import patch
from typing import Any, cast

from accounts.models import User as UserModel
from accounts.tokens import hash_token
from accounts.models import EmailVerificationToken as EmailVerificationTokenModel
from accounts.models import PasswordResetToken as PasswordResetTokenModel
from beacon.models import IngestEndpoint as IngestEndpointModel
from beacon.models import Message as MessageModel

User: Any = UserModel
EmailVerificationToken: Any = EmailVerificationTokenModel
PasswordResetToken: Any = PasswordResetTokenModel
IngestEndpoint: Any = IngestEndpointModel
Message: Any = MessageModel


class IngestTests(TestCase):
    def setUp(self):
        self.client = cast(Any, APIClient())

    @override_settings(MAX_INGEST_BYTES=10, REQUIRE_VERIFIED_EMAIL_FOR_INGEST=True)
    def test_ingest_rejects_oversize(self):
        user = User.objects.create_user(email="a@example.com", password="password123")
        user.email_verified_at = timezone.now()
        user.save(update_fields=["email_verified_at"])

        raw = "test-token"
        ep = IngestEndpoint.objects.create(
            user=user, name="ep", token_hash=hash_token(raw)
        )

        resp = self.client.post(
            f"/api/ingest/{ep.id.hex}",
            data=b"01234567890",
            content_type="text/plain",
            HTTP_X_BEACON_INGEST_KEY=raw,
        )
        self.assertEqual(resp.status_code, 413)
        self.assertEqual(Message.objects.count(), 0)

    @override_settings(MAX_INGEST_BYTES=10, REQUIRE_VERIFIED_EMAIL_FOR_INGEST=True)
    def test_ingest_rejects_invalid_utf8(self):
        user = User.objects.create_user(email="a@example.com", password="password123")
        user.email_verified_at = timezone.now()
        user.save(update_fields=["email_verified_at"])

        raw = "test-token"
        ep = IngestEndpoint.objects.create(
            user=user, name="ep", token_hash=hash_token(raw)
        )

        resp = self.client.post(
            f"/api/ingest/{ep.id.hex}",
            data=b"\xff",
            content_type="text/plain",
            HTTP_X_BEACON_INGEST_KEY=raw,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(Message.objects.count(), 0)

    @override_settings(MAX_INGEST_BYTES=10, REQUIRE_VERIFIED_EMAIL_FOR_INGEST=True)
    def test_ingest_requires_verified(self):
        user = User.objects.create_user(email="a@example.com", password="password123")

        raw = "test-token"
        ep = IngestEndpoint.objects.create(
            user=user, name="ep", token_hash=hash_token(raw)
        )

        resp = self.client.post(
            f"/api/ingest/{ep.id.hex}",
            data=b"hello",
            content_type="text/plain",
            HTTP_X_BEACON_INGEST_KEY=raw,
        )
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(Message.objects.count(), 0)

    @override_settings(MAX_INGEST_BYTES=10, REQUIRE_VERIFIED_EMAIL_FOR_INGEST=True)
    def test_ingest_rejects_missing_key_header(self):
        user = User.objects.create_user(email="a@example.com", password="password123")
        user.email_verified_at = timezone.now()
        user.save(update_fields=["email_verified_at"])

        raw = "test-token"
        ep = IngestEndpoint.objects.create(
            user=user, name="ep", token_hash=hash_token(raw)
        )

        resp = self.client.post(
            f"/api/ingest/{ep.id.hex}", data=b"hello", content_type="text/plain"
        )
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(Message.objects.count(), 0)

    @override_settings(MAX_INGEST_BYTES=10, REQUIRE_VERIFIED_EMAIL_FOR_INGEST=True)
    def test_ingest_rejects_wrong_key_header(self):
        user = User.objects.create_user(email="a@example.com", password="password123")
        user.email_verified_at = timezone.now()
        user.save(update_fields=["email_verified_at"])

        raw = "test-token"
        ep = IngestEndpoint.objects.create(
            user=user, name="ep", token_hash=hash_token(raw)
        )

        resp = self.client.post(
            f"/api/ingest/{ep.id.hex}",
            data=b"hello",
            content_type="text/plain",
            HTTP_X_BEACON_INGEST_KEY="wrong",
        )
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(Message.objects.count(), 0)

    @override_settings(MAX_INGEST_BYTES=10, REQUIRE_VERIFIED_EMAIL_FOR_INGEST=True)
    def test_ingest_rejects_revoked_endpoint(self):
        user = User.objects.create_user(email="a@example.com", password="password123")
        user.email_verified_at = timezone.now()
        user.save(update_fields=["email_verified_at"])

        raw = "test-token"
        ep = IngestEndpoint.objects.create(
            user=user, name="ep", token_hash=hash_token(raw)
        )
        ep.revoked_at = timezone.now()
        ep.save(update_fields=["revoked_at"])

        resp = self.client.post(
            f"/api/ingest/{ep.id.hex}",
            data=b"hello",
            content_type="text/plain",
            HTTP_X_BEACON_INGEST_KEY=raw,
        )
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(Message.objects.count(), 0)

    @override_settings(MAX_INGEST_BYTES=10, REQUIRE_VERIFIED_EMAIL_FOR_INGEST=True)
    def test_ingest_stores_message(self):
        user = User.objects.create_user(email="a@example.com", password="password123")
        user.email_verified_at = timezone.now()
        user.save(update_fields=["email_verified_at"])

        raw = "test-token"
        ep = IngestEndpoint.objects.create(
            user=user, name="ep", token_hash=hash_token(raw)
        )

        resp = self.client.post(
            f"/api/ingest/{ep.id.hex}",
            data=b"hello",
            content_type="text/plain",
            HTTP_X_BEACON_INGEST_KEY=raw,
        )
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(Message.objects.count(), 1)

        msg = Message.objects.get()
        self.assertEqual(msg.user_id, user.id)
        self.assertEqual(msg.ingest_endpoint_id, ep.id)
        self.assertEqual(msg.payload_text, "hello")
        self.assertEqual(
            next(
                (
                    v
                    for k, v in msg.headers_json.items()
                    if k.lower() == "x-beacon-ingest-key"
                ),
                None,
            ),
            "[REDACTED]",
        )


class EmailFailureTests(TestCase):
    def setUp(self):
        self.client = cast(Any, APIClient())

    def test_signup_does_not_500_when_email_send_fails(self):
        with patch("accounts.emails.send_mail", side_effect=Exception("smtp")):
            resp = self.client.post(
                "/api/auth/signup",
                data={"email": "b@example.com", "password": "password123"},
                format="json",
            )
        self.assertEqual(resp.status_code, 201)
        self.assertTrue(User.objects.filter(email="b@example.com").exists())
        self.assertEqual(
            EmailVerificationToken.objects.filter(user__email="b@example.com").count(),
            1,
        )

    def test_forgot_password_does_not_500_when_email_send_fails(self):
        User.objects.create_user(email="c@example.com", password="password123")
        with patch("accounts.emails.send_mail", side_effect=Exception("smtp")):
            resp = self.client.post(
                "/api/auth/forgot-password",
                data={"email": "c@example.com"},
                format="json",
            )
        self.assertEqual(resp.status_code, 204)
        self.assertEqual(
            PasswordResetToken.objects.filter(user__email="c@example.com").count(),
            1,
        )


class SignupDisabledTests(TestCase):
    def setUp(self):
        self.client = cast(Any, APIClient())

    @override_settings(ALLOW_USER_SIGNUP=False)
    def test_signup_returns_403_when_disabled(self):
        resp = self.client.post(
            "/api/auth/signup",
            data={"email": "disabled@example.com", "password": "password123"},
            format="json",
        )
        self.assertEqual(resp.status_code, 403)
        data = resp.json()
        self.assertEqual(data.get("code"), "signup_disabled")
        self.assertFalse(User.objects.filter(email="disabled@example.com").exists())
