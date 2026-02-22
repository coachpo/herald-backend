from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient
from unittest.mock import patch
from typing import Any, cast

from accounts.models import User as UserModel
from accounts.tokens import hash_token
from accounts.models import EmailVerificationToken as EmailVerificationTokenModel
from accounts.models import PasswordResetToken as PasswordResetTokenModel
from core.models import IngestEndpoint as IngestEndpointModel
from core.models import Message as MessageModel
from core.models import Channel as ChannelModel
from core.models import ForwardingRule as ForwardingRuleModel

User: Any = UserModel
EmailVerificationToken: Any = EmailVerificationTokenModel
PasswordResetToken: Any = PasswordResetTokenModel
IngestEndpoint: Any = IngestEndpointModel
Message: Any = MessageModel
Channel: Any = ChannelModel
ForwardingRule: Any = ForwardingRuleModel


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
            data=b'{"body":"hello"}',
            content_type="application/json",
            HTTP_X_HERALD_INGEST_KEY=raw,
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
            content_type="application/json",
            HTTP_X_HERALD_INGEST_KEY=raw,
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
            data=b'{"body":"hello"}',
            content_type="application/json",
            HTTP_X_HERALD_INGEST_KEY=raw,
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
            f"/api/ingest/{ep.id.hex}",
            data=b'{"body":"hello"}',
            content_type="application/json",
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
            data=b'{"body":"hello"}',
            content_type="application/json",
            HTTP_X_HERALD_INGEST_KEY="wrong-token",
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
            data=b'{"body":"hello"}',
            content_type="application/json",
            HTTP_X_HERALD_INGEST_KEY=raw,
        )
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(Message.objects.count(), 0)

    @override_settings(MAX_INGEST_BYTES=100, REQUIRE_VERIFIED_EMAIL_FOR_INGEST=True)
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
            data=b'{"title":"Hi","body":"hello","priority":4,"tags":["a"]}',
            content_type="application/json",
            HTTP_X_HERALD_INGEST_KEY=raw,
        )
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(Message.objects.count(), 1)

        msg = Message.objects.get()
        self.assertEqual(msg.user_id, user.id)
        self.assertEqual(msg.ingest_endpoint_id, ep.id)
        self.assertEqual(msg.body, "hello")
        self.assertEqual(msg.title, "Hi")
        self.assertEqual(msg.priority, 4)
        self.assertEqual(msg.tags_json, ["a"])
        self.assertEqual(
            next(
                (
                    v
                    for k, v in msg.headers_json.items()
                    if k.lower() == "x-herald-ingest-key"
                ),
                None,
            ),
            "[REDACTED]",
        )

    @override_settings(MAX_INGEST_BYTES=100, REQUIRE_VERIFIED_EMAIL_FOR_INGEST=True)
    def test_ingest_accepts_dashed_uuid_path(self):
        user = User.objects.create_user(email="a@example.com", password="password123")
        user.email_verified_at = timezone.now()
        user.save(update_fields=["email_verified_at"])

        raw = "test-token"
        ep = IngestEndpoint.objects.create(
            user=user, name="ep", token_hash=hash_token(raw)
        )

        resp = self.client.post(
            f"/api/ingest/{ep.id}",
            data=b'{"body":"hello from dashed"}',
            content_type="application/json",
            HTTP_X_HERALD_INGEST_KEY=raw,
        )
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(Message.objects.count(), 1)
        msg = Message.objects.get()
        self.assertEqual(msg.body, "hello from dashed")


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


class RateLimitTests(TestCase):
    def setUp(self):
        self.client = cast(Any, APIClient())

    def test_signup_rate_limit_per_ip(self):
        for i in range(10):
            resp = self.client.post(
                "/api/auth/signup",
                data={"email": f"rl{i}@example.com", "password": "password123"},
                format="json",
            )
            self.assertIn(resp.status_code, [201, 400])

        resp = self.client.post(
            "/api/auth/signup",
            data={"email": "rl_extra@example.com", "password": "password123"},
            format="json",
        )
        self.assertEqual(resp.status_code, 400)
        data = resp.json()
        self.assertEqual(data.get("code"), "rate_limited")

    def test_forgot_password_rate_limit_per_ip(self):
        User.objects.create_user(email="fp@example.com", password="password123")
        for _ in range(10):
            resp = self.client.post(
                "/api/auth/forgot-password",
                data={"email": "fp@example.com"},
                format="json",
            )
            self.assertEqual(resp.status_code, 204)

        resp = self.client.post(
            "/api/auth/forgot-password",
            data={"email": "fp@example.com"},
            format="json",
        )
        self.assertEqual(resp.status_code, 204)
        self.assertLessEqual(
            PasswordResetToken.objects.filter(user__email="fp@example.com").count(), 10
        )

    def test_forgot_password_rate_limit_per_email(self):
        User.objects.create_user(email="fpe@example.com", password="password123")
        for _ in range(5):
            resp = self.client.post(
                "/api/auth/forgot-password",
                data={"email": "fpe@example.com"},
                format="json",
            )
            self.assertEqual(resp.status_code, 204)

        resp = self.client.post(
            "/api/auth/forgot-password",
            data={"email": "fpe@example.com"},
            format="json",
        )
        self.assertEqual(resp.status_code, 204)
        self.assertLessEqual(
            PasswordResetToken.objects.filter(user__email="fpe@example.com").count(), 5
        )

    def test_resend_verification_rate_limit_per_user(self):
        user = User.objects.create_user(email="rv@example.com", password="password123")
        self.client.force_authenticate(user=user)

        for _ in range(3):
            resp = self.client.post("/api/auth/resend-verification")
            self.assertEqual(resp.status_code, 204)

        resp = self.client.post("/api/auth/resend-verification")
        self.assertEqual(resp.status_code, 204)
        self.assertLessEqual(
            EmailVerificationToken.objects.filter(user=user).count(), 4
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


class EdgeConfigTests(TestCase):
    def setUp(self):
        self.client = cast(Any, APIClient())
        self.user = User.objects.create_user(
            email="edge@example.com", password="password123"
        )
        self.user.email_verified_at = timezone.now()
        self.user.save(update_fields=["email_verified_at"])
        self.client.force_authenticate(user=self.user)

    def test_edge_config_requires_auth(self):
        client = cast(Any, APIClient())
        resp = client.get("/api/edge-config")
        self.assertEqual(resp.status_code, 401)

    def test_edge_config_returns_correct_shape(self):
        IngestEndpoint.objects.create(
            user=self.user, name="ep1", token_hash=hash_token("tok")
        )

        ch_bark = Channel.objects.create(user=self.user, type="bark", name="My Bark")
        ch_bark.config = {
            "server_base_url": "https://bark.example.com",
            "device_key": "dk",
        }
        ch_bark.save()

        ch_ntfy = Channel.objects.create(user=self.user, type="ntfy", name="My Ntfy")
        ch_ntfy.config = {"server_base_url": "https://ntfy.sh", "topic": "t"}
        ch_ntfy.save()

        ch_mqtt = Channel.objects.create(user=self.user, type="mqtt", name="MQTT")
        ch_mqtt.config = {"host": "mqtt.example.com"}
        ch_mqtt.save()

        ForwardingRule.objects.create(
            user=self.user,
            name="rule1",
            channel=ch_bark,
            filter_json={"body": {"contains": ["alert"]}},
            payload_template_json={"body": "{{message.body}}"},
        )

        resp = self.client.get("/api/edge-config")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        self.assertIn("ingest_endpoints", data)
        self.assertIn("channels", data)
        self.assertIn("rules", data)
        self.assertIn("version", data)
        self.assertIn("updated_at", data)

        self.assertEqual(len(data["ingest_endpoints"]), 1)
        self.assertEqual(data["ingest_endpoints"][0]["name"], "ep1")
        self.assertIn("token_hash", data["ingest_endpoints"][0])

        self.assertEqual(len(data["channels"]), 2)
        channel_types = {ch["type"] for ch in data["channels"]}
        self.assertEqual(channel_types, {"bark", "ntfy"})

        bark_ch = next(c for c in data["channels"] if c["type"] == "bark")
        self.assertEqual(bark_ch["config"]["device_key"], "dk")

        self.assertEqual(len(data["rules"]), 1)
        self.assertEqual(data["rules"][0]["name"], "rule1")
        self.assertEqual(data["rules"][0]["channel_id"], str(ch_bark.id))
        self.assertEqual(data["rules"][0]["filter"], {"body": {"contains": ["alert"]}})

    def test_edge_config_excludes_disabled_channels(self):
        ch = Channel.objects.create(user=self.user, type="bark", name="Disabled")
        ch.config = {"server_base_url": "https://bark.example.com"}
        ch.disabled_at = timezone.now()
        ch.save()

        resp = self.client.get("/api/edge-config")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.json()["channels"]), 0)

    def test_edge_config_excludes_revoked_endpoints(self):
        ep = IngestEndpoint.objects.create(
            user=self.user, name="revoked", token_hash=hash_token("tok")
        )
        ep.revoked_at = timezone.now()
        ep.save(update_fields=["revoked_at"])

        resp = self.client.get("/api/edge-config")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.json()["ingest_endpoints"]), 0)
