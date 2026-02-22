from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from accounts.models import User
from core.crypto import _fernet
from core.models import Channel


class ChannelsCreateTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="a@example.com", password="password123"
        )
        self.user.email_verified_at = timezone.now()
        self.user.save(update_fields=["email_verified_at"])
        self.client.force_authenticate(user=self.user)

    def test_create_channel_rejects_overlong_name(self):
        payload = {
            "type": "bark",
            "name": "x" * 201,
            "config": {
                "server_base_url": "https://bark.example.com",
                "device_key": "Abcdef0123456789",
            },
        }

        resp = self.client.post("/api/channels", data=payload, format="json")
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.data.get("code"), "validation_error")
        details = resp.data.get("details") or {}
        self.assertIn("name", details)

    @override_settings(CHANNEL_CONFIG_ENCRYPTION_KEY="not-a-valid-fernet-key")
    def test_create_channel_accepts_non_fernet_key_string(self):
        _fernet.cache_clear()
        try:
            payload = {
                "type": "bark",
                "name": "b",
                "config": {
                    "server_base_url": "https://bark.example.com",
                    "device_key": "Abcdef0123456789",
                },
            }

            resp = self.client.post("/api/channels", data=payload, format="json")
            self.assertEqual(resp.status_code, 201)
            cid = resp.data.get("channel", {}).get("id")
            self.assertTrue(cid)

            ch = Channel.objects.get(id=cid)
            cfg = ch.config
            self.assertEqual(cfg.get("server_base_url"), "https://bark.example.com")
            self.assertEqual(cfg.get("device_key"), "Abcdef0123456789")
        finally:
            _fernet.cache_clear()
