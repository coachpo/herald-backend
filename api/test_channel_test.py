from unittest.mock import Mock, patch

from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from accounts.models import User
from beacon.models import Channel


class ChannelTestEndpointTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="a@example.com", password="password123"
        )
        self.user.email_verified_at = timezone.now()
        self.user.save(update_fields=["email_verified_at"])
        self.client.force_authenticate(user=self.user)

    @patch("beacon.bark.send_bark_push")
    def test_channel_test_bark_sends(self, send_bark_push: Mock):
        send_bark_push.return_value = (True, {"http_status": 200})
        ch = Channel(
            user=self.user, type=Channel.TYPE_BARK, name="b", config_json_encrypted=""
        )
        ch.config = {
            "server_base_url": "https://bark.example.com",
            "device_key": "Abcdef0123456789",
            "default_payload_json": {"group": "beacon"},
        }
        ch.save()

        resp = self.client.post(
            f"/api/channels/{ch.id}/test",
            data={"title": "Smoke", "body": "Hello"},
            format="json",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data.get("channel_type"), "bark")
        self.assertEqual(resp.data.get("ok"), True)
        pr = resp.data.get("provider_response")
        self.assertIsInstance(pr, dict)
        self.assertEqual(pr.get("provider"), "bark")
        send_bark_push.assert_called()

    @patch("beacon.mqtt.send_mqtt_publish")
    def test_channel_test_mqtt_sends(self, send_mqtt_publish: Mock):
        send_mqtt_publish.return_value = (
            True,
            {"broker_host": "h", "broker_port": 1883, "topic": "t"},
        )
        ch = Channel(
            user=self.user, type=Channel.TYPE_MQTT, name="m", config_json_encrypted=""
        )
        ch.config = {
            "broker_host": "mqtt.example.com",
            "broker_port": 1883,
            "topic": "beacon/test",
            "qos": 0,
            "retain": False,
            "tls": False,
            "tls_insecure": False,
            "keepalive_seconds": 60,
        }
        ch.save()

        resp = self.client.post(
            f"/api/channels/{ch.id}/test",
            data={"body": "Hello"},
            format="json",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data.get("channel_type"), "mqtt")
        self.assertEqual(resp.data.get("ok"), True)
        pr = resp.data.get("provider_response")
        self.assertIsInstance(pr, dict)
        self.assertEqual(pr.get("provider"), "mqtt")
        send_mqtt_publish.assert_called()

    @patch("beacon.ssrf.assert_ssrf_safe")
    @patch("beacon.ntfy.send_ntfy_publish")
    def test_channel_test_ntfy_sends(
        self, send_ntfy_publish: Mock, assert_ssrf_safe: Mock
    ):
        send_ntfy_publish.return_value = (True, {"http_status": 200})
        ch = Channel(
            user=self.user, type=Channel.TYPE_NTFY, name="n", config_json_encrypted=""
        )
        ch.config = {
            "server_base_url": "https://ntfy.example.com",
            "topic": "beacon-test",
            "default_headers_json": {"Tags": "beacon"},
        }
        ch.save()

        resp = self.client.post(
            f"/api/channels/{ch.id}/test",
            data={"title": "Smoke", "body": "Hello"},
            format="json",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data.get("channel_type"), "ntfy")
        self.assertEqual(resp.data.get("ok"), True)
        pr = resp.data.get("provider_response")
        self.assertIsInstance(pr, dict)
        self.assertEqual(pr.get("provider"), "ntfy")
        send_ntfy_publish.assert_called()
