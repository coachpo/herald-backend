from django.test import TestCase

from api.serializers import ChannelUpsertRequestSerializer


class BarkChannelConfigNormalizationTests(TestCase):
    def test_extracts_device_key_from_base_url_path(self):
        ser = ChannelUpsertRequestSerializer(
            data={
                "type": "bark",
                "name": "b",
                "config": {
                    "server_base_url": "https://bark.example.com/Abcdef0123456789/",
                },
            }
        )
        self.assertTrue(ser.is_valid(), ser.errors)
        cfg = ser.validated_data["config"]
        self.assertEqual(cfg["server_base_url"], "https://bark.example.com")
        self.assertEqual(cfg["device_key"], "Abcdef0123456789")

    def test_strips_push_suffix(self):
        ser = ChannelUpsertRequestSerializer(
            data={
                "type": "bark",
                "name": "b",
                "config": {
                    "server_base_url": "https://bark.example.com/push",
                    "device_key": "Abcdef0123456789",
                },
            }
        )
        self.assertTrue(ser.is_valid(), ser.errors)
        cfg = ser.validated_data["config"]
        self.assertEqual(cfg["server_base_url"], "https://bark.example.com")

    def test_rejects_missing_device_key_and_device_keys(self):
        ser = ChannelUpsertRequestSerializer(
            data={
                "type": "bark",
                "name": "b",
                "config": {
                    "server_base_url": "https://bark.example.com",
                },
            }
        )
        self.assertFalse(ser.is_valid())
        self.assertIn("config", ser.errors)
