from django.test import TestCase

from api.serializers import ChannelUpsertRequestSerializer


class MqttChannelConfigValidationTests(TestCase):
    def test_rejects_missing_broker_host(self):
        ser = ChannelUpsertRequestSerializer(
            data={
                "type": "mqtt",
                "name": "m",
                "config": {
                    "broker_host": "",
                    "topic": "t",
                },
            }
        )
        self.assertFalse(ser.is_valid())

    def test_rejects_invalid_port(self):
        ser = ChannelUpsertRequestSerializer(
            data={
                "type": "mqtt",
                "name": "m",
                "config": {
                    "broker_host": "example.com",
                    "broker_port": 70000,
                    "topic": "t",
                },
            }
        )
        self.assertFalse(ser.is_valid())

    def test_requires_username_and_password_together(self):
        ser = ChannelUpsertRequestSerializer(
            data={
                "type": "mqtt",
                "name": "m",
                "config": {
                    "broker_host": "example.com",
                    "topic": "t",
                    "username": "u",
                },
            }
        )
        self.assertFalse(ser.is_valid())
