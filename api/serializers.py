from typing import Any

from django.utils import timezone
from rest_framework import serializers

from urllib.parse import urlparse

from accounts.models import User
from beacon.models import Channel, Delivery, ForwardingRule, IngestEndpoint, Message


class UserSerializer(serializers.ModelSerializer):
    email_verified_at = serializers.SerializerMethodField()
    created_at = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ["id", "email", "email_verified_at", "created_at"]

    def get_email_verified_at(self, obj: User):
        val: Any = getattr(obj, "email_verified_at", None)
        return val.isoformat() if val else None

    def get_created_at(self, obj: User):
        val: Any = getattr(obj, "created_at", None)
        return val.isoformat() if val else timezone.now().isoformat()


class SignupRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(min_length=8)


class LoginRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()


class ForgotPasswordRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()


class ResetPasswordRequestSerializer(serializers.Serializer):
    token = serializers.CharField()
    new_password = serializers.CharField(min_length=8)


class VerifyEmailRequestSerializer(serializers.Serializer):
    token = serializers.CharField()


class ChangeEmailRequestSerializer(serializers.Serializer):
    new_email = serializers.EmailField()


class ChangePasswordRequestSerializer(serializers.Serializer):
    old_password = serializers.CharField()
    new_password = serializers.CharField(min_length=8)


class DeleteAccountRequestSerializer(serializers.Serializer):
    password = serializers.CharField()
    confirm = serializers.CharField()

    def validate_confirm(self, value: str):
        if (value or "").strip() != "DELETE":
            raise serializers.ValidationError("must_equal_DELETE")
        return value


class IngestEndpointSerializer(serializers.ModelSerializer):
    created_at = serializers.SerializerMethodField()
    last_used_at = serializers.SerializerMethodField()
    revoked_at = serializers.SerializerMethodField()

    class Meta:
        model = IngestEndpoint
        fields = ["id", "name", "created_at", "last_used_at", "revoked_at"]

    def get_created_at(self, obj: IngestEndpoint):
        val: Any = getattr(obj, "created_at", None)
        return val.isoformat() if val else None

    def get_last_used_at(self, obj: IngestEndpoint):
        val: Any = getattr(obj, "last_used_at", None)
        return val.isoformat() if val else None

    def get_revoked_at(self, obj: IngestEndpoint):
        val: Any = getattr(obj, "revoked_at", None)
        return val.isoformat() if val else None


class IngestEndpointCreateRequestSerializer(serializers.Serializer):
    name = serializers.CharField()


class BatchDeleteRequestSerializer(serializers.Serializer):
    older_than_days = serializers.IntegerField(min_value=1, max_value=36500)
    ingest_endpoint_id = serializers.UUIDField(required=False, allow_null=True)


class BarkChannelConfigSerializer(serializers.Serializer):
    server_base_url = serializers.CharField()
    device_key = serializers.CharField(
        required=False, allow_blank=True, allow_null=True
    )
    device_keys = serializers.ListField(
        child=serializers.CharField(), required=False, allow_null=True
    )
    default_payload_json = serializers.DictField(required=False)

    def validate(self, attrs):
        raw_base = str(attrs.get("server_base_url") or "").strip()
        if raw_base.endswith("/push"):
            raw_base = raw_base[: -len("/push")]
        raw_base = raw_base.rstrip("/")

        device_key_raw = attrs.get("device_key")
        device_key = str(device_key_raw or "").strip() or None

        keys_val = attrs.get("device_keys")
        device_keys: list[str] | None
        if keys_val is None:
            device_keys = None
        else:
            cleaned = [str(x or "").strip() for x in (keys_val or [])]
            cleaned = [x for x in cleaned if x]
            device_keys = cleaned or None

        if device_key is None and device_keys is None and raw_base:
            try:
                parsed = urlparse(raw_base)
                segs = [s for s in (parsed.path or "").split("/") if s]
                if len(segs) == 1:
                    seg = segs[0]
                    looks_like_key = (
                        len(seg) >= 16
                        and any(c.isdigit() for c in seg)
                        and all(c.isalnum() or c in {"_", "-"} for c in seg)
                    )
                    if (
                        looks_like_key
                        and parsed.scheme in {"http", "https"}
                        and parsed.netloc
                    ):
                        device_key = seg
                        raw_base = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
            except Exception:
                pass

        if device_key is None and device_keys is None:
            raise serializers.ValidationError(
                {"device_key": ["required (or set device_keys)"]}
            )

        out = dict(attrs)
        out["server_base_url"] = raw_base
        out["device_key"] = device_key
        if device_keys is not None:
            out["device_keys"] = device_keys
        else:
            out["device_keys"] = None
        return out


class BarkChannelUpsertRequestSerializer(serializers.Serializer):
    type = serializers.ChoiceField(choices=["bark"])
    name = serializers.CharField()
    config = BarkChannelConfigSerializer()


class NtfyChannelConfigSerializer(serializers.Serializer):
    server_base_url = serializers.CharField()
    topic = serializers.CharField()
    access_token = serializers.CharField(
        required=False, allow_blank=True, allow_null=True
    )
    username = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    password = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    default_headers_json = serializers.DictField(required=False)

    def validate(self, attrs):
        access_token = (attrs.get("access_token") or "").strip()
        username = (attrs.get("username") or "").strip()
        password = attrs.get("password") or ""

        if access_token and (username or password):
            raise serializers.ValidationError("choose_one_auth_method")
        if (username and not password) or (password and not username):
            raise serializers.ValidationError("username_password_required")

        return attrs


class MqttChannelConfigSerializer(serializers.Serializer):
    broker_host = serializers.CharField()
    broker_port = serializers.IntegerField(required=False, min_value=1, max_value=65535)
    topic = serializers.CharField()

    username = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    password = serializers.CharField(required=False, allow_blank=True, allow_null=True)

    tls = serializers.BooleanField(required=False)
    tls_insecure = serializers.BooleanField(required=False)
    qos = serializers.IntegerField(required=False, min_value=0, max_value=2)
    retain = serializers.BooleanField(required=False)
    client_id = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    keepalive_seconds = serializers.IntegerField(
        required=False, min_value=1, max_value=3600
    )

    def validate(self, attrs):
        username = (attrs.get("username") or "").strip()
        password = attrs.get("password")
        if (username and password is None) or (password and not username):
            raise serializers.ValidationError("username_password_required")
        return attrs


class ChannelUpsertRequestSerializer(serializers.Serializer):
    type = serializers.ChoiceField(choices=["bark", "ntfy", "mqtt"])
    name = serializers.CharField(max_length=200)
    config = serializers.DictField()

    def validate(self, attrs):
        t = attrs.get("type")
        cfg = attrs.get("config") or {}

        if t == "bark":
            ser = BarkChannelConfigSerializer(data=cfg)
        elif t == "ntfy":
            ser = NtfyChannelConfigSerializer(data=cfg)
        elif t == "mqtt":
            ser = MqttChannelConfigSerializer(data=cfg)
        else:
            raise serializers.ValidationError("invalid_type")

        if not ser.is_valid():
            raise serializers.ValidationError({"config": ser.errors})

        attrs["config"] = ser.validated_data
        return attrs


class ChannelSerializer(serializers.ModelSerializer):
    created_at = serializers.SerializerMethodField()
    disabled_at = serializers.SerializerMethodField()

    class Meta:
        model = Channel
        fields = ["id", "type", "name", "created_at", "disabled_at"]

    def get_created_at(self, obj: Channel):
        val: Any = getattr(obj, "created_at", None)
        return val.isoformat() if val else None

    def get_disabled_at(self, obj: Channel):
        val: Any = getattr(obj, "disabled_at", None)
        return val.isoformat() if val else None


class RuleUpsertRequestSerializer(serializers.Serializer):
    name = serializers.CharField()
    enabled = serializers.BooleanField()
    channel_id = serializers.UUIDField()
    filter = serializers.DictField(required=False)
    payload_template = serializers.DictField(required=False)
    bark_payload_template = serializers.DictField(required=False)

    def validate(self, attrs):
        if (
            attrs.get("payload_template") is None
            and attrs.get("bark_payload_template") is None
        ):
            raise serializers.ValidationError({"payload_template": ["required"]})
        return attrs


class RuleSerializer(serializers.ModelSerializer):
    created_at = serializers.SerializerMethodField()
    updated_at = serializers.SerializerMethodField()
    channel_id = serializers.SerializerMethodField()
    filter = serializers.SerializerMethodField()
    bark_payload_template = serializers.SerializerMethodField()
    payload_template = serializers.SerializerMethodField()

    class Meta:
        model = ForwardingRule
        fields = [
            "id",
            "name",
            "enabled",
            "channel_id",
            "filter",
            "bark_payload_template",
            "payload_template",
            "created_at",
            "updated_at",
        ]

    def get_created_at(self, obj: ForwardingRule):
        val: Any = getattr(obj, "created_at", None)
        return val.isoformat() if val else None

    def get_updated_at(self, obj: ForwardingRule):
        val: Any = getattr(obj, "updated_at", None)
        return val.isoformat() if val else None

    def get_channel_id(self, obj: ForwardingRule):
        val: Any = getattr(obj, "channel_id", None)
        return str(val)

    def get_filter(self, obj: ForwardingRule):
        return obj.filter_json or {}

    def get_bark_payload_template(self, obj: ForwardingRule):
        return obj.bark_payload_template_json or {}

    def get_payload_template(self, obj: ForwardingRule):
        return obj.payload_template_json or obj.bark_payload_template_json or {}


class RuleTestRequestSerializer(serializers.Serializer):
    ingest_endpoint_id = serializers.UUIDField()
    content_type = serializers.CharField(
        required=False, allow_blank=True, allow_null=True
    )
    payload_text = serializers.CharField()


class ChannelTestRequestSerializer(serializers.Serializer):
    title = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    body = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    payload_json = serializers.DictField(required=False, allow_null=True)


class DeliverySerializer(serializers.ModelSerializer):
    next_attempt_at = serializers.SerializerMethodField()
    sent_at = serializers.SerializerMethodField()
    last_error = serializers.SerializerMethodField()
    provider_response = serializers.SerializerMethodField()
    message_id = serializers.SerializerMethodField()
    rule_id = serializers.SerializerMethodField()
    channel_id = serializers.SerializerMethodField()

    class Meta:
        model = Delivery
        fields = [
            "id",
            "message_id",
            "rule_id",
            "channel_id",
            "status",
            "attempt_count",
            "next_attempt_at",
            "sent_at",
            "last_error",
            "provider_response",
        ]

    def get_message_id(self, obj: Delivery):
        val: Any = getattr(obj, "message_id", None)
        return str(val)

    def get_rule_id(self, obj: Delivery):
        val: Any = getattr(obj, "rule_id", None)
        return str(val)

    def get_channel_id(self, obj: Delivery):
        val: Any = getattr(obj, "channel_id", None)
        return str(val)

    def get_next_attempt_at(self, obj: Delivery):
        val: Any = getattr(obj, "next_attempt_at", None)
        return val.isoformat() if val else None

    def get_sent_at(self, obj: Delivery):
        val: Any = getattr(obj, "sent_at", None)
        return val.isoformat() if val else None

    def get_last_error(self, obj: Delivery):
        return obj.last_error

    def get_provider_response(self, obj: Delivery):
        return obj.provider_response_json


class MessageSummarySerializer(serializers.ModelSerializer):
    ingest_endpoint_id = serializers.SerializerMethodField()
    received_at = serializers.SerializerMethodField()
    payload_preview = serializers.SerializerMethodField()
    deliveries = serializers.SerializerMethodField()

    class Meta:
        model = Message
        fields = [
            "id",
            "ingest_endpoint_id",
            "received_at",
            "content_type",
            "payload_preview",
            "deliveries",
        ]

    def get_ingest_endpoint_id(self, obj: Message):
        val: Any = getattr(obj, "ingest_endpoint_id", None)
        return str(val)

    def get_received_at(self, obj: Message):
        val: Any = getattr(obj, "received_at", None)
        return val.isoformat() if val else None

    def get_payload_preview(self, obj: Message):
        text = str(getattr(obj, "payload_text", "") or "")
        return text[:200]

    def get_deliveries(self, obj: Message):
        counts = {"queued": 0, "sending": 0, "retry": 0, "sent": 0, "failed": 0}
        for status, c in getattr(obj, "delivery_counts", {}).items():
            if status in counts:
                counts[status] = c
        return counts


class MessageDetailSerializer(serializers.ModelSerializer):
    ingest_endpoint_id = serializers.SerializerMethodField()
    received_at = serializers.SerializerMethodField()
    deleted_at = serializers.SerializerMethodField()
    headers = serializers.SerializerMethodField()
    query = serializers.SerializerMethodField()

    class Meta:
        model = Message
        fields = [
            "id",
            "ingest_endpoint_id",
            "received_at",
            "content_type",
            "payload_text",
            "headers",
            "query",
            "remote_ip",
            "user_agent",
            "deleted_at",
        ]

    def get_ingest_endpoint_id(self, obj: Message):
        val: Any = getattr(obj, "ingest_endpoint_id", None)
        return str(val)

    def get_received_at(self, obj: Message):
        val: Any = getattr(obj, "received_at", None)
        return val.isoformat() if val else None

    def get_deleted_at(self, obj: Message):
        val: Any = getattr(obj, "deleted_at", None)
        return val.isoformat() if val else None

    def get_headers(self, obj: Message):
        return obj.headers_json or {}

    def get_query(self, obj: Message):
        return obj.query_json or {}
