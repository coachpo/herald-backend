from django.utils import timezone
from rest_framework import serializers

from accounts.models import User
from beacon.models import Channel, Delivery, ForwardingRule, IngestEndpoint, Message


class UserSerializer(serializers.ModelSerializer):
    email_verified_at = serializers.SerializerMethodField()
    created_at = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ["id", "email", "email_verified_at", "created_at"]

    def get_email_verified_at(self, obj: User):
        return obj.email_verified_at.isoformat() if obj.email_verified_at else None

    def get_created_at(self, obj: User):
        return (
            obj.created_at.isoformat() if obj.created_at else timezone.now().isoformat()
        )


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


class IngestEndpointSerializer(serializers.ModelSerializer):
    created_at = serializers.SerializerMethodField()
    last_used_at = serializers.SerializerMethodField()
    revoked_at = serializers.SerializerMethodField()

    class Meta:
        model = IngestEndpoint
        fields = ["id", "name", "created_at", "last_used_at", "revoked_at"]

    def get_created_at(self, obj: IngestEndpoint):
        return obj.created_at.isoformat() if obj.created_at else None

    def get_last_used_at(self, obj: IngestEndpoint):
        return obj.last_used_at.isoformat() if obj.last_used_at else None

    def get_revoked_at(self, obj: IngestEndpoint):
        return obj.revoked_at.isoformat() if obj.revoked_at else None


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


class BarkChannelUpsertRequestSerializer(serializers.Serializer):
    type = serializers.ChoiceField(choices=["bark"])
    name = serializers.CharField()
    config = BarkChannelConfigSerializer()


class ChannelSerializer(serializers.ModelSerializer):
    created_at = serializers.SerializerMethodField()
    disabled_at = serializers.SerializerMethodField()

    class Meta:
        model = Channel
        fields = ["id", "type", "name", "created_at", "disabled_at"]

    def get_created_at(self, obj: Channel):
        return obj.created_at.isoformat() if obj.created_at else None

    def get_disabled_at(self, obj: Channel):
        return obj.disabled_at.isoformat() if obj.disabled_at else None


class RuleUpsertRequestSerializer(serializers.Serializer):
    name = serializers.CharField()
    enabled = serializers.BooleanField()
    channel_id = serializers.UUIDField()
    filter = serializers.DictField(required=False)
    bark_payload_template = serializers.DictField()


class RuleSerializer(serializers.ModelSerializer):
    created_at = serializers.SerializerMethodField()
    updated_at = serializers.SerializerMethodField()
    channel_id = serializers.SerializerMethodField()
    filter = serializers.SerializerMethodField()
    bark_payload_template = serializers.SerializerMethodField()

    class Meta:
        model = ForwardingRule
        fields = [
            "id",
            "name",
            "enabled",
            "channel_id",
            "filter",
            "bark_payload_template",
            "created_at",
            "updated_at",
        ]

    def get_created_at(self, obj: ForwardingRule):
        return obj.created_at.isoformat() if obj.created_at else None

    def get_updated_at(self, obj: ForwardingRule):
        return obj.updated_at.isoformat() if obj.updated_at else None

    def get_channel_id(self, obj: ForwardingRule):
        return str(obj.channel_id)

    def get_filter(self, obj: ForwardingRule):
        return obj.filter_json or {}

    def get_bark_payload_template(self, obj: ForwardingRule):
        return obj.bark_payload_template_json or {}


class RuleTestRequestSerializer(serializers.Serializer):
    ingest_endpoint_id = serializers.UUIDField()
    content_type = serializers.CharField(
        required=False, allow_blank=True, allow_null=True
    )
    payload_text = serializers.CharField()


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
        return str(obj.message_id)

    def get_rule_id(self, obj: Delivery):
        return str(obj.rule_id)

    def get_channel_id(self, obj: Delivery):
        return str(obj.channel_id)

    def get_next_attempt_at(self, obj: Delivery):
        return obj.next_attempt_at.isoformat() if obj.next_attempt_at else None

    def get_sent_at(self, obj: Delivery):
        return obj.sent_at.isoformat() if obj.sent_at else None

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
        return str(obj.ingest_endpoint_id)

    def get_received_at(self, obj: Message):
        return obj.received_at.isoformat() if obj.received_at else None

    def get_payload_preview(self, obj: Message):
        text = obj.payload_text or ""
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
        return str(obj.ingest_endpoint_id)

    def get_received_at(self, obj: Message):
        return obj.received_at.isoformat() if obj.received_at else None

    def get_deleted_at(self, obj: Message):
        return obj.deleted_at.isoformat() if obj.deleted_at else None

    def get_headers(self, obj: Message):
        return obj.headers_json or {}

    def get_query(self, obj: Message):
        return obj.query_json or {}
