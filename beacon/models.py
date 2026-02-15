import json
import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone

from .crypto import decrypt_json_bytes, encrypt_json_bytes


class IngestEndpoint(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    name = models.CharField(max_length=200)
    token_hash = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["user"]),
        ]

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None


class Message(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    ingest_endpoint = models.ForeignKey(IngestEndpoint, on_delete=models.CASCADE)
    received_at = models.DateTimeField(auto_now_add=True)

    content_type = models.CharField(max_length=255, null=True, blank=True)
    payload_text = models.TextField()
    payload_sha256 = models.CharField(max_length=64, null=True, blank=True)
    headers_json = models.JSONField(default=dict)
    query_json = models.JSONField(default=dict)
    remote_ip = models.CharField(max_length=64)
    user_agent = models.TextField(null=True, blank=True)
    deleted_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["user", "received_at"]),
            models.Index(fields=["user", "ingest_endpoint", "received_at"]),
        ]

    def soft_delete(self):
        if self.deleted_at is None:
            self.deleted_at = timezone.now()
            self.save(update_fields=["deleted_at"])


class Channel(models.Model):
    TYPE_BARK = "bark"
    TYPE_CHOICES = [(TYPE_BARK, "bark")]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    type = models.CharField(max_length=16, choices=TYPE_CHOICES)
    name = models.CharField(max_length=200)
    config_json_encrypted = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    disabled_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["user", "created_at"]),
        ]

    def get_config(self) -> dict:
        raw = decrypt_json_bytes(self.config_json_encrypted)
        return json.loads(raw.decode("utf-8"))

    def set_config(self, config: dict):
        raw = json.dumps(config, separators=(",", ":")).encode("utf-8")
        self.config_json_encrypted = encrypt_json_bytes(raw)

    config = property(get_config, set_config)


class ForwardingRule(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    name = models.CharField(max_length=200)
    enabled = models.BooleanField(default=True)

    filter_json = models.JSONField(default=dict)
    channel = models.ForeignKey(Channel, on_delete=models.CASCADE)
    bark_payload_template_json = models.JSONField(default=dict)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["user", "created_at"]),
        ]


class Delivery(models.Model):
    STATUS_QUEUED = "queued"
    STATUS_SENDING = "sending"
    STATUS_RETRY = "retry"
    STATUS_SENT = "sent"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = [
        (STATUS_QUEUED, "queued"),
        (STATUS_SENDING, "sending"),
        (STATUS_RETRY, "retry"),
        (STATUS_SENT, "sent"),
        (STATUS_FAILED, "failed"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    message = models.ForeignKey(Message, on_delete=models.CASCADE)
    rule = models.ForeignKey(ForwardingRule, on_delete=models.CASCADE)
    channel = models.ForeignKey(Channel, on_delete=models.CASCADE)

    status = models.CharField(max_length=16, choices=STATUS_CHOICES)
    attempt_count = models.IntegerField(default=0)
    next_attempt_at = models.DateTimeField(null=True, blank=True)
    sent_at = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(null=True, blank=True)
    provider_response_json = models.JSONField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["status", "next_attempt_at"]),
            models.Index(fields=["message"]),
            models.Index(fields=["user", "created_at"]),
        ]
