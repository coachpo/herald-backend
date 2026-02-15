import time
from datetime import timedelta

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from beacon.bark import build_bark_payload, send_bark_push
from beacon.mqtt import send_mqtt_publish
from beacon.ntfy import build_ntfy_request, send_ntfy_publish
from beacon.template import build_template_context, render_template
from beacon.models import Delivery


def _backoff_seconds(attempt_count: int) -> int:
    base = int(getattr(settings, "DELIVERY_BACKOFF_BASE_SECONDS", 5))
    max_delay = int(getattr(settings, "DELIVERY_BACKOFF_MAX_SECONDS", 1800))
    delay = base * (2 ** max(attempt_count - 1, 0))
    return min(max_delay, delay)


class Command(BaseCommand):
    help = "Beacon Spear delivery worker"

    def handle(self, *args, **options):
        poll = float(getattr(settings, "WORKER_POLL_SECONDS", 1.0))
        batch = int(getattr(settings, "WORKER_BATCH_SIZE", 50))

        while True:
            now = timezone.now()
            due: list[Delivery]

            with transaction.atomic():
                due = list(
                    Delivery.objects.select_for_update(skip_locked=True)
                    .select_related(
                        "message", "rule", "channel", "message__ingest_endpoint"
                    )
                    .filter(status__in=[Delivery.STATUS_QUEUED, Delivery.STATUS_RETRY])
                    .filter(next_attempt_at__lte=now)
                    .order_by("next_attempt_at")[:batch]
                )
                for d in due:
                    d.status = Delivery.STATUS_SENDING
                    d.save(update_fields=["status", "updated_at"])

            for d in due:
                self._process_one(d)

            time.sleep(poll)

    def _process_one(self, d: Delivery):
        now = timezone.now()
        max_attempts = int(getattr(settings, "DELIVERY_MAX_ATTEMPTS", 10))
        try:
            if d.rule.enabled is not True or d.channel.disabled_at is not None:
                d.status = Delivery.STATUS_FAILED
                d.last_error = "disabled"
                d.save(update_fields=["status", "last_error", "updated_at"])
                return

            t = str(d.channel.type or "").strip()
            meta: dict

            if t == "bark":
                channel_cfg = d.channel.config
                server_base_url = str(channel_cfg.get("server_base_url") or "").strip()
                if not server_base_url:
                    raise ValueError("missing_server_base_url")

                payload = build_bark_payload(
                    channel=d.channel,
                    rule=d.rule,
                    message=d.message,
                    ingest_endpoint=d.message.ingest_endpoint,
                )
                ok, meta = send_bark_push(
                    server_base_url=server_base_url, payload=payload
                )
            elif t == "ntfy":
                url, body, headers, auth = build_ntfy_request(
                    channel=d.channel,
                    rule=d.rule,
                    message=d.message,
                    ingest_endpoint=d.message.ingest_endpoint,
                )
                ok, meta = send_ntfy_publish(
                    url=url, body=body, headers=headers, auth=auth
                )
            elif t == "mqtt":
                cfg = d.channel.config
                broker_host = str(cfg.get("broker_host") or "").strip()
                broker_port = int(cfg.get("broker_port") or 1883)
                topic = str(cfg.get("topic") or "").strip()
                username = str(cfg.get("username") or "").strip() or None
                password = str(cfg.get("password") or "") if username else None
                qos = int(cfg.get("qos") or 0)
                retain = bool(cfg.get("retain") or False)
                tls = bool(cfg.get("tls") or False)
                tls_insecure = bool(cfg.get("tls_insecure") or False)
                client_id = str(cfg.get("client_id") or "").strip() or None
                keepalive = int(cfg.get("keepalive_seconds") or 60)

                ctx = build_template_context(d.message, d.message.ingest_endpoint)
                rendered = render_template(d.rule.get_payload_template(), ctx)
                payload_obj: object = rendered
                if isinstance(rendered, dict):
                    if rendered.get("body") is not None:
                        payload_obj = rendered.get("body")
                    elif rendered.get("payload") is not None:
                        payload_obj = rendered.get("payload")
                    elif rendered.get("message") is not None:
                        payload_obj = rendered.get("message")

                ok, meta = send_mqtt_publish(
                    broker_host=broker_host,
                    broker_port=broker_port,
                    topic=topic,
                    payload=payload_obj,
                    username=username,
                    password=password,
                    qos=qos,
                    retain=retain,
                    tls=tls,
                    tls_insecure=tls_insecure,
                    client_id=client_id,
                    keepalive_seconds=keepalive,
                )
            else:
                raise ValueError("unsupported_channel_type")

            meta = dict(meta)
            meta.setdefault("provider", t)

            d.provider_response_json = meta
            if ok:
                d.status = Delivery.STATUS_SENT
                d.sent_at = now
                d.last_error = None
                d.save(
                    update_fields=[
                        "status",
                        "sent_at",
                        "last_error",
                        "provider_response_json",
                        "updated_at",
                    ]
                )
                return

            raise RuntimeError(f"http_{meta.get('http_status')}")
        except Exception as e:
            d.attempt_count = int(d.attempt_count or 0) + 1
            d.last_error = str(e)

            if d.attempt_count >= max_attempts:
                d.status = Delivery.STATUS_FAILED
                d.next_attempt_at = None
                d.save(
                    update_fields=[
                        "status",
                        "attempt_count",
                        "last_error",
                        "next_attempt_at",
                        "updated_at",
                    ]
                )
                return

            d.status = Delivery.STATUS_RETRY
            d.next_attempt_at = now + timedelta(
                seconds=_backoff_seconds(d.attempt_count)
            )
            d.save(
                update_fields=[
                    "status",
                    "attempt_count",
                    "last_error",
                    "next_attempt_at",
                    "updated_at",
                ]
            )
