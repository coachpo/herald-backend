import threading
import time
import uuid

from django.core.management.base import BaseCommand
from django.utils import timezone

from accounts.models import User
from accounts.tokens import generate_secret_token, hash_token
from api.serializers import BarkChannelConfigSerializer, MqttChannelConfigSerializer
from beacon.management.commands.deliveries_worker import Command as WorkerCommand
from beacon.models import Channel, Delivery, ForwardingRule, IngestEndpoint, Message


def _require(val: str | None, *, name: str) -> str:
    s = (val or "").strip()
    if not s:
        raise ValueError(f"missing_{name}")
    return s


class Command(BaseCommand):
    help = "Smoke test Bark + MQTT providers (optional live integration)"

    def add_arguments(self, parser):
        parser.add_argument("--email", default="smoke@example.com")
        parser.add_argument("--password", default="SmokeTestPassword123!")

        parser.add_argument("--bark-url", default="")

        parser.add_argument("--mqtt-host", default="")
        parser.add_argument("--mqtt-port", default="8883")
        parser.add_argument("--mqtt-username", default="")
        parser.add_argument("--mqtt-password", default="")
        parser.add_argument("--mqtt-topic", default="beacon-spear/smoke")

        parser.add_argument(
            "--live",
            action="store_true",
            help="Run live provider calls (default: only validate dummy configs)",
        )

    def handle(self, *args, **options):
        email = str(options["email"])
        password = str(options["password"])
        live = bool(options["live"])

        user = self._ensure_verified_user(email=email, password=password)
        ep, ingest_key = self._ensure_ingest_endpoint(user)
        self.stdout.write(f"user={user.email} verified={bool(user.email_verified_at)}")
        self.stdout.write(f"ingest_endpoint_id={ep.id} ingest_key={ingest_key}")

        now = timezone.now()
        msg = Message.objects.create(
            user=user,
            ingest_endpoint=ep,
            received_at=now,
            body=f"smoke {uuid.uuid4()}",
            headers_json={},
            query_json={},
            remote_ip="127.0.0.1",
            user_agent="smoke",
        )

        self._dummy_config_checks()

        if not live:
            self.stdout.write("live=false: skipping provider network calls")
            return

        bark_url = str(options["bark_url"] or "").strip()
        mqtt_host = str(options["mqtt_host"] or "").strip()
        mqtt_username = str(options["mqtt_username"] or "").strip()
        mqtt_password = str(options["mqtt_password"] or "")
        mqtt_port = int(options["mqtt_port"])
        mqtt_topic_base = str(options["mqtt_topic"] or "beacon-spear/smoke").strip()
        mqtt_topic = f"{mqtt_topic_base.rstrip('/')}/{uuid.uuid4()}"

        if bark_url:
            bark_channel = self._create_bark_channel(
                user=user, name="smoke-bark", bark_url=bark_url
            )
            bark_rule = self._create_rule(
                user=user,
                channel=bark_channel,
                name="smoke-bark-rule",
                payload_template={"title": "Smoke", "body": "Hello from Beacon Spear"},
            )
            bark_delivery = self._enqueue_delivery(
                user, msg, bark_rule, bark_channel, now
            )
            self._run_one_delivery(bark_delivery)
            bark_delivery.refresh_from_db()
            self.stdout.write(
                f"bark status={bark_delivery.status} attempts={bark_delivery.attempt_count} last_error={bark_delivery.last_error!r}"
            )

        if mqtt_host:
            mqtt_channel = self._create_mqtt_channel(
                user=user,
                name="smoke-mqtt",
                host=mqtt_host,
                port=mqtt_port,
                topic=mqtt_topic,
                username=mqtt_username,
                password=mqtt_password,
            )
            mqtt_rule = self._create_rule(
                user=user,
                channel=mqtt_channel,
                name="smoke-mqtt-rule",
                payload_template={"body": "hello-from-beacon-spear"},
            )

            mqtt_delivery = self._enqueue_delivery(
                user, msg, mqtt_rule, mqtt_channel, now
            )
            self._run_one_delivery(mqtt_delivery)
            mqtt_delivery.refresh_from_db()
            self.stdout.write(
                f"mqtt publish status={mqtt_delivery.status} attempts={mqtt_delivery.attempt_count} last_error={mqtt_delivery.last_error!r}"
            )

            if mqtt_delivery.status == Delivery.STATUS_SENT:
                ok = self._verify_mqtt_retained_message(
                    host=mqtt_host,
                    port=mqtt_port,
                    topic=mqtt_topic,
                    username=mqtt_username,
                    password=mqtt_password,
                    timeout_seconds=10,
                )
                self.stdout.write(f"mqtt retained verify={ok}")

    def _ensure_verified_user(self, *, email: str, password: str) -> User:
        email_norm = (email or "").strip().lower()
        if not email_norm:
            raise ValueError("missing_email")

        user, _ = User.objects.get_or_create(email=email_norm)
        user.set_password(password)
        if user.email_verified_at is None:
            user.email_verified_at = timezone.now()
        user.is_active = True
        user.save()
        return user

    def _ensure_ingest_endpoint(self, user: User) -> tuple[IngestEndpoint, str]:
        ep = IngestEndpoint.objects.filter(user=user, revoked_at__isnull=True).first()
        if ep:
            return ep, "(existing)"

        raw = generate_secret_token(32)
        ep = IngestEndpoint.objects.create(
            user=user,
            name="smoke-endpoint",
            token_hash=hash_token(raw),
        )
        return ep, raw

    def _create_bark_channel(self, *, user: User, name: str, bark_url: str) -> Channel:
        ser = BarkChannelConfigSerializer(
            data={
                "server_base_url": bark_url,
            }
        )
        ser.is_valid(raise_exception=True)
        cfg = ser.validated_data

        ch = Channel(
            user=user, type=Channel.TYPE_BARK, name=name, config_json_encrypted=""
        )
        ch.config = cfg
        ch.save()
        return ch

    def _create_mqtt_channel(
        self,
        *,
        user: User,
        name: str,
        host: str,
        port: int,
        topic: str,
        username: str,
        password: str,
    ) -> Channel:
        ser = MqttChannelConfigSerializer(
            data={
                "broker_host": host,
                "broker_port": port,
                "topic": topic,
                "username": username or None,
                "password": password or None,
                "tls": True,
                "tls_insecure": False,
                "qos": 1,
                "retain": True,
                "client_id": "beacon-spear-smoke",
                "keepalive_seconds": 60,
            }
        )
        ser.is_valid(raise_exception=True)
        cfg = ser.validated_data

        ch = Channel(
            user=user, type=Channel.TYPE_MQTT, name=name, config_json_encrypted=""
        )
        ch.config = cfg
        ch.save()
        return ch

    def _create_rule(
        self,
        *,
        user: User,
        channel: Channel,
        name: str,
        payload_template: dict,
    ) -> ForwardingRule:
        return ForwardingRule.objects.create(
            user=user,
            name=name,
            enabled=True,
            channel=channel,
            filter_json={},
            payload_template_json=payload_template,
        )

    def _enqueue_delivery(
        self,
        user: User,
        msg: Message,
        rule: ForwardingRule,
        channel: Channel,
        now,
    ) -> Delivery:
        return Delivery.objects.create(
            user=user,
            message=msg,
            rule=rule,
            channel=channel,
            status=Delivery.STATUS_QUEUED,
            attempt_count=0,
            next_attempt_at=now,
        )

    def _run_one_delivery(self, d: Delivery) -> None:
        WorkerCommand()._process_one(d)

    def _dummy_config_checks(self):
        BarkChannelConfigSerializer(
            data={"server_base_url": "https://example.com"}
        ).is_valid()
        MqttChannelConfigSerializer(
            data={"broker_host": "example.com", "topic": "t"}
        ).is_valid()

    def _verify_mqtt_retained_message(
        self,
        *,
        host: str,
        port: int,
        topic: str,
        username: str,
        password: str,
        timeout_seconds: int,
    ) -> bool:
        import paho.mqtt.client as mqtt

        got = {"ok": False}
        done = threading.Event()

        def on_connect(client, userdata, flags, reason_code, properties):
            rc = getattr(reason_code, "value", reason_code)
            if int(rc) != 0:
                done.set()
                return
            client.subscribe(topic, qos=1)

        def on_message(client, userdata, msg):
            got["ok"] = True
            done.set()
            client.disconnect()

        c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        c.on_connect = on_connect
        c.on_message = on_message
        c.username_pw_set(
            _require(username, name="mqtt_username"),
            _require(password, name="mqtt_password"),
        )
        c.tls_set()
        c.connect(_require(host, name="mqtt_host"), int(port), keepalive=60)

        t = threading.Thread(target=c.loop_forever, daemon=True)
        t.start()
        done.wait(timeout_seconds)
        try:
            c.disconnect()
        except Exception:
            pass
        time.sleep(0.2)
        return bool(got["ok"])
