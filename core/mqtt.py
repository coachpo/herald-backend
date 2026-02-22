import json
import socket
import ssl

from django.conf import settings

from .ssrf import assert_host_ssrf_safe


def _encode_payload(payload: object) -> bytes:
    if payload is None:
        return b""
    if isinstance(payload, bytes):
        return payload
    if isinstance(payload, str):
        return payload.encode("utf-8")
    if isinstance(payload, (dict, list, int, float, bool)):
        return json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode(
            "utf-8"
        )
    return str(payload).encode("utf-8")


def send_mqtt_publish(
    *,
    broker_host: str,
    broker_port: int,
    topic: str,
    payload: object,
    username: str | None,
    password: str | None,
    qos: int,
    retain: bool,
    tls: bool,
    tls_insecure: bool,
    client_id: str | None,
    keepalive_seconds: int,
) -> tuple[bool, dict]:
    from paho.mqtt import publish as mqtt_publish

    host = str(broker_host).strip()
    if not host:
        raise ValueError("missing_broker_host")

    block_private = bool(getattr(settings, "MQTT_BLOCK_PRIVATE_NETWORKS", True))
    assert_host_ssrf_safe(host, block_private_networks=block_private)

    port = int(broker_port)
    if port < 1 or port > 65535:
        raise ValueError("invalid_broker_port")

    t = str(topic or "").strip()
    if not t:
        raise ValueError("missing_topic")

    msg = _encode_payload(payload)
    auth = None
    if username:
        auth = {"username": username, "password": password}

    tls_cfg = None
    if tls:
        ctx = ssl.create_default_context()
        if tls_insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        tls_cfg = ctx

    timeout = float(getattr(settings, "MQTT_SOCKET_TIMEOUT_SECONDS", 5))
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        mqtt_publish.single(
            t,
            payload=msg,
            qos=int(qos),
            retain=bool(retain),
            hostname=host,
            port=port,
            client_id=client_id or "",
            keepalive=int(keepalive_seconds),
            auth=auth,
            tls=tls_cfg,
        )
    finally:
        socket.setdefaulttimeout(old)

    return True, {
        "broker_host": host,
        "broker_port": port,
        "topic": t,
        "qos": int(qos),
        "retain": bool(retain),
    }
