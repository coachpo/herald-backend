import json
from urllib.parse import urljoin

import requests
from django.conf import settings

from .models import Channel, ForwardingRule, IngestEndpoint, Message
from .ssrf import assert_ssrf_safe
from .template import build_template_context, render_template


def build_push_url(server_base_url: str) -> str:
    base = server_base_url.rstrip("/") + "/"
    return urljoin(base, "push")


def build_bark_payload(
    *,
    channel: Channel,
    rule: ForwardingRule,
    message: Message,
    ingest_endpoint: IngestEndpoint,
) -> dict:
    cfg = channel.config
    default_payload = cfg.get("default_payload_json") or {}

    ctx = build_template_context(message, ingest_endpoint)
    tpl = rule.payload_template_json or rule.bark_payload_template_json or {}
    rendered = render_template(tpl, ctx)

    payload = dict(default_payload)
    if isinstance(rendered, dict):
        payload.update(rendered)

    if cfg.get("device_key") is not None:
        payload["device_key"] = cfg.get("device_key")
    if cfg.get("device_keys") is not None:
        payload["device_keys"] = cfg.get("device_keys")

    return payload


def send_bark_push(*, server_base_url: str, payload: dict) -> tuple[bool, dict]:
    assert_ssrf_safe(server_base_url)

    url = build_push_url(server_base_url)
    timeout = float(getattr(settings, "BARK_REQUEST_TIMEOUT_SECONDS", 5))
    resp = requests.post(url, json=payload, timeout=timeout)

    meta: dict = {
        "http_status": resp.status_code,
    }

    content_type = (
        (resp.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
    )
    body_bytes = resp.content or b""
    snippet = body_bytes[:2048]
    try:
        meta["body_snippet"] = snippet.decode("utf-8", errors="replace")
    except Exception:
        meta["body_snippet"] = repr(snippet)

    if content_type == "application/json":
        try:
            meta["json"] = resp.json()
        except json.JSONDecodeError:
            pass

    ok = 200 <= resp.status_code < 300
    return ok, meta
