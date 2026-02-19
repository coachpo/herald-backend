import json
from urllib.parse import quote, urljoin, urlparse

import requests
from django.conf import settings

from .models import Channel, ForwardingRule, IngestEndpoint, Message
from .ssrf import assert_ssrf_safe
from .template import build_template_context, render_template


def build_push_url(server_base_url: str) -> str:
    base = (server_base_url or "").strip().rstrip("/")
    if base.endswith("/push"):
        base = base[: -len("/push")]
    base = base.rstrip("/") + "/"
    return urljoin(base, "push")


def _looks_like_device_key(seg: str) -> bool:
    s = (seg or "").strip()
    if len(s) < 16:
        return False
    if not all(c.isalnum() or c in {"_", "-"} for c in s):
        return False
    has_digit = any(c.isdigit() for c in s)
    return has_digit


def _build_legacy_push_url(
    *, server_base_url: str, device_key: str, title: str | None, body: str
) -> str:
    root = (server_base_url or "").strip().rstrip("/")
    if not root:
        raise ValueError("missing_server_base_url")
    if not device_key:
        raise ValueError("missing_device_key")

    base = root.rstrip("/") + "/" + quote(device_key.strip(), safe="") + "/"
    if title:
        base += quote(title, safe="") + "/"
    base += quote(body or "", safe="")
    return base


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
    tpl = rule.get_payload_template()
    rendered = render_template(tpl, ctx)

    payload = dict(default_payload)
    if isinstance(rendered, dict):
        payload.update(rendered)

    if not payload.get("body") and message.body:
        payload["body"] = message.body
    if not payload.get("title") and message.title:
        payload["title"] = message.title

    if cfg.get("device_key") is not None:
        payload["device_key"] = cfg.get("device_key")
    if cfg.get("device_keys") is not None:
        payload["device_keys"] = cfg.get("device_keys")

    return payload


def send_bark_push(*, server_base_url: str, payload: dict) -> tuple[bool, dict]:
    assert_ssrf_safe(server_base_url)

    timeout = float(getattr(settings, "BARK_REQUEST_TIMEOUT_SECONDS", 5))

    url = build_push_url(server_base_url)
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
    if ok:
        return True, meta

    if resp.status_code in {404, 405}:
        device_key = str(payload.get("device_key") or "").strip()
        body = str(payload.get("body") or "").strip()
        if device_key and body:
            title = str(payload.get("title") or "").strip() or None

            server_root = server_base_url
            try:
                parsed = urlparse(server_base_url)
                segs = [s for s in (parsed.path or "").split("/") if s]
                if len(segs) == 1 and _looks_like_device_key(segs[0]):
                    server_root = f"{parsed.scheme}://{parsed.netloc}"
            except Exception:
                pass

            legacy_url = _build_legacy_push_url(
                server_base_url=server_root,
                device_key=device_key,
                title=title,
                body=body,
            )
            assert_ssrf_safe(legacy_url)
            legacy_resp = requests.get(legacy_url, timeout=timeout)

            legacy_meta: dict = {
                "http_status": legacy_resp.status_code,
                "fallback": "legacy_get",
            }
            snippet2 = (legacy_resp.content or b"")[:2048]
            try:
                legacy_meta["body_snippet"] = snippet2.decode("utf-8", errors="replace")
            except Exception:
                legacy_meta["body_snippet"] = repr(snippet2)

            ct2 = (
                (legacy_resp.headers.get("Content-Type") or "")
                .split(";", 1)[0]
                .strip()
                .lower()
            )
            if ct2 == "application/json":
                try:
                    legacy_meta["json"] = legacy_resp.json()
                except json.JSONDecodeError:
                    pass

            legacy_ok = 200 <= legacy_resp.status_code < 300
            return legacy_ok, legacy_meta

    return False, meta
