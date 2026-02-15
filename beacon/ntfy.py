import json
from urllib.parse import urljoin

import requests
from django.conf import settings

from .models import Channel, ForwardingRule, IngestEndpoint, Message
from .ssrf import assert_ssrf_safe
from .template import build_template_context, render_template


def build_topic_url(server_base_url: str, topic: str) -> str:
    base = server_base_url.rstrip("/") + "/"
    return urljoin(base, str(topic).lstrip("/"))


def _coerce_header_value(v: object) -> str | None:
    if v is None:
        return None
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, str):
        s = v.strip()
        return s or None
    return str(v)


def build_ntfy_request(
    *,
    channel: Channel,
    rule: ForwardingRule,
    message: Message,
    ingest_endpoint: IngestEndpoint,
) -> tuple[str, bytes, dict[str, str], tuple[str, str] | None]:
    cfg = channel.config
    server_base_url = str(cfg.get("server_base_url") or "").strip()
    topic = str(cfg.get("topic") or "").strip()
    if not server_base_url:
        raise ValueError("missing_server_base_url")
    if not topic:
        raise ValueError("missing_topic")

    url = build_topic_url(server_base_url, topic)
    block_private = bool(getattr(settings, "NTFY_BLOCK_PRIVATE_NETWORKS", True))
    assert_ssrf_safe(url, block_private_networks=block_private)

    ctx = build_template_context(message, ingest_endpoint)
    tpl = rule.get_payload_template()
    rendered = render_template(tpl, ctx)
    rendered_dict = rendered if isinstance(rendered, dict) else {}

    body_val = rendered_dict.get("body")
    if body_val is None:
        body_val = rendered_dict.get("message")
    if body_val is None:
        body_val = rendered_dict.get("text")
    body = _coerce_header_value(body_val) if body_val is not None else None
    if body is None:
        body = message.payload_text or ""

    headers: dict[str, str] = {}
    default_headers = cfg.get("default_headers_json")
    if isinstance(default_headers, dict):
        for k, v in default_headers.items():
            kk = str(k).strip()
            vv = _coerce_header_value(v)
            if kk and vv is not None:
                headers[kk] = vv

    title = _coerce_header_value(rendered_dict.get("title"))
    if title is not None:
        headers.setdefault("Title", title)

    tags = rendered_dict.get("tags")
    if isinstance(tags, list):
        joined = ",".join(str(x).strip() for x in tags if str(x).strip())
        if joined:
            headers.setdefault("Tags", joined)
    else:
        t = _coerce_header_value(tags)
        if t is not None:
            headers.setdefault("Tags", t)

    prio = _coerce_header_value(rendered_dict.get("priority"))
    if prio is not None:
        headers.setdefault("Priority", prio)

    click = _coerce_header_value(rendered_dict.get("click"))
    if click is not None:
        headers.setdefault("Click", click)

    icon = _coerce_header_value(rendered_dict.get("icon"))
    if icon is not None:
        headers.setdefault("Icon", icon)

    attach = _coerce_header_value(rendered_dict.get("attach"))
    if attach is not None:
        headers.setdefault("Attach", attach)

    markdown = rendered_dict.get("markdown")
    if isinstance(markdown, bool) and markdown:
        headers.setdefault("Markdown", "true")

    token = str(cfg.get("access_token") or "").strip()
    if token:
        headers.setdefault("Authorization", f"Bearer {token}")

    username = str(cfg.get("username") or "").strip()
    password = str(cfg.get("password") or "").strip()
    auth = (username, password) if username and password and not token else None

    return url, body.encode("utf-8"), headers, auth


def send_ntfy_publish(
    *,
    url: str,
    body: bytes,
    headers: dict[str, str],
    auth: tuple[str, str] | None,
) -> tuple[bool, dict]:
    timeout = float(getattr(settings, "NTFY_REQUEST_TIMEOUT_SECONDS", 5))
    resp = requests.post(url, data=body, headers=headers, timeout=timeout, auth=auth)

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
