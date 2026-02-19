import re
from collections.abc import Mapping
from datetime import datetime

from django.utils import timezone

from .models import IngestEndpoint, Message


_VAR_RE = re.compile(r"\{\{\s*([a-zA-Z0-9_\.]+)\s*\}\}")


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if timezone.is_naive(dt):
        dt = timezone.make_aware(dt, timezone=timezone.utc)
    return dt.isoformat()


def _lookup(path: str, ctx: Mapping[str, object]) -> object | None:
    cur: object | None = ctx
    for part in path.split("."):
        if not isinstance(cur, Mapping):
            return None
        cur = cur.get(part)
    return cur


def _render_str(s: str, ctx: Mapping[str, object]) -> str:
    def repl(m: re.Match[str]) -> str:
        val = _lookup(m.group(1), ctx)
        return "" if val is None else str(val)

    return _VAR_RE.sub(repl, s)


def render_template(value: object, ctx: Mapping[str, object]) -> object:
    if isinstance(value, str):
        return _render_str(value, ctx)
    if isinstance(value, list):
        return [render_template(v, ctx) for v in value]
    if isinstance(value, dict):
        return {k: render_template(v, ctx) for k, v in value.items()}
    return value


def build_template_context(
    message: Message, ingest_endpoint: IngestEndpoint
) -> dict[str, object]:
    tags = message.tags_json if isinstance(message.tags_json, list) else []
    extras = message.extras_json if isinstance(message.extras_json, dict) else {}

    return {
        "message": {
            "id": str(message.id),
            "received_at": _iso(message.received_at),
            "title": message.title or "",
            "body": message.body or "",
            "group": message.group or "",
            "priority": str(message.priority),
            "tags": ",".join(str(t) for t in tags),
            "url": message.url or "",
            "extras": {str(k): str(v) for k, v in extras.items()},
        },
        "request": {
            "content_type": message.content_type or "",
            "remote_ip": message.remote_ip or "",
            "user_agent": message.user_agent or "",
            "headers": message.headers_json
            if isinstance(message.headers_json, dict)
            else {},
            "query": message.query_json if isinstance(message.query_json, dict) else {},
        },
        "ingest_endpoint": {
            "id": str(ingest_endpoint.id),
            "name": ingest_endpoint.name,
        },
    }
