import hashlib
import hmac
import json
from typing import Any, cast
from urllib.parse import urlparse

from django.conf import settings
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt

from accounts.tokens import hash_token
from core.models import Delivery, ForwardingRule, IngestEndpoint, Message
from core.redaction import redact_headers
from core.rules import rule_matches_message


_DeliveryModel = cast(Any, Delivery)
_ForwardingRuleModel = cast(Any, ForwardingRule)
_IngestEndpointModel = cast(Any, IngestEndpoint)
_MessageModel = cast(Any, Message)

_ALLOWED_TOP_LEVEL_KEYS = {
    "title",
    "body",
    "group",
    "priority",
    "tags",
    "url",
    "extras",
}


def _json_error(*, code: str, message: str, status: int, details: dict | None = None):
    body: dict = {"code": code, "message": message}
    if details is not None:
        body["details"] = details
    return JsonResponse(body, status=status)


def _validate_url(value: str) -> bool:
    try:
        result = urlparse(value)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


@csrf_exempt
def ingest_view(request, endpoint_id):
    if request.method != "POST":
        return JsonResponse(
            {"code": "method_not_allowed", "message": "method not allowed"}, status=405
        )

    try:
        endpoint = _IngestEndpointModel.objects.select_related("user").get(
            id=endpoint_id
        )
    except _IngestEndpointModel.DoesNotExist:
        return _json_error(code="not_authenticated", message="unauthorized", status=401)

    raw_key = (request.headers.get("X-Herald-Ingest-Key") or "").strip()
    if not raw_key:
        return _json_error(code="not_authenticated", message="unauthorized", status=401)

    token_hash = hash_token(raw_key)
    try:
        if not hmac.compare_digest(token_hash, endpoint.token_hash):
            return _json_error(
                code="not_authenticated", message="unauthorized", status=401
            )
    except Exception:
        return _json_error(code="not_authenticated", message="unauthorized", status=401)

    if endpoint.revoked_at is not None:
        return _json_error(code="not_authenticated", message="unauthorized", status=401)

    if endpoint.deleted_at is not None:
        return _json_error(code="not_authenticated", message="unauthorized", status=401)

    user = endpoint.user
    if not user.is_active:
        return _json_error(code="forbidden", message="forbidden", status=403)

    if (
        getattr(settings, "REQUIRE_VERIFIED_EMAIL_FOR_INGEST", True)
        and user.email_verified_at is None
    ):
        return _json_error(
            code="email_not_verified", message="email not verified", status=403
        )

    raw_ct = request.META.get("CONTENT_TYPE") or ""
    ct_base = raw_ct.split(";", 1)[0].strip().lower()
    if ct_base != "application/json":
        return _json_error(
            code="unsupported_media_type",
            message="Content-Type must be application/json",
            status=415,
        )

    max_bytes = int(getattr(settings, "MAX_INGEST_BYTES", 1048576))

    cl = request.META.get("CONTENT_LENGTH")
    if cl:
        try:
            if int(cl) > max_bytes:
                return _json_error(
                    code="payload_too_large", message="payload too large", status=413
                )
        except ValueError:
            return _json_error(
                code="invalid_request", message="invalid request", status=400
            )

    buf = bytearray()
    total = 0
    while True:
        chunk = request.read(64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            return _json_error(
                code="payload_too_large", message="payload too large", status=413
            )
        buf.extend(chunk)

    try:
        raw_text = bytes(buf).decode("utf-8")
    except UnicodeDecodeError:
        return _json_error(code="invalid_utf8", message="invalid utf-8", status=400)

    try:
        data = json.loads(raw_text)
    except (json.JSONDecodeError, ValueError):
        return _json_error(code="invalid_json", message="invalid JSON", status=400)

    if not isinstance(data, dict):
        return _json_error(
            code="validation_error",
            message="request body must be a JSON object",
            status=422,
        )

    unknown_keys = set(data.keys()) - _ALLOWED_TOP_LEVEL_KEYS
    if unknown_keys:
        return _json_error(
            code="validation_error",
            message=f"unknown keys: {', '.join(sorted(unknown_keys))}",
            status=422,
        )

    body_val = data.get("body")
    if body_val is None or not isinstance(body_val, str) or not body_val.strip():
        return _json_error(
            code="validation_error",
            message="'body' is required and must be a non-empty string",
            status=422,
        )

    title_val = data.get("title")
    if title_val is not None and not isinstance(title_val, str):
        return _json_error(
            code="validation_error",
            message="'title' must be a string",
            status=422,
        )

    group_val = data.get("group")
    if group_val is not None and not isinstance(group_val, str):
        return _json_error(
            code="validation_error",
            message="'group' must be a string",
            status=422,
        )

    priority_val = data.get("priority", 3)
    if not isinstance(priority_val, int) or isinstance(priority_val, bool):
        return _json_error(
            code="validation_error",
            message="'priority' must be an integer",
            status=422,
        )
    if priority_val < 1 or priority_val > 5:
        return _json_error(
            code="validation_error",
            message="'priority' must be between 1 and 5",
            status=422,
        )

    tags_val = data.get("tags", [])
    if not isinstance(tags_val, list):
        return _json_error(
            code="validation_error",
            message="'tags' must be an array of strings",
            status=422,
        )
    for i, t in enumerate(tags_val):
        if not isinstance(t, str):
            return _json_error(
                code="validation_error",
                message=f"'tags[{i}]' must be a string",
                status=422,
            )

    url_val = data.get("url")
    if url_val is not None:
        if not isinstance(url_val, str):
            return _json_error(
                code="validation_error",
                message="'url' must be a string",
                status=422,
            )
        if url_val.strip() and not _validate_url(url_val.strip()):
            return _json_error(
                code="validation_error",
                message="'url' must be a valid URL",
                status=422,
            )

    extras_val = data.get("extras", {})
    if not isinstance(extras_val, dict):
        return _json_error(
            code="validation_error",
            message="'extras' must be an object",
            status=422,
        )
    for k, v in extras_val.items():
        if not isinstance(v, str):
            return _json_error(
                code="validation_error",
                message=f"'extras.{k}' must be a string",
                status=422,
            )

    content_type = ct_base or None
    headers = redact_headers(dict(request.headers))
    query = {k: v for k, v in request.GET.items()}

    msg = _MessageModel.objects.create(
        user=user,
        ingest_endpoint=endpoint,
        title=title_val or None,
        body=body_val,
        group=group_val or None,
        priority=priority_val,
        tags_json=tags_val,
        url=(url_val.strip() if url_val else None) or None,
        extras_json=extras_val,
        content_type=content_type,
        body_sha256=hashlib.sha256(body_val.encode("utf-8")).hexdigest(),
        headers_json=headers,
        query_json=query,
        remote_ip=request.META.get("REMOTE_ADDR") or "",
        user_agent=request.META.get("HTTP_USER_AGENT") or None,
    )

    endpoint.last_used_at = timezone.now()
    endpoint.save(update_fields=["last_used_at"])

    rules = _ForwardingRuleModel.objects.filter(user=user, enabled=True).select_related(
        "channel"
    )
    now = timezone.now()
    for rule in rules:
        if rule_matches_message(rule, msg):
            _DeliveryModel.objects.create(
                user=user,
                message=msg,
                rule=rule,
                channel=rule.channel,
                status=Delivery.STATUS_QUEUED,
                attempt_count=0,
                next_attempt_at=now,
            )

    return JsonResponse({"message_id": str(msg.id)}, status=201)
