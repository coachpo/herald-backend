import hashlib
import hmac
from typing import Any, cast

from django.conf import settings
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt

from accounts.tokens import hash_token
from beacon.models import Delivery, ForwardingRule, IngestEndpoint, Message
from beacon.redaction import redact_headers
from beacon.rules import rule_matches_message


_DeliveryModel = cast(Any, Delivery)
_ForwardingRuleModel = cast(Any, ForwardingRule)
_IngestEndpointModel = cast(Any, IngestEndpoint)
_MessageModel = cast(Any, Message)


def _json_error(*, code: str, message: str, status: int, details: dict | None = None):
    body: dict = {"code": code, "message": message}
    if details is not None:
        body["details"] = details
    return JsonResponse(body, status=status)


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

    raw_key = (request.headers.get("X-Beacon-Ingest-Key") or "").strip()
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
        payload_text = bytes(buf).decode("utf-8")
    except UnicodeDecodeError:
        return _json_error(code="invalid_utf8", message="invalid utf-8", status=400)

    content_type = request.META.get("CONTENT_TYPE")
    if content_type:
        content_type = content_type.split(";", 1)[0].strip()

    headers = redact_headers(dict(request.headers))
    query = {k: v for k, v in request.GET.items()}

    msg = _MessageModel.objects.create(
        user=user,
        ingest_endpoint=endpoint,
        content_type=content_type or None,
        payload_text=payload_text,
        payload_sha256=hashlib.sha256(bytes(buf)).hexdigest(),
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
