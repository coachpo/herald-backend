from __future__ import annotations

import time
import uuid
from datetime import timedelta
from typing import Any, cast

import requests
from django.db import transaction
from django.db.utils import OperationalError
from django.db.models import Count
from django.utils import timezone
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.tokens import generate_secret_token, hash_token
from core.models import Channel, Delivery, ForwardingRule, IngestEndpoint, Message
from core.rules import rule_matches_message
from core.template import build_template_context, render_template

from .errors import api_error
from .permissions import VerifiedEmailForUnsafeMethods
from .serializers import (
    BatchDeleteRequestSerializer,
    ChannelTestRequestSerializer,
    ChannelUpsertRequestSerializer,
    ChannelSerializer,
    DeliverySerializer,
    IngestEndpointCreateRequestSerializer,
    IngestEndpointSerializer,
    MessageDetailSerializer,
    MessageSummarySerializer,
    RuleSerializer,
    RuleTestRequestSerializer,
    RuleUpsertRequestSerializer,
)


_ChannelModel = cast(Any, Channel)
_DeliveryModel = cast(Any, Delivery)
_ForwardingRuleModel = cast(Any, ForwardingRule)
_IngestEndpointModel = cast(Any, IngestEndpoint)
_MessageModel = cast(Any, Message)
_transaction = cast(Any, transaction)


class IngestEndpointsView(APIView):
    permission_classes = [VerifiedEmailForUnsafeMethods]

    def get(self, request):
        eps = _IngestEndpointModel.objects.filter(user=request.user).order_by(
            "-created_at"
        )
        eps = eps.filter(deleted_at__isnull=True)
        return Response(
            {"endpoints": IngestEndpointSerializer(eps, many=True).data}, status=200
        )

    def post(self, request):
        ser = IngestEndpointCreateRequestSerializer(data=request.data)
        if not ser.is_valid():
            return api_error(
                code="validation_error",
                message="invalid request",
                status=400,
                details=ser.errors,
            )

        data = cast(dict[str, Any], ser.validated_data)
        raw = generate_secret_token(32)
        ep = _IngestEndpointModel.objects.create(
            user=request.user,
            name=data["name"],
            token_hash=hash_token(raw),
        )

        ingest_url = request.build_absolute_uri(f"/api/ingest/{ep.id.hex}")
        return Response(
            {
                "endpoint": IngestEndpointSerializer(ep).data,
                "ingest_key": raw,
                "ingest_url": ingest_url,
            },
            status=201,
        )


class IngestEndpointRevokeView(APIView):
    permission_classes = [VerifiedEmailForUnsafeMethods]

    def post(self, request, id: str):
        try:
            ep = _IngestEndpointModel.objects.get(
                user=request.user, id=id, deleted_at__isnull=True
            )
        except _IngestEndpointModel.DoesNotExist:
            return api_error(code="not_found", message="not found", status=404)

        if ep.revoked_at is None:
            ep.revoked_at = timezone.now()
            ep.save(update_fields=["revoked_at"])
        return Response(status=204)


class IngestEndpointArchiveView(APIView):
    permission_classes = [VerifiedEmailForUnsafeMethods]

    def delete(self, request, id: str):
        try:
            ep = _IngestEndpointModel.objects.get(
                user=request.user, id=id, deleted_at__isnull=True
            )
        except _IngestEndpointModel.DoesNotExist:
            return api_error(code="not_found", message="not found", status=404)

        now = timezone.now()
        if ep.revoked_at is None:
            ep.revoked_at = now
        if ep.deleted_at is None:
            ep.deleted_at = now
        ep.save(update_fields=["revoked_at", "deleted_at"])
        return Response(status=204)


class MessagesView(APIView):
    def get(self, request):
        qs = _MessageModel.objects.filter(
            user=request.user, deleted_at__isnull=True
        ).order_by("-received_at")

        ingest_endpoint_id = request.query_params.get("ingest_endpoint_id")
        if ingest_endpoint_id:
            qs = qs.filter(ingest_endpoint_id=ingest_endpoint_id)

        q = request.query_params.get("q")
        if q:
            qs = qs.filter(body__icontains=q)

        group = request.query_params.get("group")
        if group:
            qs = qs.filter(group=group)

        priority_min = request.query_params.get("priority_min")
        if priority_min:
            try:
                qs = qs.filter(priority__gte=int(priority_min))
            except (ValueError, TypeError):
                pass

        priority_max = request.query_params.get("priority_max")
        if priority_max:
            try:
                qs = qs.filter(priority__lte=int(priority_max))
            except (ValueError, TypeError):
                pass

        tag = request.query_params.get("tag")
        if tag:
            qs = qs.filter(tags_json__contains=[tag])

        from_ts = request.query_params.get("from")
        to_ts = request.query_params.get("to")
        if from_ts:
            qs = qs.filter(received_at__gte=from_ts)
        if to_ts:
            qs = qs.filter(received_at__lte=to_ts)

        messages = list(qs[:500])
        ids = [m.id for m in messages]
        counts = (
            _DeliveryModel.objects.filter(message_id__in=ids)
            .values("message_id", "status")
            .annotate(c=Count("id"))
        )
        by_msg: dict[str, dict[str, int]] = {}
        for row in counts:
            mid = str(row["message_id"])
            by_msg.setdefault(mid, {})[row["status"]] = int(row["c"])

        for m in messages:
            m.delivery_counts = by_msg.get(str(m.id), {})

        return Response(
            {"messages": MessageSummarySerializer(messages, many=True).data}, status=200
        )


class MessageDetailView(APIView):
    permission_classes = [VerifiedEmailForUnsafeMethods]

    def get(self, request, id: str):
        try:
            msg = _MessageModel.objects.get(
                user=request.user, id=id, deleted_at__isnull=True
            )
        except _MessageModel.DoesNotExist:
            return api_error(code="not_found", message="not found", status=404)
        return Response({"message": MessageDetailSerializer(msg).data}, status=200)

    def delete(self, request, id: str):
        try:
            msg = _MessageModel.objects.get(
                user=request.user, id=id, deleted_at__isnull=True
            )
        except _MessageModel.DoesNotExist:
            return api_error(code="not_found", message="not found", status=404)
        msg.soft_delete()
        return Response(status=204)


class MessagesBatchDeleteView(APIView):
    permission_classes = [VerifiedEmailForUnsafeMethods]

    def post(self, request):
        ser = BatchDeleteRequestSerializer(data=request.data)
        if not ser.is_valid():
            return api_error(
                code="validation_error",
                message="invalid request",
                status=400,
                details=ser.errors,
            )

        data = cast(dict[str, Any], ser.validated_data)
        days = int(data["older_than_days"])
        cutoff = timezone.now() - timedelta(days=days)
        qs = _MessageModel.objects.filter(
            user=request.user, deleted_at__isnull=True, received_at__lt=cutoff
        )

        ep_id = data.get("ingest_endpoint_id")
        if ep_id:
            qs = qs.filter(ingest_endpoint_id=ep_id)

        now = timezone.now()
        with _transaction.atomic():
            updated = qs.update(deleted_at=now)

        return Response({"deleted_count": int(updated)}, status=200)


class ChannelsView(APIView):
    permission_classes = [VerifiedEmailForUnsafeMethods]

    def get(self, request):
        qs = _ChannelModel.objects.filter(user=request.user).order_by("-created_at")
        return Response({"channels": ChannelSerializer(qs, many=True).data}, status=200)

    def post(self, request):
        ser = ChannelUpsertRequestSerializer(data=request.data)
        if not ser.is_valid():
            return api_error(
                code="validation_error",
                message="invalid request",
                status=400,
                details=ser.errors,
            )

        data = cast(dict[str, Any], ser.validated_data)
        cfg = data["config"]

        channel: Channel | None = None
        for attempt in range(3):
            try:
                ch = cast(
                    Channel,
                    _ChannelModel(
                        user=request.user,
                        type=data["type"],
                        name=data["name"],
                        config_json_encrypted="",
                    ),
                )
                ch.config = cfg
                ch.save()
                channel = ch
                break
            except OperationalError as e:
                if "database is locked" in str(e).lower() and attempt < 2:
                    time.sleep(0.05 * (2**attempt))
                    continue
                raise

        if channel is None:
            return api_error(
                code="temporarily_unavailable", message="try again", status=503
            )

        return Response(
            {"channel": ChannelSerializer(channel).data, "config": cfg}, status=201
        )


class ChannelDetailView(APIView):
    permission_classes = [VerifiedEmailForUnsafeMethods]

    def get(self, request, id: str):
        try:
            channel = _ChannelModel.objects.get(user=request.user, id=id)
        except _ChannelModel.DoesNotExist:
            return api_error(code="not_found", message="not found", status=404)
        return Response(
            {"channel": ChannelSerializer(channel).data, "config": channel.config},
            status=200,
        )

    def patch(self, request, id: str):
        ser = ChannelUpsertRequestSerializer(data=request.data)
        if not ser.is_valid():
            return api_error(
                code="validation_error",
                message="invalid request",
                status=400,
                details=ser.errors,
            )

        try:
            channel = _ChannelModel.objects.get(user=request.user, id=id)
        except _ChannelModel.DoesNotExist:
            return api_error(code="not_found", message="not found", status=404)

        data = cast(dict[str, Any], ser.validated_data)
        if data["type"] != channel.type:
            return api_error(
                code="validation_error",
                message="invalid request",
                status=400,
                details={"type": ["type_mismatch"]},
            )

        cfg = data["config"]
        channel.name = data["name"]
        channel.config = cfg
        channel.save(update_fields=["name", "config_json_encrypted"])

        return Response(
            {"channel": ChannelSerializer(channel).data, "config": cfg}, status=200
        )

    def delete(self, request, id: str):
        deleted, _ = _ChannelModel.objects.filter(user=request.user, id=id).delete()
        if not deleted:
            return api_error(code="not_found", message="not found", status=404)
        return Response(status=204)


class ChannelTestView(APIView):
    permission_classes = [VerifiedEmailForUnsafeMethods]

    def post(self, request, id: str):
        ser = ChannelTestRequestSerializer(data=request.data)
        if not ser.is_valid():
            return api_error(
                code="validation_error",
                message="invalid request",
                status=400,
                details=ser.errors,
            )

        try:
            channel = _ChannelModel.objects.get(user=request.user, id=id)
        except _ChannelModel.DoesNotExist:
            return api_error(code="not_found", message="not found", status=404)

        data = cast(dict[str, Any], ser.validated_data)
        title = str(data.get("title") or "").strip() or None
        body = str(data.get("body") or "").strip() or None
        payload_json = data.get("payload_json")
        if not body and payload_json is None:
            body = "Test notification from Herald"

        t = str(channel.type or "").strip()
        try:
            if t == "bark":
                from core.bark import send_bark_push

                cfg = channel.config
                server_base_url = str(cfg.get("server_base_url") or "").strip()
                if not server_base_url:
                    raise ValueError("missing_server_base_url")

                payload: dict = {}
                default_payload = cfg.get("default_payload_json")
                if isinstance(default_payload, dict):
                    payload.update(default_payload)
                if isinstance(payload_json, dict):
                    payload.update(payload_json)
                if title is not None:
                    payload["title"] = title
                payload.setdefault("title", "Herald test")
                if body is not None:
                    payload["body"] = body
                payload.setdefault("body", "Test notification from Herald")

                if cfg.get("device_key") is not None:
                    payload["device_key"] = cfg.get("device_key")
                if cfg.get("device_keys") is not None:
                    payload["device_keys"] = cfg.get("device_keys")

                ok, meta = send_bark_push(
                    server_base_url=server_base_url, payload=payload
                )
            elif t == "ntfy":
                from core.ntfy import send_ntfy_publish
                from urllib.parse import urljoin
                from django.conf import settings

                from core.ssrf import assert_ssrf_safe

                cfg = channel.config
                server_base_url = str(cfg.get("server_base_url") or "").strip()
                topic = str(cfg.get("topic") or "").strip()
                if not server_base_url:
                    raise ValueError("missing_server_base_url")
                if not topic:
                    raise ValueError("missing_topic")

                base = server_base_url.rstrip("/") + "/"
                url = urljoin(base, str(topic).lstrip("/"))
                block_private = bool(
                    getattr(settings, "NTFY_BLOCK_PRIVATE_NETWORKS", True)
                )
                assert_ssrf_safe(url, block_private_networks=block_private)

                headers: dict[str, str] = {}
                default_headers = cfg.get("default_headers_json")
                if isinstance(default_headers, dict):
                    for k, v in default_headers.items():
                        kk = str(k).strip()
                        if not kk:
                            continue
                        if v is None:
                            continue
                        if isinstance(v, bool):
                            vv = "true" if v else "false"
                        else:
                            vv = str(v).strip()
                        if vv:
                            headers[kk] = vv

                if title is not None:
                    headers.setdefault("Title", title)
                headers.setdefault("Title", "Herald test")

                token = str(cfg.get("access_token") or "").strip()
                if token:
                    headers.setdefault("Authorization", f"Bearer {token}")

                username = str(cfg.get("username") or "").strip()
                password = str(cfg.get("password") or "").strip()
                auth = (
                    (username, password)
                    if username and password and not token
                    else None
                )

                body_text = body or "Test notification from Herald"
                ok, meta = send_ntfy_publish(
                    url=url,
                    body=body_text.encode("utf-8"),
                    headers=headers,
                    auth=auth,
                )
            elif t == "mqtt":
                from core.mqtt import send_mqtt_publish

                cfg = channel.config
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

                payload_obj: object
                if isinstance(payload_json, dict):
                    payload_obj = payload_json
                else:
                    payload_obj = body or "Test notification from Herald"

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
                return api_error(
                    code="validation_error",
                    message="invalid channel type",
                    status=400,
                    details={"type": ["unsupported_channel_type"]},
                )
        except ValueError as e:
            return api_error(
                code="validation_error",
                message="invalid channel config",
                status=400,
                details={"error": str(e)},
            )
        except requests.RequestException as e:
            return api_error(
                code="channel_test_failed",
                message="send failed",
                status=502,
                details={"error": str(e)},
            )
        except Exception as e:
            return api_error(
                code="channel_test_failed",
                message="send failed",
                status=502,
                details={"error": str(e)},
            )

        meta = dict(meta)
        meta.setdefault("provider", t)
        return Response(
            {
                "ok": bool(ok),
                "channel_id": str(channel.id),
                "channel_type": t,
                "provider_response": meta,
            },
            status=200,
        )


class RulesView(APIView):
    permission_classes = [VerifiedEmailForUnsafeMethods]

    def get(self, request):
        qs = _ForwardingRuleModel.objects.filter(user=request.user).order_by(
            "-created_at"
        )
        return Response({"rules": RuleSerializer(qs, many=True).data}, status=200)

    def post(self, request):
        ser = RuleUpsertRequestSerializer(data=request.data)
        if not ser.is_valid():
            return api_error(
                code="validation_error",
                message="invalid request",
                status=400,
                details=ser.errors,
            )

        data = cast(dict[str, Any], ser.validated_data)
        try:
            channel = _ChannelModel.objects.get(
                user=request.user, id=data["channel_id"]
            )
        except _ChannelModel.DoesNotExist:
            return api_error(code="not_found", message="channel not found", status=404)

        tpl = data.get("payload_template") or {}

        rule = _ForwardingRuleModel.objects.create(
            user=request.user,
            name=data["name"],
            enabled=data["enabled"],
            channel=channel,
            filter_json=data.get("filter") or {},
            payload_template_json=tpl,
        )
        return Response({"rule": RuleSerializer(rule).data}, status=201)


class RuleDetailView(APIView):
    permission_classes = [VerifiedEmailForUnsafeMethods]

    def get(self, request, id: str):
        try:
            rule = _ForwardingRuleModel.objects.get(user=request.user, id=id)
        except _ForwardingRuleModel.DoesNotExist:
            return api_error(code="not_found", message="not found", status=404)
        return Response({"rule": RuleSerializer(rule).data}, status=200)

    def patch(self, request, id: str):
        ser = RuleUpsertRequestSerializer(data=request.data)
        if not ser.is_valid():
            return api_error(
                code="validation_error",
                message="invalid request",
                status=400,
                details=ser.errors,
            )

        try:
            rule = _ForwardingRuleModel.objects.get(user=request.user, id=id)
        except _ForwardingRuleModel.DoesNotExist:
            return api_error(code="not_found", message="not found", status=404)

        data = cast(dict[str, Any], ser.validated_data)
        try:
            channel = _ChannelModel.objects.get(
                user=request.user, id=data["channel_id"]
            )
        except _ChannelModel.DoesNotExist:
            return api_error(code="not_found", message="channel not found", status=404)

        tpl = data.get("payload_template") or {}

        rule.name = data["name"]
        rule.enabled = data["enabled"]
        rule.channel = channel
        rule.filter_json = data.get("filter") or {}
        rule.payload_template_json = tpl
        rule.save()

        return Response({"rule": RuleSerializer(rule).data}, status=200)

    def delete(self, request, id: str):
        deleted, _ = _ForwardingRuleModel.objects.filter(
            user=request.user, id=id
        ).delete()
        if not deleted:
            return api_error(code="not_found", message="not found", status=404)
        return Response(status=204)


class RuleTestView(APIView):
    permission_classes = [VerifiedEmailForUnsafeMethods]

    def post(self, request, id: str):
        ser = RuleTestRequestSerializer(data=request.data)
        if not ser.is_valid():
            return api_error(
                code="validation_error",
                message="invalid request",
                status=400,
                details=ser.errors,
            )

        try:
            rule = _ForwardingRuleModel.objects.get(user=request.user, id=id)
        except _ForwardingRuleModel.DoesNotExist:
            return api_error(code="not_found", message="not found", status=404)

        data = cast(dict[str, Any], ser.validated_data)
        try:
            ep = _IngestEndpointModel.objects.get(
                user=request.user, id=data["ingest_endpoint_id"]
            )
        except _IngestEndpointModel.DoesNotExist:
            return api_error(
                code="not_found", message="ingest endpoint not found", status=404
            )

        payload = data.get("payload") or {}
        msg = Message(
            id=uuid.uuid4(),
            user=request.user,
            ingest_endpoint=ep,
            received_at=timezone.now(),
            title=payload.get("title"),
            body=payload.get("body", ""),
            group=payload.get("group"),
            priority=payload.get("priority", 3),
            tags_json=payload.get("tags", []),
            url=payload.get("url"),
            extras_json=payload.get("extras", {}),
            content_type="application/json",
            headers_json={},
            query_json={},
            remote_ip="",
        )

        matches = rule_matches_message(rule, msg)
        ctx = build_template_context(msg, ep)
        tpl = rule.get_payload_template()
        rendered = render_template(tpl, ctx)
        return Response(
            {
                "matches": bool(matches),
                "channel_type": rule.channel.type,
                "rendered_payload": rendered,
            },
            status=200,
        )


class RulesTestView(APIView):
    permission_classes = [VerifiedEmailForUnsafeMethods]

    def post(self, request):
        ser = RuleTestRequestSerializer(data=request.data)
        if not ser.is_valid():
            return api_error(
                code="validation_error",
                message="invalid request",
                status=400,
                details=ser.errors,
            )

        data = cast(dict[str, Any], ser.validated_data)
        try:
            ep = _IngestEndpointModel.objects.get(
                user=request.user,
                id=data["ingest_endpoint_id"],
                deleted_at__isnull=True,
            )
        except _IngestEndpointModel.DoesNotExist:
            return api_error(
                code="not_found", message="ingest endpoint not found", status=404
            )

        payload = data.get("payload") or {}
        msg = _MessageModel(
            id=uuid.uuid4(),
            user=request.user,
            ingest_endpoint=ep,
            received_at=timezone.now(),
            title=payload.get("title"),
            body=payload.get("body", ""),
            group=payload.get("group"),
            priority=payload.get("priority", 3),
            tags_json=payload.get("tags", []),
            url=payload.get("url"),
            extras_json=payload.get("extras", {}),
            content_type="application/json",
            headers_json={},
            query_json={},
            remote_ip="",
        )

        rules_qs = (
            _ForwardingRuleModel.objects.filter(user=request.user, enabled=True)
            .select_related("channel")
            .order_by("-created_at")
        )
        total = int(rules_qs.count())

        ctx = build_template_context(msg, ep)
        matches: list[dict] = []
        for rule in rules_qs:
            if not rule_matches_message(rule, msg):
                continue
            tpl = rule.get_payload_template()
            rendered = render_template(tpl, ctx)
            matches.append(
                {
                    "rule": RuleSerializer(rule).data,
                    "channel": ChannelSerializer(rule.channel).data,
                    "channel_type": str(rule.channel.type),
                    "rendered_payload": rendered,
                }
            )

        return Response(
            {
                "matched_count": len(matches),
                "total_rules": total,
                "matches": matches,
            },
            status=200,
        )


class MessageDeliveriesView(APIView):
    def get(self, request, id: str):
        try:
            msg = _MessageModel.objects.get(
                user=request.user, id=id, deleted_at__isnull=True
            )
        except _MessageModel.DoesNotExist:
            return api_error(code="not_found", message="not found", status=404)
        ds = _DeliveryModel.objects.filter(user=request.user, message=msg).order_by(
            "created_at"
        )
        ds = ds.select_related("rule", "channel")
        return Response(
            {"deliveries": DeliverySerializer(ds, many=True).data}, status=200
        )
