from __future__ import annotations

import uuid
from datetime import timedelta

from django.db import transaction
from django.db.models import Count
from django.utils import timezone
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.tokens import generate_secret_token, hash_token
from beacon.models import Channel, Delivery, ForwardingRule, IngestEndpoint, Message
from beacon.rules import rule_matches_message
from beacon.template import build_template_context, render_template

from .errors import api_error
from .permissions import VerifiedEmailForUnsafeMethods
from .serializers import (
    BatchDeleteRequestSerializer,
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


class IngestEndpointsView(APIView):
    permission_classes = [VerifiedEmailForUnsafeMethods]

    def get(self, request):
        eps = IngestEndpoint.objects.filter(user=request.user).order_by("-created_at")
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

        raw = generate_secret_token(32)
        ep = IngestEndpoint.objects.create(
            user=request.user,
            name=ser.validated_data["name"],
            token_hash=hash_token(raw),
        )

        ingest_url = request.build_absolute_uri(f"/api/ingest/{ep.id}")
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
            ep = IngestEndpoint.objects.get(user=request.user, id=id)
        except IngestEndpoint.DoesNotExist:
            return api_error(code="not_found", message="not found", status=404)

        if ep.revoked_at is None:
            ep.revoked_at = timezone.now()
            ep.save(update_fields=["revoked_at"])
        return Response(status=204)


class MessagesView(APIView):
    def get(self, request):
        qs = Message.objects.filter(
            user=request.user, deleted_at__isnull=True
        ).order_by("-received_at")

        ingest_endpoint_id = request.query_params.get("ingest_endpoint_id")
        if ingest_endpoint_id:
            qs = qs.filter(ingest_endpoint_id=ingest_endpoint_id)

        q = request.query_params.get("q")
        if q:
            qs = qs.filter(payload_text__icontains=q)

        from_ts = request.query_params.get("from")
        to_ts = request.query_params.get("to")
        if from_ts:
            qs = qs.filter(received_at__gte=from_ts)
        if to_ts:
            qs = qs.filter(received_at__lte=to_ts)

        messages = list(qs[:500])
        ids = [m.id for m in messages]
        counts = (
            Delivery.objects.filter(message_id__in=ids)
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
            msg = Message.objects.get(user=request.user, id=id)
        except Message.DoesNotExist:
            return api_error(code="not_found", message="not found", status=404)
        return Response({"message": MessageDetailSerializer(msg).data}, status=200)

    def delete(self, request, id: str):
        try:
            msg = Message.objects.get(user=request.user, id=id, deleted_at__isnull=True)
        except Message.DoesNotExist:
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

        days = int(ser.validated_data["older_than_days"])
        cutoff = timezone.now() - timedelta(days=days)
        qs = Message.objects.filter(
            user=request.user, deleted_at__isnull=True, received_at__lt=cutoff
        )

        ep_id = ser.validated_data.get("ingest_endpoint_id")
        if ep_id:
            qs = qs.filter(ingest_endpoint_id=ep_id)

        now = timezone.now()
        with transaction.atomic():
            updated = qs.update(deleted_at=now)

        return Response({"deleted_count": int(updated)}, status=200)


class ChannelsView(APIView):
    permission_classes = [VerifiedEmailForUnsafeMethods]

    def get(self, request):
        qs = Channel.objects.filter(user=request.user).order_by("-created_at")
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

        cfg = ser.validated_data["config"]
        channel = Channel(
            user=request.user,
            type=ser.validated_data["type"],
            name=ser.validated_data["name"],
            config_json_encrypted="",
        )
        channel.config = cfg
        channel.save()

        return Response(
            {"channel": ChannelSerializer(channel).data, "config": cfg}, status=201
        )


class ChannelDetailView(APIView):
    permission_classes = [VerifiedEmailForUnsafeMethods]

    def get(self, request, id: str):
        try:
            channel = Channel.objects.get(user=request.user, id=id)
        except Channel.DoesNotExist:
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
            channel = Channel.objects.get(user=request.user, id=id)
        except Channel.DoesNotExist:
            return api_error(code="not_found", message="not found", status=404)

        if ser.validated_data["type"] != channel.type:
            return api_error(
                code="validation_error",
                message="invalid request",
                status=400,
                details={"type": ["type_mismatch"]},
            )

        cfg = ser.validated_data["config"]
        channel.name = ser.validated_data["name"]
        channel.config = cfg
        channel.save(update_fields=["name", "config_json_encrypted"])

        return Response(
            {"channel": ChannelSerializer(channel).data, "config": cfg}, status=200
        )

    def delete(self, request, id: str):
        deleted, _ = Channel.objects.filter(user=request.user, id=id).delete()
        if not deleted:
            return api_error(code="not_found", message="not found", status=404)
        return Response(status=204)


class RulesView(APIView):
    permission_classes = [VerifiedEmailForUnsafeMethods]

    def get(self, request):
        qs = ForwardingRule.objects.filter(user=request.user).order_by("-created_at")
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

        try:
            channel = Channel.objects.get(
                user=request.user, id=ser.validated_data["channel_id"]
            )
        except Channel.DoesNotExist:
            return api_error(code="not_found", message="channel not found", status=404)

        tpl = (
            ser.validated_data.get("payload_template")
            or ser.validated_data.get("bark_payload_template")
            or {}
        )

        rule = ForwardingRule.objects.create(
            user=request.user,
            name=ser.validated_data["name"],
            enabled=ser.validated_data["enabled"],
            channel=channel,
            filter_json=ser.validated_data.get("filter") or {},
            bark_payload_template_json=tpl,
            payload_template_json=tpl,
        )
        return Response({"rule": RuleSerializer(rule).data}, status=201)


class RuleDetailView(APIView):
    permission_classes = [VerifiedEmailForUnsafeMethods]

    def get(self, request, id: str):
        try:
            rule = ForwardingRule.objects.get(user=request.user, id=id)
        except ForwardingRule.DoesNotExist:
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
            rule = ForwardingRule.objects.get(user=request.user, id=id)
        except ForwardingRule.DoesNotExist:
            return api_error(code="not_found", message="not found", status=404)

        try:
            channel = Channel.objects.get(
                user=request.user, id=ser.validated_data["channel_id"]
            )
        except Channel.DoesNotExist:
            return api_error(code="not_found", message="channel not found", status=404)

        tpl = (
            ser.validated_data.get("payload_template")
            or ser.validated_data.get("bark_payload_template")
            or {}
        )

        rule.name = ser.validated_data["name"]
        rule.enabled = ser.validated_data["enabled"]
        rule.channel = channel
        rule.filter_json = ser.validated_data.get("filter") or {}
        rule.bark_payload_template_json = tpl
        rule.payload_template_json = tpl
        rule.save()

        return Response({"rule": RuleSerializer(rule).data}, status=200)

    def delete(self, request, id: str):
        deleted, _ = ForwardingRule.objects.filter(user=request.user, id=id).delete()
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
            rule = ForwardingRule.objects.get(user=request.user, id=id)
        except ForwardingRule.DoesNotExist:
            return api_error(code="not_found", message="not found", status=404)

        try:
            ep = IngestEndpoint.objects.get(
                user=request.user, id=ser.validated_data["ingest_endpoint_id"]
            )
        except IngestEndpoint.DoesNotExist:
            return api_error(
                code="not_found", message="ingest endpoint not found", status=404
            )

        msg = Message(
            id=uuid.uuid4(),
            user=request.user,
            ingest_endpoint=ep,
            received_at=timezone.now(),
            content_type=ser.validated_data.get("content_type"),
            payload_text=ser.validated_data["payload_text"],
            headers_json={},
            query_json={},
            remote_ip="",
        )

        matches = rule_matches_message(rule, msg)
        ctx = build_template_context(msg, ep)
        tpl = rule.payload_template_json or rule.bark_payload_template_json or {}
        rendered = render_template(tpl, ctx)
        return Response(
            {
                "matches": bool(matches),
                "channel_type": rule.channel.type,
                "rendered_payload": rendered,
                "rendered_bark_payload": rendered,
            },
            status=200,
        )


class MessageDeliveriesView(APIView):
    def get(self, request, id: str):
        try:
            msg = Message.objects.get(user=request.user, id=id)
        except Message.DoesNotExist:
            return api_error(code="not_found", message="not found", status=404)
        ds = Delivery.objects.filter(user=request.user, message=msg).order_by(
            "created_at"
        )
        return Response(
            {"deliveries": DeliverySerializer(ds, many=True).data}, status=200
        )
