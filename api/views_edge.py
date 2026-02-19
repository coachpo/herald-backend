from __future__ import annotations

import hashlib
import json
from typing import Any, cast

from django.utils import timezone
from rest_framework.response import Response
from rest_framework.views import APIView

from beacon.models import Channel, ForwardingRule, IngestEndpoint

_ChannelModel = cast(Any, Channel)
_ForwardingRuleModel = cast(Any, ForwardingRule)
_IngestEndpointModel = cast(Any, IngestEndpoint)


class EdgeConfigView(APIView):
    def get(self, request):
        user = request.user

        endpoints = list(
            _IngestEndpointModel.objects.filter(
                user=user, revoked_at__isnull=True, deleted_at__isnull=True
            ).values("id", "name", "token_hash")
        )

        channels = []
        for ch in _ChannelModel.objects.filter(
            user=user, disabled_at__isnull=True
        ).only("id", "type", "name", "config_json_encrypted"):
            if ch.type not in (Channel.TYPE_BARK, Channel.TYPE_NTFY):
                continue
            channels.append(
                {
                    "id": str(ch.id),
                    "type": ch.type,
                    "name": ch.name,
                    "config": ch.get_config(),
                }
            )

        rules = []
        for rule in _ForwardingRuleModel.objects.filter(
            user=user, enabled=True
        ).select_related("channel"):
            if rule.channel.type not in (Channel.TYPE_BARK, Channel.TYPE_NTFY):
                continue
            if rule.channel.disabled_at is not None:
                continue
            rules.append(
                {
                    "id": str(rule.id),
                    "name": rule.name,
                    "filter": rule.filter_json or {},
                    "channel_id": str(rule.channel_id),
                    "payload_template": rule.get_payload_template(),
                }
            )

        config = {
            "ingest_endpoints": [
                {
                    "id": str(ep["id"]),
                    "name": ep["name"],
                    "token_hash": ep["token_hash"],
                }
                for ep in endpoints
            ],
            "channels": channels,
            "rules": rules,
            "updated_at": timezone.now().isoformat(),
        }

        config_bytes = json.dumps(
            config, separators=(",", ":"), sort_keys=True
        ).encode()
        config["version"] = hashlib.sha256(config_bytes).hexdigest()[:16]

        return Response(config, status=200)
