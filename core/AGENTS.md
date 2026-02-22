# backend/core/AGENTS.md

## Overview

Core domain models and business logic — notification channels, forwarding rules, delivery worker, template rendering.

## Where to Look

| Task | Location |
|------|----------|
| Modify domain models | `models.py` (IngestEndpoint, Message, Channel, ForwardingRule, Delivery) |
| Add notification provider | New `{provider}.py` + wire in `management/commands/deliveries_worker.py` |
| Change rule matching | `rules.py` (`rule_matches_message()`) |
| Change template rendering | `template.py` (Mustache-style `{{var}}` substitution) |
| Modify SSRF checks | `ssrf.py` (blocks loopback, link-local, private IPs) |
| Change channel encryption | `crypto.py` (Fernet encrypt/decrypt for `config_json_encrypted`) |
| Modify header redaction | `redaction.py` (strips sensitive headers before storage) |

## Domain Models

```
IngestEndpoint → has many Messages
Channel        → encrypted config (Fernet), type: bark|ntfy|mqtt
ForwardingRule → belongs to Channel, has filter_json + payload_template_json
Message        → has many Deliveries (created when rules match)
Delivery       → status: queued → sending → sent|retry|failed
```

## Notification Providers

| Provider | File | Transport | SSRF Check |
|----------|------|-----------|------------|
| Bark | `bark.py` | HTTP POST `/push` (with legacy GET fallback) | `assert_ssrf_safe()` |
| ntfy | `ntfy.py` | HTTP POST to topic URL | `assert_ssrf_safe()` |
| MQTT | `mqtt.py` | TCP via paho-mqtt | `assert_host_ssrf_safe()` |

## Delivery Worker

`management/commands/deliveries_worker.py` — polling loop:
1. `SELECT FOR UPDATE SKIP LOCKED` on due deliveries (batch of 50)
2. Mark `sending`, dispatch via provider
3. On success → `sent`. On failure → `retry` with exponential backoff or `failed` after max attempts
4. Sleep 1s, repeat

Settings: `DELIVERY_MAX_ATTEMPTS` (10), `DELIVERY_BACKOFF_BASE_SECONDS` (5), `DELIVERY_BACKOFF_MAX_SECONDS` (1800)

## Template System

`template.py` — Mustache-style `{{path.to.var}}` substitution. Context built from message + ingest endpoint fields. Supports nested dict/list traversal.

## Conventions

- All models use UUID v4 PKs
- Soft-delete: `deleted_at` (Message, IngestEndpoint), `revoked_at` (IngestEndpoint), `disabled_at` (Channel)
- JSON fields suffixed `_json`: `tags_json`, `filter_json`, `headers_json`, `query_json`, `extras_json`, `payload_template_json`, `provider_response_json`
- Channel config accessed via `channel.config` property (auto encrypt/decrypt)
