# backend/api/AGENTS.md

## Overview

REST API layer — views, serializers, URL routing, ingest handler. All endpoints under `/api/`.

## Where to Look

| Task | Location |
|------|----------|
| Add resource endpoint | `urls.py` + `views_resources.py` |
| Add auth endpoint | `urls.py` + `views_auth.py` |
| Modify ingest handler | `ingest.py` (standalone, not DRF — uses raw Django views) |
| Add/modify serializer | `serializers.py` |
| Change error format | `errors.py` (`api_error()` returns `{code, message, details?}`) |
| Edge config export | `views_edge.py` |
| Rate limiting | `ratelimit.py` (Django cache-based, key + limit + window) |
| Permissions | `permissions.py` (`VerifiedEmailForUnsafeMethods`) |

## API Routes

```
auth/signup, login, refresh, logout, me, verify-email, resend-verification
auth/forgot-password, reset-password, change-email, change-password, delete-account
ingest/<uuid|uuidhex:endpoint_id>     # standalone Django view, not DRF
ingest-endpoints, ingest-endpoints/<uuid>/revoke, ingest-endpoints/<uuid>
messages, messages/batch-delete, messages/<uuid>, messages/<uuid>/deliveries
channels, channels/<uuid>, channels/<uuid>/test
rules, rules/test, rules/<uuid>, rules/<uuid>/test
edge-config
```

## Conventions

- Error responses: `api_error(code=..., message=..., status=..., details=...)` — consistent `{code, message}` shape
- Ingest endpoint is a raw Django view (`@csrf_exempt`), not a DRF APIView — no JWT auth, uses ingest token via `X-Herald-Ingest-Key` header
- Resource views use DRF `APIView` (not ViewSets or routers)
- Custom URL converter `uuidhex` registered for dashless UUID ingest URLs
- `VerifiedEmailForUnsafeMethods` permission on resource views — reads allowed for unverified users
- Type casts (`_ChannelModel = cast(Any, Channel)`) used to work around Django ORM type stubs

## Testing

- `tests.py` — main integration tests (auth + resources)
- `test_*.py` — focused test modules (bark config, channel test, MQTT, delete account, ingest endpoints)
- All tests use Django's `TestCase` with `self.client`
