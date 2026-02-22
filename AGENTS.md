# backend/AGENTS.md

## Overview

Django 5.2 + DRF backend. JSON API under `/api/`, health check at `/health`, background delivery worker via management command.

## Structure

```
backend/
├── herald/     # Django project config (settings, urls, middleware, wsgi/asgi)
├── accounts/         # Custom User model (email-only), JWT auth, refresh tokens, email verification
├── core/           # Domain models + business logic (see core/AGENTS.md)
├── api/              # REST API views, serializers, ingest handler (see api/AGENTS.md)
└── manage.py
```

## Commands

```bash
python manage.py migrate --noinput
python manage.py test                    # all unit tests
python manage.py runserver 0.0.0.0:8000  # dev API server
python manage.py deliveries_worker       # background delivery loop
python manage.py smoke_channels --live   # optional live channel smoke test
```

## Where to Look

| Task | Location |
|------|----------|
| Add API endpoint | `api/urls.py` + `api/views_resources.py` or new view file |
| Add auth endpoint | `api/urls.py` + `api/views_auth.py` |
| Modify domain models | `core/models.py` → `makemigrations` |
| Add notification provider | `core/{provider}.py` + wire in `deliveries_worker.py` |
| Change CORS behavior | `herald/middleware.py` (custom, not django-cors-headers) |
| Modify JWT auth | `accounts/jwt.py` (custom, not simplejwt) |
| Change settings/env | `herald/settings.py` (custom .env loader, no python-dotenv; SQLite default, no Postgres driver) |

## Conventions

- All models use UUID v4 primary keys
- Soft-delete via nullable `deleted_at`/`revoked_at`/`disabled_at` timestamps
- Channel configs encrypted with Fernet in `config_json_encrypted` field
- JSON fields suffixed `_json` (e.g., `tags_json`, `filter_json`, `headers_json`)
- Custom URL converter `uuidhex` for dashless UUID ingest URLs
- No Celery/RQ — worker is a polling management command with exponential backoff
- No external auth library — custom JWT implementation in `accounts/jwt.py`
- Refresh token rotation with `family_id` tracking for replay detection

## Security (Do Not)

- Keep SSRF checks in `core/ssrf.py` enabled — blocks loopback, link-local, private IPs
- Do not log secrets (device keys, access tokens, passwords)
- Do not bypass `CHANNEL_CONFIG_ENCRYPTION_KEY` — channel configs must be encrypted at rest
- Sensitive headers are redacted before storage (see `core/redaction.py`)

## Testing

- `python manage.py test` runs all tests
- Test files: `api/tests.py`, `api/test_*.py`, `core/tests.py`, `core/test_*.py`, `accounts/tests.py`
- Tests use Django's built-in test runner (no pytest)
- Smoke tests require live credentials: `python manage.py smoke_channels --live`
