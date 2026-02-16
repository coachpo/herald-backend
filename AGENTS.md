# backend/AGENTS.md

## Project Overview

Django 5 + Django REST Framework backend.

- JSON API is served under `/api/...`
- Health check: `GET /healthz`
- Background worker: `python manage.py deliveries_worker`

Channel configs are stored encrypted in the DB (`Channel.config_json_encrypted`).

## Build And Test Commands

Run these from `backend/`.

- Run migrations:
  - `python manage.py migrate --noinput`
- Run backend unit tests:
  - `python manage.py test`

## Local Dev

- Start API server:
  - `python manage.py runserver 0.0.0.0:8000`
- Start delivery worker:
  - `python manage.py deliveries_worker`

## Smoke / Integration

- Optional live channel smoke (requires real provider credentials):
  - `python manage.py smoke_channels --live --bark-url <...> --mqtt-host <...> --mqtt-username <...> --mqtt-password <...>`

## Security Considerations

- Keep SSRF checks in `beacon/ssrf.py` enabled.
- Do not log secrets (device keys, access tokens, passwords).
