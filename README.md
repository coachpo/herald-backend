# Beacon Spear Backend (Django)

Implements the v0.1 backend JSON API + ingest endpoint + delivery worker.

## Local dev

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python manage.py migrate
python manage.py runserver 0.0.0.0:8000
```

Run the worker in a second terminal:

```bash
. .venv/bin/activate
python manage.py deliveries_worker
```

## Notes

- APIs are served under `/api/*`.
- Ingest endpoint: `POST /api/ingest/{token}`.
- Dashboard auth uses JWT access tokens (`Authorization: Bearer ...`) and a refresh token returned in JSON (rotated on refresh).
