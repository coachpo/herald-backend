FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./requirements.txt
RUN python -m pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

ENV DJANGO_SETTINGS_MODULE=beacon_spear.settings

CMD ["sh", "-c", "python manage.py migrate --noinput && gunicorn beacon_spear.wsgi:application --bind 0.0.0.0:8000 --workers ${WEB_CONCURRENCY:-2} --access-logfile - --error-logfile -"]
