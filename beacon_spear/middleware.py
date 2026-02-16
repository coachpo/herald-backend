from __future__ import annotations

from django.conf import settings
from django.http import HttpResponse


class CorsMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        origin = request.headers.get("Origin")
        allowed = set(getattr(settings, "CORS_ALLOWED_ORIGINS", []) or [])

        if origin and origin in allowed:
            if request.method == "OPTIONS" and request.headers.get(
                "Access-Control-Request-Method"
            ):
                res = HttpResponse(status=204)
            else:
                res = self.get_response(request)

            res["Access-Control-Allow-Origin"] = origin
            res["Access-Control-Allow-Methods"] = (
                "GET, POST, PUT, PATCH, DELETE, OPTIONS"
            )

            requested_headers = request.headers.get("Access-Control-Request-Headers")
            if requested_headers:
                res["Access-Control-Allow-Headers"] = requested_headers
            else:
                res["Access-Control-Allow-Headers"] = (
                    "Authorization, Content-Type, Accept, X-Beacon-Ingest-Key"
                )

            res["Access-Control-Max-Age"] = "600"

            vary = res.get("Vary")
            if vary:
                if "Origin" not in {v.strip() for v in vary.split(",")}:
                    res["Vary"] = f"{vary}, Origin"
            else:
                res["Vary"] = "Origin"

            return res

        return self.get_response(request)
