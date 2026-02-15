from rest_framework.response import Response


def api_error(
    *, code: str, message: str, status: int, details: dict | None = None
) -> Response:
    body: dict = {"code": code, "message": message}
    if details is not None:
        body["details"] = details
    return Response(body, status=status)
