from django.core.cache import cache


def allow_rate(*, key: str, limit: int, window_seconds: int) -> bool:
    current = cache.get(key)
    if current is None:
        cache.set(key, 1, timeout=window_seconds)
        return True
    if int(current) >= limit:
        return False
    cache.set(key, int(current) + 1, timeout=window_seconds)
    return True
