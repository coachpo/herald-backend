import uuid


class UUIDHexConverter:
    regex = r"[0-9a-fA-F]{32}"

    def to_python(self, value: str) -> uuid.UUID:
        return uuid.UUID(hex=value)

    def to_url(self, value: uuid.UUID) -> str:
        return value.hex
