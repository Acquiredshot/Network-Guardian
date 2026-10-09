import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

_RESERVED_FIELDS = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__)
_SENSITIVE_NAMES = {"api_key", "authorization", "password", "secret", "token"}


def _safe_value(name: str, value: Any) -> Any:
    if any(part in name.lower() for part in _SENSITIVE_NAMES):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {key: _safe_value(str(key), item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_safe_value(name, item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        fields = {
            key: _safe_value(key, value)
            for key, value in record.__dict__.items()
            if key not in _RESERVED_FIELDS and not key.startswith("_")
        }
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            **fields,
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, separators=(",", ":"), default=str)


def configure_logging(service: str, level: int = logging.INFO) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    logging.getLogger("security_event_pipeline").setLevel(level)
    logging.getLogger("security_event_pipeline").info(
        "logging_configured",
        extra={"service": service},
    )