import json
import logging

from shared.logging import JsonFormatter


def test_json_formatter_redacts_sensitive_fields():
    record = logging.LogRecord(
        "test",
        logging.INFO,
        __file__,
        1,
        "request_completed",
        (),
        None,
    )
    record.api_key = "do-not-log"
    record.event_id = "event-1"

    payload = json.loads(JsonFormatter().format(record))

    assert payload["api_key"] == "[REDACTED]"
    assert payload["event_id"] == "event-1"