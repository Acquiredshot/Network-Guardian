from unittest.mock import MagicMock
from uuid import uuid4

from shared import database


def test_late_publish_preserves_worker_processing_state(monkeypatch):
    connect = MagicMock()
    monkeypatch.setattr(database.psycopg, "connect", connect)
    event_id = uuid4()

    database.update_event_status("unused-test-url", event_id, "published")

    sql, values = connect.return_value.__enter__.return_value.execute.call_args.args
    assert "CASE WHEN processing_status = 'accepted' THEN %s ELSE processing_status END" in sql
    assert "published_at = now()" in sql
    assert values == ["published", event_id]


def test_worker_status_updates_are_unchanged(monkeypatch):
    connect = MagicMock()
    monkeypatch.setattr(database.psycopg, "connect", connect)
    event_id = uuid4()

    database.update_event_status("unused-test-url", event_id, "processing", retry_count=1)

    sql, values = connect.return_value.__enter__.return_value.execute.call_args.args
    assert "processing_status = %s" in sql
    assert "CASE" not in sql
    assert values == ["processing", 1, event_id]
