from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb


def record_event_accepted(database_url: str, event: dict[str, Any]) -> None:
    with psycopg.connect(database_url, connect_timeout=2) as connection:
        connection.execute(
            """
            INSERT INTO normalized_events
                (event_id, source, event_type, occurred_at, accepted_at, payload, metadata)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (event_id) DO NOTHING
            """,
            (
                UUID(str(event["event_id"])),
                event["source"],
                event["event_type"],
                event["occurred_at"],
                event["accepted_at"],
                Jsonb(event["payload"]),
                Jsonb(event.get("metadata", {})),
            ),
        )


def update_event_status(
    database_url: str,
    event_id: str | UUID,
    status: str,
    *,
    failure_reason: str | None = None,
    retry_count: int | None = None,
) -> None:
    fields = ["processing_status = %s"]
    values: list[Any] = [status]
    if status == "published":
        fields.append("published_at = now()")
    if status == "processed":
        fields.append("processed_at = now()")
    if failure_reason is not None:
        fields.append("failure_reason = %s")
        values.append(failure_reason[:256])
    if retry_count is not None:
        fields.append("retry_count = %s")
        values.append(retry_count)
    values.append(UUID(str(event_id)))
    with psycopg.connect(database_url, connect_timeout=2) as connection:
        connection.execute(
            f"UPDATE normalized_events SET {', '.join(fields)} WHERE event_id = %s",
            values,
        )


def get_event_status(database_url: str, event_id: UUID) -> dict[str, Any] | None:
    with psycopg.connect(database_url, row_factory=dict_row, connect_timeout=2) as connection:
        row = connection.execute(
            """
            SELECT event_id, processing_status, accepted_at, published_at,
                   processed_at, retry_count, failure_reason
            FROM normalized_events
            WHERE event_id = %s
            """,
            (event_id,),
        ).fetchone()
    if row is None:
        return None
    return {
        "event_id": row["event_id"],
        "status": row["processing_status"],
        "accepted_at": row["accepted_at"],
        "published_at": row["published_at"],
        "processed_at": row["processed_at"],
        "retry_count": row["retry_count"],
        "failure_reason": row["failure_reason"],
    }


def persist_event_result(database_url: str, event: dict[str, Any], incident: dict[str, Any] | None) -> None:
    with psycopg.connect(database_url) as connection:
        connection.execute(
            """
            INSERT INTO normalized_events
                (event_id, source, event_type, occurred_at, accepted_at, payload, metadata)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (event_id) DO NOTHING
            """,
            (
                UUID(str(event["event_id"])),
                event["source"],
                event["event_type"],
                event["occurred_at"],
                event["accepted_at"],
                Jsonb(event["payload"]),
                Jsonb(event.get("metadata", {})),
            ),
        )
        connection.execute(
            "UPDATE normalized_events SET processing_status = 'processed', processed_at = now() WHERE event_id = %s",
            (UUID(str(event["event_id"])),),
        )

        if incident is None:
            return

        existing = connection.execute(
            "SELECT incident_id FROM incidents WHERE event_id = %s",
            (UUID(str(event["event_id"])),),
        ).fetchone()
        incident_row = connection.execute(
            """
            INSERT INTO incidents (incident_id, event_id, status)
            VALUES (%s, %s, %s)
            ON CONFLICT (event_id) DO UPDATE SET updated_at = now()
            RETURNING incident_id
            """,
            (
                UUID(str(incident["incident_id"])),
                UUID(str(event["event_id"])),
                incident["status"],
            ),
        ).fetchone()
        incident_id = incident_row[0]

        connection.execute("DELETE FROM detections WHERE incident_id = %s", (incident_id,))
        for detection in incident["detections"]:
            connection.execute(
                """
                INSERT INTO detections (incident_id, event_id, rule, severity, details)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    incident_id,
                    UUID(str(event["event_id"])),
                    detection["rule"],
                    detection["severity"],
                    Jsonb(detection),
                ),
            )

        connection.execute("DELETE FROM risk_scores WHERE incident_id = %s", (incident_id,))
        connection.execute(
            "INSERT INTO risk_scores (incident_id, score) VALUES (%s, %s)",
            (incident_id, incident["risk"]),
        )
        if existing is None:
            connection.execute(
                "INSERT INTO incident_lifecycle (incident_id, status) VALUES (%s, %s)",
                (incident_id, incident["status"]),
            )


def get_incident(database_url: str, incident_id: UUID) -> dict[str, Any] | None:
    with psycopg.connect(database_url, row_factory=dict_row) as connection:
        incident = connection.execute(
            """
            SELECT i.incident_id, i.status, i.created_at, i.updated_at, i.resolved_at,
                   r.score AS risk
            FROM incidents AS i
            LEFT JOIN LATERAL (
                SELECT score FROM risk_scores
                WHERE incident_id = i.incident_id
                ORDER BY calculated_at DESC LIMIT 1
            ) AS r ON true
            WHERE i.incident_id = %s
            """,
            (incident_id,),
        ).fetchone()
        if incident is None:
            return None

        detections = connection.execute(
            "SELECT rule, severity, details FROM detections WHERE incident_id = %s ORDER BY detection_id",
            (incident_id,),
        ).fetchall()
    timestamps = {"created_at": incident["created_at"], "updated_at": incident["updated_at"]}
    if incident["resolved_at"] is not None:
        timestamps["resolved_at"] = incident["resolved_at"]
    return {
        "incident_id": incident["incident_id"],
        "status": incident["status"],
        "risk": incident["risk"] or 0,
        "detections": [
            {"rule": row["rule"], "severity": row["severity"], **row["details"]}
            for row in detections
        ],
        "timestamps": timestamps,
    }


def dashboard_summary(database_url: str) -> dict[str, Any]:
    hour = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
    first_hour = hour - timedelta(hours=23)
    with psycopg.connect(database_url, row_factory=dict_row, connect_timeout=2) as connection:
        total_events = connection.execute("SELECT count(*) AS count FROM normalized_events").fetchone()["count"]
        active_incidents = connection.execute(
            "SELECT count(*) AS count FROM incidents WHERE status IN ('open', 'investigating')"
        ).fetchone()["count"]
        active_threats = connection.execute(
            """
            SELECT count(*) AS count
            FROM detections AS d
            JOIN incidents AS i ON i.incident_id = d.incident_id
            WHERE i.status IN ('open', 'investigating')
            """
        ).fetchone()["count"]
        test_data = connection.execute(
            """
            SELECT count(DISTINCT e.event_id) AS test_event_count,
                   count(DISTINCT i.incident_id) FILTER (
                       WHERE i.status IN ('open', 'investigating')
                   ) AS test_active_incidents,
                   count(DISTINCT d.detection_id) FILTER (
                       WHERE i.status IN ('open', 'investigating')
                   ) AS test_active_detections
            FROM normalized_events AS e
            LEFT JOIN incidents AS i ON i.event_id = e.event_id
            LEFT JOIN detections AS d ON d.event_id = e.event_id
            WHERE e.metadata->>'purpose' = 'integration-verification'
            """
        ).fetchone()
        buckets = connection.execute(
            """
            SELECT date_trunc('hour', occurred_at) AS timestamp, count(*) AS count
            FROM normalized_events
            WHERE occurred_at >= %s AND occurred_at < %s
            GROUP BY date_trunc('hour', occurred_at)
            """,
            (first_hour, hour + timedelta(hours=1)),
        ).fetchall()
        detections_by_rule = connection.execute(
            """
            SELECT d.rule, d.severity, count(*) AS count
            FROM detections AS d
            JOIN incidents AS i ON i.incident_id = d.incident_id
            WHERE i.status IN ('open', 'investigating')
            GROUP BY d.rule, d.severity
            ORDER BY count(*) DESC, d.rule
            """
        ).fetchall()
    counts = {row["timestamp"].replace(tzinfo=UTC) if row["timestamp"].tzinfo is None else row["timestamp"].astimezone(UTC): row["count"] for row in buckets}
    return {
        "total_events": total_events,
        "active_threats": active_threats,
        "active_incidents": active_incidents,
        "test_event_count": test_data["test_event_count"],
        "test_active_incidents": test_data["test_active_incidents"],
        "test_active_detections": test_data["test_active_detections"],
        "event_activity": [
            {"timestamp": first_hour + timedelta(hours=index), "count": counts.get(first_hour + timedelta(hours=index), 0)}
            for index in range(24)
        ],
        "active_detections_by_rule": detections_by_rule,
    }


def list_events(
    database_url: str,
    *,
    limit: int,
    offset: int,
    query: str | None = None,
    source: str | None = None,
    event_type: str | None = None,
    status: str | None = None,
    severity: str | None = None,
    sort_by: str = "occurred_at",
    sort_order: str = "desc",
) -> dict[str, Any]:
    conditions: list[str] = []
    values: list[Any] = []
    if query:
        conditions.append("(e.event_id::text ILIKE %s OR e.source ILIKE %s OR e.event_type ILIKE %s OR e.payload::text ILIKE %s OR e.metadata::text ILIKE %s)")
        pattern = f"%{query}%"
        values.extend([pattern] * 5)
    if source:
        conditions.append("e.source ILIKE %s")
        values.append(f"%{source}%")
    if event_type:
        conditions.append("e.event_type ILIKE %s")
        values.append(f"%{event_type}%")
    if status:
        conditions.append("e.processing_status = %s")
        values.append(status)
    if severity:
        conditions.append("EXISTS (SELECT 1 FROM detections AS sd WHERE sd.event_id = e.event_id AND lower(sd.severity) = lower(%s))")
        values.append(severity)
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    sort_columns = {
        "occurred_at": "e.occurred_at",
        "accepted_at": "e.accepted_at",
        "source": "e.source",
        "event_type": "e.event_type",
        "status": "e.processing_status",
    }
    order_column = sort_columns.get(sort_by, "e.occurred_at")
    order_direction = "ASC" if sort_order.lower() == "asc" else "DESC"
    with psycopg.connect(database_url, row_factory=dict_row, connect_timeout=2) as connection:
        total = connection.execute(f"SELECT count(*) AS count FROM normalized_events AS e {where}", values).fetchone()["count"]
        rows = connection.execute(
            f"""
            SELECT e.event_id, e.source, e.event_type, e.occurred_at, e.accepted_at,
                   e.published_at, e.processed_at, e.processing_status AS status,
                   e.retry_count, e.failure_reason, e.payload, e.metadata,
                   d.severity, d.incident_id, COALESCE(d.detections, '[]'::jsonb) AS detections
            FROM normalized_events AS e
            LEFT JOIN LATERAL (
                SELECT i.incident_id,
                       (SELECT severity FROM detections WHERE incident_id = i.incident_id
                        ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END DESC
                        LIMIT 1) AS severity,
                       (SELECT jsonb_agg(jsonb_build_object('rule', rule, 'severity', severity) ORDER BY detection_id)
                        FROM detections WHERE incident_id = i.incident_id) AS detections
                FROM incidents AS i WHERE i.event_id = e.event_id LIMIT 1
            ) AS d ON true
            {where}
            ORDER BY {order_column} {order_direction}, e.event_id
            LIMIT %s OFFSET %s
            """,
            [*values, limit, offset],
        ).fetchall()
    return {"items": rows, "total": total, "limit": limit, "offset": offset}


def list_incidents(
    database_url: str,
    *,
    limit: int,
    offset: int,
    query: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    conditions: list[str] = []
    values: list[Any] = []
    if query:
        conditions.append(
            "(i.incident_id::text ILIKE %s OR e.event_id::text ILIKE %s OR e.source ILIKE %s OR e.event_type ILIKE %s "
            "OR EXISTS (SELECT 1 FROM detections AS sd WHERE sd.incident_id = i.incident_id AND sd.rule ILIKE %s))"
        )
        pattern = f"%{query}%"
        values.extend([pattern] * 5)
    if status:
        conditions.append("i.status = %s")
        values.append(status)
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    with psycopg.connect(database_url, row_factory=dict_row, connect_timeout=2) as connection:
        total = connection.execute(
            f"SELECT count(*) AS count FROM incidents AS i JOIN normalized_events AS e ON e.event_id = i.event_id {where}",
            values,
        ).fetchone()["count"]
        rows = connection.execute(
            f"""
            SELECT i.incident_id, i.status, i.created_at, i.updated_at, i.resolved_at,
                   e.event_id, e.source AS event_source, e.event_type,
                   COALESCE(r.score, 0) AS risk,
                   COALESCE(d.detection_count, 0) AS detection_count,
                   d.highest_severity, COALESCE(d.detections, '[]'::jsonb) AS detections
            FROM incidents AS i
            JOIN normalized_events AS e ON e.event_id = i.event_id
            LEFT JOIN LATERAL (
                SELECT score FROM risk_scores WHERE incident_id = i.incident_id
                ORDER BY calculated_at DESC LIMIT 1
            ) AS r ON true
            LEFT JOIN LATERAL (
                SELECT count(*) AS detection_count,
                       (array_agg(severity ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END DESC))[1] AS highest_severity,
                       jsonb_agg(jsonb_build_object('rule', rule, 'severity', severity) ORDER BY detection_id) AS detections
                FROM detections WHERE incident_id = i.incident_id
            ) AS d ON true
            {where}
            ORDER BY CASE i.status WHEN 'open' THEN 0 WHEN 'investigating' THEN 1 ELSE 2 END,
                     i.updated_at DESC, i.incident_id
            LIMIT %s OFFSET %s
            """,
            [*values, limit, offset],
        ).fetchall()
    return {"items": rows, "total": total, "limit": limit, "offset": offset}


def list_detections(
    database_url: str,
    *,
    limit: int,
    offset: int,
    query: str | None = None,
    severity: str | None = None,
    rule: str | None = None,
) -> dict[str, Any]:
    conditions: list[str] = []
    values: list[Any] = []
    if query:
        conditions.append("(d.rule ILIKE %s OR d.event_id::text ILIKE %s OR d.incident_id::text ILIKE %s OR e.source ILIKE %s OR e.event_type ILIKE %s OR d.details::text ILIKE %s)")
        pattern = f"%{query}%"
        values.extend([pattern] * 6)
    if severity:
        conditions.append("lower(d.severity) = lower(%s)")
        values.append(severity)
    if rule:
        conditions.append("d.rule ILIKE %s")
        values.append(f"%{rule}%")
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    joins = "JOIN normalized_events AS e ON e.event_id = d.event_id JOIN incidents AS i ON i.incident_id = d.incident_id"
    with psycopg.connect(database_url, row_factory=dict_row, connect_timeout=2) as connection:
        total = connection.execute(f"SELECT count(*) AS count FROM detections AS d {joins} {where}", values).fetchone()["count"]
        rows = connection.execute(
            f"""
            SELECT d.detection_id, d.incident_id, d.event_id, d.rule, d.severity,
                   d.detected_at, d.details, e.source, e.event_type, e.occurred_at,
                   i.status AS incident_status, COALESCE(r.score, 0) AS risk
            FROM detections AS d
            {joins}
            LEFT JOIN LATERAL (
                SELECT score FROM risk_scores WHERE incident_id = i.incident_id
                ORDER BY calculated_at DESC LIMIT 1
            ) AS r ON true
            {where}
            ORDER BY d.detected_at DESC, d.detection_id DESC
            LIMIT %s OFFSET %s
            """,
            [*values, limit, offset],
        ).fetchall()
    return {"items": rows, "total": total, "limit": limit, "offset": offset}


def get_incident_timeline(database_url: str, incident_id: UUID) -> list[dict[str, Any]]:
    with psycopg.connect(database_url, row_factory=dict_row, connect_timeout=2) as connection:
        rows = connection.execute(
            """
            SELECT accepted_at AS timestamp, 'event_accepted' AS kind, 'Event accepted' AS summary,
                   jsonb_build_object('event_id', event_id, 'source', source, 'event_type', event_type) AS details
            FROM normalized_events WHERE event_id = (SELECT event_id FROM incidents WHERE incident_id = %s)
            UNION ALL
            SELECT published_at, 'event_published', 'Event published', jsonb_build_object('event_id', event_id)
            FROM normalized_events WHERE event_id = (SELECT event_id FROM incidents WHERE incident_id = %s) AND published_at IS NOT NULL
            UNION ALL
            SELECT processed_at, 'event_processed', 'Event processed', jsonb_build_object('event_id', event_id)
            FROM normalized_events WHERE event_id = (SELECT event_id FROM incidents WHERE incident_id = %s) AND processed_at IS NOT NULL
            UNION ALL
            SELECT changed_at, 'incident_status', 'Incident status: ' || status, details
            FROM incident_lifecycle WHERE incident_id = %s
            UNION ALL
            SELECT detected_at, 'detection', 'Detection: ' || rule, jsonb_build_object('severity', severity, 'details', details)
            FROM detections WHERE incident_id = %s
            ORDER BY timestamp
            """,
            (incident_id, incident_id, incident_id, incident_id, incident_id),
        ).fetchall()
    return rows


def get_incident_graph(database_url: str, incident_id: UUID) -> dict[str, Any] | None:
    with psycopg.connect(database_url, row_factory=dict_row, connect_timeout=2) as connection:
        incident = connection.execute(
            """
            SELECT i.incident_id, i.status, e.event_id, e.source, e.event_type, e.occurred_at
            FROM incidents AS i JOIN normalized_events AS e ON e.event_id = i.event_id
            WHERE i.incident_id = %s
            """,
            (incident_id,),
        ).fetchone()
        if incident is None:
            return None
        detections = connection.execute(
            "SELECT detection_id, rule, severity FROM detections WHERE incident_id = %s ORDER BY detection_id",
            (incident_id,),
        ).fetchall()
    event_node = f"event:{incident['event_id']}"
    incident_node = f"incident:{incident['incident_id']}"
    nodes = [
        {
            "id": event_node,
            "kind": "event",
            "label": f"{incident['source']} · {incident['event_type']}",
            "details": {"event_id": incident["event_id"], "occurred_at": incident["occurred_at"]},
        },
        {
            "id": incident_node,
            "kind": "incident",
            "label": f"Incident · {incident['status']}",
            "details": {"incident_id": incident["incident_id"], "status": incident["status"]},
        },
    ]
    edges = [{"source": event_node, "target": incident_node, "relation": "raised_incident"}]
    for detection in detections:
        detection_node = f"detection:{detection['detection_id']}"
        nodes.append(
            {
                "id": detection_node,
                "kind": "detection",
                "label": f"{detection['rule']} · {detection['severity']}",
                "details": {"detection_id": detection["detection_id"], "rule": detection["rule"], "severity": detection["severity"]},
            }
        )
        edges.append({"source": event_node, "target": detection_node, "relation": "triggered_detection"})
    return {"nodes": nodes, "edges": edges}