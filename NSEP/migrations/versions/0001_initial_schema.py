"""Create the security event pipeline schema."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "normalized_events",
        sa.Column("event_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("source", sa.String(length=128), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column(
            "metadata",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    op.create_index("ix_normalized_events_occurred_at", "normalized_events", ["occurred_at"])
    op.create_index("ix_normalized_events_source_type", "normalized_events", ["source", "event_type"])

    op.create_table(
        "incidents",
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "event_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("normalized_events.event_id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="open"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('open', 'investigating', 'resolved')",
            name="ck_incidents_status",
        ),
        sa.CheckConstraint(
            "status <> 'resolved' OR resolved_at IS NOT NULL",
            name="ck_incidents_resolved_at",
        ),
    )
    op.create_index("ix_incidents_status_updated_at", "incidents", ["status", "updated_at"])

    op.create_table(
        "detections",
        sa.Column("detection_id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column(
            "incident_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("incidents.incident_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "event_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("normalized_events.event_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("rule", sa.String(length=128), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("details", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "severity IN ('low', 'medium', 'high', 'critical')",
            name="ck_detections_severity",
        ),
        sa.UniqueConstraint("incident_id", "rule", name="uq_detections_incident_rule"),
    )
    op.create_index("ix_detections_event_id", "detections", ["event_id"])

    op.create_table(
        "risk_scores",
        sa.Column("risk_score_id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column(
            "incident_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("incidents.incident_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("score", sa.SmallInteger(), nullable=False),
        sa.Column("calculated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("score BETWEEN 0 AND 100", name="ck_risk_scores_score_range"),
    )
    op.create_index("ix_risk_scores_incident_calculated", "risk_scores", ["incident_id", "calculated_at"])

    op.create_table(
        "incident_lifecycle",
        sa.Column("lifecycle_id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column(
            "incident_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("incidents.incident_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("details", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.CheckConstraint(
            "status IN ('open', 'investigating', 'resolved')",
            name="ck_incident_lifecycle_status",
        ),
    )
    op.create_index(
        "ix_incident_lifecycle_incident_changed",
        "incident_lifecycle",
        ["incident_id", "changed_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_incident_lifecycle_incident_changed", table_name="incident_lifecycle")
    op.drop_table("incident_lifecycle")
    op.drop_index("ix_risk_scores_incident_calculated", table_name="risk_scores")
    op.drop_table("risk_scores")
    op.drop_index("ix_detections_event_id", table_name="detections")
    op.drop_table("detections")
    op.drop_index("ix_incidents_status_updated_at", table_name="incidents")
    op.drop_table("incidents")
    op.drop_index("ix_normalized_events_source_type", table_name="normalized_events")
    op.drop_index("ix_normalized_events_occurred_at", table_name="normalized_events")
    op.drop_table("normalized_events")