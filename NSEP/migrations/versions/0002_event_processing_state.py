"""Track event processing state for end-to-end response verification."""

from alembic import op
import sqlalchemy as sa


revision = "0002_event_processing_state"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "normalized_events",
        sa.Column("processing_status", sa.String(length=32), nullable=False, server_default="accepted"),
    )
    op.add_column("normalized_events", sa.Column("published_at", sa.DateTime(timezone=True)))
    op.add_column("normalized_events", sa.Column("processed_at", sa.DateTime(timezone=True)))
    op.add_column("normalized_events", sa.Column("failure_reason", sa.String(length=256)))
    op.add_column(
        "normalized_events",
        sa.Column("retry_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_check_constraint(
        "ck_normalized_events_processing_status",
        "normalized_events",
        "processing_status IN ('accepted', 'published', 'processing', 'processed', 'failed')",
    )
    op.create_index("ix_normalized_events_processing_status", "normalized_events", ["processing_status"])


def downgrade() -> None:
    op.drop_index("ix_normalized_events_processing_status", table_name="normalized_events")
    op.drop_constraint("ck_normalized_events_processing_status", "normalized_events", type_="check")
    op.drop_column("normalized_events", "retry_count")
    op.drop_column("normalized_events", "failure_reason")
    op.drop_column("normalized_events", "processed_at")
    op.drop_column("normalized_events", "published_at")
    op.drop_column("normalized_events", "processing_status")