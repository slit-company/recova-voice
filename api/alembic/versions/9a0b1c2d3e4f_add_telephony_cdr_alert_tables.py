"""add telephony cdr alert tables

Revision ID: 9a0b1c2d3e4f
Revises: d6a7b8c9e0f1
Create Date: 2026-07-09 03:30:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "9a0b1c2d3e4f"
down_revision: Union[str, None] = "d6a7b8c9e0f1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _shared_identity_columns() -> list[sa.Column]:
    return [
        sa.Column("call_attempt_id", sa.String(length=128), nullable=False),
        sa.Column("idempotency_key", sa.String(length=255), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=True),
        sa.Column("telephony_configuration_id", sa.Integer(), nullable=True),
        sa.Column("telephony_phone_number_id", sa.Integer(), nullable=True),
        sa.Column("inventory_id", sa.Integer(), nullable=True),
        sa.Column("workflow_id", sa.Integer(), nullable=True),
        sa.Column("workflow_run_id", sa.Integer(), nullable=True),
        sa.Column("campaign_id", sa.Integer(), nullable=True),
        sa.Column("queued_run_id", sa.Integer(), nullable=True),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("provider_call_id_hash", sa.String(length=64), nullable=True),
        sa.Column("direction", sa.String(length=16), nullable=False),
        sa.Column("failure_category", sa.String(length=64), nullable=True),
        sa.Column("release_reason", sa.String(length=64), nullable=True),
        sa.Column("admission_slot_id", sa.String(length=128), nullable=True),
        sa.Column("from_number_masked", sa.String(length=64), nullable=True),
        sa.Column("from_number_hash", sa.String(length=64), nullable=True),
        sa.Column("to_number_masked", sa.String(length=64), nullable=True),
        sa.Column("to_number_hash", sa.String(length=64), nullable=True),
        sa.Column("duration_seconds", sa.Integer(), nullable=True),
        sa.Column(
            "artifact_recording_expected",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column(
            "artifact_recording_present",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column(
            "artifact_transcript_expected",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column(
            "artifact_transcript_present",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column(
            "artifact_payload",
            sa.JSON(),
            server_default=sa.text("'{}'::json"),
            nullable=False,
        ),
        sa.Column(
            "provider_payload_redacted",
            sa.JSON(),
            server_default=sa.text("'{}'::json"),
            nullable=False,
        ),
        sa.Column("contract_version", sa.String(length=64), nullable=True),
        sa.Column(
            "is_contract_fixture",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column(
            "live_trunk_validated",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column("schema_version", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    ]


def _identity_foreign_keys() -> list[sa.ForeignKeyConstraint]:
    return [
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["telephony_configuration_id"],
            ["telephony_configurations.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["telephony_phone_number_id"],
            ["telephony_phone_numbers.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(["workflow_id"], ["workflows.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["workflow_run_id"], ["workflow_runs.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["queued_run_id"], ["queued_runs.id"], ondelete="SET NULL"
        ),
    ]


def upgrade() -> None:
    op.create_table(
        "telephony_call_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("event_id", sa.String(length=128), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=True),
        *_shared_identity_columns(),
        *_identity_foreign_keys(),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "idempotency_key", name="uq_telephony_call_events_idempotency"
        ),
    )
    op.create_index(
        op.f("ix_telephony_call_events_id"), "telephony_call_events", ["id"], unique=False
    )
    op.create_index(
        "ix_telephony_call_events_attempt",
        "telephony_call_events",
        ["call_attempt_id"],
        unique=False,
    )
    op.create_index(
        "ix_telephony_call_events_org_created",
        "telephony_call_events",
        ["organization_id", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_telephony_call_events_workflow_run",
        "telephony_call_events",
        ["workflow_run_id"],
        unique=False,
    )
    op.create_index(
        "ix_telephony_call_events_provider_status",
        "telephony_call_events",
        ["provider", "status"],
        unique=False,
    )

    op.create_table(
        "telephony_cdrs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("terminal_status", sa.String(length=64), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("answered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        *_shared_identity_columns(),
        *_identity_foreign_keys(),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("call_attempt_id", name="uq_telephony_cdrs_attempt"),
        sa.UniqueConstraint("idempotency_key", name="uq_telephony_cdrs_idempotency"),
    )
    op.create_index(op.f("ix_telephony_cdrs_id"), "telephony_cdrs", ["id"], unique=False)
    op.create_index(
        "ix_telephony_cdrs_org_created",
        "telephony_cdrs",
        ["organization_id", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_telephony_cdrs_workflow_run",
        "telephony_cdrs",
        ["workflow_run_id"],
        unique=False,
    )
    op.create_index(
        "ix_telephony_cdrs_provider_status",
        "telephony_cdrs",
        ["provider", "terminal_status"],
        unique=False,
    )
    op.create_index(
        "ix_telephony_cdrs_live_readiness",
        "telephony_cdrs",
        ["organization_id", "created_at"],
        unique=False,
        postgresql_where=sa.text(
            "is_contract_fixture = false AND live_trunk_validated = true"
        ),
    )

    op.create_table(
        "telephony_ops_alerts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("alert_type", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("dedupe_key", sa.String(length=255), nullable=False),
        sa.Column("summary", sa.String(length=512), nullable=False),
        sa.Column(
            "details_redacted",
            sa.JSON(),
            server_default=sa.text("'{}'::json"),
            nullable=False,
        ),
        sa.Column("organization_id", sa.Integer(), nullable=True),
        sa.Column("provider", sa.String(length=64), nullable=True),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column(
            "is_contract_fixture",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column(
            "should_page_live_ops",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column(
            "occurrence_count", sa.Integer(), server_default=sa.text("1"), nullable=False
        ),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("escalated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("dedupe_key", name="uq_telephony_ops_alerts_dedupe"),
    )
    op.create_index(
        op.f("ix_telephony_ops_alerts_id"),
        "telephony_ops_alerts",
        ["id"],
        unique=False,
    )
    op.create_index(
        "ix_telephony_ops_alerts_type_status",
        "telephony_ops_alerts",
        ["alert_type", "status"],
        unique=False,
    )
    op.create_index(
        "ix_telephony_ops_alerts_org_seen",
        "telephony_ops_alerts",
        ["organization_id", "last_seen_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_telephony_ops_alerts_org_seen", table_name="telephony_ops_alerts")
    op.drop_index("ix_telephony_ops_alerts_type_status", table_name="telephony_ops_alerts")
    op.drop_index(op.f("ix_telephony_ops_alerts_id"), table_name="telephony_ops_alerts")
    op.drop_table("telephony_ops_alerts")

    op.drop_index("ix_telephony_cdrs_live_readiness", table_name="telephony_cdrs")
    op.drop_index("ix_telephony_cdrs_provider_status", table_name="telephony_cdrs")
    op.drop_index("ix_telephony_cdrs_workflow_run", table_name="telephony_cdrs")
    op.drop_index("ix_telephony_cdrs_org_created", table_name="telephony_cdrs")
    op.drop_index(op.f("ix_telephony_cdrs_id"), table_name="telephony_cdrs")
    op.drop_table("telephony_cdrs")

    op.drop_index(
        "ix_telephony_call_events_provider_status", table_name="telephony_call_events"
    )
    op.drop_index("ix_telephony_call_events_workflow_run", table_name="telephony_call_events")
    op.drop_index("ix_telephony_call_events_org_created", table_name="telephony_call_events")
    op.drop_index("ix_telephony_call_events_attempt", table_name="telephony_call_events")
    op.drop_index(op.f("ix_telephony_call_events_id"), table_name="telephony_call_events")
    op.drop_table("telephony_call_events")
