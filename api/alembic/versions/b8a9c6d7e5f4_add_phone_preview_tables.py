"""add phone preview tables

Revision ID: b8a9c6d7e5f4
Revises: 6bd9f67ec994, f2e1d0c9b8a7, cdcf9f65913b
Create Date: 2026-05-29 01:23:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b8a9c6d7e5f4"
down_revision: Union[str, Sequence[str], None] = (
    "6bd9f67ec994",
    "f2e1d0c9b8a7",
    "cdcf9f65913b",
)
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "telephony_phone_numbers",
        sa.Column("address_masked", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "telephony_phone_numbers",
        sa.Column("address_hash", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "telephony_phone_numbers",
        sa.Column("address_encrypted_raw", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_phone_numbers_address_hash",
        "telephony_phone_numbers",
        ["address_hash"],
        unique=False,
        postgresql_where=sa.text("address_hash IS NOT NULL"),
    )

    op.create_table(
        "phone_preview_verifications",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("phone_number_hash", sa.String(length=64), nullable=False),
        sa.Column("phone_number_masked", sa.String(length=32), nullable=False),
        sa.Column("code_hash", sa.String(length=128), nullable=False),
        sa.Column("code_salt", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column(
            "attempts", sa.Integer(), server_default=sa.text("0"), nullable=False
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_phone_preview_verifications_lookup",
        "phone_preview_verifications",
        ["organization_id", "user_id", "phone_number_hash", "status"],
        unique=False,
    )
    op.create_index(
        "ix_phone_preview_verifications_expires_at",
        "phone_preview_verifications",
        ["expires_at"],
        unique=False,
    )

    op.create_table(
        "phone_preview_sessions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("workflow_id", sa.Integer(), nullable=False),
        sa.Column("workflow_run_id", sa.Integer(), nullable=True),
        sa.Column("verification_id", sa.Integer(), nullable=True),
        sa.Column("phone_number_hash", sa.String(length=64), nullable=False),
        sa.Column("phone_number_masked", sa.String(length=32), nullable=False),
        sa.Column("destination_phone_encrypted", sa.Text(), nullable=True),
        sa.Column("display_name", sa.String(length=120), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=True),
        sa.Column("provider_call_id", sa.String(length=255), nullable=True),
        sa.Column("failure_reason", sa.String(length=255), nullable=True),
        sa.Column("max_duration_seconds", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["workflow_id"], ["workflows.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["workflow_run_id"], ["workflow_runs.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["verification_id"],
            ["phone_preview_verifications.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_phone_preview_sessions_owner",
        "phone_preview_sessions",
        ["organization_id", "user_id", "status"],
        unique=False,
    )
    op.create_index(
        "ix_phone_preview_sessions_workflow_run",
        "phone_preview_sessions",
        ["workflow_run_id"],
        unique=False,
    )
    op.create_index(
        "ix_phone_preview_sessions_phone",
        "phone_preview_sessions",
        ["organization_id", "phone_number_hash", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_phone_preview_sessions_expires_at",
        "phone_preview_sessions",
        ["expires_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_phone_preview_sessions_expires_at", table_name="phone_preview_sessions"
    )
    op.drop_index(
        "ix_phone_preview_sessions_phone", table_name="phone_preview_sessions"
    )
    op.drop_index(
        "ix_phone_preview_sessions_workflow_run",
        table_name="phone_preview_sessions",
    )
    op.drop_index(
        "ix_phone_preview_sessions_owner", table_name="phone_preview_sessions"
    )
    op.drop_table("phone_preview_sessions")
    op.drop_index(
        "ix_phone_preview_verifications_expires_at",
        table_name="phone_preview_verifications",
    )
    op.drop_index(
        "ix_phone_preview_verifications_lookup",
        table_name="phone_preview_verifications",
    )
    op.drop_table("phone_preview_verifications")
    op.drop_index(
        "ix_phone_numbers_address_hash", table_name="telephony_phone_numbers"
    )
    op.drop_column("telephony_phone_numbers", "address_encrypted_raw")
    op.drop_column("telephony_phone_numbers", "address_hash")
    op.drop_column("telephony_phone_numbers", "address_masked")
