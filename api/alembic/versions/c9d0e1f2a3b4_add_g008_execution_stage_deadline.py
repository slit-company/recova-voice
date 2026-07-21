"""persist database-clock G008 execution stage deadline

Revision ID: c9d0e1f2a3b4
Revises: b6c7d8e9f0a1
Create Date: 2026-07-20
"""
from alembic import op
import sqlalchemy as sa


revision = "c9d0e1f2a3b4"
down_revision = "b6c7d8e9f0a1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "g008_execution_stages",
        sa.Column("stage_deadline_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_check_constraint(
        "ck_g008_execution_stage_deadline",
        "g008_execution_stages",
        "stage_deadline_at IS NULL OR "
        "(started_at IS NOT NULL AND "
        "stage_deadline_at = started_at + interval '60 seconds')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_g008_execution_stage_deadline",
        "g008_execution_stages",
        type_="check",
    )
    op.drop_column("g008_execution_stages", "stage_deadline_at")
