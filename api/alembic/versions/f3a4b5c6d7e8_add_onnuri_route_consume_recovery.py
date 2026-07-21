"""persist dedicated route consume receipt recovery

Revision ID: f3a4b5c6d7e8
Revises: f2a3b4c5d6e7
Create Date: 2026-07-21
"""

from alembic import op
import sqlalchemy as sa

revision = "f3a4b5c6d7e8"
down_revision = "f2a3b4c5d6e7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "onnuri_outbound_diagnostic_capabilities",
        sa.Column("encrypted_consume_recovery", sa.Text(), nullable=True),
    )
    op.add_column(
        "onnuri_outbound_diagnostic_capabilities",
        sa.Column("consume_response_digest", sa.String(64), nullable=True),
    )
    op.execute(
        "ALTER TABLE onnuri_outbound_diagnostic_capabilities "
        "ADD CONSTRAINT ck_onnuri_outbound_diagnostic_capability_consume_digest "
        "CHECK (consume_response_digest IS NULL OR consume_response_digest ~ '^[0-9a-f]{64}$')"
    )
    op.execute(
        "ALTER TABLE onnuri_outbound_diagnostic_capabilities "
        "ADD CONSTRAINT ck_onnuri_outbound_diagnostic_capability_consume_recovery "
        "CHECK ((encrypted_consume_recovery IS NULL) = (consume_response_digest IS NULL) "
        "AND (consumed_at IS NULL) = (diagnostic_attempt_id IS NULL) "
        "AND (consumed_at IS NULL OR (encrypted_consume_recovery IS NOT NULL "
        "AND consume_response_digest IS NOT NULL)))"
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_onnuri_outbound_diagnostic_capability_consume_recovery",
        "onnuri_outbound_diagnostic_capabilities",
    )
    op.drop_constraint(
        "ck_onnuri_outbound_diagnostic_capability_consume_digest",
        "onnuri_outbound_diagnostic_capabilities",
    )
    op.drop_column("onnuri_outbound_diagnostic_capabilities", "consume_response_digest")
    op.drop_column("onnuri_outbound_diagnostic_capabilities", "encrypted_consume_recovery")
