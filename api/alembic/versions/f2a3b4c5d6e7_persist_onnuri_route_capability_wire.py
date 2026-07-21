"""persist exact signed Onnuri route capability recovery material

Revision ID: f2a3b4c5d6e7
Revises: e1f2a3b4c5d6
Create Date: 2026-07-21
"""

from alembic import op
import sqlalchemy as sa

revision = "f2a3b4c5d6e7"
down_revision = "e1f2a3b4c5d6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "onnuri_outbound_diagnostic_capabilities",
        sa.Column("token_digest", sa.String(64), nullable=True),
    )
    op.add_column(
        "onnuri_outbound_diagnostic_capabilities",
        sa.Column("signature_digest", sa.String(64), nullable=True),
    )
    op.add_column(
        "onnuri_outbound_diagnostic_capabilities",
        sa.Column("encrypted_capability_recovery", sa.Text(), nullable=True),
    )
    op.execute(
        "DO $$ BEGIN "
        "IF EXISTS (SELECT 1 FROM onnuri_outbound_diagnostic_capabilities) THEN "
        "RAISE EXCEPTION 'onnuri route capability wire migration requires an empty table'; "
        "END IF; END $$"
    )
    op.execute(
        "ALTER TABLE onnuri_outbound_diagnostic_capabilities "
        "ADD CONSTRAINT ck_onnuri_outbound_diagnostic_capability_wire_digests "
        "CHECK (token_digest ~ '^[0-9a-f]{64}$' AND signature_digest ~ '^[0-9a-f]{64}$')"
    )
    op.alter_column("onnuri_outbound_diagnostic_capabilities", "token_digest", nullable=False)
    op.alter_column("onnuri_outbound_diagnostic_capabilities", "signature_digest", nullable=False)
    op.alter_column("onnuri_outbound_diagnostic_capabilities", "encrypted_capability_recovery", nullable=False)


def downgrade() -> None:
    op.drop_constraint("ck_onnuri_outbound_diagnostic_capability_wire_digests", "onnuri_outbound_diagnostic_capabilities")
    op.drop_column("onnuri_outbound_diagnostic_capabilities", "encrypted_capability_recovery")
    op.drop_column("onnuri_outbound_diagnostic_capabilities", "signature_digest")
    op.drop_column("onnuri_outbound_diagnostic_capabilities", "token_digest")
