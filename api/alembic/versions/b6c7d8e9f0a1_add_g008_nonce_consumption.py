"""add atomic G008 nonce consumption

Revision ID: b6c7d8e9f0a1
Revises: a5b6c7d8e9f0
Create Date: 2026-07-18
"""

from alembic import op
import sqlalchemy as sa


revision = "b6c7d8e9f0a1"
down_revision = "a5b6c7d8e9f0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "g008_execution_nonce_consumptions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("execution_seal_uuid", sa.String(length=36), nullable=False),
        sa.Column("execution_nonce_digest", sa.String(length=64), nullable=False),
        sa.Column("candidate_digest", sa.String(length=64), nullable=False),
        sa.Column("gate_envelope_digest", sa.String(length=64), nullable=False),
        sa.Column("trusted_keyset_digest", sa.String(length=64), nullable=False),
        sa.Column(
            "consumed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("clock_timestamp()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "execution_nonce_digest ~ '^[0-9a-f]{64}$' AND "
            "candidate_digest ~ '^[0-9a-f]{64}$' AND "
            "gate_envelope_digest ~ '^[0-9a-f]{64}$' AND "
            "trusted_keyset_digest ~ '^[0-9a-f]{64}$'",
            name="ck_g008_execution_nonce_consumption_digests",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "execution_nonce_digest", name="uq_g008_execution_nonce_digest"
        ),
        sa.UniqueConstraint(
            "execution_seal_uuid", name="uq_g008_execution_nonce_seal"
        ),
    )
    op.create_index(
        op.f("ix_g008_execution_nonce_consumptions_id"),
        "g008_execution_nonce_consumptions",
        ["id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_g008_execution_nonce_consumptions_id"),
        table_name="g008_execution_nonce_consumptions",
    )
    op.drop_table("g008_execution_nonce_consumptions")
