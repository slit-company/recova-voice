"""add durable Onnuri restricted-adapter replay ledger

Revision ID: e1f2a3b4c5d6
Revises: d0e1f2a3b4c5
Create Date: 2026-07-21
"""
from alembic import op
import sqlalchemy as sa

revision = "e1f2a3b4c5d6"
down_revision = "d0e1f2a3b4c5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "onnuri_route_adapter_replays",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("key_id", sa.String(255), nullable=False),
        sa.Column("challenge_nonce", sa.String(43), nullable=False),
        sa.Column("audience", sa.String(128), nullable=False),
        sa.Column("signature_sha256", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("key_id", "challenge_nonce", "audience", "signature_sha256", name="uq_onnuri_route_adapter_replay"),
        sa.CheckConstraint("signature_sha256 ~ '^[0-9a-f]{64}$'", name="ck_onnuri_route_adapter_replay_signature"),
    )
    op.create_index("ix_onnuri_route_adapter_replay_expires_at", "onnuri_route_adapter_replays", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_onnuri_route_adapter_replay_expires_at", table_name="onnuri_route_adapter_replays")
    op.drop_table("onnuri_route_adapter_replays")
