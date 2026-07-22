"""add G040 bounded IP-to-IP execution mode

Revision ID: h5b6c7d8e9f0
Revises: g4a5b6c7d8e9
Create Date: 2026-07-22
"""

from alembic import op
import sqlalchemy as sa


revision = "h5b6c7d8e9f0"
down_revision = "g4a5b6c7d8e9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "g008_execution_seals",
        sa.Column(
            "execution_mode",
            sa.String(32),
            nullable=False,
            server_default="legacy_registration",
        ),
    )
    op.add_column(
        "g008_execution_seals", sa.Column("owned_target_digest", sa.String(64))
    )
    op.add_column(
        "g008_execution_seals", sa.Column("source_external_ipv4", sa.String(15))
    )
    op.add_column(
        "g008_execution_seals", sa.Column("peer_signaling_ipv4_cidr", sa.String(18))
    )
    op.add_column(
        "g008_execution_seals", sa.Column("peer_signaling_udp_port", sa.Integer())
    )
    op.create_check_constraint(
        "ck_g008_execution_seal_mode",
        "g008_execution_seals",
        "execution_mode IN ('legacy_registration','ip_to_ip_no_register')",
    )
    op.create_check_constraint(
        "ck_g008_execution_seal_mode_binding",
        "g008_execution_seals",
        "(execution_mode = 'legacy_registration' AND owned_target_digest IS NULL "
        "AND source_external_ipv4 IS NULL AND peer_signaling_ipv4_cidr IS NULL "
        "AND peer_signaling_udp_port IS NULL) OR "
        "(execution_mode = 'ip_to_ip_no_register' AND "
        "owned_target_digest ~ '^[0-9a-f]{64}$' AND "
        "source_external_ipv4 ~ '^([0-9]{1,3}\\.){3}[0-9]{1,3}$' AND "
        "peer_signaling_ipv4_cidr ~ '^([0-9]{1,3}\\.){3}[0-9]{1,3}/32$' AND "
        "peer_signaling_udp_port = 5060)",
    )
    op.drop_constraint(
        "ck_g008_execution_stage_order", "g008_execution_stages", type_="check"
    )
    op.create_check_constraint(
        "ck_g008_execution_stage_order",
        "g008_execution_stages",
        "(ordinal = 1 AND stage IN ('register','peer_attach')) OR "
        "(ordinal = 2 AND stage = 'outbound_call') OR "
        "(ordinal = 3 AND stage = 'inbound_call') OR "
        "(ordinal = 4 AND stage IN ('unregister','peer_detach'))",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_g008_execution_stage_order", "g008_execution_stages", type_="check"
    )
    op.create_check_constraint(
        "ck_g008_execution_stage_order",
        "g008_execution_stages",
        "(ordinal = 1 AND stage = 'register') OR "
        "(ordinal = 2 AND stage = 'outbound_call') OR "
        "(ordinal = 3 AND stage = 'inbound_call') OR "
        "(ordinal = 4 AND stage = 'unregister')",
    )
    op.drop_constraint(
        "ck_g008_execution_seal_mode_binding", "g008_execution_seals", type_="check"
    )
    op.drop_constraint(
        "ck_g008_execution_seal_mode", "g008_execution_seals", type_="check"
    )
    op.drop_column("g008_execution_seals", "peer_signaling_udp_port")
    op.drop_column("g008_execution_seals", "peer_signaling_ipv4_cidr")
    op.drop_column("g008_execution_seals", "source_external_ipv4")
    op.drop_column("g008_execution_seals", "owned_target_digest")
    op.drop_column("g008_execution_seals", "execution_mode")
