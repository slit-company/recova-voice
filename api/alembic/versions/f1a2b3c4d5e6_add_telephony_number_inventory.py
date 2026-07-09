"""add telephony number inventory

Revision ID: f1a2b3c4d5e6
Revises: d6a7b8c9e0f1
Create Date: 2026-07-09 03:25:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f1a2b3c4d5e6"
down_revision: Union[str, Sequence[str], None] = "d6a7b8c9e0f1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "telephony_number_inventory",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("provider", sa.String(length=32), server_default="jambonz", nullable=False),
        sa.Column("trunk_group", sa.String(length=64), nullable=True),
        sa.Column("organization_id", sa.Integer(), nullable=True),
        sa.Column("telephony_configuration_id", sa.Integer(), nullable=True),
        sa.Column("telephony_phone_number_id", sa.Integer(), nullable=True),
        sa.Column("address_normalized", sa.String(length=255), nullable=False),
        sa.Column("address_masked", sa.String(length=255), nullable=True),
        sa.Column("address_hash", sa.String(length=64), nullable=True),
        sa.Column("address_encrypted_raw", sa.Text(), nullable=True),
        sa.Column("address_type", sa.String(length=16), nullable=False),
        sa.Column("country_code", sa.String(length=2), nullable=True),
        sa.Column("label", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=32), server_default="available", nullable=False),
        sa.Column("reservation_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("quarantined_reason", sa.Text(), nullable=True),
        sa.Column("retired_reason", sa.Text(), nullable=True),
        sa.Column(
            "extra_metadata",
            sa.JSON(),
            server_default=sa.text("'{}'::json"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="SET NULL"
        ),
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
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "provider",
            "address_normalized",
            name="uq_telephony_number_inventory_provider_address",
        ),
    )
    op.create_index(
        "ix_telephony_number_inventory_provider_status",
        "telephony_number_inventory",
        ["provider", "status"],
        unique=False,
    )
    op.create_index(
        "ix_telephony_number_inventory_org_status",
        "telephony_number_inventory",
        ["organization_id", "status"],
        unique=False,
    )
    op.create_index(
        "ix_telephony_number_inventory_address_hash",
        "telephony_number_inventory",
        ["address_hash"],
        unique=False,
        postgresql_where=sa.text("address_hash IS NOT NULL"),
    )
    op.create_index(
        "uq_telephony_number_inventory_phone_number",
        "telephony_number_inventory",
        ["telephony_phone_number_id"],
        unique=True,
        postgresql_where=sa.text("telephony_phone_number_id IS NOT NULL"),
    )

    op.create_table(
        "telephony_number_inventory_audit",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("inventory_id", sa.Integer(), nullable=False),
        sa.Column("actor_user_id", sa.Integer(), nullable=True),
        sa.Column("organization_id", sa.Integer(), nullable=True),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("from_status", sa.String(length=32), nullable=True),
        sa.Column("to_status", sa.String(length=32), nullable=True),
        sa.Column(
            "details",
            sa.JSON(),
            server_default=sa.text("'{}'::json"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["inventory_id"], ["telephony_number_inventory.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["actor_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_telephony_number_inventory_audit_inventory",
        "telephony_number_inventory_audit",
        ["inventory_id"],
        unique=False,
    )
    op.create_index(
        "ix_telephony_number_inventory_audit_actor",
        "telephony_number_inventory_audit",
        ["actor_user_id"],
        unique=False,
    )
    op.create_index(
        "ix_telephony_number_inventory_audit_created",
        "telephony_number_inventory_audit",
        ["created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_telephony_number_inventory_audit_created",
        table_name="telephony_number_inventory_audit",
    )
    op.drop_index(
        "ix_telephony_number_inventory_audit_actor",
        table_name="telephony_number_inventory_audit",
    )
    op.drop_index(
        "ix_telephony_number_inventory_audit_inventory",
        table_name="telephony_number_inventory_audit",
    )
    op.drop_table("telephony_number_inventory_audit")
    op.drop_index(
        "uq_telephony_number_inventory_phone_number",
        table_name="telephony_number_inventory",
    )
    op.drop_index(
        "ix_telephony_number_inventory_address_hash",
        table_name="telephony_number_inventory",
    )
    op.drop_index(
        "ix_telephony_number_inventory_org_status",
        table_name="telephony_number_inventory",
    )
    op.drop_index(
        "ix_telephony_number_inventory_provider_status",
        table_name="telephony_number_inventory",
    )
    op.drop_table("telephony_number_inventory")
