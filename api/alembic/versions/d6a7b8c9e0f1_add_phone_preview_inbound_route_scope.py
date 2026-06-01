"""add phone preview inbound route scope

Revision ID: d6a7b8c9e0f1
Revises: c0a1b2c3d4e5
Create Date: 2026-06-01 17:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d6a7b8c9e0f1"
down_revision: Union[str, Sequence[str], None] = "c0a1b2c3d4e5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "phone_preview_sessions",
        sa.Column(
            "preview_telephony_configuration_id",
            sa.Integer(),
            nullable=True,
        ),
    )
    op.add_column(
        "phone_preview_sessions",
        sa.Column("preview_from_phone_number_id", sa.Integer(), nullable=True),
    )
    op.create_foreign_key(
        "fk_phone_preview_sessions_preview_telephony_configuration_id",
        "phone_preview_sessions",
        "telephony_configurations",
        ["preview_telephony_configuration_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        "fk_phone_preview_sessions_preview_from_phone_number_id",
        "phone_preview_sessions",
        "telephony_phone_numbers",
        ["preview_from_phone_number_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_phone_preview_sessions_inbound_route",
        "phone_preview_sessions",
        [
            "phone_number_global_hash",
            "provider",
            "preview_telephony_configuration_id",
            "preview_from_phone_number_id",
            "updated_at",
        ],
        unique=False,
        postgresql_where=sa.text(
            "phone_number_global_hash IS NOT NULL "
            "AND preview_from_phone_number_id IS NOT NULL"
        ),
    )


def downgrade() -> None:
    op.drop_index(
        "ix_phone_preview_sessions_inbound_route",
        table_name="phone_preview_sessions",
    )
    op.drop_constraint(
        "fk_phone_preview_sessions_preview_from_phone_number_id",
        "phone_preview_sessions",
        type_="foreignkey",
    )
    op.drop_constraint(
        "fk_phone_preview_sessions_preview_telephony_configuration_id",
        "phone_preview_sessions",
        type_="foreignkey",
    )
    op.drop_column("phone_preview_sessions", "preview_from_phone_number_id")
    op.drop_column("phone_preview_sessions", "preview_telephony_configuration_id")
