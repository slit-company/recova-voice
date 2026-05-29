"""add phone preview global phone hash

Revision ID: c0a1b2c3d4e5
Revises: b8a9c6d7e5f4
Create Date: 2026-05-29 14:30:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c0a1b2c3d4e5"
down_revision: Union[str, Sequence[str], None] = "b8a9c6d7e5f4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "phone_preview_sessions",
        sa.Column("phone_number_global_hash", sa.String(length=64), nullable=True),
    )
    op.create_index(
        "ix_phone_preview_sessions_global_phone",
        "phone_preview_sessions",
        ["phone_number_global_hash", "created_at"],
        unique=False,
        postgresql_where=sa.text("phone_number_global_hash IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index(
        "ix_phone_preview_sessions_global_phone",
        table_name="phone_preview_sessions",
    )
    op.drop_column("phone_preview_sessions", "phone_number_global_hash")
