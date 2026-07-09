"""backfill inventory assignment metadata

Revision ID: f2a4b6c8d0e1
Revises: f1a2b3c4d5e6, 9a0b1c2d3e4f
Create Date: 2026-07-09 06:40:00.000000

"""

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f2a4b6c8d0e1"
down_revision: Union[str, Sequence[str], None] = (
    "f1a2b3c4d5e6",
    "9a0b1c2d3e4f",
)
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None




def upgrade() -> None:
    op.execute(
        """
        UPDATE telephony_phone_numbers AS phone
        SET extra_metadata = (
            COALESCE(phone.extra_metadata, '{}'::json)::jsonb
            || jsonb_build_object(
                'recova_inventory_state', 'assigned',
                'managed_by', 'recova_number_inventory',
                'inventory_id', inventory.id
            )
        )::json
        FROM telephony_number_inventory AS inventory
        WHERE inventory.telephony_phone_number_id = phone.id
          AND inventory.status = 'assigned'
          AND inventory.provider = 'jambonz'
          AND inventory.organization_id = phone.organization_id
          AND inventory.address_normalized = phone.address_normalized
        """
    )
    op.execute(
        """
        UPDATE telephony_number_inventory AS inventory
        SET extra_metadata = (
            COALESCE(inventory.extra_metadata, '{}'::json)::jsonb
            || jsonb_build_object(
                'recova_inventory_state', 'assigned',
                'managed_by', 'recova_number_inventory',
                'inventory_id', inventory.id,
                'telephony_phone_number_id', phone.id
            )
        )::json
        FROM telephony_phone_numbers AS phone
        WHERE inventory.telephony_phone_number_id = phone.id
          AND inventory.status = 'assigned'
          AND inventory.provider = 'jambonz'
          AND inventory.organization_id = phone.organization_id
          AND inventory.address_normalized = phone.address_normalized
        """
    )


def downgrade() -> None:
    pass
