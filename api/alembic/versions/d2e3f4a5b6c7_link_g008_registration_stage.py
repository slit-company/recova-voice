"""link Onnuri registration gates to G008 execution stages

Revision ID: d2e3f4a5b6c7
Revises: c1d2e3f4a5b6
"""

from alembic import op
import sqlalchemy as sa


revision = "d2e3f4a5b6c7"
down_revision = "c1d2e3f4a5b6"
branch_labels = None
depends_on = None


_ATTESTATION_COMPLETE = """
(execution_attestation_digest IS NULL) =
(execution_attestation_signature_digest IS NULL) AND
(execution_attestation_digest IS NULL) =
(execution_attestation_key_id IS NULL) AND
(execution_attestation_digest IS NULL) =
(execution_attestation_key_digest IS NULL) AND
(execution_attestation_digest IS NULL) =
(execution_attested_at IS NULL)
"""

_TERMINAL_ATTESTED = """
(state IN ('completed','failed','contained')) =
(execution_attestation_digest IS NOT NULL AND
 execution_attestation_signature_digest IS NOT NULL AND
 execution_attestation_key_id IS NOT NULL AND
 execution_attestation_key_digest IS NOT NULL AND
 execution_attested_at IS NOT NULL)
"""


def upgrade() -> None:
    op.add_column(
        "onnuri_registration_gates",
        sa.Column("execution_stage_id", sa.Integer(), nullable=True),
    )
    op.add_column(
        "onnuri_registration_gates",
        sa.Column(
            "execution_attestation_signature_digest", sa.String(64), nullable=True
        ),
    )
    op.add_column(
        "onnuri_registration_gates",
        sa.Column("execution_attestation_key_digest", sa.String(64), nullable=True),
    )
    op.create_foreign_key(
        "fk_onnuri_reg_execution_stage",
        "onnuri_registration_gates",
        "g008_execution_stages",
        ["execution_stage_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_index(
        "uq_onnuri_reg_execution_stage",
        "onnuri_registration_gates",
        ["execution_stage_id"],
        unique=True,
        postgresql_where=sa.text("execution_stage_id IS NOT NULL"),
    )
    op.create_check_constraint(
        "ck_onnuri_reg_execution_attestation_signature_digest",
        "onnuri_registration_gates",
        "execution_attestation_signature_digest IS NULL OR "
        "execution_attestation_signature_digest ~ '^[0-9a-f]{64}$'",
    )
    op.create_check_constraint(
        "ck_onnuri_reg_execution_attestation_key_digest",
        "onnuri_registration_gates",
        "execution_attestation_key_digest IS NULL OR "
        "execution_attestation_key_digest ~ '^[0-9a-f]{64}$'",
    )
    op.drop_constraint(
        "ck_onnuri_reg_execution_attestation_complete",
        "onnuri_registration_gates",
        type_="check",
    )
    op.drop_constraint(
        "ck_onnuri_reg_terminal_attested",
        "onnuri_registration_gates",
        type_="check",
    )
    # NOT VALID preserves historical terminal rows without manufacturing missing
    # signature/key evidence while enforcing the complete tuple for new writes.
    op.execute(
        "ALTER TABLE onnuri_registration_gates ADD CONSTRAINT "
        "ck_onnuri_reg_execution_attestation_complete CHECK ("
        f"{_ATTESTATION_COMPLETE}) NOT VALID"
    )
    op.execute(
        "ALTER TABLE onnuri_registration_gates ADD CONSTRAINT "
        "ck_onnuri_reg_terminal_attested CHECK ("
        f"{_TERMINAL_ATTESTED}) NOT VALID"
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_onnuri_reg_terminal_attested",
        "onnuri_registration_gates",
        type_="check",
    )
    op.drop_constraint(
        "ck_onnuri_reg_execution_attestation_complete",
        "onnuri_registration_gates",
        type_="check",
    )
    op.create_check_constraint(
        "ck_onnuri_reg_execution_attestation_complete",
        "onnuri_registration_gates",
        "(execution_attestation_digest IS NULL) = "
        "(execution_attestation_key_id IS NULL) AND "
        "(execution_attestation_digest IS NULL) = "
        "(execution_attested_at IS NULL)",
    )
    op.create_check_constraint(
        "ck_onnuri_reg_terminal_attested",
        "onnuri_registration_gates",
        "(state IN ('completed','failed','contained')) = "
        "(execution_attestation_digest IS NOT NULL)",
    )
    op.drop_constraint(
        "ck_onnuri_reg_execution_attestation_key_digest",
        "onnuri_registration_gates",
        type_="check",
    )
    op.drop_constraint(
        "ck_onnuri_reg_execution_attestation_signature_digest",
        "onnuri_registration_gates",
        type_="check",
    )
    op.drop_index(
        "uq_onnuri_reg_execution_stage",
        table_name="onnuri_registration_gates",
    )
    op.drop_constraint(
        "fk_onnuri_reg_execution_stage",
        "onnuri_registration_gates",
        type_="foreignkey",
    )
    op.drop_column(
        "onnuri_registration_gates", "execution_attestation_key_digest"
    )
    op.drop_column(
        "onnuri_registration_gates", "execution_attestation_signature_digest"
    )
    op.drop_column("onnuri_registration_gates", "execution_stage_id")
