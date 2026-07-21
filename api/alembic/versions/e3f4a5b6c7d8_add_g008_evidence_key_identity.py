"""add dedicated G008 execution evidence key identities

Revision ID: e3f4a5b6c7d8
Revises: d2e3f4a5b6c7
"""

from alembic import op
import sqlalchemy as sa


revision = "e3f4a5b6c7d8"
down_revision = "d2e3f4a5b6c7"
branch_labels = None
depends_on = None


_SEAL_CONTAINMENT_V2 = """(state = 'contained' AND contained_at IS NOT NULL AND containment_class IS NOT NULL AND containment_evidence_digest IS NOT NULL AND containment_evidence_signature_digest IS NOT NULL AND containment_evidence_key_digest IS NOT NULL AND containment_evidence_key_id IS NOT NULL) OR (state <> 'contained' AND contained_at IS NULL AND containment_class IS NULL AND containment_evidence_digest IS NULL AND containment_evidence_signature_digest IS NULL AND containment_evidence_key_digest IS NULL AND containment_evidence_key_id IS NULL)"""
_SEAL_FINAL_V2 = """(state = 'completed' AND completed_at IS NOT NULL AND final_evidence_digest IS NOT NULL AND final_evidence_signature_digest IS NOT NULL AND final_evidence_key_digest IS NOT NULL AND final_evidence_key_id IS NOT NULL) OR (state <> 'completed' AND completed_at IS NULL AND final_evidence_digest IS NULL AND final_evidence_signature_digest IS NULL AND final_evidence_key_digest IS NULL AND final_evidence_key_id IS NULL)"""
_STAGE_TERMINAL_V2 = """(state IN ('pending','started') AND finalized_at IS NULL AND terminal_class IS NULL AND evidence_digest IS NULL AND evidence_signature_digest IS NULL AND evidence_key_digest IS NULL AND evidence_key_id IS NULL) OR (state IN ('succeeded','failed','contained') AND finalized_at IS NOT NULL AND terminal_class IS NOT NULL AND evidence_digest IS NOT NULL AND evidence_signature_digest IS NOT NULL AND evidence_key_digest IS NOT NULL AND evidence_key_id IS NOT NULL)"""
_SEAL_CONTAINMENT_V1 = """(state = 'contained' AND contained_at IS NOT NULL AND containment_class IS NOT NULL AND containment_evidence_digest IS NOT NULL AND containment_evidence_signature_digest IS NOT NULL AND containment_evidence_key_digest IS NOT NULL) OR (state <> 'contained' AND contained_at IS NULL AND containment_class IS NULL AND containment_evidence_digest IS NULL AND containment_evidence_signature_digest IS NULL AND containment_evidence_key_digest IS NULL)"""
_SEAL_FINAL_V1 = """(state = 'completed' AND completed_at IS NOT NULL AND final_evidence_digest IS NOT NULL AND final_evidence_signature_digest IS NOT NULL AND final_evidence_key_digest IS NOT NULL) OR (state <> 'completed' AND completed_at IS NULL AND final_evidence_digest IS NULL AND final_evidence_signature_digest IS NULL AND final_evidence_key_digest IS NULL)"""
_STAGE_TERMINAL_V1 = """(state IN ('pending','started') AND finalized_at IS NULL AND terminal_class IS NULL AND evidence_digest IS NULL AND evidence_signature_digest IS NULL AND evidence_key_digest IS NULL) OR (state IN ('succeeded','failed','contained') AND finalized_at IS NOT NULL AND terminal_class IS NOT NULL AND evidence_digest IS NOT NULL AND evidence_signature_digest IS NOT NULL AND evidence_key_digest IS NOT NULL)"""


def _replace_checks(*, seal_containment: str, seal_final: str, stage_terminal: str) -> None:
    op.drop_constraint(
        "ck_g008_execution_seal_containment",
        "g008_execution_seals",
        type_="check",
    )
    op.drop_constraint(
        "ck_g008_execution_seal_final_evidence",
        "g008_execution_seals",
        type_="check",
    )
    op.drop_constraint(
        "ck_g008_execution_stage_terminal",
        "g008_execution_stages",
        type_="check",
    )
    op.create_check_constraint(
        "ck_g008_execution_seal_containment",
        "g008_execution_seals",
        seal_containment,
    )
    op.create_check_constraint(
        "ck_g008_execution_seal_final_evidence",
        "g008_execution_seals",
        seal_final,
    )
    op.create_check_constraint(
        "ck_g008_execution_stage_terminal",
        "g008_execution_stages",
        stage_terminal,
    )


def upgrade() -> None:
    op.add_column(
        "g008_execution_seals",
        sa.Column("containment_evidence_key_id", sa.String(128), nullable=True),
    )
    op.add_column(
        "g008_execution_seals",
        sa.Column("final_evidence_key_id", sa.String(128), nullable=True),
    )
    op.add_column(
        "g008_execution_stages",
        sa.Column("evidence_key_id", sa.String(128), nullable=True),
    )
    _replace_checks(
        seal_containment=_SEAL_CONTAINMENT_V2,
        seal_final=_SEAL_FINAL_V2,
        stage_terminal=_STAGE_TERMINAL_V2,
    )
    op.execute("""
    CREATE FUNCTION g008_execution_evidence_key_guard() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
      IF TG_TABLE_NAME = 'g008_execution_seals' THEN
        IF OLD.final_evidence_digest IS NOT NULL AND
           (NEW.final_evidence_digest, NEW.final_evidence_signature_digest,
            NEW.final_evidence_key_digest, NEW.final_evidence_key_id,
            NEW.completed_at) IS DISTINCT FROM
           (OLD.final_evidence_digest, OLD.final_evidence_signature_digest,
            OLD.final_evidence_key_digest, OLD.final_evidence_key_id,
            OLD.completed_at) THEN
          RAISE EXCEPTION 'g008 final evidence identity is write-once';
        END IF;
        IF OLD.containment_evidence_digest IS NOT NULL AND
           (NEW.containment_evidence_digest,
            NEW.containment_evidence_signature_digest,
            NEW.containment_evidence_key_digest,
            NEW.containment_evidence_key_id, NEW.contained_at) IS DISTINCT FROM
           (OLD.containment_evidence_digest,
            OLD.containment_evidence_signature_digest,
            OLD.containment_evidence_key_digest,
            OLD.containment_evidence_key_id, OLD.contained_at) THEN
          RAISE EXCEPTION 'g008 containment evidence identity is write-once';
        END IF;
      ELSE
        IF OLD.evidence_digest IS NOT NULL AND
           (NEW.evidence_digest, NEW.evidence_signature_digest,
            NEW.evidence_key_digest, NEW.evidence_key_id,
            NEW.finalized_at) IS DISTINCT FROM
           (OLD.evidence_digest, OLD.evidence_signature_digest,
            OLD.evidence_key_digest, OLD.evidence_key_id,
            OLD.finalized_at) THEN
          RAISE EXCEPTION 'g008 stage evidence identity is write-once';
        END IF;
      END IF;
      RETURN NEW;
    END $$;
    """)
    op.execute("""
    CREATE TRIGGER trg_g008_execution_seal_evidence_key_guard
      BEFORE UPDATE ON g008_execution_seals FOR EACH ROW
      EXECUTE FUNCTION g008_execution_evidence_key_guard();
    """)
    op.execute("""
    CREATE TRIGGER trg_g008_execution_stage_evidence_key_guard
      BEFORE UPDATE ON g008_execution_stages FOR EACH ROW
      EXECUTE FUNCTION g008_execution_evidence_key_guard();
    """)


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER trg_g008_execution_stage_evidence_key_guard "
        "ON g008_execution_stages"
    )
    op.execute(
        "DROP TRIGGER trg_g008_execution_seal_evidence_key_guard "
        "ON g008_execution_seals"
    )
    op.execute("DROP FUNCTION g008_execution_evidence_key_guard()")
    _replace_checks(
        seal_containment=_SEAL_CONTAINMENT_V1,
        seal_final=_SEAL_FINAL_V1,
        stage_terminal=_STAGE_TERMINAL_V1,
    )
    op.drop_column("g008_execution_stages", "evidence_key_id")
    op.drop_column("g008_execution_seals", "final_evidence_key_id")
    op.drop_column("g008_execution_seals", "containment_evidence_key_id")
