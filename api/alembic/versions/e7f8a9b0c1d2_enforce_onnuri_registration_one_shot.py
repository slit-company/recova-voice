"""enforce one-shot Onnuri registration authority

Revision ID: e7f8a9b0c1d2
Revises: d6e7f8a9b0c1
"""

from alembic import op
import sqlalchemy as sa


revision = "e7f8a9b0c1d2"
down_revision = "d6e7f8a9b0c1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint(
        "ck_onnuri_reg_retransmits", "onnuri_registration_gates", type_="check"
    )
    op.create_check_constraint(
        "ck_onnuri_reg_retransmits",
        "onnuri_registration_gates",
        "retransmission_count BETWEEN 0 AND 2",
    )
    op.create_index(
        "uq_onnuri_reg_one_register",
        "onnuri_registration_gates",
        ["envelope_id"],
        unique=True,
        postgresql_where=sa.text("operation_kind = 'register'"),
    )
    op.create_index(
        "uq_onnuri_reg_one_unregister",
        "onnuri_registration_gates",
        ["unregisters_gate_id"],
        unique=True,
        postgresql_where=sa.text(
            "operation_kind = 'unregister' AND unregisters_gate_id IS NOT NULL"
        ),
    )
    op.execute("""
    CREATE FUNCTION onnuri_registration_gate_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF TG_OP = 'INSERT' THEN
        IF (NEW.operation_kind = 'register' AND NEW.unregisters_gate_id IS NOT NULL)
           OR (NEW.operation_kind = 'unregister' AND NOT EXISTS (
             SELECT 1 FROM onnuri_registration_gates prior
             WHERE prior.id = NEW.unregisters_gate_id
               AND prior.envelope_id = NEW.envelope_id
               AND prior.operation_kind = 'register'
           )) THEN
          RAISE EXCEPTION 'onnuri registration linkage is invalid';
        END IF;
        RETURN NEW;
      END IF;

      IF (NEW.envelope_id, NEW.operation_kind, NEW.unregisters_gate_id,
          NEW.request_digest, NEW.created_at) IS DISTINCT FROM
         (OLD.envelope_id, OLD.operation_kind, OLD.unregisters_gate_id,
          OLD.request_digest, OLD.created_at) THEN
        RAISE EXCEPTION 'onnuri registration identity is immutable';
      END IF;
      IF NEW.transaction_count < OLD.transaction_count
         OR NEW.retransmission_count < OLD.retransmission_count THEN
        RAISE EXCEPTION 'onnuri registration counters are forward-only';
      END IF;
      IF OLD.state IN ('completed', 'failed', 'contained') THEN
        RAISE EXCEPTION 'onnuri registration terminal state is immutable';
      END IF;
      IF NEW.state <> OLD.state AND NOT (
        (OLD.state = 'pending' AND NEW.state IN ('challenged', 'completed', 'failed', 'contained'))
        OR (OLD.state = 'challenged' AND NEW.state IN ('completed', 'failed', 'contained'))
      ) THEN
        RAISE EXCEPTION 'onnuri registration lifecycle is forward-only';
      END IF;
      IF NEW.state IN ('completed', 'failed', 'contained')
         AND NEW.terminal_at IS NULL THEN
        RAISE EXCEPTION 'onnuri registration terminal evidence is required';
      END IF;
      IF OLD.terminal_at IS NOT NULL
         AND NEW.terminal_at IS DISTINCT FROM OLD.terminal_at THEN
        RAISE EXCEPTION 'onnuri registration terminal evidence is immutable';
      END IF;
      RETURN NEW;
    END $$;
    """)
    op.execute("""
    CREATE TRIGGER trg_onnuri_registration_gate_guard
    BEFORE INSERT OR UPDATE ON onnuri_registration_gates
    FOR EACH ROW EXECUTE FUNCTION onnuri_registration_gate_guard()
    """)


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS trg_onnuri_registration_gate_guard "
        "ON onnuri_registration_gates"
    )
    op.execute("DROP FUNCTION IF EXISTS onnuri_registration_gate_guard()")
    op.drop_index("uq_onnuri_reg_one_unregister", table_name="onnuri_registration_gates")
    op.drop_index("uq_onnuri_reg_one_register", table_name="onnuri_registration_gates")
    op.drop_constraint(
        "ck_onnuri_reg_retransmits", "onnuri_registration_gates", type_="check"
    )
    op.create_check_constraint(
        "ck_onnuri_reg_retransmits",
        "onnuri_registration_gates",
        "retransmission_count >= 0",
    )
