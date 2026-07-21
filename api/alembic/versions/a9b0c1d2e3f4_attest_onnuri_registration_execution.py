"""attest Onnuri registration execution

Revision ID: a9b0c1d2e3f4
Revises: f8a9b0c1d2e3
"""

from alembic import op
import sqlalchemy as sa


revision = "a9b0c1d2e3f4"
down_revision = "f8a9b0c1d2e3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM onnuri_registration_gates
        WHERE state IN ('completed', 'failed', 'contained')
      ) THEN
        RAISE EXCEPTION
          'preexisting terminal Onnuri registration gates cannot be attested';
      END IF;
    END $$;
    """)
    op.add_column(
        "onnuri_registration_gates",
        sa.Column("execution_attestation_digest", sa.String(64), nullable=True),
    )
    op.add_column(
        "onnuri_registration_gates",
        sa.Column("execution_attestation_key_id", sa.String(128), nullable=True),
    )
    op.add_column(
        "onnuri_registration_gates",
        sa.Column("execution_attested_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_check_constraint(
        "ck_onnuri_reg_execution_attestation_digest",
        "onnuri_registration_gates",
        "execution_attestation_digest IS NULL OR "
        "execution_attestation_digest ~ '^[0-9a-f]{64}$'",
    )
    op.create_check_constraint(
        "ck_onnuri_reg_execution_attestation_key_id",
        "onnuri_registration_gates",
        "execution_attestation_key_id IS NULL OR "
        "execution_attestation_key_id ~ '^[a-z0-9][a-z0-9._-]{0,127}$'",
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
    op.create_index(
        "uq_onnuri_reg_execution_attestation_digest",
        "onnuri_registration_gates",
        ["execution_attestation_digest"],
        unique=True,
        postgresql_where=sa.text("execution_attestation_digest IS NOT NULL"),
    )
    op.execute("""
    CREATE OR REPLACE FUNCTION onnuri_registration_gate_guard()
    RETURNS trigger LANGUAGE plpgsql AS $$
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
      IF NEW.state IN ('completed', 'failed', 'contained') AND (
          NEW.terminal_at IS NULL
          OR NEW.execution_attestation_digest IS NULL
          OR NEW.execution_attestation_key_id IS NULL
          OR NEW.execution_attested_at IS NULL
      ) THEN
        RAISE EXCEPTION 'onnuri registration terminal attestation is required';
      END IF;
      IF NEW.state NOT IN ('completed', 'failed', 'contained') AND (
          NEW.execution_attestation_digest IS NOT NULL
          OR NEW.execution_attestation_key_id IS NOT NULL
          OR NEW.execution_attested_at IS NOT NULL
      ) THEN
        RAISE EXCEPTION 'onnuri registration attestation requires terminal state';
      END IF;
      IF OLD.execution_attestation_digest IS NOT NULL AND
         (NEW.execution_attestation_digest, NEW.execution_attestation_key_id,
          NEW.execution_attested_at) IS DISTINCT FROM
         (OLD.execution_attestation_digest, OLD.execution_attestation_key_id,
          OLD.execution_attested_at) THEN
        RAISE EXCEPTION 'onnuri registration execution attestation is immutable';
      END IF;
      IF OLD.terminal_at IS NOT NULL
         AND NEW.terminal_at IS DISTINCT FROM OLD.terminal_at THEN
        RAISE EXCEPTION 'onnuri registration terminal evidence is immutable';
      END IF;
      RETURN NEW;
    END $$;
    """)
    op.execute("""
    CREATE FUNCTION onnuri_registration_obligation_guard()
    RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE
      target_envelope_id integer;
    BEGIN
      target_envelope_id := OLD.id;
      IF TG_OP = 'UPDATE'
         AND (NEW.state, NEW.revoked_at, NEW.contained_at) IS NOT DISTINCT FROM
             (OLD.state, OLD.revoked_at, OLD.contained_at) THEN
        RETURN NEW;
      END IF;
      IF EXISTS (
        SELECT 1
        FROM onnuri_registration_gates register_gate
        WHERE register_gate.envelope_id = target_envelope_id
          AND register_gate.operation_kind = 'register'
          AND register_gate.transaction_count = 1
          AND NOT EXISTS (
            SELECT 1
            FROM onnuri_registration_gates unregister_gate
            WHERE unregister_gate.unregisters_gate_id = register_gate.id
              AND unregister_gate.operation_kind = 'unregister'
              AND unregister_gate.state = 'completed'
              AND unregister_gate.execution_attestation_digest IS NOT NULL
              AND unregister_gate.execution_attestation_key_id IS NOT NULL
              AND unregister_gate.execution_attested_at IS NOT NULL
          )
      ) THEN
        RAISE EXCEPTION
          'onnuri registration compensation obligation is outstanding';
      END IF;
      IF TG_OP = 'DELETE' THEN
        RETURN OLD;
      END IF;
      RETURN NEW;
    END $$;
    """)
    op.execute("""
    CREATE TRIGGER trg_onnuri_registration_obligation_guard
    BEFORE UPDATE OR DELETE ON onnuri_staging_smoke_envelopes
    FOR EACH ROW EXECUTE FUNCTION onnuri_registration_obligation_guard()
    """)


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS trg_onnuri_registration_obligation_guard "
        "ON onnuri_staging_smoke_envelopes"
    )
    op.execute("DROP FUNCTION IF EXISTS onnuri_registration_obligation_guard()")
    op.execute("""
    CREATE OR REPLACE FUNCTION onnuri_registration_gate_guard()
    RETURNS trigger LANGUAGE plpgsql AS $$
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
    op.drop_index(
        "uq_onnuri_reg_execution_attestation_digest",
        table_name="onnuri_registration_gates",
    )
    for constraint in (
        "ck_onnuri_reg_terminal_attested",
        "ck_onnuri_reg_execution_attestation_complete",
        "ck_onnuri_reg_execution_attestation_key_id",
        "ck_onnuri_reg_execution_attestation_digest",
    ):
        op.drop_constraint(constraint, "onnuri_registration_gates", type_="check")
    op.drop_column("onnuri_registration_gates", "execution_attested_at")
    op.drop_column("onnuri_registration_gates", "execution_attestation_key_id")
    op.drop_column("onnuri_registration_gates", "execution_attestation_digest")
