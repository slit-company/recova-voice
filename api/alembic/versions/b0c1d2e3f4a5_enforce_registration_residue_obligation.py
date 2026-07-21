"""enforce Onnuri registration residue obligation

Revision ID: b0c1d2e3f4a5
Revises: a9b0c1d2e3f4
"""

from alembic import op
import sqlalchemy as sa


revision = "b0c1d2e3f4a5"
down_revision = "a9b0c1d2e3f4"
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
          'preexisting terminal Onnuri registration gates lack exact wire evidence';
      END IF;
    END $$;
    """)
    op.add_column(
        "onnuri_registration_gates",
        sa.Column(
            "unregister_required",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        "onnuri_registration_gates",
        sa.Column("unregister_satisfied_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "onnuri_registration_gates",
        sa.Column("wire_request_count", sa.Integer(), nullable=True),
    )
    op.execute("""
    UPDATE onnuri_registration_gates
    SET unregister_required = true
    WHERE operation_kind = 'register' AND transaction_count = 1
    """)
    op.create_check_constraint(
        "ck_onnuri_reg_wire_request_count",
        "onnuri_registration_gates",
        "wire_request_count IS NULL OR wire_request_count BETWEEN 0 AND 2",
    )
    op.create_check_constraint(
        "ck_onnuri_reg_terminal_wire_count",
        "onnuri_registration_gates",
        "(state IN ('completed','failed','contained')) = "
        "(wire_request_count IS NOT NULL)",
    )
    op.create_check_constraint(
        "ck_onnuri_reg_unregister_obligation",
        "onnuri_registration_gates",
        "(operation_kind = 'register' OR NOT unregister_required) AND "
        "(unregister_satisfied_at IS NULL OR "
        "(operation_kind = 'register' AND unregister_required))",
    )
    op.create_check_constraint(
        "ck_onnuri_reg_consumed_obligation",
        "onnuri_registration_gates",
        "operation_kind <> 'register' OR transaction_count = 0 "
        "OR unregister_required",
    )
    op.execute("""
    CREATE OR REPLACE FUNCTION onnuri_registration_gate_guard()
    RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF TG_OP = 'INSERT' THEN
        IF NEW.unregister_required OR NEW.unregister_satisfied_at IS NOT NULL
           OR NEW.wire_request_count IS NOT NULL
           OR (NEW.operation_kind = 'register' AND NEW.unregisters_gate_id IS NOT NULL)
           OR (NEW.operation_kind = 'unregister' AND NOT EXISTS (
             SELECT 1 FROM onnuri_registration_gates prior
             WHERE prior.id = NEW.unregisters_gate_id
               AND prior.envelope_id = NEW.envelope_id
               AND prior.operation_kind = 'register'
               AND prior.unregister_required
               AND prior.unregister_satisfied_at IS NULL
           )) THEN
          RAISE EXCEPTION 'onnuri registration linkage or obligation is invalid';
        END IF;
        RETURN NEW;
      END IF;
      IF NEW.operation_kind = 'register'
         AND OLD.transaction_count = 0
         AND NEW.transaction_count = 1 THEN
        NEW.unregister_required := true;
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
      IF OLD.unregister_required AND NOT NEW.unregister_required THEN
        RAISE EXCEPTION 'onnuri unregister obligation is write-once';
      END IF;
      IF NOT OLD.unregister_required AND NEW.unregister_required AND NOT (
          NEW.operation_kind = 'register'
          AND OLD.transaction_count = 0
          AND NEW.transaction_count = 1
      ) THEN
        RAISE EXCEPTION 'onnuri unregister obligation requires consumed register';
      END IF;
      IF OLD.unregister_satisfied_at IS NOT NULL
         AND NEW.unregister_satisfied_at IS DISTINCT FROM OLD.unregister_satisfied_at THEN
        RAISE EXCEPTION 'onnuri unregister satisfaction is immutable';
      END IF;
      IF OLD.unregister_satisfied_at IS NULL
         AND NEW.unregister_satisfied_at IS NOT NULL AND NOT (
           NEW.operation_kind = 'register'
           AND NEW.unregister_required
           AND EXISTS (
             SELECT 1 FROM onnuri_registration_gates unregister_gate
             WHERE unregister_gate.unregisters_gate_id = NEW.id
               AND unregister_gate.operation_kind = 'unregister'
               AND unregister_gate.state = 'completed'
               AND unregister_gate.failure_class = 'succeeded'
               AND unregister_gate.accepted_expires_at IS NOT NULL
               AND unregister_gate.wire_request_count > 0
               AND unregister_gate.execution_attestation_digest IS NOT NULL
           )
         ) THEN
        RAISE EXCEPTION 'onnuri unregister satisfaction requires exact success';
      END IF;
      IF OLD.state IN ('completed', 'failed', 'contained') THEN
        IF OLD.unregister_satisfied_at IS NULL
           AND NEW.unregister_satisfied_at IS NOT NULL
           AND (NEW.state, NEW.transaction_count, NEW.retransmission_count,
                NEW.challenge_digest, NEW.failure_class, NEW.accepted_expires_at,
                NEW.terminal_at, NEW.execution_attestation_digest,
                NEW.execution_attestation_key_id, NEW.execution_attested_at,
                NEW.wire_request_count, NEW.unregister_required) IS NOT DISTINCT FROM
               (OLD.state, OLD.transaction_count, OLD.retransmission_count,
                OLD.challenge_digest, OLD.failure_class, OLD.accepted_expires_at,
                OLD.terminal_at, OLD.execution_attestation_digest,
                OLD.execution_attestation_key_id, OLD.execution_attested_at,
                OLD.wire_request_count, OLD.unregister_required) THEN
          RETURN NEW;
        END IF;
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
          OR NEW.wire_request_count IS NULL
      ) THEN
        RAISE EXCEPTION 'onnuri registration terminal attestation is required';
      END IF;
      IF NEW.state NOT IN ('completed', 'failed', 'contained') AND (
          NEW.execution_attestation_digest IS NOT NULL
          OR NEW.execution_attestation_key_id IS NOT NULL
          OR NEW.execution_attested_at IS NOT NULL
          OR NEW.wire_request_count IS NOT NULL
      ) THEN
        RAISE EXCEPTION 'onnuri registration attestation requires terminal state';
      END IF;
      IF OLD.execution_attestation_digest IS NOT NULL AND
         (NEW.execution_attestation_digest, NEW.execution_attestation_key_id,
          NEW.execution_attested_at, NEW.wire_request_count) IS DISTINCT FROM
         (OLD.execution_attestation_digest, OLD.execution_attestation_key_id,
          OLD.execution_attested_at, OLD.wire_request_count) THEN
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
    CREATE FUNCTION onnuri_registration_satisfy_obligation()
    RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF NEW.operation_kind = 'unregister'
         AND NEW.state = 'completed'
         AND NEW.failure_class = 'succeeded'
         AND NEW.accepted_expires_at IS NOT NULL
         AND NEW.wire_request_count > 0
         AND NEW.execution_attestation_digest IS NOT NULL THEN
        UPDATE onnuri_registration_gates
        SET unregister_satisfied_at = NEW.terminal_at
        WHERE id = NEW.unregisters_gate_id
          AND unregister_required
          AND unregister_satisfied_at IS NULL;
      END IF;
      RETURN NEW;
    END $$;
    """)
    op.execute("""
    CREATE TRIGGER trg_onnuri_registration_satisfy_obligation
    AFTER UPDATE ON onnuri_registration_gates
    FOR EACH ROW EXECUTE FUNCTION onnuri_registration_satisfy_obligation()
    """)
    op.execute("""
    CREATE OR REPLACE FUNCTION onnuri_registration_obligation_guard()
    RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF TG_OP = 'UPDATE'
         AND (NEW.state, NEW.revoked_at, NEW.contained_at, NEW.terminal_at)
             IS NOT DISTINCT FROM
             (OLD.state, OLD.revoked_at, OLD.contained_at, OLD.terminal_at) THEN
        RETURN NEW;
      END IF;
      IF EXISTS (
        SELECT 1 FROM onnuri_registration_gates register_gate
        WHERE register_gate.envelope_id = OLD.id
          AND register_gate.operation_kind = 'register'
          AND register_gate.unregister_required
          AND register_gate.unregister_satisfied_at IS NULL
      ) THEN
        RAISE EXCEPTION 'onnuri registration compensation obligation is outstanding';
      END IF;
      IF TG_OP = 'DELETE' THEN
        RETURN OLD;
      END IF;
      RETURN NEW;
    END $$;
    """)
    op.execute("""
    CREATE FUNCTION onnuri_registration_attempt_terminal_guard()
    RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF NEW.state = 'terminal' AND OLD.state <> 'terminal' AND EXISTS (
        SELECT 1 FROM onnuri_registration_gates register_gate
        WHERE register_gate.envelope_id = NEW.envelope_id
          AND register_gate.operation_kind = 'register'
          AND register_gate.unregister_required
          AND register_gate.unregister_satisfied_at IS NULL
      ) THEN
        RAISE EXCEPTION 'onnuri registration compensation obligation is outstanding';
      END IF;
      RETURN NEW;
    END $$;
    """)
    op.execute("""
    CREATE TRIGGER trg_onnuri_registration_attempt_terminal_guard
    BEFORE UPDATE ON onnuri_staging_smoke_attempts
    FOR EACH ROW EXECUTE FUNCTION onnuri_registration_attempt_terminal_guard()
    """)


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS trg_onnuri_registration_attempt_terminal_guard "
        "ON onnuri_staging_smoke_attempts"
    )
    op.execute("DROP FUNCTION IF EXISTS onnuri_registration_attempt_terminal_guard()")
    op.execute(
        "DROP TRIGGER IF EXISTS trg_onnuri_registration_satisfy_obligation "
        "ON onnuri_registration_gates"
    )
    op.execute("DROP FUNCTION IF EXISTS onnuri_registration_satisfy_obligation()")
    op.execute("""
    CREATE OR REPLACE FUNCTION onnuri_registration_obligation_guard()
    RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM onnuri_registration_gates register_gate
        WHERE register_gate.envelope_id = OLD.id
          AND register_gate.operation_kind = 'register'
          AND register_gate.transaction_count = 1
          AND NOT EXISTS (
            SELECT 1 FROM onnuri_registration_gates unregister_gate
            WHERE unregister_gate.unregisters_gate_id = register_gate.id
              AND unregister_gate.operation_kind = 'unregister'
              AND unregister_gate.state = 'completed'
              AND unregister_gate.execution_attestation_digest IS NOT NULL
          )
      ) THEN
        RAISE EXCEPTION 'onnuri registration compensation obligation is outstanding';
      END IF;
      IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
      RETURN NEW;
    END $$;
    """)
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
    op.drop_constraint(
        "ck_onnuri_reg_consumed_obligation",
        "onnuri_registration_gates",
        type_="check",
    )
    op.drop_constraint(
        "ck_onnuri_reg_unregister_obligation",
        "onnuri_registration_gates",
        type_="check",
    )
    op.drop_constraint(
        "ck_onnuri_reg_terminal_wire_count",
        "onnuri_registration_gates",
        type_="check",
    )
    op.drop_constraint(
        "ck_onnuri_reg_wire_request_count",
        "onnuri_registration_gates",
        type_="check",
    )
    op.drop_column("onnuri_registration_gates", "wire_request_count")
    op.drop_column("onnuri_registration_gates", "unregister_satisfied_at")
    op.drop_column("onnuri_registration_gates", "unregister_required")
