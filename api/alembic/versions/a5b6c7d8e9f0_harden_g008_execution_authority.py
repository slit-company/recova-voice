"""harden G008 execution authority and recoverable issuance

Revision ID: a5b6c7d8e9f0
Revises: f4a5b6c7d8e9
Create Date: 2026-07-18
"""

from alembic import op
import sqlalchemy as sa


revision = "a5b6c7d8e9f0"
down_revision = "f4a5b6c7d8e9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint(
        "ck_g008_execution_seal_state", "g008_execution_seals", type_="check"
    )
    op.create_check_constraint(
        "ck_g008_execution_seal_state",
        "g008_execution_seals",
        "state IN ('sealed','running','cleanup_required','residue_blocked',"
        "'contained','completed','failed')",
    )
    op.add_column(
        "g008_execution_seals",
        sa.Column("containment_evidence_canonical", sa.LargeBinary()),
    )
    op.add_column(
        "g008_execution_seals",
        sa.Column("containment_evidence_signature", sa.LargeBinary()),
    )
    op.add_column(
        "g008_execution_seals",
        sa.Column("final_evidence_canonical", sa.LargeBinary()),
    )
    op.add_column(
        "g008_execution_seals",
        sa.Column("final_evidence_signature", sa.LargeBinary()),
    )
    op.add_column(
        "g008_execution_stages",
        sa.Column("evidence_canonical", sa.LargeBinary()),
    )
    op.add_column(
        "g008_execution_stages",
        sa.Column("evidence_signature", sa.LargeBinary()),
    )
    op.create_check_constraint(
        "ck_g008_stage_execution_artifact",
        "g008_execution_stages",
        "(state IN ('pending','started') AND evidence_canonical IS NULL "
        "AND evidence_signature IS NULL) OR "
        "(state IN ('succeeded','failed','contained') "
        "AND octet_length(evidence_canonical) > 0 "
        "AND octet_length(evidence_signature) = 64 "
        "AND encode(sha256(evidence_canonical), 'hex') = evidence_digest "
        "AND encode(sha256(evidence_signature), 'hex') = evidence_signature_digest)",
    )
    op.create_check_constraint(
        "ck_g008_seal_final_artifact",
        "g008_execution_seals",
        "(final_evidence_canonical IS NULL AND final_evidence_signature IS NULL) OR "
        "(octet_length(final_evidence_canonical) > 0 "
        "AND octet_length(final_evidence_signature) = 64 "
        "AND encode(sha256(final_evidence_canonical), 'hex') = final_evidence_digest "
        "AND encode(sha256(final_evidence_signature), 'hex') = final_evidence_signature_digest)",
    )
    op.create_check_constraint(
        "ck_g008_seal_containment_artifact",
        "g008_execution_seals",
        "(containment_evidence_canonical IS NULL AND containment_evidence_signature IS NULL) OR "
        "(octet_length(containment_evidence_canonical) > 0 "
        "AND octet_length(containment_evidence_signature) = 64 "
        "AND encode(sha256(containment_evidence_canonical), 'hex') = containment_evidence_digest "
        "AND encode(sha256(containment_evidence_signature), 'hex') = containment_evidence_signature_digest)",
    )

    op.create_table(
        "g008_outbound_bindings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("organizations.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "execution_stage_id",
            sa.Integer(),
            sa.ForeignKey("g008_execution_stages.id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "smoke_attempt_id",
            sa.Integer(),
            sa.ForeignKey("onnuri_staging_smoke_attempts.id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column("account_uuid", sa.String(255), nullable=False),
        sa.Column("application_uuid", sa.String(255), nullable=False),
        sa.Column("stock_call_id_digest", sa.String(64), nullable=False, unique=True),
        sa.Column("authority_deadline_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("terminal_class", sa.String(64), nullable=False),
        sa.Column("terminal_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "bound_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("clock_timestamp()"),
        ),
        sa.CheckConstraint(
            "terminal_class = 'call_completed'",
            name="ck_g008_outbound_binding_completed",
        ),
        sa.CheckConstraint(
            "terminal_at <= authority_deadline_at "
            "AND bound_at >= terminal_at "
            "AND bound_at < authority_deadline_at",
            name="ck_g008_outbound_binding_timeline",
        ),
        sa.CheckConstraint(
            "stock_call_id_digest ~ '^[0-9a-f]{64}$'",
            name="ck_g008_outbound_binding_digest",
        ),
    )
    op.execute(
        """
        CREATE FUNCTION g008_outbound_binding_write_once_guard() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          IF TG_OP = 'INSERT' THEN
            PERFORM 1
            FROM onnuri_staging_smoke_callback_events callback_event
            WHERE callback_event.attempt_id = NEW.smoke_attempt_id
              AND callback_event.normalized_status = 'completed'
              AND callback_event.accepted_at = NEW.terminal_at
            FOR KEY SHARE;
            IF NOT FOUND THEN
              RAISE EXCEPTION 'g008 outbound binding callback provenance missing';
            END IF;
          END IF;
          IF TG_OP = 'UPDATE' THEN
            IF to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
              RAISE EXCEPTION 'g008 outbound binding is immutable';
            END IF;
          ELSIF NOT EXISTS (
            SELECT 1
            FROM g008_execution_stages stage
            JOIN g008_execution_seals seal
              ON seal.id = stage.execution_seal_id
            JOIN onnuri_staging_smoke_attempts attempt
              ON attempt.id = NEW.smoke_attempt_id
            JOIN onnuri_staging_smoke_envelopes envelope
              ON envelope.id = attempt.envelope_id
            JOIN onnuri_staging_smoke_callback_events callback_event
              ON callback_event.attempt_id = attempt.id
             AND callback_event.normalized_status = 'completed'
             AND callback_event.accepted_at = attempt.terminal_at
            WHERE stage.id = NEW.execution_stage_id
              AND stage.organization_id = NEW.organization_id
              AND stage.stage = 'outbound_call'
              AND stage.ordinal = 2
              AND stage.state = 'started'
              AND stage.started_at IS NOT NULL
              AND attempt.allocated_at >= stage.started_at
              AND seal.organization_id = NEW.organization_id
              AND seal.state = 'running'
              AND seal.candidate_digest = envelope.candidate_digest
              AND seal.gate_envelope_digest =
                  encode(sha256(convert_to(envelope.envelope_uuid, 'UTF8')), 'hex')
              AND seal.destination_hmac_digest = envelope.destination_hmac_digest
              AND attempt.organization_id = NEW.organization_id
              AND envelope.organization_id = NEW.organization_id
              AND attempt.direction = 'outbound'
              AND attempt.state = 'terminal'
              AND attempt.terminal_class = 'call_completed'
              AND attempt.dispatch_receipt_digest IS NOT NULL
              AND attempt.account_id = NEW.account_uuid
              AND attempt.application_id = NEW.application_uuid
              AND attempt.stock_call_id_digest = NEW.stock_call_id_digest
              AND attempt.authority_deadline_at = NEW.authority_deadline_at
              AND attempt.terminal_at = NEW.terminal_at
              AND attempt.terminal_at <= attempt.authority_deadline_at
              AND callback_event.accepted_at = NEW.terminal_at
              AND callback_event.accepted_at < NEW.authority_deadline_at
              AND NEW.bound_at >= callback_event.accepted_at
              AND NEW.bound_at < NEW.authority_deadline_at
              AND envelope.max_outbound_attempts = 1
              AND envelope.max_inbound_attempts = 1
              AND envelope.max_concurrency = 1
              AND envelope.retries = 0
              AND envelope.max_duration_seconds = 60
          ) THEN
            RAISE EXCEPTION 'g008 outbound binding authority mismatch';
          END IF;
          RETURN NEW;
        END;
        $$;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_g008_outbound_binding_write_once
        BEFORE INSERT OR UPDATE ON g008_outbound_bindings
        FOR EACH ROW EXECUTE FUNCTION g008_outbound_binding_write_once_guard();
        """
    )

    op.execute(
        """
        CREATE FUNCTION g008_registration_stage_required_guard() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          IF EXISTS (
            SELECT 1
            FROM onnuri_staging_smoke_envelopes envelope
            WHERE envelope.id = NEW.envelope_id
              AND envelope.evaluator_version = 'recova_onnuri_smoke_authority_v3'
          ) THEN
            IF NEW.execution_stage_id IS NULL OR NOT EXISTS (
              SELECT 1
              FROM onnuri_staging_smoke_envelopes envelope
              JOIN g008_execution_seals seal
                ON seal.organization_id = envelope.organization_id
               AND seal.candidate_digest = envelope.candidate_digest
               AND seal.gate_envelope_digest =
                   encode(sha256(convert_to(envelope.envelope_uuid, 'UTF8')), 'hex')
               AND seal.destination_hmac_digest = envelope.destination_hmac_digest
               AND seal.schema_version = 'recova-g008-execution-seal-v1'
               AND seal.retry_count = 0
               AND seal.concurrency_count = 1
               AND seal.call_deadline_seconds = 60
              JOIN g008_execution_stages stage
                ON stage.execution_seal_id = seal.id
               AND stage.organization_id = seal.organization_id
              WHERE envelope.id = NEW.envelope_id
                AND stage.id = NEW.execution_stage_id
                AND (
                  (
                    NEW.state IN ('pending', 'challenged')
                    AND stage.state = 'started'
                  )
                  OR
                  (
                    NEW.state IN ('completed', 'failed', 'contained')
                    AND stage.state = CASE NEW.state
                      WHEN 'completed' THEN 'succeeded'
                      ELSE NEW.state
                    END
                    AND NEW.failure_class = stage.state
                    AND NEW.terminal_at = stage.finalized_at
                    AND NEW.execution_attestation_digest = stage.evidence_digest
                    AND NEW.execution_attestation_signature_digest =
                        stage.evidence_signature_digest
                    AND NEW.execution_attestation_key_digest =
                        stage.evidence_key_digest
                    AND NEW.execution_attestation_key_id = stage.evidence_key_id
                  )
                )
                AND (
                  (NEW.operation_kind = 'register'
                   AND stage.stage = 'register' AND stage.ordinal = 1)
                  OR
                  (NEW.operation_kind = 'unregister'
                   AND stage.stage = 'unregister' AND stage.ordinal = 4)
                )
            ) THEN
              RAISE EXCEPTION 'G008 registration requires exact execution stage';
            END IF;
            IF NEW.retransmission_count <> 0
               OR (NEW.state = 'pending' AND NEW.transaction_count <> 0)
               OR (
                 NEW.state IN ('challenged','completed','failed','contained')
                 AND NEW.transaction_count <> 1
               ) THEN
              RAISE EXCEPTION 'G008 registration must have exact transaction and retry counts';
            END IF;
          END IF;
          RETURN NEW;
        END;
        $$;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_g008_registration_stage_required
        BEFORE INSERT OR UPDATE ON onnuri_registration_gates
        FOR EACH ROW EXECUTE FUNCTION g008_registration_stage_required_guard();
        """
    )

    op.add_column(
        "g008_inbound_bindings",
        sa.Column(
            "lease_expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now() + interval '15 seconds'"),
        ),
    )
    op.add_column(
        "g008_inbound_bindings",
        sa.Column(
            "issuance_attempt_count", sa.Integer(), nullable=False, server_default="1"
        ),
    )
    op.create_check_constraint(
        "ck_g008_inbound_binding_bound_before_deadline",
        "g008_inbound_bindings",
        "bound_at IS NULL OR bound_at < authority_deadline_at",
    )
    op.create_check_constraint(
        "ck_g008_inbound_stage_binding_deadline",
        "g008_execution_stages",
        "bound_at IS NULL OR bound_at < authority_deadline_at",
    )
    op.create_check_constraint(
        "ck_g008_inbound_binding_lease",
        "g008_inbound_bindings",
        "lease_expires_at <= authority_deadline_at AND issuance_attempt_count >= 1",
    )
    op.execute(
        """
        CREATE FUNCTION g008_execution_artifact_write_once_guard() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          IF OLD.evidence_canonical IS NOT NULL AND
             ROW(NEW.evidence_canonical, NEW.evidence_signature) IS DISTINCT FROM
             ROW(OLD.evidence_canonical, OLD.evidence_signature) THEN
            RAISE EXCEPTION 'g008 stage evidence artifact is immutable';
          END IF;
          RETURN NEW;
        END;
        $$;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_g008_execution_artifact_write_once
        BEFORE UPDATE ON g008_execution_stages
        FOR EACH ROW EXECUTE FUNCTION g008_execution_artifact_write_once_guard();
        """
    )


    op.execute(
        """
        CREATE OR REPLACE FUNCTION g008_execution_seal_guard() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          IF TG_OP = 'INSERT' THEN
            IF NEW.state <> 'sealed' OR NEW.started_at IS NOT NULL
               OR NEW.contained_at IS NOT NULL OR NEW.completed_at IS NOT NULL
               OR NEW.failed_at IS NOT NULL THEN
              RAISE EXCEPTION 'g008 execution seal must begin sealed';
            END IF;
            RETURN NEW;
          END IF;
          IF OLD.state IN ('contained','completed','failed','residue_blocked') THEN
            RAISE EXCEPTION 'g008 terminal execution is immutable';
          END IF;
          IF NOT (
            OLD.state = NEW.state
            OR (OLD.state = 'sealed' AND NEW.state IN
                ('running','contained','failed','cleanup_required'))
            OR (OLD.state = 'running' AND NEW.state IN
                ('contained','completed','failed','cleanup_required'))
            OR (OLD.state = 'cleanup_required' AND NEW.state IN
                ('failed','residue_blocked'))
            OR (
              OLD.state = 'cleanup_required' AND NEW.state = 'running'
              AND NOT EXISTS (
                SELECT 1
                FROM onnuri_registration_gates gate
                JOIN g008_execution_stages stage
                  ON stage.id = gate.execution_stage_id
                WHERE stage.execution_seal_id = NEW.id
                  AND gate.transaction_count = 1
                  AND gate.unregister_required
                  AND gate.unregister_satisfied_at IS NULL
              )
            )
          ) THEN
            RAISE EXCEPTION 'g008 execution transition is not forward-only';
          END IF;
          IF ROW(NEW.execution_seal_uuid, NEW.schema_version, NEW.organization_id,
                 NEW.execution_nonce_digest, NEW.candidate_digest,
                 NEW.gate_envelope_digest, NEW.destination_hmac_digest,
                 NEW.reserved_inbound_did_digest, NEW.reserved_inbound_caller_digest,
                 NEW.policy_digest, NEW.retry_count, NEW.concurrency_count,
                 NEW.call_deadline_seconds, NEW.live_window_starts_at,
                 NEW.live_window_expires_at, NEW.sealed_at, NEW.created_at)
             IS DISTINCT FROM
             ROW(OLD.execution_seal_uuid, OLD.schema_version, OLD.organization_id,
                 OLD.execution_nonce_digest, OLD.candidate_digest,
                 OLD.gate_envelope_digest, OLD.destination_hmac_digest,
                 OLD.reserved_inbound_did_digest, OLD.reserved_inbound_caller_digest,
                 OLD.policy_digest, OLD.retry_count, OLD.concurrency_count,
                 OLD.call_deadline_seconds, OLD.live_window_starts_at,
                 OLD.live_window_expires_at, OLD.sealed_at, OLD.created_at) THEN
            RAISE EXCEPTION 'g008 execution seal binding is immutable';
          END IF;
          IF OLD.started_at IS NOT NULL
             AND NEW.started_at IS DISTINCT FROM OLD.started_at THEN
            RAISE EXCEPTION 'g008 execution start is immutable';
          END IF;
          IF OLD.final_evidence_digest IS NOT NULL AND
             ROW(NEW.final_evidence_digest, NEW.final_evidence_signature_digest,
                 NEW.final_evidence_key_digest, NEW.final_evidence_canonical,
                 NEW.final_evidence_signature, NEW.completed_at)
             IS DISTINCT FROM
             ROW(OLD.final_evidence_digest, OLD.final_evidence_signature_digest,
                 OLD.final_evidence_key_digest, OLD.final_evidence_canonical,
                 OLD.final_evidence_signature, OLD.completed_at) THEN
            RAISE EXCEPTION 'g008 final evidence is write-once';
          END IF;
          RETURN NEW;
        END;
        $$;
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION g008_execution_stage_guard() RETURNS trigger
        LANGUAGE plpgsql AS $$
        DECLARE
          parent g008_execution_seals%ROWTYPE;
          cleanup_start boolean;
        BEGIN
          SELECT * INTO parent FROM g008_execution_seals
          WHERE id = NEW.execution_seal_id;
          IF NOT FOUND OR
             ROW(NEW.organization_id, NEW.execution_nonce_digest,
                 NEW.candidate_digest, NEW.gate_envelope_digest)
             IS DISTINCT FROM
             ROW(parent.organization_id, parent.execution_nonce_digest,
                 parent.candidate_digest, parent.gate_envelope_digest) THEN
            RAISE EXCEPTION 'g008 stage binding does not match execution seal';
          END IF;
          IF TG_OP = 'INSERT' THEN
            IF NEW.state <> 'pending' THEN
              RAISE EXCEPTION 'g008 stage must begin pending';
            END IF;
            RETURN NEW;
          END IF;
          IF ROW(NEW.stage_uuid, NEW.execution_seal_id, NEW.organization_id,
                 NEW.execution_nonce_digest, NEW.candidate_digest,
                 NEW.gate_envelope_digest, NEW.stage, NEW.ordinal)
             IS DISTINCT FROM
             ROW(OLD.stage_uuid, OLD.execution_seal_id, OLD.organization_id,
                 OLD.execution_nonce_digest, OLD.candidate_digest,
                 OLD.gate_envelope_digest, OLD.stage, OLD.ordinal) THEN
            RAISE EXCEPTION 'g008 stage identity is immutable';
          END IF;
          IF OLD.state IN ('succeeded','failed','contained') THEN
            RAISE EXCEPTION 'g008 terminal stage is immutable';
          END IF;
          IF NOT (
            OLD.state = NEW.state
            OR (OLD.state = 'pending' AND NEW.state = 'started')
            OR (OLD.state = 'started'
                AND NEW.state IN ('succeeded','failed','contained'))
          ) THEN
            RAISE EXCEPTION 'g008 stage transition is not forward-only';
          END IF;
          cleanup_start := NEW.ordinal = 4
            AND parent.state IN ('running','cleanup_required')
            AND EXISTS (
              SELECT 1
              FROM onnuri_registration_gates gate
              JOIN g008_execution_stages register_stage
                ON register_stage.id = gate.execution_stage_id
              WHERE register_stage.execution_seal_id = NEW.execution_seal_id
                AND register_stage.ordinal = 1
                AND gate.transaction_count = 1
                AND gate.unregister_required
                AND gate.unregister_satisfied_at IS NULL
            );
          IF OLD.state = 'pending' AND NEW.state = 'started' AND (
            EXISTS (
              SELECT 1 FROM g008_execution_stages active
              WHERE active.execution_seal_id = NEW.execution_seal_id
                AND active.id <> NEW.id AND active.state = 'started'
            )
            OR (
              NOT cleanup_start AND (
                parent.state NOT IN ('sealed','running')
                OR clock_timestamp() < parent.live_window_starts_at
                OR clock_timestamp() >= parent.live_window_expires_at
                OR EXISTS (
                  SELECT 1 FROM g008_execution_stages prior
                  WHERE prior.execution_seal_id = NEW.execution_seal_id
                    AND prior.ordinal < NEW.ordinal
                    AND prior.state <> 'succeeded'
                )
              )
            )
          ) THEN
            RAISE EXCEPTION 'g008 stage start violates order or live authority';
          END IF;
          IF NEW.ordinal = 2 AND NEW.state = 'succeeded'
             AND NOT EXISTS (
               SELECT 1 FROM g008_outbound_bindings outbound
               WHERE outbound.execution_stage_id = NEW.id
                 AND outbound.organization_id = NEW.organization_id
                 AND outbound.terminal_class = NEW.terminal_class
             ) THEN
            RAISE EXCEPTION 'g008 outbound stage success requires terminal observation';
          END IF;
          IF NEW.ordinal = 3 AND NEW.state = 'succeeded'
             AND NEW.stock_call_id_digest IS NULL THEN
            RAISE EXCEPTION 'g008 inbound stage success requires bound stock call';
          END IF;
          IF OLD.started_at IS NOT NULL
             AND NEW.started_at IS DISTINCT FROM OLD.started_at THEN
            RAISE EXCEPTION 'g008 stage start is immutable';
          END IF;
          IF OLD.stock_call_id_digest IS NOT NULL AND
             ROW(NEW.account_uuid, NEW.application_uuid, NEW.run_uuid,
                 NEW.attempt_uuid, NEW.stock_call_id_digest,
                 NEW.idempotency_digest, NEW.request_digest, NEW.did_digest,
                 NEW.caller_digest, NEW.authority_deadline_at, NEW.bound_at,
                 NEW.bind_receipt_digest, NEW.bind_receipt_signature_digest)
             IS DISTINCT FROM
             ROW(OLD.account_uuid, OLD.application_uuid, OLD.run_uuid,
                 OLD.attempt_uuid, OLD.stock_call_id_digest,
                 OLD.idempotency_digest, OLD.request_digest, OLD.did_digest,
                 OLD.caller_digest, OLD.authority_deadline_at, OLD.bound_at,
                 OLD.bind_receipt_digest, OLD.bind_receipt_signature_digest) THEN
            RAISE EXCEPTION 'g008 inbound claim is write-once';
          END IF;
          RETURN NEW;
        END;
        $$;
        """
    )

def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS trg_g008_registration_stage_required "
        "ON onnuri_registration_gates"
    )
    op.execute("DROP FUNCTION IF EXISTS g008_registration_stage_required_guard()")
    op.drop_constraint(
        "ck_g008_inbound_stage_binding_deadline",
        "g008_execution_stages",
        type_="check",
    )
    op.drop_constraint(
        "ck_g008_inbound_binding_bound_before_deadline",
        "g008_inbound_bindings",
        type_="check",
    )
    op.execute(
        "DROP TRIGGER IF EXISTS trg_g008_execution_artifact_write_once ON g008_execution_stages"
    )
    op.execute("DROP FUNCTION IF EXISTS g008_execution_artifact_write_once_guard()")
    op.drop_constraint(
        "ck_g008_inbound_binding_lease", "g008_inbound_bindings", type_="check"
    )
    op.drop_column("g008_inbound_bindings", "issuance_attempt_count")
    op.drop_column("g008_inbound_bindings", "lease_expires_at")
    op.execute(
        "DROP TRIGGER IF EXISTS trg_g008_outbound_binding_write_once ON g008_outbound_bindings"
    )
    op.execute("DROP FUNCTION IF EXISTS g008_outbound_binding_write_once_guard()")
    op.drop_table("g008_outbound_bindings")
    op.drop_constraint(
        "ck_g008_seal_containment_artifact", "g008_execution_seals", type_="check"
    )
    op.drop_constraint(
        "ck_g008_seal_final_artifact", "g008_execution_seals", type_="check"
    )
    op.drop_constraint(
        "ck_g008_stage_execution_artifact", "g008_execution_stages", type_="check"
    )
    op.drop_column("g008_execution_stages", "evidence_signature")
    op.drop_column("g008_execution_stages", "evidence_canonical")
    op.drop_column("g008_execution_seals", "final_evidence_signature")
    op.drop_column("g008_execution_seals", "final_evidence_canonical")
    op.drop_column("g008_execution_seals", "containment_evidence_signature")
    op.drop_column("g008_execution_seals", "containment_evidence_canonical")
    op.drop_constraint(
        "ck_g008_execution_seal_state", "g008_execution_seals", type_="check"
    )
    op.create_check_constraint(
        "ck_g008_execution_seal_state",
        "g008_execution_seals",
        "state IN ('sealed','running','contained','completed','failed')",
    )
