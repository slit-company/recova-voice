"""permit only contained execution cleanup unregister transition

Revision ID: g4a5b6c7d8e9
Revises: f3a4b5c6d7e8
Create Date: 2026-07-21
"""

from alembic import op

revision = "g4a5b6c7d8e9"
down_revision = "f3a4b5c6d7e8"
branch_labels = None
depends_on = None



def _seal_guard() -> str:
    return """
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
            SELECT 1 FROM onnuri_registration_gates gate
            JOIN g008_execution_stages stage ON stage.id = gate.execution_stage_id
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
      IF OLD.started_at IS NOT NULL AND NEW.started_at IS DISTINCT FROM OLD.started_at THEN
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


def _stage_guard(*, contained_cleanup: bool) -> str:
    parent_states = "'running','cleanup_required','contained'" if contained_cleanup else "'running','cleanup_required'"
    return f"""
    CREATE OR REPLACE FUNCTION g008_execution_stage_guard() RETURNS trigger
    LANGUAGE plpgsql AS $$
    DECLARE parent g008_execution_seals%ROWTYPE; cleanup_start boolean;
    BEGIN
      SELECT * INTO parent FROM g008_execution_seals WHERE id = NEW.execution_seal_id;
      IF NOT FOUND OR ROW(NEW.organization_id, NEW.execution_nonce_digest, NEW.candidate_digest, NEW.gate_envelope_digest)
         IS DISTINCT FROM ROW(parent.organization_id, parent.execution_nonce_digest, parent.candidate_digest, parent.gate_envelope_digest) THEN
        RAISE EXCEPTION 'g008 stage binding does not match execution seal';
      END IF;
      IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'pending' THEN RAISE EXCEPTION 'g008 stage must begin pending'; END IF;
        RETURN NEW;
      END IF;
      IF ROW(NEW.stage_uuid, NEW.execution_seal_id, NEW.organization_id, NEW.execution_nonce_digest, NEW.candidate_digest, NEW.gate_envelope_digest, NEW.stage, NEW.ordinal)
         IS DISTINCT FROM ROW(OLD.stage_uuid, OLD.execution_seal_id, OLD.organization_id, OLD.execution_nonce_digest, OLD.candidate_digest, OLD.gate_envelope_digest, OLD.stage, OLD.ordinal) THEN
        RAISE EXCEPTION 'g008 stage identity is immutable';
      END IF;
      IF OLD.state IN ('succeeded','failed','contained') THEN RAISE EXCEPTION 'g008 terminal stage is immutable'; END IF;
      IF NOT (OLD.state = NEW.state OR (OLD.state = 'pending' AND NEW.state = 'started') OR (OLD.state = 'started' AND NEW.state IN ('succeeded','failed','contained'))) THEN
        RAISE EXCEPTION 'g008 stage transition is not forward-only';
      END IF;
      cleanup_start := NEW.ordinal = 4
        AND parent.state IN ({parent_states})
        AND EXISTS (
          SELECT 1
          FROM onnuri_registration_gates register_gate
          JOIN g008_execution_stages register_stage
            ON register_stage.id = register_gate.execution_stage_id
          WHERE register_stage.execution_seal_id = NEW.execution_seal_id
            AND register_stage.organization_id = NEW.organization_id
            AND register_stage.ordinal = 1
            AND register_gate.operation_kind = 'register'
            AND register_gate.transaction_count = 1
            AND register_gate.unregister_required
            AND register_gate.unregister_satisfied_at IS NULL
        );
      IF OLD.state = 'pending' AND NEW.state = 'started' AND (EXISTS (SELECT 1 FROM g008_execution_stages active WHERE active.execution_seal_id = NEW.execution_seal_id AND active.id <> NEW.id AND active.state = 'started') OR (NOT cleanup_start AND (parent.state NOT IN ('sealed','running') OR clock_timestamp() < parent.live_window_starts_at OR clock_timestamp() >= parent.live_window_expires_at OR EXISTS (SELECT 1 FROM g008_execution_stages prior WHERE prior.execution_seal_id = NEW.execution_seal_id AND prior.ordinal < NEW.ordinal AND prior.state <> 'succeeded')))) THEN
        RAISE EXCEPTION 'g008 stage start violates order or live authority';
      END IF;
      IF NEW.ordinal = 2 AND NEW.state = 'succeeded' AND NOT EXISTS (SELECT 1 FROM g008_outbound_bindings outbound WHERE outbound.execution_stage_id = NEW.id AND outbound.organization_id = NEW.organization_id AND outbound.terminal_class = NEW.terminal_class) THEN RAISE EXCEPTION 'g008 outbound stage success requires terminal observation'; END IF;
      IF NEW.ordinal = 3 AND NEW.state = 'succeeded' AND NEW.stock_call_id_digest IS NULL THEN RAISE EXCEPTION 'g008 inbound stage success requires bound stock call'; END IF;
      IF OLD.started_at IS NOT NULL AND NEW.started_at IS DISTINCT FROM OLD.started_at THEN RAISE EXCEPTION 'g008 stage start is immutable'; END IF;
      IF OLD.stock_call_id_digest IS NOT NULL AND ROW(NEW.account_uuid, NEW.application_uuid, NEW.run_uuid, NEW.attempt_uuid, NEW.stock_call_id_digest, NEW.idempotency_digest, NEW.request_digest, NEW.did_digest, NEW.caller_digest, NEW.authority_deadline_at, NEW.bound_at, NEW.bind_receipt_digest, NEW.bind_receipt_signature_digest) IS DISTINCT FROM ROW(OLD.account_uuid, OLD.application_uuid, OLD.run_uuid, OLD.attempt_uuid, OLD.stock_call_id_digest, OLD.idempotency_digest, OLD.request_digest, OLD.did_digest, OLD.caller_digest, OLD.authority_deadline_at, OLD.bound_at, OLD.bind_receipt_digest, OLD.bind_receipt_signature_digest) THEN RAISE EXCEPTION 'g008 inbound claim is write-once'; END IF;
      RETURN NEW;
    END;
    $$;
    """


def upgrade() -> None:
    op.execute(_seal_guard())
    op.execute(_stage_guard(contained_cleanup=True))


def downgrade() -> None:
    op.execute(_seal_guard())
    op.execute(_stage_guard(contained_cleanup=False))
