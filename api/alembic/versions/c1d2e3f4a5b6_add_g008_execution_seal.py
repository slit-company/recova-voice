"""add DB-backed G008 execution seal

Revision ID: c1d2e3f4a5b6
Revises: b0c1d2e3f4a5
"""

from alembic import op
import sqlalchemy as sa


revision = "c1d2e3f4a5b6"
down_revision = "b0c1d2e3f4a5"
branch_labels = None
depends_on = None

_DIGEST = "VALUE ~ '^[0-9a-f]{64}$'"


def _digest_check(column: str) -> sa.CheckConstraint:
    return sa.CheckConstraint(
        _DIGEST.replace("VALUE", column), name=f"ck_g008_{column}_sha256"
    )


def upgrade() -> None:
    op.create_table(
        "g008_execution_seals",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("execution_seal_uuid", sa.String(36), nullable=False, unique=True, server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("schema_version", sa.String(64), nullable=False, server_default="recova-g008-execution-seal-v1"),
        sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("execution_nonce_digest", sa.String(64), nullable=False, unique=True),
        sa.Column("candidate_digest", sa.String(64), nullable=False),
        sa.Column("gate_envelope_digest", sa.String(64), nullable=False),
        sa.Column("destination_hmac_digest", sa.String(64), nullable=False),
        sa.Column("reserved_inbound_did_digest", sa.String(64), nullable=False),
        sa.Column("reserved_inbound_caller_digest", sa.String(64), nullable=False),
        sa.Column("policy_digest", sa.String(64), nullable=False),
        sa.Column("retry_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("concurrency_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("call_deadline_seconds", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("state", sa.String(16), nullable=False, server_default="sealed"),
        sa.Column("live_window_starts_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("live_window_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("sealed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("containment_class", sa.String(64)),
        sa.Column("containment_evidence_digest", sa.String(64)),
        sa.Column("containment_evidence_signature_digest", sa.String(64)),
        sa.Column("containment_evidence_key_digest", sa.String(64)),
        sa.Column("contained_at", sa.DateTime(timezone=True)),
        sa.Column("final_evidence_digest", sa.String(64)),
        sa.Column("final_evidence_signature_digest", sa.String(64)),
        sa.Column("final_evidence_key_digest", sa.String(64)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("failed_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint("execution_seal_uuid ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'", name="ck_g008_execution_seal_uuid"),
        sa.CheckConstraint("schema_version = 'recova-g008-execution-seal-v1'", name="ck_g008_execution_seal_schema"),
        sa.CheckConstraint("retry_count = 0 AND concurrency_count = 1 AND call_deadline_seconds = 60", name="ck_g008_execution_seal_policy"),
        sa.CheckConstraint("state IN ('sealed','running','contained','completed','failed')", name="ck_g008_execution_seal_state"),
        sa.CheckConstraint("live_window_starts_at < live_window_expires_at AND sealed_at < live_window_expires_at", name="ck_g008_execution_seal_window"),
        sa.CheckConstraint("(state = 'contained' AND contained_at IS NOT NULL AND containment_class IS NOT NULL AND containment_evidence_digest IS NOT NULL AND containment_evidence_signature_digest IS NOT NULL AND containment_evidence_key_digest IS NOT NULL) OR (state <> 'contained' AND contained_at IS NULL AND containment_class IS NULL AND containment_evidence_digest IS NULL AND containment_evidence_signature_digest IS NULL AND containment_evidence_key_digest IS NULL)", name="ck_g008_execution_seal_containment"),
        sa.CheckConstraint("(state = 'completed' AND completed_at IS NOT NULL AND final_evidence_digest IS NOT NULL AND final_evidence_signature_digest IS NOT NULL AND final_evidence_key_digest IS NOT NULL) OR (state <> 'completed' AND completed_at IS NULL AND final_evidence_digest IS NULL AND final_evidence_signature_digest IS NULL AND final_evidence_key_digest IS NULL)", name="ck_g008_execution_seal_final_evidence"),
        sa.CheckConstraint("(state = 'failed') = (failed_at IS NOT NULL)", name="ck_g008_execution_seal_failure"),
        sa.CheckConstraint("(containment_evidence_digest IS NULL OR containment_evidence_digest ~ '^[0-9a-f]{64}$') AND (containment_evidence_signature_digest IS NULL OR containment_evidence_signature_digest ~ '^[0-9a-f]{64}$') AND (containment_evidence_key_digest IS NULL OR containment_evidence_key_digest ~ '^[0-9a-f]{64}$') AND (final_evidence_digest IS NULL OR final_evidence_digest ~ '^[0-9a-f]{64}$') AND (final_evidence_signature_digest IS NULL OR final_evidence_signature_digest ~ '^[0-9a-f]{64}$') AND (final_evidence_key_digest IS NULL OR final_evidence_key_digest ~ '^[0-9a-f]{64}$')", name="ck_g008_execution_seal_evidence_digests"),
        *[_digest_check(name) for name in (
            "execution_nonce_digest", "candidate_digest", "gate_envelope_digest",
            "destination_hmac_digest", "reserved_inbound_did_digest",
            "reserved_inbound_caller_digest", "policy_digest",
        )],
    )
    op.create_index(
        "ix_g008_execution_seal_inbound_reservation",
        "g008_execution_seals",
        ["organization_id", "reserved_inbound_did_digest", "reserved_inbound_caller_digest", "candidate_digest", "gate_envelope_digest"],
        postgresql_where=sa.text("state IN ('sealed','running')"),
    )

    op.create_table(
        "g008_execution_stages",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("stage_uuid", sa.String(36), nullable=False, unique=True, server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("execution_seal_id", sa.Integer(), sa.ForeignKey("g008_execution_seals.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("execution_nonce_digest", sa.String(64), nullable=False),
        sa.Column("candidate_digest", sa.String(64), nullable=False),
        sa.Column("gate_envelope_digest", sa.String(64), nullable=False),
        sa.Column("stage", sa.String(32), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("terminal_class", sa.String(64)),
        sa.Column("evidence_digest", sa.String(64)),
        sa.Column("evidence_signature_digest", sa.String(64)),
        sa.Column("evidence_key_digest", sa.String(64)),
        sa.Column("finalized_at", sa.DateTime(timezone=True)),
        sa.Column("account_uuid", sa.String(36)),
        sa.Column("application_uuid", sa.String(36)),
        sa.Column("run_uuid", sa.String(36)),
        sa.Column("attempt_uuid", sa.String(36)),
        sa.Column("stock_call_id_digest", sa.String(64)),
        sa.Column("idempotency_digest", sa.String(64)),
        sa.Column("request_digest", sa.String(64)),
        sa.Column("did_digest", sa.String(64)),
        sa.Column("caller_digest", sa.String(64)),
        sa.Column("authority_deadline_at", sa.DateTime(timezone=True)),
        sa.Column("bound_at", sa.DateTime(timezone=True)),
        sa.Column("bind_receipt_digest", sa.String(64)),
        sa.Column("bind_receipt_signature_digest", sa.String(64)),
        sa.UniqueConstraint("execution_seal_id", "ordinal", name="uq_g008_execution_stage_ordinal"),
        sa.UniqueConstraint("execution_seal_id", "stage", name="uq_g008_execution_stage_kind"),
        sa.UniqueConstraint("stock_call_id_digest", name="uq_g008_execution_stage_stock_call"),
        sa.CheckConstraint("stage_uuid ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'", name="ck_g008_execution_stage_uuid"),
        sa.CheckConstraint("(ordinal = 1 AND stage = 'register') OR (ordinal = 2 AND stage = 'outbound_call') OR (ordinal = 3 AND stage = 'inbound_call') OR (ordinal = 4 AND stage = 'unregister')", name="ck_g008_execution_stage_order"),
        sa.CheckConstraint("state IN ('pending','started','succeeded','failed','contained')", name="ck_g008_execution_stage_state"),
        sa.CheckConstraint("(state = 'pending') = (started_at IS NULL)", name="ck_g008_execution_stage_started"),
        sa.CheckConstraint("(state IN ('pending','started') AND finalized_at IS NULL AND terminal_class IS NULL AND evidence_digest IS NULL AND evidence_signature_digest IS NULL AND evidence_key_digest IS NULL) OR (state IN ('succeeded','failed','contained') AND finalized_at IS NOT NULL AND terminal_class IS NOT NULL AND evidence_digest IS NOT NULL AND evidence_signature_digest IS NOT NULL AND evidence_key_digest IS NOT NULL)", name="ck_g008_execution_stage_terminal"),
        sa.CheckConstraint("(stock_call_id_digest IS NULL AND account_uuid IS NULL AND application_uuid IS NULL AND run_uuid IS NULL AND attempt_uuid IS NULL AND idempotency_digest IS NULL AND request_digest IS NULL AND did_digest IS NULL AND caller_digest IS NULL AND authority_deadline_at IS NULL AND bound_at IS NULL AND bind_receipt_digest IS NULL AND bind_receipt_signature_digest IS NULL) OR (stock_call_id_digest IS NOT NULL AND account_uuid IS NOT NULL AND application_uuid IS NOT NULL AND run_uuid IS NOT NULL AND attempt_uuid IS NOT NULL AND idempotency_digest IS NOT NULL AND request_digest IS NOT NULL AND did_digest IS NOT NULL AND caller_digest IS NOT NULL AND authority_deadline_at IS NOT NULL AND bound_at IS NOT NULL AND bind_receipt_digest IS NOT NULL AND bind_receipt_signature_digest IS NOT NULL)", name="ck_g008_execution_stage_inbound_binding"),
        sa.CheckConstraint("(evidence_digest IS NULL OR evidence_digest ~ '^[0-9a-f]{64}$') AND (evidence_signature_digest IS NULL OR evidence_signature_digest ~ '^[0-9a-f]{64}$') AND (evidence_key_digest IS NULL OR evidence_key_digest ~ '^[0-9a-f]{64}$') AND (stock_call_id_digest IS NULL OR stock_call_id_digest ~ '^[0-9a-f]{64}$') AND (idempotency_digest IS NULL OR idempotency_digest ~ '^[0-9a-f]{64}$') AND (request_digest IS NULL OR request_digest ~ '^[0-9a-f]{64}$') AND (did_digest IS NULL OR did_digest ~ '^[0-9a-f]{64}$') AND (caller_digest IS NULL OR caller_digest ~ '^[0-9a-f]{64}$') AND (bind_receipt_digest IS NULL OR bind_receipt_digest ~ '^[0-9a-f]{64}$') AND (bind_receipt_signature_digest IS NULL OR bind_receipt_signature_digest ~ '^[0-9a-f]{64}$')", name="ck_g008_execution_stage_digests"),
        sa.CheckConstraint("stock_call_id_digest IS NULL OR (stage = 'inbound_call' AND ordinal = 3 AND state <> 'pending')", name="ck_g008_execution_stage_inbound_only"),
    )
    op.create_index("ix_g008_execution_stage_seal_order", "g008_execution_stages", ["execution_seal_id", "ordinal"])

    op.execute("""
    CREATE FUNCTION g008_execution_seal_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'sealed' OR NEW.started_at IS NOT NULL OR NEW.contained_at IS NOT NULL
           OR NEW.completed_at IS NOT NULL OR NEW.failed_at IS NOT NULL THEN
          RAISE EXCEPTION 'g008 execution seal must begin sealed';
        END IF;
        RETURN NEW;
      END IF;
      IF (NEW.execution_seal_uuid, NEW.schema_version, NEW.organization_id,
          NEW.execution_nonce_digest, NEW.candidate_digest, NEW.gate_envelope_digest,
          NEW.destination_hmac_digest, NEW.reserved_inbound_did_digest,
          NEW.reserved_inbound_caller_digest, NEW.policy_digest, NEW.retry_count,
          NEW.concurrency_count, NEW.call_deadline_seconds, NEW.live_window_starts_at,
          NEW.live_window_expires_at, NEW.sealed_at, NEW.created_at) IS DISTINCT FROM
         (OLD.execution_seal_uuid, OLD.schema_version, OLD.organization_id,
          OLD.execution_nonce_digest, OLD.candidate_digest, OLD.gate_envelope_digest,
          OLD.destination_hmac_digest, OLD.reserved_inbound_did_digest,
          OLD.reserved_inbound_caller_digest, OLD.policy_digest, OLD.retry_count,
          OLD.concurrency_count, OLD.call_deadline_seconds, OLD.live_window_starts_at,
          OLD.live_window_expires_at, OLD.sealed_at, OLD.created_at) THEN
        RAISE EXCEPTION 'g008 execution seal binding is immutable';
      END IF;
      IF OLD.state IN ('contained','completed','failed') THEN
        RAISE EXCEPTION 'g008 terminal execution is immutable';
      END IF;
      IF NOT ((OLD.state = 'sealed' AND NEW.state IN ('running','contained','failed')) OR
              (OLD.state = 'running' AND NEW.state IN ('contained','completed','failed')) OR
              OLD.state = NEW.state) THEN
        RAISE EXCEPTION 'g008 execution transition is not forward-only';
      END IF;
      IF OLD.started_at IS NOT NULL AND NEW.started_at IS DISTINCT FROM OLD.started_at THEN
        RAISE EXCEPTION 'g008 execution start is immutable';
      END IF;
      IF OLD.final_evidence_digest IS NOT NULL AND
         (NEW.final_evidence_digest, NEW.final_evidence_signature_digest,
          NEW.final_evidence_key_digest, NEW.completed_at) IS DISTINCT FROM
         (OLD.final_evidence_digest, OLD.final_evidence_signature_digest,
          OLD.final_evidence_key_digest, OLD.completed_at) THEN
        RAISE EXCEPTION 'g008 final evidence is write-once';
      END IF;
      RETURN NEW;
    END $$;
    """)
    op.execute("""
    CREATE TRIGGER trg_g008_execution_seal_guard BEFORE INSERT OR UPDATE
      ON g008_execution_seals FOR EACH ROW EXECUTE FUNCTION g008_execution_seal_guard();
    """)
    op.execute("""
    CREATE FUNCTION g008_execution_stage_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE parent g008_execution_seals%ROWTYPE;
    BEGIN
      SELECT * INTO parent FROM g008_execution_seals WHERE id = NEW.execution_seal_id;
      IF NOT FOUND OR (NEW.organization_id, NEW.execution_nonce_digest,
          NEW.candidate_digest, NEW.gate_envelope_digest) IS DISTINCT FROM
         (parent.organization_id, parent.execution_nonce_digest,
          parent.candidate_digest, parent.gate_envelope_digest) THEN
        RAISE EXCEPTION 'g008 stage binding does not match execution seal';
      END IF;
      IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'pending' THEN RAISE EXCEPTION 'g008 stage must begin pending'; END IF;
        RETURN NEW;
      END IF;
      IF (NEW.stage_uuid, NEW.execution_seal_id, NEW.organization_id,
          NEW.execution_nonce_digest, NEW.candidate_digest, NEW.gate_envelope_digest,
          NEW.stage, NEW.ordinal) IS DISTINCT FROM
         (OLD.stage_uuid, OLD.execution_seal_id, OLD.organization_id,
          OLD.execution_nonce_digest, OLD.candidate_digest, OLD.gate_envelope_digest,
          OLD.stage, OLD.ordinal) THEN
        RAISE EXCEPTION 'g008 stage identity is immutable';
      END IF;
      IF OLD.state IN ('succeeded','failed','contained') THEN
        RAISE EXCEPTION 'g008 terminal stage is immutable';
      END IF;
      IF NOT ((OLD.state = 'pending' AND NEW.state = 'started') OR
              (OLD.state = 'started' AND NEW.state IN ('succeeded','failed','contained')) OR
              OLD.state = NEW.state) THEN
        RAISE EXCEPTION 'g008 stage transition is not forward-only';
      END IF;
      IF OLD.state = 'pending' AND NEW.state = 'started' AND (
          parent.state NOT IN ('sealed','running')
          OR clock_timestamp() < parent.live_window_starts_at
          OR clock_timestamp() >= parent.live_window_expires_at
          OR EXISTS (
            SELECT 1 FROM g008_execution_stages prior
            WHERE prior.execution_seal_id = NEW.execution_seal_id
              AND prior.ordinal < NEW.ordinal AND prior.state <> 'succeeded'
          )
          OR EXISTS (
            SELECT 1 FROM g008_execution_stages active
            WHERE active.execution_seal_id = NEW.execution_seal_id
              AND active.id <> NEW.id AND active.state = 'started'
          )
      ) THEN
        RAISE EXCEPTION 'g008 stage start violates order or live authority';
      END IF;
      IF OLD.state = 'pending' AND NEW.state = 'started'
         AND parent.state = 'sealed' THEN
        UPDATE g008_execution_seals
        SET state = 'running', started_at = NEW.started_at
        WHERE id = parent.id;
        parent.state := 'running';
      END IF;
      IF NEW.ordinal = 3 AND NEW.state = 'succeeded'
         AND NEW.stock_call_id_digest IS NULL THEN
        RAISE EXCEPTION 'g008 inbound stage success requires bound stock call';
      END IF;
      IF OLD.stock_call_id_digest IS NULL
         AND NEW.stock_call_id_digest IS NOT NULL AND (
           OLD.state <> 'started'
           OR parent.state <> 'running'
           OR NEW.did_digest IS DISTINCT FROM parent.reserved_inbound_did_digest
           OR NEW.caller_digest IS DISTINCT FROM parent.reserved_inbound_caller_digest
           OR clock_timestamp() < parent.live_window_starts_at
           OR clock_timestamp() >= parent.live_window_expires_at
         ) THEN
        RAISE EXCEPTION 'g008 inbound claim is not live or reservation-bound';
      END IF;
      IF OLD.started_at IS NOT NULL AND NEW.started_at IS DISTINCT FROM OLD.started_at THEN
        RAISE EXCEPTION 'g008 stage start is immutable';
      END IF;
      IF OLD.stock_call_id_digest IS NOT NULL AND
         (NEW.account_uuid, NEW.application_uuid, NEW.run_uuid, NEW.attempt_uuid,
          NEW.stock_call_id_digest, NEW.idempotency_digest, NEW.request_digest,
          NEW.did_digest, NEW.caller_digest, NEW.authority_deadline_at, NEW.bound_at,
          NEW.bind_receipt_digest, NEW.bind_receipt_signature_digest) IS DISTINCT FROM
         (OLD.account_uuid, OLD.application_uuid, OLD.run_uuid, OLD.attempt_uuid,
          OLD.stock_call_id_digest, OLD.idempotency_digest, OLD.request_digest,
          OLD.did_digest, OLD.caller_digest, OLD.authority_deadline_at, OLD.bound_at,
          OLD.bind_receipt_digest, OLD.bind_receipt_signature_digest) THEN
        RAISE EXCEPTION 'g008 inbound claim is write-once';
      END IF;
      RETURN NEW;
    END $$;
    """)
    op.execute("""
    CREATE TRIGGER trg_g008_execution_stage_guard BEFORE INSERT OR UPDATE
      ON g008_execution_stages FOR EACH ROW EXECUTE FUNCTION g008_execution_stage_guard();
    """)
    op.execute("""
    CREATE FUNCTION g008_execution_delete_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      RAISE EXCEPTION 'g008 execution ledger rows are immutable';
    END $$;
    """)
    op.execute("""
    CREATE TRIGGER trg_g008_execution_stage_delete_guard
      BEFORE DELETE ON g008_execution_stages
      FOR EACH ROW EXECUTE FUNCTION g008_execution_delete_guard();
    """)
    op.execute("""
    CREATE TRIGGER trg_g008_execution_seal_delete_guard
      BEFORE DELETE ON g008_execution_seals
      FOR EACH ROW EXECUTE FUNCTION g008_execution_delete_guard();
    """)
    op.execute("""
    CREATE FUNCTION g008_execution_exact_stages_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF (SELECT count(*) FROM g008_execution_stages WHERE execution_seal_id = NEW.id) <> 4 THEN
        RAISE EXCEPTION 'g008 execution requires exactly four stages';
      END IF;
      RETURN NULL;
    END $$;
    """)
    op.execute("""
    CREATE CONSTRAINT TRIGGER trg_g008_execution_exact_stages
      AFTER INSERT ON g008_execution_seals DEFERRABLE INITIALLY DEFERRED
      FOR EACH ROW EXECUTE FUNCTION g008_execution_exact_stages_guard();
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_g008_execution_seal_delete_guard ON g008_execution_seals")
    op.execute("DROP TRIGGER IF EXISTS trg_g008_execution_stage_delete_guard ON g008_execution_stages")
    op.execute("DROP FUNCTION IF EXISTS g008_execution_delete_guard()")
    op.execute("DROP TRIGGER IF EXISTS trg_g008_execution_exact_stages ON g008_execution_seals")
    op.execute("DROP FUNCTION IF EXISTS g008_execution_exact_stages_guard()")
    op.execute("DROP TRIGGER IF EXISTS trg_g008_execution_stage_guard ON g008_execution_stages")
    op.execute("DROP FUNCTION IF EXISTS g008_execution_stage_guard()")
    op.execute("DROP TRIGGER IF EXISTS trg_g008_execution_seal_guard ON g008_execution_seals")
    op.execute("DROP FUNCTION IF EXISTS g008_execution_seal_guard()")
    op.drop_index("ix_g008_execution_stage_seal_order", table_name="g008_execution_stages")
    op.drop_table("g008_execution_stages")
    op.drop_index("ix_g008_execution_seal_inbound_reservation", table_name="g008_execution_seals")
    op.drop_table("g008_execution_seals")
