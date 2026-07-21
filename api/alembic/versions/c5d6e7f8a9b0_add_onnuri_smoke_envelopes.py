"""add versioned Onnuri smoke authority envelopes

Revision ID: c5d6e7f8a9b0
Revises: b4d5e6f7a8b9
"""

from alembic import op
import sqlalchemy as sa

revision = "c5d6e7f8a9b0"
down_revision = "b4d5e6f7a8b9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "onnuri_staging_smoke_envelopes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("envelope_uuid", sa.String(36), nullable=False, unique=True, server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("evaluator_version", sa.String(64), nullable=False),
        sa.Column("proof_id", sa.Integer(), sa.ForeignKey("onnuri_staging_preflight_proofs.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("inventory_id", sa.Integer(), sa.ForeignKey("telephony_number_inventory.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("telephony_configuration_id", sa.Integer(), sa.ForeignKey("telephony_configurations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("workflow_id", sa.Integer(), sa.ForeignKey("workflows.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("destination_hmac_key_id", sa.String(255), nullable=False),
        sa.Column("destination_hmac_domain", sa.String(128), nullable=False, server_default="recova.onnuri.smoke.destination.v1"),
        sa.Column("destination_hmac_key_version", sa.String(128), nullable=False),
        sa.Column("destination_hmac_digest", sa.String(128), nullable=False),
        sa.Column("dispatch_key_id", sa.String(255), nullable=False),
        sa.Column("dispatch_algorithm_policy_id", sa.String(128), nullable=False),
        sa.Column("dispatch_domain", sa.String(128), nullable=False),
        sa.Column("media_key_id", sa.String(255), nullable=False),
        sa.Column("media_algorithm_policy_id", sa.String(128), nullable=False),
        sa.Column("media_domain", sa.String(128), nullable=False),
        sa.Column("policy_digest", sa.String(64), nullable=False),
        sa.Column("candidate_digest", sa.String(128), nullable=False),
        sa.Column("phase_b_manifest_digest", sa.String(128), nullable=False),
        sa.Column("phase_c_iac_digest", sa.String(128), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("max_inbound_attempts", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("max_outbound_attempts", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("max_duration_seconds", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("max_concurrency", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("cps", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("retries", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("state", sa.String(32), nullable=False, server_default="armed"),
        sa.Column("live_window_starts_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("live_window_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("destroy_deadline", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("contained_at", sa.DateTime(timezone=True)),
        sa.Column("terminal_at", sa.DateTime(timezone=True)),
        sa.Column("containment_reason", sa.String(128)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint("evaluator_version = 'recova_onnuri_smoke_authority_v2'", name="ck_onnuri_smoke_evaluator"),
        sa.CheckConstraint("max_attempts = 3 AND max_inbound_attempts = 1 AND max_outbound_attempts = 1", name="ck_onnuri_smoke_attempt_limits"),
        sa.CheckConstraint("max_duration_seconds = 60 AND max_concurrency = 1 AND cps = 1 AND retries = 0", name="ck_onnuri_smoke_runtime_limits"),
        sa.CheckConstraint("dispatch_key_id <> media_key_id AND dispatch_domain <> media_domain", name="ck_onnuri_smoke_key_separation"),
        sa.CheckConstraint("destination_hmac_domain = 'recova.onnuri.smoke.destination.v1'", name="ck_onnuri_smoke_destination_domain"),
        sa.CheckConstraint("live_window_starts_at < live_window_expires_at AND live_window_expires_at <= expires_at AND expires_at <= destroy_deadline", name="ck_onnuri_smoke_windows"),
    )
    op.create_index("uq_onnuri_smoke_active_envelope", "onnuri_staging_smoke_envelopes", ["organization_id"], unique=True, postgresql_where=sa.text("state = 'armed'"))

    op.create_table(
        "onnuri_staging_smoke_attempts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("attempt_uuid", sa.String(36), nullable=False, unique=True, server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("envelope_id", sa.Integer(), sa.ForeignKey("onnuri_staging_smoke_envelopes.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("proof_id", sa.Integer(), sa.ForeignKey("onnuri_staging_preflight_proofs.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("inventory_id", sa.Integer(), sa.ForeignKey("telephony_number_inventory.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("telephony_configuration_id", sa.Integer(), sa.ForeignKey("telephony_configurations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("workflow_id", sa.Integer(), sa.ForeignKey("workflows.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("direction", sa.String(16), nullable=False),
        sa.Column("state", sa.String(64), nullable=False, server_default="allocated"),
        sa.Column("authenticated_operator_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("workflow_owner_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("allocation_request_digest", sa.String(128), nullable=False),
        sa.Column("manual_acknowledgement_digest", sa.String(128)),
        sa.Column("manual_acknowledged_at", sa.DateTime(timezone=True)),
        sa.Column("dispatch_receipt_digest", sa.String(128)),
        sa.Column("stock_call_id_digest", sa.String(128), unique=True),
        sa.Column("bind_callback_nonce_digest", sa.String(128)),
        sa.Column("inbound_tuple_digest", sa.String(64)),
        sa.Column("stock_bound_at", sa.DateTime(timezone=True)),
        sa.Column("authority_kind", sa.String(64)),
        sa.Column("authority_wall_at", sa.DateTime(timezone=True)),
        sa.Column("authority_deadline_at", sa.DateTime(timezone=True)),
        sa.Column("authority_budget_seconds", sa.Integer()),
        sa.Column("observed_carrier_answer_at", sa.DateTime(timezone=True)),
        sa.Column("terminal_class", sa.String(64)),
        sa.Column("terminal_reason", sa.String(128)),
        sa.Column("allocated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("terminal_at", sa.DateTime(timezone=True)),
        sa.Column("contained_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("envelope_id", "ordinal", name="uq_onnuri_smoke_attempt_ordinal"),
        sa.UniqueConstraint("envelope_id", "idempotency_key", name="uq_onnuri_smoke_attempt_idempotency"),
        sa.CheckConstraint("ordinal BETWEEN 1 AND 3", name="ck_onnuri_smoke_attempt_ordinal"),
        sa.CheckConstraint("direction IN ('inbound','outbound')", name="ck_onnuri_smoke_attempt_direction"),
        sa.CheckConstraint("direction = 'inbound' OR inbound_tuple_digest IS NULL", name="ck_onnuri_smoke_inbound_tuple_direction"),
        sa.CheckConstraint("authority_budget_seconds IS NULL OR authority_budget_seconds BETWEEN 1 AND 60", name="ck_onnuri_smoke_authority_budget"),
        sa.CheckConstraint("(manual_acknowledgement_digest IS NULL) = (manual_acknowledged_at IS NULL)", name="ck_onnuri_smoke_manual_ack_pair"),
    )
    op.create_index("uq_onnuri_smoke_one_active_attempt", "onnuri_staging_smoke_attempts", ["envelope_id"], unique=True, postgresql_where=sa.text("state NOT IN ('terminal','contained')"))

    op.create_table(
        "onnuri_staging_capability_consumptions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("attempt_id", sa.Integer(), sa.ForeignKey("onnuri_staging_smoke_attempts.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("domain", sa.String(128), nullable=False),
        sa.Column("key_id", sa.String(255), nullable=False),
        sa.Column("algorithm_policy_id", sa.String(128), nullable=False),
        sa.Column("nonce_digest", sa.String(128), nullable=False),
        sa.Column("token_digest", sa.String(128), nullable=False),
        sa.Column("request_digest", sa.String(128), nullable=False),
        sa.Column("receipt_digest", sa.String(128), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True)),
        sa.Column("encrypted_issue_recovery", sa.Text()),
        sa.Column("encrypted_consume_recovery", sa.Text()),
        sa.Column("consume_response_digest", sa.String(128)),
        sa.Column("recovery_erased_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("kind", "key_id", "nonce_digest", name="uq_onnuri_smoke_cap_nonce"),
        sa.UniqueConstraint("attempt_id", "kind", name="uq_onnuri_smoke_attempt_cap"),
        sa.CheckConstraint("kind IN ('dispatch','media')", name="ck_onnuri_smoke_cap_kind"),
        sa.CheckConstraint("issued_at < expires_at", name="ck_onnuri_smoke_cap_expiry"),
    )

    op.create_table(
        "onnuri_staging_answer_authorizations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("attempt_id", sa.Integer(), sa.ForeignKey("onnuri_staging_smoke_attempts.id", ondelete="RESTRICT"), nullable=False, unique=True),
        sa.Column("direction", sa.String(16), nullable=False),
        sa.Column("authority_kind", sa.String(64), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False, unique=True),
        sa.Column("callback_nonce_digest", sa.String(128), nullable=False, unique=True),
        sa.Column("canonical_request_digest", sa.String(128), nullable=False),
        sa.Column("canonical_response_digest", sa.String(128), nullable=False),
        sa.Column("encrypted_response_recovery", sa.Text()),
        sa.Column("committed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("budget_seconds", sa.Integer(), nullable=False),
        sa.Column("approved_pause_milliseconds", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("observed_carrier_answer_at", sa.DateTime(timezone=True)),
        sa.Column("recovery_erased_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("authority_kind IN ('outbound_observed_answer','inbound_preanswer_commit')", name="ck_onnuri_smoke_answer_kind"),
        sa.CheckConstraint("budget_seconds BETWEEN 1 AND 60", name="ck_onnuri_smoke_answer_budget"),
        sa.CheckConstraint("approved_pause_milliseconds >= 0", name="ck_onnuri_smoke_answer_pause"),
    )

    op.create_table(
        "onnuri_registration_gates",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("envelope_id", sa.Integer(), sa.ForeignKey("onnuri_staging_smoke_envelopes.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("operation_uuid", sa.String(36), nullable=False, unique=True, server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("operation_kind", sa.String(16), nullable=False),
        sa.Column("unregisters_gate_id", sa.Integer(), sa.ForeignKey("onnuri_registration_gates.id", ondelete="RESTRICT")),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("request_digest", sa.String(128), nullable=False),
        sa.Column("challenge_digest", sa.String(128)),
        sa.Column("transaction_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("retransmission_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("requested_expires_seconds", sa.Integer()),
        sa.Column("accepted_expires_at", sa.DateTime(timezone=True)),
        sa.Column("failure_class", sa.String(64)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("terminal_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("operation_kind IN ('register','unregister')", name="ck_onnuri_reg_kind"),
        sa.CheckConstraint("state IN ('pending','challenged','completed','failed','contained')", name="ck_onnuri_reg_state"),
        sa.CheckConstraint("transaction_count BETWEEN 0 AND 2", name="ck_onnuri_reg_transactions"),
        sa.CheckConstraint("retransmission_count >= 0", name="ck_onnuri_reg_retransmits"),
    )

    for table in ("onnuri_staging_preflight_authorization_leases", "onnuri_staging_smoke_dispatch_attempts"):
        op.add_column(table, sa.Column("evaluator_version", sa.String(64)))
        op.add_column(table, sa.Column("smoke_envelope_id", sa.Integer(), sa.ForeignKey("onnuri_staging_smoke_envelopes.id", ondelete="RESTRICT")))
        op.add_column(table, sa.Column("smoke_attempt_id", sa.Integer(), sa.ForeignKey("onnuri_staging_smoke_attempts.id", ondelete="RESTRICT")))
        op.add_column(table, sa.Column("authenticated_operator_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="RESTRICT")))
        op.add_column(table, sa.Column("workflow_owner_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="RESTRICT")))
        op.add_column(table, sa.Column("evaluator_idempotency_key", sa.String(128)))
        op.create_check_constraint(
            f"ck_{table}_v2_linkage", table,
            "((evaluator_version IS NULL OR evaluator_version = 'recova_onnuri_staging_policy_v1') "
            "AND smoke_envelope_id IS NULL AND smoke_attempt_id IS NULL "
            "AND authenticated_operator_user_id IS NULL AND workflow_owner_user_id IS NULL "
            "AND evaluator_idempotency_key IS NULL) OR "
            "(evaluator_version = 'recova_onnuri_smoke_authority_v2' "
            "AND smoke_envelope_id IS NOT NULL AND smoke_attempt_id IS NOT NULL "
            "AND authenticated_operator_user_id IS NOT NULL "
            "AND workflow_owner_user_id IS NOT NULL "
            "AND evaluator_idempotency_key IS NOT NULL)"
        )

    op.execute("""
    CREATE FUNCTION onnuri_smoke_immutable_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF OLD.evaluator_version = 'recova_onnuri_smoke_authority_v2' AND
         (NEW.evaluator_version, NEW.smoke_envelope_id, NEW.smoke_attempt_id,
          NEW.authenticated_operator_user_id, NEW.workflow_owner_user_id,
          NEW.evaluator_idempotency_key) IS DISTINCT FROM
         (OLD.evaluator_version, OLD.smoke_envelope_id, OLD.smoke_attempt_id,
          OLD.authenticated_operator_user_id, OLD.workflow_owner_user_id,
          OLD.evaluator_idempotency_key) THEN
        RAISE EXCEPTION 'onnuri smoke evaluator linkage is immutable';
      END IF;
      RETURN NEW;
    END $$;
    """)
    for table in ("onnuri_staging_preflight_authorization_leases", "onnuri_staging_smoke_dispatch_attempts"):
        op.execute(f"CREATE TRIGGER trg_{table}_smoke_immutable BEFORE UPDATE ON {table} FOR EACH ROW EXECUTE FUNCTION onnuri_smoke_immutable_guard()")
    op.execute("""
    CREATE FUNCTION onnuri_smoke_legacy_linkage_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF NEW.evaluator_version = 'recova_onnuri_smoke_authority_v2' AND NOT EXISTS (
        SELECT 1
        FROM onnuri_staging_smoke_attempts a
        JOIN onnuri_staging_smoke_envelopes e ON e.id = a.envelope_id
        WHERE a.id = NEW.smoke_attempt_id
          AND e.id = NEW.smoke_envelope_id
          AND a.organization_id = NEW.organization_id
          AND a.proof_id = NEW.proof_id
          AND a.authenticated_operator_user_id = NEW.authenticated_operator_user_id
          AND a.workflow_owner_user_id = NEW.workflow_owner_user_id
          AND a.idempotency_key = NEW.evaluator_idempotency_key
      ) THEN
        RAISE EXCEPTION 'onnuri smoke evaluator tenant tuple mismatch';
      END IF;
      RETURN NEW;
    END $$;
    """)
    for table in ("onnuri_staging_preflight_authorization_leases", "onnuri_staging_smoke_dispatch_attempts"):
        op.execute(
            f"CREATE TRIGGER trg_{table}_smoke_linkage BEFORE INSERT OR UPDATE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION onnuri_smoke_legacy_linkage_guard()"
        )
    op.execute("""
    CREATE FUNCTION onnuri_smoke_authority_row_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE old_fixed jsonb; new_fixed jsonb;
    BEGIN
      IF TG_TABLE_NAME = 'onnuri_staging_smoke_envelopes' THEN
        old_fixed := to_jsonb(OLD) - ARRAY['state','revoked_at','contained_at','terminal_at','containment_reason'];
        new_fixed := to_jsonb(NEW) - ARRAY['state','revoked_at','contained_at','terminal_at','containment_reason'];
      ELSIF TG_TABLE_NAME = 'onnuri_staging_smoke_attempts' THEN
        old_fixed := to_jsonb(OLD) - ARRAY['state','dispatch_receipt_digest','stock_call_id_digest','bind_callback_nonce_digest','inbound_tuple_digest','stock_bound_at','authority_kind','authority_wall_at','authority_deadline_at','authority_budget_seconds','observed_carrier_answer_at','terminal_class','terminal_reason','terminal_at','contained_at'];
        new_fixed := to_jsonb(NEW) - ARRAY['state','dispatch_receipt_digest','stock_call_id_digest','bind_callback_nonce_digest','inbound_tuple_digest','stock_bound_at','authority_kind','authority_wall_at','authority_deadline_at','authority_budget_seconds','observed_carrier_answer_at','terminal_class','terminal_reason','terminal_at','contained_at'];
      ELSIF TG_TABLE_NAME = 'onnuri_staging_capability_consumptions' THEN
        old_fixed := to_jsonb(OLD) - ARRAY['consumed_at','encrypted_issue_recovery','encrypted_consume_recovery','consume_response_digest','recovery_erased_at'];
        new_fixed := to_jsonb(NEW) - ARRAY['consumed_at','encrypted_issue_recovery','encrypted_consume_recovery','consume_response_digest','recovery_erased_at'];
      ELSE
        old_fixed := to_jsonb(OLD) - ARRAY['recovery_erased_at','encrypted_response_recovery'];
        new_fixed := to_jsonb(NEW) - ARRAY['recovery_erased_at','encrypted_response_recovery'];
      END IF;
      IF old_fixed IS DISTINCT FROM new_fixed THEN
        RAISE EXCEPTION 'onnuri smoke authority row is immutable';
      END IF;
      IF TG_TABLE_NAME = 'onnuri_staging_smoke_envelopes' THEN
        IF (NEW.state, NEW.revoked_at, NEW.contained_at, NEW.terminal_at,
            NEW.containment_reason) IS DISTINCT FROM
           (OLD.state, OLD.revoked_at, OLD.contained_at, OLD.terminal_at,
            OLD.containment_reason) AND NOT (
          OLD.state = 'armed' AND NEW.state = 'contained'
          AND OLD.revoked_at IS NULL AND OLD.contained_at IS NULL
          AND OLD.terminal_at IS NULL AND NEW.revoked_at IS NULL
          AND NEW.contained_at IS NOT NULL AND NEW.terminal_at IS NULL
          AND COALESCE(btrim(NEW.containment_reason), '') <> ''
        ) THEN
          RAISE EXCEPTION 'onnuri smoke envelope lifecycle is forward-only';
        END IF;
      END IF;
      IF TG_TABLE_NAME = 'onnuri_staging_smoke_attempts' THEN
        IF OLD.state IS DISTINCT FROM NEW.state THEN
          IF NEW.state IN ('terminal', 'contained') THEN
            IF OLD.state IN ('terminal', 'contained')
               OR NEW.terminal_class IS NULL
               OR NEW.terminal_reason IS NULL
               OR NEW.terminal_at IS NULL
               OR (NEW.state = 'terminal' AND NEW.contained_at IS NOT NULL)
               OR (NEW.state = 'contained' AND NEW.contained_at IS NULL) THEN
              RAISE EXCEPTION 'onnuri smoke attempt terminal transition is invalid';
            END IF;
          ELSIF NOT (
            (OLD.direction = 'outbound' AND OLD.state = 'allocated'
             AND NEW.state = 'dispatch_issuing')
            OR (OLD.direction = 'outbound' AND OLD.state = 'dispatch_issuing'
                AND NEW.state = 'dispatch_issued')
            OR (OLD.direction = 'outbound' AND OLD.state = 'dispatch_issued'
                AND NEW.state = 'dispatch_consumed')
            OR (OLD.direction = 'outbound' AND OLD.state = 'dispatch_consumed'
                AND NEW.state = 'stock_bound')
            OR (OLD.direction = 'inbound' AND OLD.state = 'allocated'
                AND NEW.state = 'stock_bound')
            OR (OLD.state = 'stock_bound' AND NEW.state = 'media_issuing')
            OR (OLD.direction = 'outbound' AND OLD.state = 'media_issuing'
                AND NEW.state = 'outbound_answer_recorded_media_issued'
                AND NEW.authority_kind = 'outbound_observed_answer')
            OR (OLD.direction = 'inbound' AND OLD.state = 'media_issuing'
                AND NEW.state = 'inbound_answer_committed_media_issued'
                AND NEW.authority_kind = 'inbound_preanswer_commit')
            OR (OLD.state IN (
                  'outbound_answer_recorded_media_issued',
                  'inbound_answer_committed_media_issued'
                ) AND NEW.state = 'running')
          ) OR (NEW.terminal_class, NEW.terminal_reason, NEW.terminal_at,
                NEW.contained_at) IS DISTINCT FROM
               (OLD.terminal_class, OLD.terminal_reason, OLD.terminal_at,
                OLD.contained_at) THEN
            RAISE EXCEPTION 'onnuri smoke attempt lifecycle is forward-only';
          END IF;
        ELSIF (NEW.terminal_class, NEW.terminal_reason, NEW.terminal_at,
               NEW.contained_at) IS DISTINCT FROM
              (OLD.terminal_class, OLD.terminal_reason, OLD.terminal_at,
               OLD.contained_at) THEN
          RAISE EXCEPTION 'onnuri smoke attempt terminal evidence is immutable';
        END IF;
        IF ((OLD.dispatch_receipt_digest IS NOT NULL AND
             NEW.dispatch_receipt_digest IS DISTINCT FROM OLD.dispatch_receipt_digest) OR
            (OLD.stock_call_id_digest IS NOT NULL AND
             NEW.stock_call_id_digest IS DISTINCT FROM OLD.stock_call_id_digest) OR
            (OLD.bind_callback_nonce_digest IS NOT NULL AND
             NEW.bind_callback_nonce_digest IS DISTINCT FROM
             OLD.bind_callback_nonce_digest) OR
            (OLD.inbound_tuple_digest IS NOT NULL AND
             NEW.inbound_tuple_digest IS DISTINCT FROM OLD.inbound_tuple_digest) OR
            (OLD.stock_bound_at IS NOT NULL AND
             NEW.stock_bound_at IS DISTINCT FROM OLD.stock_bound_at) OR
            (OLD.authority_kind IS NOT NULL AND
             (NEW.authority_kind, NEW.authority_wall_at, NEW.authority_deadline_at,
              NEW.authority_budget_seconds, NEW.observed_carrier_answer_at)
             IS DISTINCT FROM
             (OLD.authority_kind, OLD.authority_wall_at, OLD.authority_deadline_at,
              OLD.authority_budget_seconds, OLD.observed_carrier_answer_at)) OR
            (OLD.authority_kind IS NULL AND NEW.authority_kind IS NULL AND
             NEW.observed_carrier_answer_at IS DISTINCT FROM
             OLD.observed_carrier_answer_at) OR
            (NEW.authority_kind = 'outbound_observed_answer' AND
             NEW.observed_carrier_answer_at IS DISTINCT FROM NEW.authority_wall_at) OR
            (NEW.authority_kind IS DISTINCT FROM 'outbound_observed_answer' AND
             NEW.observed_carrier_answer_at IS NOT NULL)) THEN
          RAISE EXCEPTION 'onnuri smoke issuance, binding and authority are write-once';
        END IF;
      END IF;
      IF TG_TABLE_NAME = 'onnuri_staging_answer_authorizations' THEN
        IF NOT (
          (NEW.encrypted_response_recovery, NEW.recovery_erased_at) IS NOT DISTINCT FROM
          (OLD.encrypted_response_recovery, OLD.recovery_erased_at)
          OR
          (OLD.encrypted_response_recovery IS NOT NULL AND
           OLD.recovery_erased_at IS NULL AND
           NEW.encrypted_response_recovery IS NULL AND
           NEW.recovery_erased_at IS NOT NULL)
        ) THEN
          RAISE EXCEPTION 'onnuri smoke recovery material is erase-only';
        END IF;
      END IF;
      IF TG_TABLE_NAME = 'onnuri_staging_capability_consumptions' THEN
        IF NOT (
          NEW.consumed_at IS NOT DISTINCT FROM OLD.consumed_at
          OR (OLD.consumed_at IS NULL AND NEW.consumed_at IS NOT NULL)
        ) THEN
          RAISE EXCEPTION 'onnuri smoke capability consumption is write-once';
        END IF;
        IF NOT (
          (NEW.encrypted_issue_recovery, NEW.encrypted_consume_recovery,
           NEW.consume_response_digest, NEW.recovery_erased_at) IS NOT DISTINCT FROM
          (OLD.encrypted_issue_recovery, OLD.encrypted_consume_recovery,
           OLD.consume_response_digest, OLD.recovery_erased_at)
          OR
          (OLD.recovery_erased_at IS NULL AND NEW.recovery_erased_at IS NOT NULL AND
           NEW.encrypted_issue_recovery IS NULL AND
           NEW.encrypted_consume_recovery IS NULL AND
           NEW.consume_response_digest IS NOT DISTINCT FROM OLD.consume_response_digest)
          OR
          (NEW.encrypted_issue_recovery IS NOT DISTINCT FROM OLD.encrypted_issue_recovery AND
           OLD.encrypted_consume_recovery IS NULL AND
           OLD.consume_response_digest IS NULL AND
           NEW.encrypted_consume_recovery IS NOT NULL AND
           NEW.consume_response_digest IS NOT NULL AND
           NEW.recovery_erased_at IS NULL)
        ) THEN
          RAISE EXCEPTION 'onnuri smoke capability recovery material is write-once or erase-only';
        END IF;
      END IF;
      RETURN NEW;
    END $$;
    """)
    for table in (
        "onnuri_staging_smoke_envelopes",
        "onnuri_staging_smoke_attempts",
        "onnuri_staging_capability_consumptions",
        "onnuri_staging_answer_authorizations",
    ):
        op.execute(
            f"CREATE TRIGGER trg_{table}_authority_immutable BEFORE UPDATE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION onnuri_smoke_authority_row_guard()"
        )
    op.execute("""
    CREATE FUNCTION onnuri_smoke_no_delete_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      RAISE EXCEPTION 'onnuri smoke authority history cannot be deleted';
    END $$;
    """)
    for table in (
        "onnuri_staging_smoke_envelopes",
        "onnuri_staging_smoke_attempts",
        "onnuri_staging_capability_consumptions",
        "onnuri_staging_answer_authorizations",
        "onnuri_registration_gates",
    ):
        op.execute(
            f"CREATE TRIGGER trg_{table}_no_delete BEFORE DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION onnuri_smoke_no_delete_guard()"
        )


def downgrade() -> None:
    for table in (
        "onnuri_registration_gates",
        "onnuri_staging_answer_authorizations",
        "onnuri_staging_capability_consumptions",
        "onnuri_staging_smoke_attempts",
        "onnuri_staging_smoke_envelopes",
    ):
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_no_delete ON {table}")
    op.execute("DROP FUNCTION IF EXISTS onnuri_smoke_no_delete_guard()")
    for table in (
        "onnuri_staging_answer_authorizations",
        "onnuri_staging_capability_consumptions",
        "onnuri_staging_smoke_attempts",
        "onnuri_staging_smoke_envelopes",
    ):
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_authority_immutable ON {table}")
    op.execute("DROP FUNCTION IF EXISTS onnuri_smoke_authority_row_guard()")
    for table in ("onnuri_staging_smoke_dispatch_attempts", "onnuri_staging_preflight_authorization_leases"):
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_smoke_linkage ON {table}")
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_smoke_immutable ON {table}")
        op.drop_constraint(f"ck_{table}_v2_linkage", table, type_="check")
        for column in ("evaluator_idempotency_key", "workflow_owner_user_id", "authenticated_operator_user_id", "smoke_attempt_id", "smoke_envelope_id", "evaluator_version"):
            op.drop_column(table, column)
    op.execute("DROP FUNCTION IF EXISTS onnuri_smoke_legacy_linkage_guard()")
    op.execute("DROP FUNCTION IF EXISTS onnuri_smoke_immutable_guard()")
    op.drop_table("onnuri_registration_gates")
    op.drop_table("onnuri_staging_answer_authorizations")
    op.drop_table("onnuri_staging_capability_consumptions")
    op.drop_index("uq_onnuri_smoke_one_active_attempt", table_name="onnuri_staging_smoke_attempts")
    op.drop_table("onnuri_staging_smoke_attempts")
    op.drop_index("uq_onnuri_smoke_active_envelope", table_name="onnuri_staging_smoke_envelopes")
    op.drop_table("onnuri_staging_smoke_envelopes")
