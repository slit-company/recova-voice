"""add Onnuri staging preflight persistence

Revision ID: b4d5e6f7a8b9
Revises: f2a4b6c8d0e1
Create Date: 2026-07-13 16:45:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "b4d5e6f7a8b9"
down_revision: Union[str, Sequence[str], None] = "f2a4b6c8d0e1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_constraint(
        "uq_telephony_number_inventory_provider_address",
        "telephony_number_inventory",
        type_="unique",
    )
    op.create_index(
        "uq_telephony_number_inventory_provider_address_active",
        "telephony_number_inventory",
        ["provider", "address_normalized"],
        unique=True,
        postgresql_where=sa.text("status != 'retired'"),
    )
    op.alter_column(
        "telephony_number_inventory_audit",
        "action",
        existing_type=sa.String(length=32),
        type_=sa.String(length=64),
        existing_nullable=False,
    )
    op.create_table(
        "onnuri_staging_candidates",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("candidate_uuid", sa.String(length=36), nullable=False, unique=True, server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("inventory_id", sa.Integer(), sa.ForeignKey("telephony_number_inventory.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False, server_default="jambonz"),
        sa.Column("normalized_did", sa.String(length=255), nullable=False),
        sa.Column("classification", sa.String(length=64), nullable=False, server_default="onnuri_staging_candidate_v1"),
        sa.Column("environment", sa.String(length=32), nullable=False, server_default="staging"),
        sa.Column("state", sa.String(length=32), nullable=False, server_default="active"),
        sa.Column("retired_at", sa.DateTime(timezone=True)),
        sa.Column("retired_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("retired_reason", sa.Text()),
        sa.Column("created_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index(
        "uq_onnuri_staging_candidate_active_inventory",
        "onnuri_staging_candidates",
        ["inventory_id"],
        unique=True,
        postgresql_where=sa.text("state = 'active'"),
    )
    op.create_index(
        "uq_onnuri_staging_candidate_active_provider_did_environment",
        "onnuri_staging_candidates",
        ["provider", "normalized_did", "environment"],
        unique=True,
        postgresql_where=sa.text("state = 'active'"),
    )
    op.create_table(
        "onnuri_staging_preflight_proofs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("candidate_id", sa.Integer(), sa.ForeignKey("onnuri_staging_candidates.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("inventory_id", sa.Integer(), sa.ForeignKey("telephony_number_inventory.id", ondelete="SET NULL")),
        sa.Column("scope_key", sa.String(length=255), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False, server_default="jambonz"),
        sa.Column("environment", sa.String(length=32), nullable=False, server_default="staging"),
        sa.Column("onboarding_kind", sa.String(length=64), nullable=False, server_default="onnuri_staging_preflight_v1"),
        sa.Column("canonical_input", sa.JSON(), nullable=False),
        sa.Column("canonical_hash", sa.String(length=64), nullable=False),
        sa.Column("approved", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("passed", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("predicate_class", sa.String(length=64), nullable=False),
        sa.Column("evaluator", sa.String(length=128)),
        sa.Column("signer", sa.String(length=128)),
        sa.Column("approved_at", sa.DateTime(timezone=True)),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("revoke_reason", sa.Text()),
        sa.Column("invalidated_at", sa.DateTime(timezone=True)),
        sa.Column("invalidated_reason", sa.Text()),
        sa.Column("is_current", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("scope_key", "revision", name="uq_onnuri_preflight_scope_revision"),
    )
    op.create_index("uq_onnuri_preflight_current_scope", "onnuri_staging_preflight_proofs", ["scope_key"], unique=True, postgresql_where=sa.text("is_current"))
    op.create_index("uq_onnuri_preflight_current_inventory", "onnuri_staging_preflight_proofs", ["inventory_id"], unique=True, postgresql_where=sa.text("inventory_id IS NOT NULL AND is_current"))
    for name, columns in (
        ("ix_onnuri_preflight_candidate", ["candidate_id"]),
        ("ix_onnuri_preflight_org", ["organization_id"]),
        ("ix_onnuri_preflight_expiry", ["expires_at"]),
        ("ix_onnuri_preflight_hash", ["canonical_hash"]),
    ):
        op.create_index(name, "onnuri_staging_preflight_proofs", columns)
    op.create_table(
        "onnuri_staging_preflight_expiry_jobs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("proof_id", sa.Integer(), sa.ForeignKey("onnuri_staging_preflight_proofs.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False, server_default="scheduled"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("leased_at", sa.DateTime(timezone=True)),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("failed_at", sa.DateTime(timezone=True)),
        sa.Column("error", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_onnuri_preflight_expiry_job_state_run_at", "onnuri_staging_preflight_expiry_jobs", ["state", "run_at"])
    op.create_table(
        "onnuri_staging_preflight_authorization_leases",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("lease_uuid", sa.String(length=36), nullable=False, unique=True, server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("proof_id", sa.Integer(), sa.ForeignKey("onnuri_staging_preflight_proofs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("inventory_id", sa.Integer(), sa.ForeignKey("telephony_number_inventory.id", ondelete="CASCADE"), nullable=False),
        sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("actor_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("attempt_kind", sa.String(length=16), nullable=False),
        sa.Column("application_attempt_id", sa.String(length=128), nullable=False, unique=True),
        sa.Column("state", sa.String(length=16), nullable=False, server_default="active"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True)),
        sa.Column("invalidated_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_onnuri_preflight_lease_proof_state", "onnuri_staging_preflight_authorization_leases", ["proof_id", "state", "created_at"])
    op.create_index("ix_onnuri_preflight_lease_expiry", "onnuri_staging_preflight_authorization_leases", ["state", "expires_at"])
    op.create_table(
        "onnuri_staging_smoke_dispatch_attempts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("application_attempt_id", sa.String(length=128), nullable=False, unique=True),
        sa.Column("lease_id", sa.Integer(), sa.ForeignKey("onnuri_staging_preflight_authorization_leases.id", ondelete="RESTRICT"), nullable=False, unique=True),
        sa.Column("proof_id", sa.Integer(), sa.ForeignKey("onnuri_staging_preflight_proofs.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("inventory_id", sa.Integer(), sa.ForeignKey("telephony_number_inventory.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("attempt_kind", sa.String(length=16), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False, server_default="pending"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("dispatched_at", sa.DateTime(timezone=True)),
        sa.Column("failed_at", sa.DateTime(timezone=True)),
        sa.Column("failure_reason", sa.Text()),
    )
    op.create_index("ix_onnuri_smoke_dispatch_org_state", "onnuri_staging_smoke_dispatch_attempts", ["organization_id", "state", "created_at"])
    op.add_column("telephony_number_inventory", sa.Column("onnuri_staging_candidate_id", sa.Integer(), nullable=True))
    op.add_column("telephony_number_inventory", sa.Column("onnuri_preflight_proof_id", sa.Integer(), nullable=True))
    op.add_column("telephony_number_inventory", sa.Column("onnuri_preflight_proof_hash", sa.String(length=64), nullable=True))
    op.create_foreign_key("fk_inventory_onnuri_candidate", "telephony_number_inventory", "onnuri_staging_candidates", ["onnuri_staging_candidate_id"], ["id"], ondelete="SET NULL")
    op.create_foreign_key("fk_inventory_onnuri_proof", "telephony_number_inventory", "onnuri_staging_preflight_proofs", ["onnuri_preflight_proof_id"], ["id"], ondelete="SET NULL")
    op.execute("""
        CREATE FUNCTION protect_onnuri_staging_candidate() RETURNS trigger AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'onnuri_staging_candidate_delete_forbidden';
          END IF;
          IF OLD.candidate_uuid IS DISTINCT FROM NEW.candidate_uuid
             OR OLD.inventory_id IS DISTINCT FROM NEW.inventory_id
             OR OLD.provider IS DISTINCT FROM NEW.provider
             OR OLD.normalized_did IS DISTINCT FROM NEW.normalized_did
             OR OLD.classification IS DISTINCT FROM NEW.classification
             OR OLD.environment IS DISTINCT FROM NEW.environment
             OR OLD.created_by_user_id IS DISTINCT FROM NEW.created_by_user_id
             OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
            RAISE EXCEPTION 'onnuri_staging_candidate_immutable';
          END IF;
          IF OLD.state <> NEW.state AND NOT (
            OLD.state = 'active' AND NEW.state = 'retired'
            AND current_setting('recova.onnuri_candidate_lifecycle', true) = 'retire'
          ) THEN
            RAISE EXCEPTION 'onnuri_staging_candidate_invalid_lifecycle';
          END IF;
          IF NEW.state = 'retired' AND (
            NEW.retired_at IS NULL OR NEW.retired_by_user_id IS NULL
            OR NEW.retired_reason IS NULL OR btrim(NEW.retired_reason) = ''
          ) THEN
            RAISE EXCEPTION 'onnuri_staging_candidate_retirement_provenance_required';
          END IF;
          IF NEW.state = 'active' AND (
            NEW.retired_at IS NOT NULL OR NEW.retired_by_user_id IS NOT NULL
            OR NEW.retired_reason IS NOT NULL
          ) THEN
            RAISE EXCEPTION 'onnuri_staging_candidate_active_state_inconsistent';
          END IF;
          IF OLD.state = 'retired' AND (
            OLD.retired_at IS DISTINCT FROM NEW.retired_at
            OR OLD.retired_by_user_id IS DISTINCT FROM NEW.retired_by_user_id
            OR OLD.retired_reason IS DISTINCT FROM NEW.retired_reason
          ) THEN
            RAISE EXCEPTION 'onnuri_staging_candidate_retirement_immutable';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)
    op.execute("""
        CREATE TRIGGER protect_onnuri_staging_candidate_trigger
        BEFORE UPDATE OR DELETE ON onnuri_staging_candidates
        FOR EACH ROW EXECUTE FUNCTION protect_onnuri_staging_candidate();
    """)
    op.execute("""
        CREATE FUNCTION protect_onnuri_staging_preflight_proof() RETURNS trigger AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'onnuri_staging_preflight_proof_delete_forbidden';
          END IF;
          IF OLD.is_current = false AND NEW.is_current = true THEN
            RAISE EXCEPTION 'onnuri_staging_preflight_proof_reactivation_forbidden';
          END IF;
          IF OLD.revoked_at IS NOT NULL AND (
            NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
            OR NEW.revoked_by_user_id IS DISTINCT FROM OLD.revoked_by_user_id
            OR NEW.revoke_reason IS DISTINCT FROM OLD.revoke_reason
          ) THEN
            RAISE EXCEPTION 'onnuri_staging_preflight_proof_revocation_immutable';
          END IF;
          IF OLD.invalidated_at IS NOT NULL AND (
            NEW.invalidated_at IS DISTINCT FROM OLD.invalidated_at
            OR NEW.invalidated_reason IS DISTINCT FROM OLD.invalidated_reason
          ) THEN
            RAISE EXCEPTION 'onnuri_staging_preflight_proof_invalidation_immutable';
          END IF;
          IF NEW.revoked_at IS NOT NULL AND (
            NEW.revoked_by_user_id IS NULL OR NEW.revoke_reason IS NULL
            OR btrim(NEW.revoke_reason) = ''
          ) THEN
            RAISE EXCEPTION 'onnuri_staging_preflight_proof_revocation_provenance_required';
          END IF;
          IF NEW.revoked_at IS NULL AND (
            NEW.revoked_by_user_id IS NOT NULL OR NEW.revoke_reason IS NOT NULL
          ) THEN
            RAISE EXCEPTION 'onnuri_staging_preflight_proof_revocation_inconsistent';
          END IF;
          IF NEW.invalidated_at IS NOT NULL AND (
            NEW.invalidated_reason IS NULL OR btrim(NEW.invalidated_reason) = ''
          ) THEN
            RAISE EXCEPTION 'onnuri_staging_preflight_proof_invalidation_provenance_required';
          END IF;
          IF NEW.invalidated_at IS NULL AND NEW.invalidated_reason IS NOT NULL THEN
            RAISE EXCEPTION 'onnuri_staging_preflight_proof_invalidation_inconsistent';
          END IF;
          IF NEW.revoked_at IS NOT NULL AND NEW.invalidated_at IS NOT NULL THEN
            RAISE EXCEPTION 'onnuri_staging_preflight_proof_terminal_cause_conflict';
          END IF;
          IF NEW.is_current = false
             AND NEW.revoked_at IS NULL AND NEW.invalidated_at IS NULL THEN
            RAISE EXCEPTION 'onnuri_staging_preflight_proof_terminal_state_required';
          END IF;
          IF OLD.candidate_id IS DISTINCT FROM NEW.candidate_id
             OR OLD.organization_id IS DISTINCT FROM NEW.organization_id
             OR OLD.scope_key IS DISTINCT FROM NEW.scope_key
             OR OLD.revision IS DISTINCT FROM NEW.revision
             OR OLD.provider IS DISTINCT FROM NEW.provider
             OR OLD.environment IS DISTINCT FROM NEW.environment
             OR OLD.onboarding_kind IS DISTINCT FROM NEW.onboarding_kind
             OR OLD.canonical_input::jsonb IS DISTINCT FROM NEW.canonical_input::jsonb
             OR OLD.canonical_hash IS DISTINCT FROM NEW.canonical_hash
             OR OLD.approved IS DISTINCT FROM NEW.approved
             OR OLD.passed IS DISTINCT FROM NEW.passed
             OR OLD.predicate_class IS DISTINCT FROM NEW.predicate_class
             OR OLD.evaluator IS DISTINCT FROM NEW.evaluator
             OR OLD.signer IS DISTINCT FROM NEW.signer
             OR OLD.approved_at IS DISTINCT FROM NEW.approved_at
             OR OLD.created_by_user_id IS DISTINCT FROM NEW.created_by_user_id
             OR OLD.created_at IS DISTINCT FROM NEW.created_at
             OR OLD.expires_at IS DISTINCT FROM NEW.expires_at THEN
            RAISE EXCEPTION 'onnuri_staging_preflight_proof_immutable';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)
    op.execute("""
        CREATE TRIGGER protect_onnuri_staging_preflight_proof_trigger
        BEFORE UPDATE OR DELETE ON onnuri_staging_preflight_proofs
        FOR EACH ROW EXECUTE FUNCTION protect_onnuri_staging_preflight_proof();
    """)
    op.execute("""
        CREATE FUNCTION protect_onnuri_staging_preflight_lease() RETURNS trigger AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'onnuri_staging_preflight_lease_delete_forbidden';
          END IF;
          IF OLD.state <> 'active' OR NEW.state NOT IN ('active', 'consumed', 'invalidated') THEN
            RAISE EXCEPTION 'onnuri_staging_preflight_lease_invalid_transition';
          END IF;
          IF NEW.state = 'active' AND (
            NEW.consumed_at IS NOT NULL OR NEW.invalidated_at IS NOT NULL
          ) THEN
            RAISE EXCEPTION 'onnuri_staging_preflight_lease_active_inconsistent';
          END IF;
          IF NEW.state = 'consumed' AND (
            NEW.consumed_at IS NULL OR NEW.invalidated_at IS NOT NULL
          ) THEN
            RAISE EXCEPTION 'onnuri_staging_preflight_lease_consumption_inconsistent';
          END IF;
          IF NEW.state = 'invalidated' AND (
            NEW.invalidated_at IS NULL OR NEW.consumed_at IS NOT NULL
          ) THEN
            RAISE EXCEPTION 'onnuri_staging_preflight_lease_invalidation_inconsistent';
          END IF;
          IF OLD.proof_id IS DISTINCT FROM NEW.proof_id
             OR OLD.inventory_id IS DISTINCT FROM NEW.inventory_id
             OR OLD.organization_id IS DISTINCT FROM NEW.organization_id
             OR OLD.actor_user_id IS DISTINCT FROM NEW.actor_user_id
             OR OLD.attempt_kind IS DISTINCT FROM NEW.attempt_kind
             OR OLD.application_attempt_id IS DISTINCT FROM NEW.application_attempt_id
             OR OLD.created_at IS DISTINCT FROM NEW.created_at
             OR OLD.expires_at IS DISTINCT FROM NEW.expires_at THEN
            RAISE EXCEPTION 'onnuri_staging_preflight_lease_immutable';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)
    op.execute("""
        CREATE TRIGGER protect_onnuri_staging_preflight_lease_trigger
        BEFORE UPDATE OR DELETE ON onnuri_staging_preflight_authorization_leases
        FOR EACH ROW EXECUTE FUNCTION protect_onnuri_staging_preflight_lease();
    """)
    op.execute("""
        CREATE FUNCTION protect_onnuri_staging_smoke_dispatch_attempt() RETURNS trigger AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'onnuri_smoke_dispatch_attempt_delete_forbidden';
          END IF;
          IF OLD.state <> 'pending'
             OR NEW.state NOT IN ('pending', 'dispatched', 'failed') THEN
            RAISE EXCEPTION 'onnuri_smoke_dispatch_attempt_invalid_transition';
          END IF;
          IF OLD.application_attempt_id IS DISTINCT FROM NEW.application_attempt_id
             OR OLD.lease_id IS DISTINCT FROM NEW.lease_id
             OR OLD.proof_id IS DISTINCT FROM NEW.proof_id
             OR OLD.inventory_id IS DISTINCT FROM NEW.inventory_id
             OR OLD.organization_id IS DISTINCT FROM NEW.organization_id
             OR OLD.attempt_kind IS DISTINCT FROM NEW.attempt_kind
             OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
            RAISE EXCEPTION 'onnuri_smoke_dispatch_attempt_immutable';
          END IF;
          IF NEW.state = 'pending' AND (
            NEW.dispatched_at IS NOT NULL OR NEW.failed_at IS NOT NULL
            OR NEW.failure_reason IS NOT NULL
          ) THEN
            RAISE EXCEPTION 'onnuri_smoke_dispatch_attempt_pending_inconsistent';
          END IF;
          IF NEW.state = 'dispatched' AND (
            NEW.dispatched_at IS NULL OR NEW.failed_at IS NOT NULL
            OR NEW.failure_reason IS NOT NULL
          ) THEN
            RAISE EXCEPTION 'onnuri_smoke_dispatch_attempt_dispatched_inconsistent';
          END IF;
          IF NEW.state = 'failed' AND (
            NEW.failed_at IS NULL OR NEW.dispatched_at IS NOT NULL
            OR NEW.failure_reason IS NULL OR btrim(NEW.failure_reason) = ''
          ) THEN
            RAISE EXCEPTION 'onnuri_smoke_dispatch_attempt_failed_inconsistent';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)
    op.execute("""
        CREATE TRIGGER protect_onnuri_staging_smoke_dispatch_attempt_trigger
        BEFORE UPDATE OR DELETE ON onnuri_staging_smoke_dispatch_attempts
        FOR EACH ROW EXECUTE FUNCTION protect_onnuri_staging_smoke_dispatch_attempt();
    """)
    op.execute("""
        CREATE FUNCTION validate_onnuri_staging_smoke_dispatch_attempt_insert() RETURNS trigger AS $$
        BEGIN
          IF NEW.state <> 'pending'
             OR NEW.dispatched_at IS NOT NULL
             OR NEW.failed_at IS NOT NULL
             OR NEW.failure_reason IS NOT NULL
             OR btrim(NEW.application_attempt_id) = '' THEN
            RAISE EXCEPTION 'onnuri_smoke_dispatch_attempt_insert_invalid';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)
    op.execute("""
        CREATE TRIGGER validate_onnuri_staging_smoke_dispatch_attempt_insert_trigger
        BEFORE INSERT ON onnuri_staging_smoke_dispatch_attempts
        FOR EACH ROW EXECUTE FUNCTION validate_onnuri_staging_smoke_dispatch_attempt_insert();
    """)


def downgrade() -> None:
    raise NotImplementedError(
        "Onnuri staging preflight provenance is intentionally irreversible."
    )