"""add authority-owned G008 inbound bindings

Revision ID: f4a5b6c7d8e9
Revises: e3f4a5b6c7d8
Create Date: 2026-07-18
"""

from alembic import op
import sqlalchemy as sa


revision = "f4a5b6c7d8e9"
down_revision = "e3f4a5b6c7d8"
branch_labels = None
depends_on = None


_INPUT_UUID = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
_AUTHORITY_UUID = "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
_SHA256 = "^[0-9a-f]{64}$"


def upgrade() -> None:
    op.create_table(
        "g008_inbound_bindings",
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
        ),
        sa.Column("account_uuid", sa.String(36), nullable=False),
        sa.Column("application_uuid", sa.String(36), nullable=False),
        sa.Column("stock_call_uuid", sa.String(36), nullable=False),
        sa.Column("stock_call_id_digest", sa.String(64), nullable=False),
        sa.Column("did_digest", sa.String(64), nullable=False),
        sa.Column("caller_digest", sa.String(64), nullable=False),
        sa.Column("direction", sa.String(16), nullable=False, server_default="inbound"),
        sa.Column(
            "run_uuid",
            sa.String(36),
            nullable=False,
            server_default=sa.text("gen_random_uuid()::text"),
        ),
        sa.Column(
            "attempt_uuid",
            sa.String(36),
            nullable=False,
            server_default=sa.text("gen_random_uuid()::text"),
        ),
        sa.Column(
            "idempotency_uuid",
            sa.String(36),
            nullable=False,
            server_default=sa.text("gen_random_uuid()::text"),
        ),
        sa.Column(
            "bind_receipt_uuid",
            sa.String(36),
            nullable=False,
            server_default=sa.text("gen_random_uuid()::text"),
        ),
        sa.Column("request_digest", sa.String(64), nullable=False),
        sa.Column(
            "receipt_schema",
            sa.String(64),
            nullable=False,
            server_default="recova-g008-inbound-bind-receipt-v1",
        ),
        sa.Column(
            "receipt_domain",
            sa.String(128),
            nullable=False,
            server_default="recova.onnuri.smoke.g008.inbound-bind.v1",
        ),
        sa.Column("receipt_algorithm", sa.String(16), nullable=False, server_default="ES256"),
        sa.Column("receipt_key_id", sa.String(128)),
        sa.Column("receipt_spki_digest", sa.String(64)),
        sa.Column("receipt_signature_digest", sa.String(64)),
        sa.Column("receipt_unsigned_digest", sa.String(64)),
        sa.Column("recovery_ciphertext", sa.Text()),
        sa.Column("recovery_ciphertext_digest", sa.String(64)),
        sa.Column("canonical_claims", sa.JSON(), nullable=False),
        sa.Column("state", sa.String(16), nullable=False, server_default="issuing"),
        sa.Column("authority_deadline_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "issued_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("bound_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint(
            "organization_id",
            "account_uuid",
            "stock_call_id_digest",
            name="uq_g008_inbound_binding_tenant_account_stock",
        ),
        sa.UniqueConstraint("execution_stage_id", name="uq_g008_inbound_binding_stage"),
        sa.UniqueConstraint("run_uuid", name="uq_g008_inbound_binding_run"),
        sa.UniqueConstraint("attempt_uuid", name="uq_g008_inbound_binding_attempt"),
        sa.UniqueConstraint(
            "idempotency_uuid", name="uq_g008_inbound_binding_idempotency"
        ),
        sa.UniqueConstraint(
            "bind_receipt_uuid", name="uq_g008_inbound_binding_receipt"
        ),
        sa.CheckConstraint(
            "direction = 'inbound'", name="ck_g008_inbound_binding_direction"
        ),
        sa.CheckConstraint(
            "receipt_schema = 'recova-g008-inbound-bind-receipt-v1' "
            "AND receipt_domain = 'recova.onnuri.smoke.g008.inbound-bind.v1' "
            "AND receipt_algorithm = 'ES256'",
            name="ck_g008_inbound_binding_receipt_contract",
        ),
        sa.CheckConstraint(
            "state IN ('issuing','bound')", name="ck_g008_inbound_binding_state"
        ),
        sa.CheckConstraint(
            "(state = 'issuing' AND receipt_key_id IS NULL "
            "AND receipt_spki_digest IS NULL AND receipt_signature_digest IS NULL "
            "AND receipt_unsigned_digest IS NULL "
            "AND recovery_ciphertext IS NULL "
            "AND recovery_ciphertext_digest IS NULL AND bound_at IS NULL) OR "
            "(state = 'bound' AND receipt_key_id IS NOT NULL "
            "AND receipt_spki_digest IS NOT NULL "
            "AND receipt_signature_digest IS NOT NULL "
            "AND receipt_unsigned_digest IS NOT NULL "
            "AND recovery_ciphertext IS NOT NULL "
            "AND recovery_ciphertext_digest IS NOT NULL "
            "AND bound_at IS NOT NULL)",
            name="ck_g008_inbound_binding_finalization",
        ),
        sa.CheckConstraint(
            f"account_uuid ~ '{_INPUT_UUID}' "
            f"AND application_uuid ~ '{_INPUT_UUID}' "
            f"AND stock_call_uuid ~ '{_INPUT_UUID}' "
            f"AND run_uuid ~ '{_AUTHORITY_UUID}' "
            f"AND attempt_uuid ~ '{_AUTHORITY_UUID}' "
            f"AND idempotency_uuid ~ '{_AUTHORITY_UUID}' "
            f"AND bind_receipt_uuid ~ '{_AUTHORITY_UUID}'",
            name="ck_g008_inbound_binding_uuids",
        ),
        sa.CheckConstraint(
            f"stock_call_id_digest ~ '{_SHA256}' AND did_digest ~ '{_SHA256}' "
            f"AND caller_digest ~ '{_SHA256}' AND request_digest ~ '{_SHA256}' "
            f"AND (receipt_spki_digest IS NULL OR receipt_spki_digest ~ '{_SHA256}') "
            f"AND (receipt_signature_digest IS NULL OR receipt_signature_digest ~ '{_SHA256}') "
            f"AND (receipt_unsigned_digest IS NULL OR receipt_unsigned_digest ~ '{_SHA256}') "
            f"AND (recovery_ciphertext_digest IS NULL OR recovery_ciphertext_digest ~ '{_SHA256}')",
            name="ck_g008_inbound_binding_digests",
        ),
        sa.CheckConstraint(
            "authority_deadline_at >= issued_at + interval '60 seconds'",
            name="ck_g008_inbound_binding_deadline",
        ),
    )
    op.execute(
        """
        CREATE FUNCTION g008_inbound_binding_write_once_guard() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          IF ROW(
            NEW.organization_id, NEW.execution_stage_id, NEW.account_uuid,
            NEW.application_uuid, NEW.stock_call_uuid,
            NEW.stock_call_id_digest, NEW.did_digest, NEW.caller_digest,
            NEW.direction, NEW.run_uuid, NEW.attempt_uuid,
            NEW.idempotency_uuid, NEW.bind_receipt_uuid, NEW.request_digest,
            NEW.receipt_schema, NEW.receipt_domain, NEW.receipt_algorithm,
            NEW.canonical_claims::jsonb, NEW.authority_deadline_at, NEW.issued_at
          ) IS DISTINCT FROM ROW(
            OLD.organization_id, OLD.execution_stage_id, OLD.account_uuid,
            OLD.application_uuid, OLD.stock_call_uuid,
            OLD.stock_call_id_digest, OLD.did_digest, OLD.caller_digest,
            OLD.direction, OLD.run_uuid, OLD.attempt_uuid,
            OLD.idempotency_uuid, OLD.bind_receipt_uuid, OLD.request_digest,
            OLD.receipt_schema, OLD.receipt_domain, OLD.receipt_algorithm,
            OLD.canonical_claims::jsonb, OLD.authority_deadline_at, OLD.issued_at
          ) THEN
            RAISE EXCEPTION 'g008 inbound binding identity is write-once';
          END IF;
          IF OLD.state = 'bound' AND to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
            RAISE EXCEPTION 'g008 inbound binding receipt is write-once';
          END IF;
          RETURN NEW;
        END;
        $$;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_g008_inbound_binding_write_once
        BEFORE UPDATE ON g008_inbound_bindings
        FOR EACH ROW EXECUTE FUNCTION g008_inbound_binding_write_once_guard()
        """
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS trg_g008_inbound_binding_write_once "
        "ON g008_inbound_bindings"
    )
    op.execute("DROP FUNCTION IF EXISTS g008_inbound_binding_write_once_guard()")
    op.drop_table("g008_inbound_bindings")
