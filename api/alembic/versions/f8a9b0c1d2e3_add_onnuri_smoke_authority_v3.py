"""bind provider prerequisites into Onnuri smoke authority v3

Revision ID: f8a9b0c1d2e3
Revises: e7f8a9b0c1d2
"""

from alembic import op
import sqlalchemy as sa


revision = "f8a9b0c1d2e3"
down_revision = "e7f8a9b0c1d2"
branch_labels = None
depends_on = None


_RECEIPT_COLUMNS = (
    "provider_balance_currency_receipt_digest",
    "supplier_signaling_media_receipt_digest",
    "tenant_mapping_receipt_digest",
    "secret_version_manifest_receipt_digest",
    "gate_decision_receipt_digest",
)


def upgrade() -> None:
    for column in _RECEIPT_COLUMNS:
        op.add_column(
            "onnuri_staging_smoke_envelopes",
            sa.Column(column, sa.String(64), nullable=True),
        )
    op.add_column(
        "onnuri_staging_smoke_envelopes",
        sa.Column("sealed_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.drop_constraint(
        "ck_onnuri_smoke_evaluator",
        "onnuri_staging_smoke_envelopes",
        type_="check",
    )
    op.create_check_constraint(
        "ck_onnuri_smoke_evaluator",
        "onnuri_staging_smoke_envelopes",
        "evaluator_version IN ('recova_onnuri_smoke_authority_v2', "
        "'recova_onnuri_smoke_authority_v3')",
    )
    op.create_check_constraint(
        "ck_onnuri_smoke_prerequisite_receipts",
        "onnuri_staging_smoke_envelopes",
        "(evaluator_version = 'recova_onnuri_smoke_authority_v2' AND "
        "provider_balance_currency_receipt_digest IS NULL AND "
        "supplier_signaling_media_receipt_digest IS NULL AND "
        "tenant_mapping_receipt_digest IS NULL AND "
        "secret_version_manifest_receipt_digest IS NULL AND "
        "gate_decision_receipt_digest IS NULL AND sealed_at IS NULL) OR "
        "(evaluator_version = 'recova_onnuri_smoke_authority_v3' AND "
        "provider_balance_currency_receipt_digest IS NOT NULL AND "
        "provider_balance_currency_receipt_digest ~ '^[0-9a-f]{64}$' AND "
        "supplier_signaling_media_receipt_digest IS NOT NULL AND "
        "supplier_signaling_media_receipt_digest ~ '^[0-9a-f]{64}$' AND "
        "tenant_mapping_receipt_digest IS NOT NULL AND "
        "tenant_mapping_receipt_digest ~ '^[0-9a-f]{64}$' AND "
        "secret_version_manifest_receipt_digest IS NOT NULL AND "
        "secret_version_manifest_receipt_digest ~ '^[0-9a-f]{64}$' AND "
        "gate_decision_receipt_digest IS NOT NULL AND "
        "gate_decision_receipt_digest ~ '^[0-9a-f]{64}$' AND "
        "sealed_at IS NOT NULL)",
    )
    op.execute("""
    CREATE FUNCTION onnuri_smoke_v3_seal_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF NEW.evaluator_version = 'recova_onnuri_smoke_authority_v3' THEN
        NEW.sealed_at := statement_timestamp();
      ELSIF NEW.sealed_at IS NOT NULL THEN
        RAISE EXCEPTION 'onnuri smoke v2 authority cannot be sealed';
      END IF;
      RETURN NEW;
    END $$;
    """)
    op.execute(
        "CREATE TRIGGER trg_onnuri_smoke_v3_seal "
        "BEFORE INSERT ON onnuri_staging_smoke_envelopes FOR EACH ROW "
        "EXECUTE FUNCTION onnuri_smoke_v3_seal_guard()"
    )
    op.execute("""
    CREATE FUNCTION onnuri_smoke_v3_live_transition_guard() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1
        FROM onnuri_staging_smoke_envelopes envelope
        WHERE envelope.id = NEW.envelope_id
          AND envelope.evaluator_version = 'recova_onnuri_smoke_authority_v3'
          AND envelope.sealed_at IS NOT NULL
          AND envelope.provider_balance_currency_receipt_digest ~ '^[0-9a-f]{64}$'
          AND envelope.supplier_signaling_media_receipt_digest ~ '^[0-9a-f]{64}$'
          AND envelope.tenant_mapping_receipt_digest ~ '^[0-9a-f]{64}$'
          AND envelope.secret_version_manifest_receipt_digest ~ '^[0-9a-f]{64}$'
          AND envelope.gate_decision_receipt_digest ~ '^[0-9a-f]{64}$'
          AND (
            TG_TABLE_NAME <> 'onnuri_staging_smoke_attempts'
            OR envelope.organization_id =
              (to_jsonb(NEW)->>'organization_id')::integer
          )
      ) THEN
        RAISE EXCEPTION 'onnuri smoke v3 prerequisites are required';
      END IF;
      RETURN NEW;
    END $$;
    """)
    for table in (
        "onnuri_staging_smoke_attempts",
        "onnuri_registration_gates",
    ):
        op.execute(
            f"CREATE TRIGGER trg_{table}_v3_prerequisites "
            f"BEFORE INSERT ON {table} FOR EACH ROW "
            "EXECUTE FUNCTION onnuri_smoke_v3_live_transition_guard()"
        )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS trg_onnuri_smoke_v3_seal "
        "ON onnuri_staging_smoke_envelopes"
    )
    op.execute("DROP FUNCTION IF EXISTS onnuri_smoke_v3_seal_guard()")
    for table in (
        "onnuri_staging_smoke_attempts",
        "onnuri_registration_gates",
    ):
        op.execute(
            f"DROP TRIGGER IF EXISTS trg_{table}_v3_prerequisites ON {table}"
        )
    op.execute("DROP FUNCTION IF EXISTS onnuri_smoke_v3_live_transition_guard()")
    op.execute(
        "ALTER TABLE onnuri_staging_smoke_envelopes "
        "DISABLE TRIGGER trg_onnuri_staging_smoke_envelopes_authority_immutable"
    )
    op.execute("""
    UPDATE onnuri_staging_smoke_envelopes
    SET evaluator_version = 'recova_onnuri_smoke_authority_v2',
        state = 'contained',
        contained_at = COALESCE(contained_at, statement_timestamp()),
        containment_reason = COALESCE(
            containment_reason, 'authority-v3-schema-downgrade'
        ),
        provider_balance_currency_receipt_digest = NULL,
        supplier_signaling_media_receipt_digest = NULL,
        tenant_mapping_receipt_digest = NULL,
        secret_version_manifest_receipt_digest = NULL,
        gate_decision_receipt_digest = NULL,
        sealed_at = NULL
    WHERE evaluator_version = 'recova_onnuri_smoke_authority_v3'
    """)
    op.execute(
        "ALTER TABLE onnuri_staging_smoke_envelopes "
        "ENABLE TRIGGER trg_onnuri_staging_smoke_envelopes_authority_immutable"
    )
    op.drop_constraint(
        "ck_onnuri_smoke_prerequisite_receipts",
        "onnuri_staging_smoke_envelopes",
        type_="check",
    )
    op.drop_constraint(
        "ck_onnuri_smoke_evaluator",
        "onnuri_staging_smoke_envelopes",
        type_="check",
    )
    op.create_check_constraint(
        "ck_onnuri_smoke_evaluator",
        "onnuri_staging_smoke_envelopes",
        "evaluator_version = 'recova_onnuri_smoke_authority_v2'",
    )
    op.drop_column("onnuri_staging_smoke_envelopes", "sealed_at")
    for column in reversed(_RECEIPT_COLUMNS):
        op.drop_column("onnuri_staging_smoke_envelopes", column)
