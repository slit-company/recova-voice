"""add durable Onnuri facade authority state

Revision ID: d6e7f8a9b0c1
Revises: c5d6e7f8a9b0
"""

from alembic import op
import sqlalchemy as sa
import hashlib
import re

revision = "d6e7f8a9b0c1"
down_revision = "c5d6e7f8a9b0"
branch_labels = None
depends_on = None
_PREDECESSOR_AUTHORITY_GUARD_SHA256 = (
    "bef5a8c27eb9b2e52a254218627981a7c904e606dd673250a7c76ff4ef25fb12"
)
_INSTALLED_AUTHORITY_GUARD_SHA256 = (
    "5313c83153a10f2cd206e981d425683fc176d4e38c4f74ba3f82331e0ecbd269"
)


def _normalized_definition(definition: str) -> str:
    return re.sub(r"\s+", " ", definition)


def upgrade() -> None:
    op.add_column("onnuri_staging_smoke_attempts", sa.Column("account_id", sa.String(255)))
    op.add_column("onnuri_staging_smoke_attempts", sa.Column("application_id", sa.String(255)))
    op.add_column("onnuri_staging_smoke_attempts", sa.Column("run_id", sa.String(255)))
    op.create_check_constraint(
        "ck_onnuri_smoke_attempt_bound_context",
        "onnuri_staging_smoke_attempts",
        "(account_id IS NULL AND application_id IS NULL AND run_id IS NULL) OR "
        "(account_id IS NOT NULL AND application_id IS NOT NULL AND run_id IS NOT NULL)",
    )
    op.create_index(
        "ix_onnuri_smoke_attempt_stock_lookup",
        "onnuri_staging_smoke_attempts",
        ["organization_id", "account_id", "stock_call_id_digest"],
    )
    bind = op.get_bind()
    predecessor_definition = bind.execute(
        sa.text("""
            SELECT pg_get_functiondef(procedure.oid)
            FROM pg_proc procedure
            JOIN pg_namespace namespace ON namespace.oid = procedure.pronamespace
            WHERE procedure.proname = 'onnuri_smoke_authority_row_guard'
              AND namespace.nspname = current_schema()
              AND procedure.pronargs = 0
        """)
    ).scalar_one_or_none()
    if (
        predecessor_definition is None
        or hashlib.sha256(
            _normalized_definition(predecessor_definition).encode("utf-8")
        ).hexdigest()
        != _PREDECESSOR_AUTHORITY_GUARD_SHA256
    ):
        raise RuntimeError(
            "onnuri_smoke_authority_row_guard predecessor definition is incompatible"
        )
    installed_definition = predecessor_definition.replace(
        "'authority_budget_seconds','observed_carrier_answer_at','terminal_class'",
        "'authority_budget_seconds','observed_carrier_answer_at','account_id',"
        "'application_id','run_id','terminal_class'",
    )
    bind.execute(sa.text(installed_definition))
    installed_definition = bind.execute(
        sa.text("""
            SELECT pg_get_functiondef(procedure.oid)
            FROM pg_proc procedure
            JOIN pg_namespace namespace ON namespace.oid = procedure.pronamespace
            WHERE procedure.proname = 'onnuri_smoke_authority_row_guard'
              AND namespace.nspname = current_schema()
              AND procedure.pronargs = 0
        """)
    ).scalar_one()
    if (
        hashlib.sha256(
            _normalized_definition(installed_definition).encode("utf-8")
        ).hexdigest()
        != _INSTALLED_AUTHORITY_GUARD_SHA256
    ):
        raise RuntimeError(
            "onnuri_smoke_authority_row_guard installed definition is incompatible"
        )
    op.execute("""
    CREATE FUNCTION onnuri_smoke_facade_context_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF (NEW.account_id IS NULL) <> (NEW.application_id IS NULL)
         OR (NEW.account_id IS NULL) <> (NEW.run_id IS NULL) THEN
        RAISE EXCEPTION 'onnuri smoke facade context is incomplete';
      END IF;
      IF OLD.account_id IS NOT NULL AND
         (NEW.account_id, NEW.application_id, NEW.run_id) IS DISTINCT FROM
         (OLD.account_id, OLD.application_id, OLD.run_id) THEN
        RAISE EXCEPTION 'onnuri smoke facade context is immutable';
      END IF;
      RETURN NEW;
    END $$;
    """)
    op.execute(
        "CREATE TRIGGER trg_onnuri_smoke_attempt_facade_context "
        "BEFORE UPDATE ON onnuri_staging_smoke_attempts FOR EACH ROW "
        "EXECUTE FUNCTION onnuri_smoke_facade_context_guard()"
    )
    op.create_table(
        "onnuri_staging_smoke_callback_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("attempt_id", sa.Integer(), sa.ForeignKey("onnuri_staging_smoke_attempts.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("event_nonce_digest", sa.String(128), nullable=False),
        sa.Column("idempotency_key", sa.String(255), nullable=False),
        sa.Column("request_digest", sa.String(128), nullable=False),
        sa.Column("event_type", sa.String(16), nullable=False),
        sa.Column("normalized_status", sa.String(64), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("duration_seconds", sa.Integer()),
        sa.Column("redacted_cause_category", sa.String(64)),
        sa.UniqueConstraint("attempt_id", "event_nonce_digest", name="uq_onnuri_smoke_callback_nonce"),
        sa.CheckConstraint("event_type IN ('status','cdr')", name="ck_onnuri_smoke_callback_event_type"),
        sa.CheckConstraint("duration_seconds IS NULL OR duration_seconds BETWEEN 0 AND 3600", name="ck_onnuri_smoke_callback_duration"),
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_onnuri_smoke_attempt_facade_context ON onnuri_staging_smoke_attempts")
    op.execute("DROP FUNCTION IF EXISTS onnuri_smoke_facade_context_guard()")
    op.drop_table("onnuri_staging_smoke_callback_events")
    op.execute("""
    DO $$
    DECLARE definition text;
    BEGIN
      SELECT pg_get_functiondef(p.oid) INTO definition
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE p.proname = 'onnuri_smoke_authority_row_guard'
        AND n.nspname = current_schema();
      definition := replace(
        definition,
        $old$'authority_budget_seconds','observed_carrier_answer_at','account_id','application_id','run_id','terminal_class'$old$,
        $new$'authority_budget_seconds','observed_carrier_answer_at','terminal_class'$new$
      );
      EXECUTE definition;
    END $$;
    """)
    op.drop_index("ix_onnuri_smoke_attempt_stock_lookup", table_name="onnuri_staging_smoke_attempts")
    op.drop_constraint("ck_onnuri_smoke_attempt_bound_context", "onnuri_staging_smoke_attempts", type_="check")
    op.drop_column("onnuri_staging_smoke_attempts", "run_id")
    op.drop_column("onnuri_staging_smoke_attempts", "application_id")
    op.drop_column("onnuri_staging_smoke_attempts", "account_id")
