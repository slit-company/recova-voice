"""add isolated Onnuri outbound diagnostic v1 persistence

Revision ID: d0e1f2a3b4c5
Revises: c9d0e1f2a3b4
Create Date: 2026-07-21
"""
from alembic import op
import sqlalchemy as sa
from api.db.models import ONNURI_OUTBOUND_DIAGNOSTIC_PRODUCT_CHECK

revision = "d0e1f2a3b4c5"
down_revision = "c9d0e1f2a3b4"
branch_labels = None
depends_on = None

_DIGESTS = "destination_hmac_digest ~ '^[0-9a-f]{64}$' AND caller_digest ~ '^[0-9a-f]{64}$' AND operator_credential_digest ~ '^[0-9a-f]{64}$' AND candidate_digest ~ '^[0-9a-f]{64}$' AND provider_digest ~ '^[0-9a-f]{64}$' AND route_digest ~ '^[0-9a-f]{64}$' AND nat_firewall_digest ~ '^[0-9a-f]{64}$' AND keyset_digest ~ '^[0-9a-f]{64}$' AND request_digest ~ '^[0-9a-f]{64}$'"


def upgrade() -> None:

    op.create_table(
        "onnuri_outbound_diagnostic_attempts",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("attempt_uuid", sa.String(36), nullable=False, unique=True),
        sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("envelope_id", sa.Integer(), sa.ForeignKey("onnuri_staging_smoke_envelopes.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("inventory_id", sa.Integer(), sa.ForeignKey("telephony_number_inventory.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("telephony_configuration_id", sa.Integer(), sa.ForeignKey("telephony_configurations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("authenticated_operator_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False), sa.Column("idempotency_key", sa.String(255), nullable=False), sa.Column("fixture_digest", sa.String(64), nullable=False),
        sa.Column("destination_hmac_digest", sa.String(64), nullable=False), sa.Column("destination_hmac_key_version", sa.String(128), nullable=False), sa.Column("caller_digest", sa.String(64), nullable=False), sa.Column("operator_role", sa.String(64), nullable=False), sa.Column("operator_credential_digest", sa.String(64), nullable=False), sa.Column("candidate_digest", sa.String(64), nullable=False), sa.Column("provider_digest", sa.String(64), nullable=False), sa.Column("route_digest", sa.String(64), nullable=False), sa.Column("nat_firewall_digest", sa.String(64), nullable=False), sa.Column("keyset_digest", sa.String(64), nullable=False), sa.Column("request_digest", sa.String(64), nullable=False),
        sa.Column("dispatch", sa.String(32), nullable=False, server_default="not_submitted"), sa.Column("signaling", sa.String(32), nullable=False, server_default="unknown"), sa.Column("answer", sa.String(32), nullable=False, server_default="unknown"), sa.Column("media", sa.String(32), nullable=False, server_default="unknown"), sa.Column("terminal", sa.String(32), nullable=False, server_default="open"),
        sa.Column("reconciliation_cutoff_at", sa.DateTime(timezone=True), nullable=False), sa.Column("event_sequence", sa.Integer(), nullable=False, server_default="0"), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")), sa.Column("terminal_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("envelope_id", "ordinal", name="uq_onnuri_outbound_diagnostic_ordinal"), sa.UniqueConstraint("envelope_id", "idempotency_key", name="uq_onnuri_outbound_diagnostic_idempotency"),
        sa.CheckConstraint("ordinal BETWEEN 1 AND 3", name="ck_onnuri_outbound_diagnostic_ordinal"), sa.CheckConstraint("fixture_digest ~ '^[0-9a-f]{64}$'", name="ck_onnuri_outbound_diagnostic_fixture_digest"), sa.CheckConstraint(_DIGESTS, name="ck_onnuri_outbound_diagnostic_digests"),
        sa.CheckConstraint(ONNURI_OUTBOUND_DIAGNOSTIC_PRODUCT_CHECK, name="ck_onnuri_outbound_diagnostic_product"),
        sa.CheckConstraint("reconciliation_cutoff_at <= created_at + interval '60 seconds'", name="ck_onnuri_outbound_diagnostic_cutoff"),
    )
    op.create_index("uq_onnuri_outbound_diagnostic_active", "onnuri_outbound_diagnostic_attempts", ["envelope_id"], unique=True, postgresql_where=sa.text("terminal = 'open'"))
    op.create_table(
        "onnuri_outbound_diagnostic_capabilities",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("nonce_digest", sa.String(64), nullable=False, unique=True),
        sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("envelope_id", sa.Integer(), sa.ForeignKey("onnuri_staging_smoke_envelopes.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("authorization_attempt_id", sa.Integer(), sa.ForeignKey("onnuri_staging_smoke_attempts.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("authenticated_operator_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("idempotency_key", sa.String(255), nullable=False),
        sa.Column("request_digest", sa.String(64), nullable=False), sa.Column("candidate_digest", sa.String(64), nullable=False), sa.Column("gate_envelope_digest", sa.String(64), nullable=False), sa.Column("route_profile_digest", sa.String(64), nullable=False), sa.Column("route_digest", sa.String(64), nullable=False), sa.Column("provider_digest", sa.String(64), nullable=False), sa.Column("keyset_digest", sa.String(64), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.Column("revoked_at", sa.DateTime(timezone=True)), sa.Column("consumed_at", sa.DateTime(timezone=True)),
        sa.Column("diagnostic_attempt_id", sa.Integer(), sa.ForeignKey("onnuri_outbound_diagnostic_attempts.id", ondelete="RESTRICT"), unique=True),
        sa.UniqueConstraint("authorization_attempt_id", "idempotency_key", name="uq_onnuri_outbound_diagnostic_capability_idempotency"),
        sa.CheckConstraint("nonce_digest ~ '^[0-9a-f]{64}$' AND request_digest ~ '^[0-9a-f]{64}$' AND candidate_digest ~ '^[0-9a-f]{64}$' AND gate_envelope_digest ~ '^[0-9a-f]{64}$' AND route_profile_digest ~ '^[0-9a-f]{64}$' AND route_digest ~ '^[0-9a-f]{64}$' AND provider_digest ~ '^[0-9a-f]{64}$' AND keyset_digest ~ '^[0-9a-f]{64}$'", name="ck_onnuri_outbound_diagnostic_capability_digests"),
        sa.CheckConstraint("expires_at > issued_at", name="ck_onnuri_outbound_diagnostic_capability_expiry"),
    )
    op.create_table("onnuri_outbound_diagnostic_events", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("attempt_id", sa.Integer(), sa.ForeignKey("onnuri_outbound_diagnostic_attempts.id", ondelete="RESTRICT"), nullable=False), sa.Column("sequence", sa.Integer(), nullable=False), sa.Column("operation", sa.String(64), nullable=False), sa.Column("provenance_digest", sa.String(64), nullable=False), sa.Column("idempotency_key", sa.String(255), nullable=False), sa.Column("expected_dispatch", sa.String(32), nullable=False), sa.Column("expected_signaling", sa.String(32), nullable=False), sa.Column("expected_answer", sa.String(32), nullable=False), sa.Column("expected_media", sa.String(32), nullable=False), sa.Column("expected_terminal", sa.String(32), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")), sa.UniqueConstraint("attempt_id", "sequence", name="uq_onnuri_outbound_diagnostic_event_sequence"), sa.UniqueConstraint("attempt_id", "idempotency_key", name="uq_onnuri_outbound_diagnostic_event_idempotency"), sa.CheckConstraint("provenance_digest ~ '^[0-9a-f]{64}$'", name="ck_onnuri_outbound_diagnostic_event_digest"))
    op.create_table("onnuri_outbound_diagnostic_late_evidence", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("attempt_id", sa.Integer(), sa.ForeignKey("onnuri_outbound_diagnostic_attempts.id", ondelete="RESTRICT"), nullable=False), sa.Column("evidence_digest", sa.String(64), nullable=False), sa.Column("evidence_kind", sa.String(64), nullable=False), sa.Column("received_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")), sa.UniqueConstraint("attempt_id", "evidence_digest", name="uq_onnuri_outbound_diagnostic_late_evidence"), sa.CheckConstraint("evidence_digest ~ '^[0-9a-f]{64}$'", name="ck_onnuri_outbound_diagnostic_late_evidence_digest"))


def downgrade() -> None:
    op.drop_table("onnuri_outbound_diagnostic_late_evidence")
    op.drop_table("onnuri_outbound_diagnostic_events")
    op.drop_table("onnuri_outbound_diagnostic_capabilities")
    op.drop_index("uq_onnuri_outbound_diagnostic_active", table_name="onnuri_outbound_diagnostic_attempts")
    op.drop_table("onnuri_outbound_diagnostic_attempts")
