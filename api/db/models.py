import uuid
from datetime import UTC, datetime

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    CheckConstraint,
    Index,
    Integer,
    LargeBinary,
    String,
    Table,
    Text,
    UniqueConstraint,
    and_,
    text,
)
from sqlalchemy.orm import declarative_base, relationship

from api.constants import DEFAULT_CAMPAIGN_RETRY_CONFIG

from ..enums import (
    CallType,
    IntegrationAction,
    ToolCategory,
    ToolStatus,
    TriggerState,
    WebhookCredentialType,
    WorkflowRunState,
    WorkflowStatus,
)

Base = declarative_base()
ONNURI_EVALUATOR_LINKAGE_CHECK = (
    "((evaluator_version IS NULL OR evaluator_version = "
    "'recova_onnuri_staging_policy_v1') AND smoke_envelope_id IS NULL "
    "AND smoke_attempt_id IS NULL AND authenticated_operator_user_id IS NULL "
    "AND workflow_owner_user_id IS NULL AND evaluator_idempotency_key IS NULL) "
    "OR (evaluator_version = 'recova_onnuri_smoke_authority_v2' "
    "AND smoke_envelope_id IS NOT NULL AND smoke_attempt_id IS NOT NULL "
    "AND authenticated_operator_user_id IS NOT NULL "
    "AND workflow_owner_user_id IS NOT NULL "
    "AND evaluator_idempotency_key IS NOT NULL)"
)
ONNURI_OUTBOUND_DIAGNOSTIC_PRODUCT_CHECK = "(dispatch, signaling, answer, media, terminal) IN ((\'not_submitted\',\'unknown\',\'unknown\',\'unknown\',\'open\'),(\'submission_reserved\',\'unknown\',\'unknown\',\'unknown\',\'open\'),(\'submitted\',\'unknown\',\'unknown\',\'unknown\',\'open\'),(\'stock_accepted\',\'unknown\',\'unknown\',\'unknown\',\'open\'),(\'ambiguous_submission\',\'unknown\',\'unknown\',\'unknown\',\'open\'),(\'ambiguous_submission\',\'unknown\',\'unknown\',\'unknown\',\'ambiguous_submission\'),(\'dispatch_denied\',\'unknown\',\'unknown\',\'unknown\',\'dispatch_denied\'),(\'stock_accepted\',\'no_final_response\',\'unknown\',\'unknown\',\'open\'),(\'stock_accepted\',\'provisional_only\',\'unknown\',\'unknown\',\'open\'),(\'stock_accepted\',\'final_2xx\',\'unknown\',\'unknown\',\'open\'),(\'stock_accepted\',\'final_2xx\',\'answered\',\'unknown\',\'open\'),(\'stock_accepted\',\'final_2xx\',\'answered\',\'none\',\'answered_no_matching_rtp\'),(\'stock_accepted\',\'final_2xx\',\'answered\',\'rtp_one_way\',\'answered_rtp_one_way\'),(\'stock_accepted\',\'final_2xx\',\'answered\',\'rtp_bidirectional\',\'completed\'),(\'stock_accepted\',\'final_2xx\',\'unknown\',\'unknown\',\'event_unavailable\'),(\'stock_accepted\',\'final_2xx\',\'answered\',\'unknown\',\'event_unavailable\'),(\'stock_accepted\',\'final_3xx_6xx\',\'unknown\',\'unknown\',\'open\'),(\'stock_accepted\',\'final_3xx_6xx\',\'not_answered\',\'unknown\',\'open\'),(\'stock_accepted\',\'final_3xx_6xx\',\'not_answered\',\'not_applicable\',\'carrier_rejected\'),(\'stock_accepted\',\'no_final_response\',\'unknown\',\'unknown\',\'provisional_timeout\'),(\'stock_accepted\',\'provisional_only\',\'unknown\',\'unknown\',\'provisional_timeout\'),(\'submitted\',\'unknown\',\'unknown\',\'unknown\',\'authority_expired\'),(\'stock_accepted\',\'unknown\',\'unknown\',\'unknown\',\'authority_expired\'),(\'submission_reserved\',\'unknown\',\'unknown\',\'unknown\',\'authority_expired\'),(\'ambiguous_submission\',\'unknown\',\'unknown\',\'unknown\',\'authority_expired\'),(\'not_submitted\',\'unknown\',\'unknown\',\'unknown\',\'contained\'),(\'submission_reserved\',\'unknown\',\'unknown\',\'unknown\',\'contained\'),(\'submitted\',\'unknown\',\'unknown\',\'unknown\',\'contained\'),(\'stock_accepted\',\'unknown\',\'unknown\',\'unknown\',\'contained\'),(\'ambiguous_submission\',\'unknown\',\'unknown\',\'unknown\',\'contained\'),(\'stock_accepted\',\'no_final_response\',\'unknown\',\'unknown\',\'contained\'),(\'stock_accepted\',\'provisional_only\',\'unknown\',\'unknown\',\'contained\'),(\'stock_accepted\',\'final_2xx\',\'unknown\',\'unknown\',\'contained\'),(\'stock_accepted\',\'final_2xx\',\'answered\',\'unknown\',\'contained\'),(\'stock_accepted\',\'final_3xx_6xx\',\'unknown\',\'unknown\',\'contained\'),(\'stock_accepted\',\'final_3xx_6xx\',\'not_answered\',\'unknown\',\'contained\'))"


# TODO: remove workflow_defintion after migration, remove nullable workflow_defintion_id from Workflow and Workflowrun


# Association table for many-to-many relationship between users and organizations
organization_users_association = Table(
    "organization_users",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id"), primary_key=True),
    Column(
        "organization_id", Integer, ForeignKey("organizations.id"), primary_key=True
    ),
)


class UserModel(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    provider_id = Column(String, unique=True, index=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    workflows = relationship("WorkflowModel", back_populates="user")
    selected_organization_id = Column(
        Integer, ForeignKey("organizations.id"), nullable=True
    )
    selected_organization = relationship("OrganizationModel", back_populates="users")
    organizations = relationship(
        "OrganizationModel",
        secondary=organization_users_association,
        back_populates="users",
    )
    is_superuser = Column(Boolean, default=False)
    email = Column(String, unique=True, index=True, nullable=True)
    password_hash = Column(String, nullable=True)


class UserConfigurationModel(Base):
    __tablename__ = "user_configurations"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    configuration = Column(JSON, nullable=False, default=dict)
    last_validated_at = Column(DateTime(timezone=True), nullable=True)


# New Organization model
class OrganizationModel(Base):
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, index=True)
    provider_id = Column(String, unique=True, index=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    # Quota fields
    quota_type = Column(
        Enum("monthly", "annual", name="quota_type"),
        nullable=False,
        default="monthly",
        server_default=text("'monthly'::quota_type"),
    )
    quota_dograh_tokens = Column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    quota_reset_day = Column(
        Integer, nullable=False, default=1, server_default=text("1")
    )  # 1-28, only for monthly
    quota_start_date = Column(DateTime(timezone=True), nullable=True)  # Only for annual
    quota_enabled = Column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )

    price_per_second_usd = Column(Float, nullable=True)

    # Relationships
    users = relationship(
        "UserModel",
        secondary=organization_users_association,
        back_populates="organizations",
    )
    integrations = relationship("IntegrationModel", back_populates="organization")
    usage_cycles = relationship(
        "OrganizationUsageCycleModel", back_populates="organization"
    )
    configurations = relationship(
        "OrganizationConfigurationModel", back_populates="organization"
    )
    api_keys = relationship("APIKeyModel", back_populates="organization")


class APIKeyModel(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    name = Column(String, nullable=False)
    key_hash = Column(String, nullable=False, unique=True, index=True)
    key_prefix = Column(String, nullable=False)  # Store first 8 chars for display
    is_active = Column(Boolean, default=True, nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    archived_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    organization = relationship("OrganizationModel", back_populates="api_keys")
    created_by_user = relationship("UserModel")

    # Indexes for performance
    __table_args__ = (
        Index("ix_api_keys_organization_id", "organization_id"),
        Index("ix_api_keys_key_hash", "key_hash"),
        Index("ix_api_keys_active", "is_active"),
    )


class OrganizationConfigurationModel(Base):
    __tablename__ = "organization_configurations"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    key = Column(String, nullable=False)
    value = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    # Relationships
    organization = relationship("OrganizationModel", back_populates="configurations")

    # Constraints and indexes
    __table_args__ = (
        UniqueConstraint("organization_id", "key", name="_organization_key_uc"),
        Index("ix_organization_configurations_organization_id", "organization_id"),
    )


class TelephonyConfigurationModel(Base):
    __tablename__ = "telephony_configurations"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    name = Column(String(64), nullable=False)
    provider = Column(String(32), nullable=False)
    credentials = Column(JSON, nullable=False, default=dict)
    is_default_outbound = Column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    organization = relationship("OrganizationModel")
    phone_numbers = relationship(
        "TelephonyPhoneNumberModel",
        back_populates="configuration",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "name", name="uq_telephony_configurations_org_name"
        ),
        Index("ix_telephony_configurations_org", "organization_id"),
        Index(
            "uq_telephony_configurations_default",
            "organization_id",
            unique=True,
            postgresql_where=text("is_default_outbound = true"),
        ),
    )


class TelephonyPhoneNumberModel(Base):
    __tablename__ = "telephony_phone_numbers"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    telephony_configuration_id = Column(
        Integer,
        ForeignKey("telephony_configurations.id", ondelete="CASCADE"),
        nullable=False,
    )
    address = Column(String(255), nullable=False)
    address_normalized = Column(String(255), nullable=False)
    address_masked = Column(String(255), nullable=True)
    address_hash = Column(String(64), nullable=True)
    address_encrypted_raw = Column(Text, nullable=True)
    address_type = Column(String(16), nullable=False)
    country_code = Column(String(2), nullable=True)
    label = Column(String(64), nullable=True)
    inbound_workflow_id = Column(
        Integer,
        ForeignKey("workflows.id", ondelete="SET NULL"),
        nullable=True,
    )
    is_active = Column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    is_default_caller_id = Column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    extra_metadata = Column(
        JSON, nullable=False, default=dict, server_default=text("'{}'::json")
    )
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    configuration = relationship(
        "TelephonyConfigurationModel", back_populates="phone_numbers"
    )
    inbound_workflow = relationship("WorkflowModel")

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "address_normalized",
            name="uq_phone_numbers_org_address",
        ),
        Index("ix_phone_numbers_config", "telephony_configuration_id"),
        Index(
            "ix_phone_numbers_address_hash",
            "address_hash",
            postgresql_where=text("address_hash IS NOT NULL"),
        ),
        Index(
            "ix_phone_numbers_workflow",
            "inbound_workflow_id",
            postgresql_where=text("inbound_workflow_id IS NOT NULL"),
        ),
        Index(
            "ix_phone_numbers_inbound_lookup",
            "address_normalized",
            "organization_id",
            postgresql_where=text("is_active = true"),
        ),
        Index(
            "uq_phone_numbers_default_caller",
            "telephony_configuration_id",
            unique=True,
            postgresql_where=text("is_default_caller_id = true"),
        ),
    )
class TelephonyCallEventModel(Base):
    __tablename__ = "telephony_call_events"

    id = Column(Integer, primary_key=True, index=True)
    call_attempt_id = Column(String(128), nullable=False)
    event_id = Column(String(128), nullable=False)
    idempotency_key = Column(String(255), nullable=False)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True
    )
    telephony_configuration_id = Column(
        Integer,
        ForeignKey("telephony_configurations.id", ondelete="SET NULL"),
        nullable=True,
    )
    telephony_phone_number_id = Column(
        Integer,
        ForeignKey("telephony_phone_numbers.id", ondelete="SET NULL"),
        nullable=True,
    )
    inventory_id = Column(Integer, nullable=True)
    workflow_id = Column(
        Integer, ForeignKey("workflows.id", ondelete="SET NULL"), nullable=True
    )
    workflow_run_id = Column(
        Integer, ForeignKey("workflow_runs.id", ondelete="SET NULL"), nullable=True
    )
    campaign_id = Column(
        Integer, ForeignKey("campaigns.id", ondelete="SET NULL"), nullable=True
    )
    queued_run_id = Column(
        Integer, ForeignKey("queued_runs.id", ondelete="SET NULL"), nullable=True
    )
    provider = Column(String(64), nullable=False)
    provider_call_id_hash = Column(String(64), nullable=True)
    direction = Column(String(16), nullable=False)
    event_type = Column(String(64), nullable=False)
    status = Column(String(64), nullable=True)
    failure_category = Column(String(64), nullable=True)
    release_reason = Column(String(64), nullable=True)
    admission_slot_id = Column(String(128), nullable=True)
    from_number_masked = Column(String(64), nullable=True)
    from_number_hash = Column(String(64), nullable=True)
    to_number_masked = Column(String(64), nullable=True)
    to_number_hash = Column(String(64), nullable=True)
    occurred_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    duration_seconds = Column(Integer, nullable=True)
    artifact_recording_expected = Column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    artifact_recording_present = Column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    artifact_transcript_expected = Column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    artifact_transcript_present = Column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    artifact_payload = Column(
        JSON, nullable=False, default=dict, server_default=text("'{}'::json")
    )
    provider_payload_redacted = Column(
        JSON, nullable=False, default=dict, server_default=text("'{}'::json")
    )
    contract_version = Column(String(64), nullable=True)
    is_contract_fixture = Column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    live_trunk_validated = Column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    schema_version = Column(Integer, nullable=False, default=1, server_default=text("1"))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    __table_args__ = (
        UniqueConstraint(
            "idempotency_key", name="uq_telephony_call_events_idempotency"
        ),
        Index("ix_telephony_call_events_attempt", "call_attempt_id"),
        Index("ix_telephony_call_events_org_created", "organization_id", "created_at"),
        Index("ix_telephony_call_events_workflow_run", "workflow_run_id"),
        Index("ix_telephony_call_events_provider_status", "provider", "status"),
    )


class TelephonyCDRModel(Base):
    __tablename__ = "telephony_cdrs"

    id = Column(Integer, primary_key=True, index=True)
    call_attempt_id = Column(String(128), nullable=False)
    idempotency_key = Column(String(255), nullable=False)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True
    )
    telephony_configuration_id = Column(
        Integer,
        ForeignKey("telephony_configurations.id", ondelete="SET NULL"),
        nullable=True,
    )
    telephony_phone_number_id = Column(
        Integer,
        ForeignKey("telephony_phone_numbers.id", ondelete="SET NULL"),
        nullable=True,
    )
    inventory_id = Column(Integer, nullable=True)
    workflow_id = Column(
        Integer, ForeignKey("workflows.id", ondelete="SET NULL"), nullable=True
    )
    workflow_run_id = Column(
        Integer, ForeignKey("workflow_runs.id", ondelete="SET NULL"), nullable=True
    )
    campaign_id = Column(
        Integer, ForeignKey("campaigns.id", ondelete="SET NULL"), nullable=True
    )
    queued_run_id = Column(
        Integer, ForeignKey("queued_runs.id", ondelete="SET NULL"), nullable=True
    )
    provider = Column(String(64), nullable=False)
    provider_call_id_hash = Column(String(64), nullable=True)
    direction = Column(String(16), nullable=False)
    terminal_status = Column(String(64), nullable=False)
    failure_category = Column(String(64), nullable=True)
    release_reason = Column(String(64), nullable=True)
    admission_slot_id = Column(String(128), nullable=True)
    from_number_masked = Column(String(64), nullable=True)
    from_number_hash = Column(String(64), nullable=True)
    to_number_masked = Column(String(64), nullable=True)
    to_number_hash = Column(String(64), nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    answered_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    duration_seconds = Column(Integer, nullable=True)
    artifact_recording_expected = Column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    artifact_recording_present = Column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    artifact_transcript_expected = Column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    artifact_transcript_present = Column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    artifact_payload = Column(
        JSON, nullable=False, default=dict, server_default=text("'{}'::json")
    )
    provider_payload_redacted = Column(
        JSON, nullable=False, default=dict, server_default=text("'{}'::json")
    )
    contract_version = Column(String(64), nullable=True)
    is_contract_fixture = Column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    live_trunk_validated = Column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    schema_version = Column(Integer, nullable=False, default=1, server_default=text("1"))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    __table_args__ = (
        UniqueConstraint("call_attempt_id", name="uq_telephony_cdrs_attempt"),
        UniqueConstraint("idempotency_key", name="uq_telephony_cdrs_idempotency"),
        Index("ix_telephony_cdrs_org_created", "organization_id", "created_at"),
        Index("ix_telephony_cdrs_workflow_run", "workflow_run_id"),
        Index("ix_telephony_cdrs_provider_status", "provider", "terminal_status"),
        Index(
            "ix_telephony_cdrs_live_readiness",
            "organization_id",
            "created_at",
            postgresql_where=text(
                "is_contract_fixture = false AND live_trunk_validated = true"
            ),
        ),
    )


class TelephonyOpsAlertModel(Base):
    __tablename__ = "telephony_ops_alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_type = Column(String(64), nullable=False)
    severity = Column(String(16), nullable=False)
    dedupe_key = Column(String(255), nullable=False)
    summary = Column(String(512), nullable=False)
    details_redacted = Column(
        JSON, nullable=False, default=dict, server_default=text("'{}'::json")
    )
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True
    )
    provider = Column(String(64), nullable=True)
    source = Column(String(64), nullable=False, default="runtime")
    status = Column(String(32), nullable=False, default="active")
    is_contract_fixture = Column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    should_page_live_ops = Column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    occurrence_count = Column(Integer, nullable=False, default=1, server_default=text("1"))
    first_seen_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    last_seen_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    escalated_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    __table_args__ = (
        UniqueConstraint("dedupe_key", name="uq_telephony_ops_alerts_dedupe"),
        Index("ix_telephony_ops_alerts_type_status", "alert_type", "status"),
        Index("ix_telephony_ops_alerts_org_seen", "organization_id", "last_seen_at"),
    )


class TelephonyNumberInventoryModel(Base):
    __tablename__ = "telephony_number_inventory"

    id = Column(Integer, primary_key=True, index=True)
    provider = Column(
        String(32),
        nullable=False,
        default="jambonz",
        server_default=text("'jambonz'"),
    )
    trunk_group = Column(String(64), nullable=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True
    )
    telephony_configuration_id = Column(
        Integer,
        ForeignKey("telephony_configurations.id", ondelete="SET NULL"),
        nullable=True,
    )
    telephony_phone_number_id = Column(
        Integer,
        ForeignKey("telephony_phone_numbers.id", ondelete="SET NULL"),
        nullable=True,
    )
    onnuri_staging_candidate_id = Column(
        Integer,
        ForeignKey("onnuri_staging_candidates.id", ondelete="SET NULL"),
        nullable=True,
    )
    onnuri_preflight_proof_id = Column(
        Integer,
        ForeignKey("onnuri_staging_preflight_proofs.id", ondelete="SET NULL"),
        nullable=True,
    )
    onnuri_preflight_proof_hash = Column(String(64), nullable=True)
    address_normalized = Column(String(255), nullable=False)
    address_masked = Column(String(255), nullable=True)
    address_hash = Column(String(64), nullable=True)
    address_encrypted_raw = Column(Text, nullable=True)
    address_type = Column(String(16), nullable=False)
    country_code = Column(String(2), nullable=True)
    label = Column(String(64), nullable=True)
    status = Column(
        String(32),
        nullable=False,
        default="available",
        server_default=text("'available'"),
    )
    reservation_expires_at = Column(DateTime(timezone=True), nullable=True)
    quarantined_reason = Column(Text, nullable=True)
    retired_reason = Column(Text, nullable=True)
    extra_metadata = Column(
        JSON, nullable=False, default=dict, server_default=text("'{}'::json")
    )
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    organization = relationship("OrganizationModel")
    telephony_configuration = relationship("TelephonyConfigurationModel")
    telephony_phone_number = relationship("TelephonyPhoneNumberModel")

    __table_args__ = (
        Index(
            "uq_telephony_number_inventory_provider_address_active",
            "provider",
            "address_normalized",
            unique=True,
            postgresql_where=text("status != 'retired'"),
        ),
        Index("ix_telephony_number_inventory_provider_status", "provider", "status"),
        Index(
            "ix_telephony_number_inventory_org_status",
            "organization_id",
            "status",
        ),
        Index(
            "ix_telephony_number_inventory_address_hash",
            "address_hash",
            postgresql_where=text("address_hash IS NOT NULL"),
        ),
        Index(
            "uq_telephony_number_inventory_phone_number",
            "telephony_phone_number_id",
            unique=True,
            postgresql_where=text("telephony_phone_number_id IS NOT NULL"),
        ),
    )


class TelephonyNumberInventoryAuditModel(Base):
    __tablename__ = "telephony_number_inventory_audit"

    id = Column(Integer, primary_key=True, index=True)
    inventory_id = Column(
        Integer,
        ForeignKey("telephony_number_inventory.id", ondelete="CASCADE"),
        nullable=False,
    )
    actor_user_id = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True
    )
    action = Column(String(64), nullable=False)
    from_status = Column(String(32), nullable=True)
    to_status = Column(String(32), nullable=True)
    details = Column(
        JSON, nullable=False, default=dict, server_default=text("'{}'::json")
    )
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    inventory = relationship("TelephonyNumberInventoryModel")
    actor = relationship("UserModel")
    organization = relationship("OrganizationModel")

    __table_args__ = (
        Index("ix_telephony_number_inventory_audit_inventory", "inventory_id"),
        Index("ix_telephony_number_inventory_audit_actor", "actor_user_id"),
        Index("ix_telephony_number_inventory_audit_created", "created_at"),
    )


class G008ExecutionNonceConsumptionModel(Base):
    """Write-once tenant-bound consumption of one sealed execution nonce."""

    __tablename__ = "g008_execution_nonce_consumptions"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False
    )
    execution_seal_uuid = Column(String(36), nullable=False)
    execution_nonce_digest = Column(String(64), nullable=False)
    candidate_digest = Column(String(64), nullable=False)
    gate_envelope_digest = Column(String(64), nullable=False)
    trusted_keyset_digest = Column(String(64), nullable=False)
    consumed_at = Column(
        DateTime(timezone=True), nullable=False, server_default=text("clock_timestamp()")
    )

    __table_args__ = (
        UniqueConstraint(
            "execution_seal_uuid", name="uq_g008_execution_nonce_seal"
        ),
        UniqueConstraint(
            "execution_nonce_digest", name="uq_g008_execution_nonce_digest"
        ),
        CheckConstraint(
            "execution_nonce_digest ~ '^[0-9a-f]{64}$' AND "
            "candidate_digest ~ '^[0-9a-f]{64}$' AND "
            "gate_envelope_digest ~ '^[0-9a-f]{64}$' AND "
            "trusted_keyset_digest ~ '^[0-9a-f]{64}$'",
            name="ck_g008_execution_nonce_consumption_digests",
        ),
    )


class G008ExecutionSealModel(Base):
    """Tenant-bound, redacted authority for one four-stage G008 execution."""

    __tablename__ = "g008_execution_seals"

    id = Column(Integer, primary_key=True, index=True)
    execution_seal_uuid = Column(
        String(36),
        nullable=False,
        unique=True,
        default=lambda: str(uuid.uuid4()),
        server_default=text("gen_random_uuid()::text"),
    )
    schema_version = Column(
        String(64),
        nullable=False,
        default="recova-g008-execution-seal-v1",
        server_default=text("'recova-g008-execution-seal-v1'"),
    )
    execution_mode = Column(
        String(32),
        nullable=False,
        default="legacy_registration",
        server_default=text("'legacy_registration'"),
    )
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False
    )
    execution_nonce_digest = Column(String(64), nullable=False, unique=True)
    candidate_digest = Column(String(64), nullable=False)
    gate_envelope_digest = Column(String(64), nullable=False)
    destination_hmac_digest = Column(String(64), nullable=False)
    owned_target_digest = Column(String(64), nullable=True)
    source_external_ipv4 = Column(String(15), nullable=True)
    peer_signaling_ipv4_cidr = Column(String(18), nullable=True)
    peer_signaling_udp_port = Column(Integer, nullable=True)
    reserved_inbound_did_digest = Column(String(64), nullable=False)
    reserved_inbound_caller_digest = Column(String(64), nullable=False)
    policy_digest = Column(String(64), nullable=False)
    retry_count = Column(Integer, nullable=False, default=0, server_default=text("0"))
    concurrency_count = Column(
        Integer, nullable=False, default=1, server_default=text("1")
    )
    call_deadline_seconds = Column(
        Integer, nullable=False, default=60, server_default=text("60")
    )
    state = Column(
        String(16), nullable=False, default="sealed", server_default=text("'sealed'")
    )
    live_window_starts_at = Column(DateTime(timezone=True), nullable=False)
    live_window_expires_at = Column(DateTime(timezone=True), nullable=False)
    sealed_at = Column(DateTime(timezone=True), nullable=False)
    started_at = Column(DateTime(timezone=True), nullable=True)
    containment_class = Column(String(64), nullable=True)
    containment_evidence_digest = Column(String(64), nullable=True)
    containment_evidence_signature_digest = Column(String(64), nullable=True)
    containment_evidence_key_digest = Column(String(64), nullable=True)
    containment_evidence_key_id = Column(String(128), nullable=True)
    contained_at = Column(DateTime(timezone=True), nullable=True)
    containment_evidence_canonical = Column(LargeBinary, nullable=True)
    containment_evidence_signature = Column(LargeBinary, nullable=True)
    final_evidence_digest = Column(String(64), nullable=True)
    final_evidence_signature_digest = Column(String(64), nullable=True)
    final_evidence_key_digest = Column(String(64), nullable=True)
    final_evidence_key_id = Column(String(128), nullable=True)
    final_evidence_canonical = Column(LargeBinary, nullable=True)
    final_evidence_signature = Column(LargeBinary, nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    failed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        server_default=text("now()"),
    )

    __table_args__ = (
        CheckConstraint(
            "schema_version = 'recova-g008-execution-seal-v1'",
            name="ck_g008_execution_seal_schema",
        ),
        CheckConstraint(
            "execution_mode IN ('legacy_registration','ip_to_ip_no_register')",
            name="ck_g008_execution_seal_mode",
        ),
        CheckConstraint(
            "(execution_mode = 'legacy_registration' AND owned_target_digest IS NULL "
            "AND source_external_ipv4 IS NULL AND peer_signaling_ipv4_cidr IS NULL "
            "AND peer_signaling_udp_port IS NULL) OR "
            "(execution_mode = 'ip_to_ip_no_register' AND "
            "owned_target_digest ~ '^[0-9a-f]{64}$' AND "
            "source_external_ipv4 ~ '^([0-9]{1,3}\\.){3}[0-9]{1,3}$' AND "
            "peer_signaling_ipv4_cidr ~ '^([0-9]{1,3}\\.){3}[0-9]{1,3}/32$' AND "
            "peer_signaling_udp_port = 5060)",
            name="ck_g008_execution_seal_mode_binding",
        ),
        CheckConstraint(
            "retry_count = 0 AND concurrency_count = 1 "
            "AND call_deadline_seconds = 60",
            name="ck_g008_execution_seal_policy",
        ),
        CheckConstraint(
            "state IN ('sealed','running','cleanup_required','residue_blocked',"
            "'contained','completed','failed')",
            name="ck_g008_execution_seal_state",
        ),
        CheckConstraint(
            "live_window_starts_at < live_window_expires_at "
            "AND sealed_at < live_window_expires_at",
            name="ck_g008_execution_seal_window",
        ),
        CheckConstraint(
            "(state = 'contained' AND contained_at IS NOT NULL "
            "AND containment_class IS NOT NULL "
            "AND containment_evidence_digest IS NOT NULL "
            "AND containment_evidence_signature_digest IS NOT NULL "
            "AND containment_evidence_key_digest IS NOT NULL "
            "AND containment_evidence_key_id IS NOT NULL) OR "
            "(state <> 'contained' AND contained_at IS NULL "
            "AND containment_class IS NULL "
            "AND containment_evidence_digest IS NULL "
            "AND containment_evidence_signature_digest IS NULL "
            "AND containment_evidence_key_digest IS NULL "
            "AND containment_evidence_key_id IS NULL)",
            name="ck_g008_execution_seal_containment",
        ),
        CheckConstraint(
            "(state = 'completed' AND completed_at IS NOT NULL "
            "AND final_evidence_digest IS NOT NULL "
            "AND final_evidence_signature_digest IS NOT NULL "
            "AND final_evidence_key_digest IS NOT NULL "
            "AND final_evidence_key_id IS NOT NULL) OR "
            "(state <> 'completed' AND completed_at IS NULL "
            "AND final_evidence_digest IS NULL "
            "AND final_evidence_signature_digest IS NULL "
            "AND final_evidence_key_digest IS NULL "
            "AND final_evidence_key_id IS NULL)",
            name="ck_g008_execution_seal_final_evidence",
        ),
        CheckConstraint(
            "(state = 'failed') = (failed_at IS NOT NULL)",
            name="ck_g008_execution_seal_failure",
        ),
        CheckConstraint(
            "(containment_evidence_digest IS NULL OR "
            "containment_evidence_digest ~ '^[0-9a-f]{64}$') AND "
            "(containment_evidence_signature_digest IS NULL OR "
            "containment_evidence_signature_digest ~ '^[0-9a-f]{64}$') AND "
            "(containment_evidence_key_digest IS NULL OR "
            "containment_evidence_key_digest ~ '^[0-9a-f]{64}$') AND "
            "(final_evidence_digest IS NULL OR "
            "final_evidence_digest ~ '^[0-9a-f]{64}$') AND "
            "(final_evidence_signature_digest IS NULL OR "
            "final_evidence_signature_digest ~ '^[0-9a-f]{64}$') AND "
            "(final_evidence_key_digest IS NULL OR "
            "final_evidence_key_digest ~ '^[0-9a-f]{64}$')",
            name="ck_g008_execution_seal_evidence_digests",
        ),
        Index(
            "ix_g008_execution_seal_inbound_reservation",
            "organization_id",
            "reserved_inbound_did_digest",
            "reserved_inbound_caller_digest",
            "candidate_digest",
            "gate_envelope_digest",
            postgresql_where=text("state IN ('sealed','running')"),
        ),
    )


class G008ExecutionStageModel(Base):
    """One immutable-position stage in a G008 execution."""

    __tablename__ = "g008_execution_stages"

    id = Column(Integer, primary_key=True, index=True)
    stage_uuid = Column(
        String(36),
        nullable=False,
        unique=True,
        default=lambda: str(uuid.uuid4()),
        server_default=text("gen_random_uuid()::text"),
    )
    execution_seal_id = Column(
        Integer,
        ForeignKey("g008_execution_seals.id", ondelete="RESTRICT"),
        nullable=False,
    )
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False
    )
    execution_nonce_digest = Column(String(64), nullable=False)
    candidate_digest = Column(String(64), nullable=False)
    gate_envelope_digest = Column(String(64), nullable=False)
    stage = Column(String(32), nullable=False)
    ordinal = Column(Integer, nullable=False)
    state = Column(
        String(16), nullable=False, default="pending", server_default=text("'pending'")
    )
    started_at = Column(DateTime(timezone=True), nullable=True)
    stage_deadline_at = Column(DateTime(timezone=True), nullable=True)
    terminal_class = Column(String(64), nullable=True)
    evidence_digest = Column(String(64), nullable=True)
    evidence_signature_digest = Column(String(64), nullable=True)
    evidence_key_digest = Column(String(64), nullable=True)
    evidence_key_id = Column(String(128), nullable=True)
    evidence_canonical = Column(LargeBinary, nullable=True)
    evidence_signature = Column(LargeBinary, nullable=True)
    finalized_at = Column(DateTime(timezone=True), nullable=True)
    account_uuid = Column(String(36), nullable=True)
    application_uuid = Column(String(36), nullable=True)
    run_uuid = Column(String(36), nullable=True)
    attempt_uuid = Column(String(36), nullable=True)
    stock_call_id_digest = Column(String(64), nullable=True)
    idempotency_digest = Column(String(64), nullable=True)
    request_digest = Column(String(64), nullable=True)
    did_digest = Column(String(64), nullable=True)
    caller_digest = Column(String(64), nullable=True)
    authority_deadline_at = Column(DateTime(timezone=True), nullable=True)
    bound_at = Column(DateTime(timezone=True), nullable=True)
    bind_receipt_digest = Column(String(64), nullable=True)
    bind_receipt_signature_digest = Column(String(64), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "execution_seal_id", "ordinal", name="uq_g008_execution_stage_ordinal"
        ),
        UniqueConstraint(
            "execution_seal_id", "stage", name="uq_g008_execution_stage_kind"
        ),
        UniqueConstraint(
            "stock_call_id_digest", name="uq_g008_execution_stage_stock_call"
        ),
        CheckConstraint(
            "(ordinal = 1 AND stage IN ('register','peer_attach')) OR "
            "(ordinal = 2 AND stage = 'outbound_call') OR "
            "(ordinal = 3 AND stage = 'inbound_call') OR "
            "(ordinal = 4 AND stage IN ('unregister','peer_detach'))",
            name="ck_g008_execution_stage_order",
        ),
        CheckConstraint(
            "state IN ('pending','started','succeeded','failed','contained')",
            name="ck_g008_execution_stage_state",
        ),
        CheckConstraint(
            "(state = 'pending') = (started_at IS NULL)",
            name="ck_g008_execution_stage_started",
        ),
        CheckConstraint(
            "(state IN ('pending','started') AND finalized_at IS NULL "
            "AND terminal_class IS NULL AND evidence_digest IS NULL "
            "AND evidence_signature_digest IS NULL "
            "AND evidence_key_digest IS NULL AND evidence_key_id IS NULL) OR "
            "(state IN ('succeeded','failed','contained') "
            "AND finalized_at IS NOT NULL AND terminal_class IS NOT NULL "
            "AND evidence_digest IS NOT NULL "
            "AND evidence_signature_digest IS NOT NULL "
            "AND evidence_key_digest IS NOT NULL AND evidence_key_id IS NOT NULL)",
            name="ck_g008_execution_stage_terminal",
        ),
        CheckConstraint(
            "stage_deadline_at IS NULL OR "
            "(started_at IS NOT NULL AND "
            "stage_deadline_at = started_at + interval '60 seconds')",
            name="ck_g008_execution_stage_deadline",
        ),
        CheckConstraint(
            "(stock_call_id_digest IS NULL AND account_uuid IS NULL "
            "AND application_uuid IS NULL AND run_uuid IS NULL "
            "AND attempt_uuid IS NULL AND idempotency_digest IS NULL "
            "AND request_digest IS NULL AND did_digest IS NULL "
            "AND caller_digest IS NULL AND authority_deadline_at IS NULL "
            "AND bound_at IS NULL AND bind_receipt_digest IS NULL "
            "AND bind_receipt_signature_digest IS NULL) OR "
            "(stock_call_id_digest IS NOT NULL AND account_uuid IS NOT NULL "
            "AND application_uuid IS NOT NULL AND run_uuid IS NOT NULL "
            "AND attempt_uuid IS NOT NULL AND idempotency_digest IS NOT NULL "
            "AND request_digest IS NOT NULL AND did_digest IS NOT NULL "
            "AND caller_digest IS NOT NULL AND authority_deadline_at IS NOT NULL "
            "AND bound_at IS NOT NULL AND bind_receipt_digest IS NOT NULL "
            "AND bind_receipt_signature_digest IS NOT NULL)",
            name="ck_g008_execution_stage_inbound_binding",
        ),
        CheckConstraint(
            "bound_at IS NULL OR bound_at < authority_deadline_at",
            name="ck_g008_inbound_stage_binding_deadline",
        ),
        CheckConstraint(
            "(evidence_digest IS NULL OR evidence_digest ~ '^[0-9a-f]{64}$') "
            "AND (evidence_signature_digest IS NULL OR "
            "evidence_signature_digest ~ '^[0-9a-f]{64}$') "
            "AND (evidence_key_digest IS NULL OR "
            "evidence_key_digest ~ '^[0-9a-f]{64}$') "
            "AND (stock_call_id_digest IS NULL OR "
            "stock_call_id_digest ~ '^[0-9a-f]{64}$') "
            "AND (idempotency_digest IS NULL OR "
            "idempotency_digest ~ '^[0-9a-f]{64}$') "
            "AND (request_digest IS NULL OR request_digest ~ '^[0-9a-f]{64}$') "
            "AND (did_digest IS NULL OR did_digest ~ '^[0-9a-f]{64}$') "
            "AND (caller_digest IS NULL OR caller_digest ~ '^[0-9a-f]{64}$') "
            "AND (bind_receipt_digest IS NULL OR "
            "bind_receipt_digest ~ '^[0-9a-f]{64}$') "
            "AND (bind_receipt_signature_digest IS NULL OR "
            "bind_receipt_signature_digest ~ '^[0-9a-f]{64}$')",
            name="ck_g008_execution_stage_digests",
        ),
        CheckConstraint(
            "stock_call_id_digest IS NULL OR "
            "(stage = 'inbound_call' AND ordinal = 3 AND state <> 'pending')",
            name="ck_g008_execution_stage_inbound_only",
        ),
        Index(
            "ix_g008_execution_stage_seal_order",
            "execution_seal_id",
            "ordinal",
        ),
    )


class G008OutboundBindingModel(Base):
    """Authority-owned terminal observation for the G008 outbound call."""

    __tablename__ = "g008_outbound_bindings"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False
    )
    execution_stage_id = Column(
        Integer,
        ForeignKey("g008_execution_stages.id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    )
    smoke_attempt_id = Column(
        Integer,
        ForeignKey("onnuri_staging_smoke_attempts.id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    )
    account_uuid = Column(String(255), nullable=False)
    application_uuid = Column(String(255), nullable=False)
    stock_call_id_digest = Column(String(64), nullable=False, unique=True)
    authority_deadline_at = Column(DateTime(timezone=True), nullable=False)
    terminal_class = Column(String(64), nullable=False)
    terminal_at = Column(DateTime(timezone=True), nullable=False)
    bound_at = Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )

    __table_args__ = (
        CheckConstraint(
            "terminal_class = 'call_completed'",
            name="ck_g008_outbound_binding_completed",
        ),
        CheckConstraint(
            "terminal_at <= authority_deadline_at AND bound_at >= terminal_at",
            name="ck_g008_outbound_binding_timeline",
        ),
        CheckConstraint(
            "stock_call_id_digest ~ '^[0-9a-f]{64}$'",
            name="ck_g008_outbound_binding_digest",
        ),
    )
class G008InboundBindingModel(Base):
    """Authority-owned binding between one inbound stock call and G008 stage 3."""

    __tablename__ = "g008_inbound_bindings"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False
    )
    execution_stage_id = Column(
        Integer,
        ForeignKey("g008_execution_stages.id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    )
    account_uuid = Column(String(36), nullable=False)
    application_uuid = Column(String(36), nullable=False)
    stock_call_uuid = Column(String(36), nullable=False)
    stock_call_id_digest = Column(String(64), nullable=False)
    did_digest = Column(String(64), nullable=False)
    caller_digest = Column(String(64), nullable=False)
    direction = Column(
        String(16), nullable=False, default="inbound", server_default=text("'inbound'")
    )
    run_uuid = Column(
        String(36),
        nullable=False,
        unique=True,
        default=lambda: str(uuid.uuid4()),
        server_default=text("gen_random_uuid()::text"),
    )
    attempt_uuid = Column(
        String(36),
        nullable=False,
        unique=True,
        default=lambda: str(uuid.uuid4()),
        server_default=text("gen_random_uuid()::text"),
    )
    idempotency_uuid = Column(
        String(36),
        nullable=False,
        unique=True,
        default=lambda: str(uuid.uuid4()),
        server_default=text("gen_random_uuid()::text"),
    )
    bind_receipt_uuid = Column(
        String(36),
        nullable=False,
        unique=True,
        default=lambda: str(uuid.uuid4()),
        server_default=text("gen_random_uuid()::text"),
    )
    request_digest = Column(String(64), nullable=False)
    receipt_schema = Column(
        String(64),
        nullable=False,
        default="recova-g008-inbound-bind-receipt-v1",
        server_default=text("'recova-g008-inbound-bind-receipt-v1'"),
    )
    receipt_domain = Column(
        String(128),
        nullable=False,
        default="recova.onnuri.smoke.g008.inbound-bind.v1",
        server_default=text("'recova.onnuri.smoke.g008.inbound-bind.v1'"),
    )
    receipt_algorithm = Column(
        String(16), nullable=False, default="ES256", server_default=text("'ES256'")
    )
    receipt_key_id = Column(String(128), nullable=True)
    receipt_spki_digest = Column(String(64), nullable=True)
    receipt_signature_digest = Column(String(64), nullable=True)
    receipt_unsigned_digest = Column(String(64), nullable=True)
    recovery_ciphertext = Column(Text, nullable=True)
    recovery_ciphertext_digest = Column(String(64), nullable=True)
    canonical_claims = Column(JSON, nullable=False)
    state = Column(
        String(16), nullable=False, default="issuing", server_default=text("'issuing'")
    )
    lease_expires_at = Column(DateTime(timezone=True), nullable=False)
    issuance_attempt_count = Column(
        Integer, nullable=False, default=1, server_default=text("1")
    )
    authority_deadline_at = Column(DateTime(timezone=True), nullable=False)
    issued_at = Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    bound_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "account_uuid",
            "stock_call_id_digest",
            name="uq_g008_inbound_binding_tenant_account_stock",
        ),
        CheckConstraint(
            "direction = 'inbound'", name="ck_g008_inbound_binding_direction"
        ),
        CheckConstraint(
            "receipt_schema = 'recova-g008-inbound-bind-receipt-v1' "
            "AND receipt_domain = 'recova.onnuri.smoke.g008.inbound-bind.v1' "
            "AND receipt_algorithm = 'ES256'",
            name="ck_g008_inbound_binding_receipt_contract",
        ),
        CheckConstraint(
            "state IN ('issuing','bound')",
            name="ck_g008_inbound_binding_state",
        ),
        CheckConstraint(
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
        CheckConstraint(
            "account_uuid ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            "[0-9a-f]{4}-[0-9a-f]{12}$' "
            "AND application_uuid ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            "[0-9a-f]{4}-[0-9a-f]{12}$' "
            "AND stock_call_uuid ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            "[0-9a-f]{4}-[0-9a-f]{12}$' "
            "AND run_uuid ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
            "[89ab][0-9a-f]{3}-[0-9a-f]{12}$' "
            "AND attempt_uuid ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
            "[89ab][0-9a-f]{3}-[0-9a-f]{12}$' "
            "AND idempotency_uuid ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
            "[89ab][0-9a-f]{3}-[0-9a-f]{12}$' "
            "AND bind_receipt_uuid ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
            "[89ab][0-9a-f]{3}-[0-9a-f]{12}$'",
            name="ck_g008_inbound_binding_uuids",
        ),
        CheckConstraint(
            "stock_call_id_digest ~ '^[0-9a-f]{64}$' "
            "AND did_digest ~ '^[0-9a-f]{64}$' "
            "AND caller_digest ~ '^[0-9a-f]{64}$' "
            "AND request_digest ~ '^[0-9a-f]{64}$' "
            "AND (receipt_spki_digest IS NULL OR "
            "receipt_spki_digest ~ '^[0-9a-f]{64}$') "
            "AND (receipt_signature_digest IS NULL OR "
            "receipt_signature_digest ~ '^[0-9a-f]{64}$') "
            "AND (receipt_unsigned_digest IS NULL OR "
            "receipt_unsigned_digest ~ '^[0-9a-f]{64}$') "
            "AND (recovery_ciphertext_digest IS NULL OR "
            "recovery_ciphertext_digest ~ '^[0-9a-f]{64}$')",
            name="ck_g008_inbound_binding_digests",
        ),
        CheckConstraint(
            "lease_expires_at <= authority_deadline_at "
            "AND issuance_attempt_count >= 1",
            name="ck_g008_inbound_binding_lease",
        ),
        CheckConstraint(
            "authority_deadline_at >= issued_at + interval '60 seconds'",
            name="ck_g008_inbound_binding_deadline",
        ),
        CheckConstraint(
            "bound_at IS NULL OR bound_at < authority_deadline_at",
            name="ck_g008_inbound_binding_bound_before_deadline",
        ),
    )

class OnnuriStagingCandidateModel(Base):
    """Immutable provenance for an Onnuri staging inventory candidate."""

    __tablename__ = "onnuri_staging_candidates"

    id = Column(Integer, primary_key=True, index=True)
    candidate_uuid = Column(
        String(36),
        nullable=False,
        unique=True,
        default=lambda: str(uuid.uuid4()),
        server_default=text("gen_random_uuid()::text"),
    )
    inventory_id = Column(
        Integer,
        ForeignKey("telephony_number_inventory.id", ondelete="RESTRICT"),
        nullable=False,
    )
    provider = Column(
        String(32), nullable=False, default="jambonz", server_default=text("'jambonz'")
    )
    normalized_did = Column(String(255), nullable=False)
    classification = Column(
        String(64),
        nullable=False,
        default="onnuri_staging_candidate_v1",
        server_default=text("'onnuri_staging_candidate_v1'"),
    )
    environment = Column(
        String(32), nullable=False, default="staging", server_default=text("'staging'")
    )
    state = Column(
        String(32), nullable=False, default="active", server_default=text("'active'")
    )
    retired_at = Column(DateTime(timezone=True), nullable=True)
    retired_by_user_id = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    retired_reason = Column(Text, nullable=True)
    created_by_user_id = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    inventory = relationship(
        "TelephonyNumberInventoryModel", foreign_keys=[inventory_id]
    )
    created_by = relationship("UserModel", foreign_keys=[created_by_user_id])
    retired_by = relationship("UserModel", foreign_keys=[retired_by_user_id])

    __table_args__ = (
        Index(
            "uq_onnuri_staging_candidate_active_inventory",
            "inventory_id",
            unique=True,
            postgresql_where=text("state = 'active'"),
        ),
        Index(
            "uq_onnuri_staging_candidate_active_provider_did_environment",
            "provider",
            "normalized_did",
            "environment",
            unique=True,
            postgresql_where=text("state = 'active'"),
        ),
    )


class OnnuriStagingPreflightProofModel(Base):
    """Password-free, revisioned approval record for one staging candidate."""

    __tablename__ = "onnuri_staging_preflight_proofs"

    id = Column(Integer, primary_key=True, index=True)
    candidate_id = Column(
        Integer,
        ForeignKey("onnuri_staging_candidates.id", ondelete="RESTRICT"),
        nullable=False,
    )
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False
    )
    inventory_id = Column(
        Integer,
        ForeignKey("telephony_number_inventory.id", ondelete="SET NULL"),
        nullable=True,
    )
    scope_key = Column(String(255), nullable=False)
    revision = Column(Integer, nullable=False)
    provider = Column(
        String(32), nullable=False, default="jambonz", server_default=text("'jambonz'")
    )
    environment = Column(
        String(32), nullable=False, default="staging", server_default=text("'staging'")
    )
    onboarding_kind = Column(
        String(64),
        nullable=False,
        default="onnuri_staging_preflight_v1",
        server_default=text("'onnuri_staging_preflight_v1'"),
    )
    canonical_input = Column(JSON, nullable=False)
    canonical_hash = Column(String(64), nullable=False)
    approved = Column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    passed = Column(Boolean, nullable=False, default=False, server_default=text("false"))
    predicate_class = Column(String(64), nullable=False)
    evaluator = Column(String(128), nullable=True)
    signer = Column(String(128), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revoked_by_user_id = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    revoke_reason = Column(Text, nullable=True)
    invalidated_at = Column(DateTime(timezone=True), nullable=True)
    invalidated_reason = Column(Text, nullable=True)
    is_current = Column(Boolean, nullable=False, default=True, server_default=text("true"))
    created_by_user_id = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    candidate = relationship("OnnuriStagingCandidateModel")
    organization = relationship("OrganizationModel")
    inventory = relationship(
        "TelephonyNumberInventoryModel", foreign_keys=[inventory_id]
    )
    created_by = relationship("UserModel", foreign_keys=[created_by_user_id])
    revoked_by = relationship("UserModel", foreign_keys=[revoked_by_user_id])

    __table_args__ = (
        UniqueConstraint("scope_key", "revision", name="uq_onnuri_preflight_scope_revision"),
        Index(
            "uq_onnuri_preflight_current_scope",
            "scope_key",
            unique=True,
            postgresql_where=text("is_current"),
        ),
        Index(
            "uq_onnuri_preflight_current_inventory",
            "inventory_id",
            unique=True,
            postgresql_where=text("inventory_id IS NOT NULL AND is_current"),
        ),
        Index("ix_onnuri_preflight_candidate", "candidate_id"),
        Index("ix_onnuri_preflight_org", "organization_id"),
        Index("ix_onnuri_preflight_expiry", "expires_at"),
        Index("ix_onnuri_preflight_hash", "canonical_hash"),
    )


class OnnuriStagingPreflightExpiryJobModel(Base):
    __tablename__ = "onnuri_staging_preflight_expiry_jobs"

    id = Column(Integer, primary_key=True, index=True)
    proof_id = Column(
        Integer,
        ForeignKey("onnuri_staging_preflight_proofs.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    run_at = Column(DateTime(timezone=True), nullable=False)
    state = Column(
        String(32), nullable=False, default="scheduled", server_default=text("'scheduled'")
    )
    attempts = Column(Integer, nullable=False, default=0, server_default=text("0"))
    leased_at = Column(DateTime(timezone=True), nullable=True)
    lease_expires_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    failed_at = Column(DateTime(timezone=True), nullable=True)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    proof = relationship("OnnuriStagingPreflightProofModel")

    __table_args__ = (
        Index("ix_onnuri_preflight_expiry_job_state_run_at", "state", "run_at"),
    )
class OnnuriStagingPreflightAuthorizationLeaseModel(Base):
    """Atomic, short-lived authorization for one no-soak smoke attempt."""

    __tablename__ = "onnuri_staging_preflight_authorization_leases"

    id = Column(Integer, primary_key=True, index=True)
    lease_uuid = Column(
        String(36),
        nullable=False,
        unique=True,
        default=lambda: str(uuid.uuid4()),
        server_default=text("gen_random_uuid()::text"),
    )
    proof_id = Column(
        Integer,
        ForeignKey("onnuri_staging_preflight_proofs.id", ondelete="CASCADE"),
        nullable=False,
    )
    inventory_id = Column(
        Integer,
        ForeignKey("telephony_number_inventory.id", ondelete="CASCADE"),
        nullable=False,
    )
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    actor_user_id = Column(
        Integer, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    attempt_kind = Column(String(16), nullable=False)
    application_attempt_id = Column(String(128), nullable=False, unique=True)
    evaluator_version = Column(String(64), nullable=True)
    smoke_envelope_id = Column(
        Integer, ForeignKey("onnuri_staging_smoke_envelopes.id", ondelete="RESTRICT"),
        nullable=True
    )
    smoke_attempt_id = Column(
        Integer, ForeignKey("onnuri_staging_smoke_attempts.id", ondelete="RESTRICT"),
        nullable=True
    )
    authenticated_operator_user_id = Column(
        Integer, ForeignKey("users.id", ondelete="RESTRICT"), nullable=True
    )
    workflow_owner_user_id = Column(
        Integer, ForeignKey("users.id", ondelete="RESTRICT"), nullable=True
    )
    evaluator_idempotency_key = Column(String(128), nullable=True)
    state = Column(
        String(16), nullable=False, default="active", server_default=text("'active'")
    )
    expires_at = Column(DateTime(timezone=True), nullable=False)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
    invalidated_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        server_default=text("now()"),
    )

    proof = relationship("OnnuriStagingPreflightProofModel")
    inventory = relationship("TelephonyNumberInventoryModel")
    organization = relationship("OrganizationModel")
    actor = relationship("UserModel", foreign_keys=[actor_user_id])

    __table_args__ = (
        Index(
            "ix_onnuri_preflight_lease_proof_state",
            "proof_id",
            "state",
            "created_at",
        ),
        Index(
            "ix_onnuri_preflight_lease_expiry",
            "state",
            "expires_at",
        ),
        CheckConstraint(
            ONNURI_EVALUATOR_LINKAGE_CHECK,
            name="ck_onnuri_staging_preflight_authorization_leases_v2_linkage",
        ),
    )
class OnnuriStagingSmokeDispatchAttemptModel(Base):
    """Durable pending/terminal record for one authorized smoke dispatch."""

    __tablename__ = "onnuri_staging_smoke_dispatch_attempts"

    id = Column(Integer, primary_key=True, index=True)
    application_attempt_id = Column(String(128), nullable=False, unique=True)
    lease_id = Column(
        Integer,
        ForeignKey(
            "onnuri_staging_preflight_authorization_leases.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
        unique=True,
    )
    proof_id = Column(
        Integer,
        ForeignKey("onnuri_staging_preflight_proofs.id", ondelete="RESTRICT"),
        nullable=False,
    )
    inventory_id = Column(
        Integer,
        ForeignKey("telephony_number_inventory.id", ondelete="RESTRICT"),
        nullable=False,
    )
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False
    )
    attempt_kind = Column(String(16), nullable=False)
    evaluator_version = Column(String(64), nullable=True)
    smoke_envelope_id = Column(
        Integer, ForeignKey("onnuri_staging_smoke_envelopes.id", ondelete="RESTRICT"),
        nullable=True
    )
    smoke_attempt_id = Column(
        Integer, ForeignKey("onnuri_staging_smoke_attempts.id", ondelete="RESTRICT"),
        nullable=True
    )
    authenticated_operator_user_id = Column(
        Integer, ForeignKey("users.id", ondelete="RESTRICT"), nullable=True
    )
    workflow_owner_user_id = Column(
        Integer, ForeignKey("users.id", ondelete="RESTRICT"), nullable=True
    )
    evaluator_idempotency_key = Column(String(128), nullable=True)
    state = Column(
        String(16), nullable=False, default="pending", server_default=text("'pending'")
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        server_default=text("now()"),
    )
    dispatched_at = Column(DateTime(timezone=True), nullable=True)
    failed_at = Column(DateTime(timezone=True), nullable=True)
    failure_reason = Column(Text, nullable=True)

    lease = relationship("OnnuriStagingPreflightAuthorizationLeaseModel")
    proof = relationship("OnnuriStagingPreflightProofModel")
    inventory = relationship("TelephonyNumberInventoryModel")
    organization = relationship("OrganizationModel")

    __table_args__ = (
        Index(
            "ix_onnuri_smoke_dispatch_org_state",
            "organization_id",
            "state",
            "created_at",
        ),
        CheckConstraint(
            ONNURI_EVALUATOR_LINKAGE_CHECK,
            name="ck_onnuri_staging_smoke_dispatch_attempts_v2_linkage",
        ),
    )


class OnnuriSmokeEnvelopeModel(Base):
    """Versioned, tenant-bound authority for the bounded Onnuri live smoke."""

    __tablename__ = "onnuri_staging_smoke_envelopes"

    id = Column(Integer, primary_key=True, index=True)
    envelope_uuid = Column(
        String(36), nullable=False, unique=True, default=lambda: str(uuid.uuid4()),
        server_default=text("gen_random_uuid()::text")
    )
    evaluator_version = Column(String(64), nullable=False)
    proof_id = Column(
        Integer, ForeignKey("onnuri_staging_preflight_proofs.id", ondelete="RESTRICT"),
        nullable=False
    )
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False
    )
    inventory_id = Column(
        Integer, ForeignKey("telephony_number_inventory.id", ondelete="RESTRICT"),
        nullable=False
    )
    telephony_configuration_id = Column(
        Integer, ForeignKey("telephony_configurations.id", ondelete="RESTRICT"),
        nullable=False
    )
    workflow_id = Column(
        Integer, ForeignKey("workflows.id", ondelete="RESTRICT"), nullable=False
    )
    destination_hmac_key_id = Column(String(255), nullable=False)
    destination_hmac_domain = Column(
        String(128),
        nullable=False,
        default="recova.onnuri.smoke.destination.v1",
        server_default=text("'recova.onnuri.smoke.destination.v1'"),
    )
    destination_hmac_key_version = Column(String(128), nullable=False)
    destination_hmac_digest = Column(String(128), nullable=False)
    dispatch_key_id = Column(String(255), nullable=False)
    dispatch_algorithm_policy_id = Column(String(128), nullable=False)
    dispatch_domain = Column(String(128), nullable=False)
    media_key_id = Column(String(255), nullable=False)
    media_algorithm_policy_id = Column(String(128), nullable=False)
    media_domain = Column(String(128), nullable=False)
    policy_digest = Column(String(64), nullable=False)
    candidate_digest = Column(String(128), nullable=False)
    phase_b_manifest_digest = Column(String(128), nullable=False)
    phase_c_iac_digest = Column(String(128), nullable=False)
    provider_balance_currency_receipt_digest = Column(String(64), nullable=True)
    supplier_signaling_media_receipt_digest = Column(String(64), nullable=True)
    tenant_mapping_receipt_digest = Column(String(64), nullable=True)
    secret_version_manifest_receipt_digest = Column(String(64), nullable=True)
    gate_decision_receipt_digest = Column(String(64), nullable=True)
    sealed_at = Column(DateTime(timezone=True), nullable=True)
    max_attempts = Column(Integer, nullable=False, default=3, server_default=text("3"))
    max_inbound_attempts = Column(Integer, nullable=False, default=1, server_default=text("1"))
    max_outbound_attempts = Column(Integer, nullable=False, default=1, server_default=text("1"))
    max_duration_seconds = Column(Integer, nullable=False, default=60, server_default=text("60"))
    max_concurrency = Column(Integer, nullable=False, default=1, server_default=text("1"))
    cps = Column(Integer, nullable=False, default=1, server_default=text("1"))
    retries = Column(Integer, nullable=False, default=0, server_default=text("0"))
    state = Column(String(32), nullable=False, default="armed", server_default=text("'armed'"))
    live_window_starts_at = Column(DateTime(timezone=True), nullable=False)
    live_window_expires_at = Column(DateTime(timezone=True), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    destroy_deadline = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    contained_at = Column(DateTime(timezone=True), nullable=True)
    terminal_at = Column(DateTime(timezone=True), nullable=True)
    containment_reason = Column(String(128), nullable=True)
    created_at = Column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC),
        server_default=text("now()")
    )

    __table_args__ = (
        CheckConstraint(
            "evaluator_version IN "
            "('recova_onnuri_smoke_authority_v2', "
            "'recova_onnuri_smoke_authority_v3')",
            name="ck_onnuri_smoke_evaluator",
        ),
        CheckConstraint(
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
            name="ck_onnuri_smoke_prerequisite_receipts",
        ),
        CheckConstraint("max_attempts = 3", name="ck_onnuri_smoke_envelope_max_attempts"),
        CheckConstraint("max_inbound_attempts = 1", name="ck_onnuri_smoke_envelope_inbound"),
        CheckConstraint("max_outbound_attempts = 1", name="ck_onnuri_smoke_envelope_outbound"),
        CheckConstraint("max_duration_seconds = 60", name="ck_onnuri_smoke_envelope_duration"),
        CheckConstraint(
            "max_concurrency = 1 AND cps = 1 AND retries = 0",
            name="ck_onnuri_smoke_envelope_rate"
        ),
        CheckConstraint("dispatch_key_id <> media_key_id", name="ck_onnuri_smoke_distinct_keys"),
        CheckConstraint("dispatch_domain <> media_domain", name="ck_onnuri_smoke_distinct_domains"),
        CheckConstraint(
            "destination_hmac_domain = 'recova.onnuri.smoke.destination.v1'",
            name="ck_onnuri_smoke_destination_domain",
        ),
        CheckConstraint(
            "live_window_starts_at < live_window_expires_at AND "
            "live_window_expires_at <= expires_at AND expires_at <= destroy_deadline",
            name="ck_onnuri_smoke_envelope_windows"
        ),
        Index(
            "uq_onnuri_smoke_active_envelope",
            "organization_id", unique=True,
            postgresql_where=text("state = 'armed'")
        ),
    )


class OnnuriSmokeAttemptModel(Base):
    """Permanently counted allocation and its immutable authority timeline."""

    __tablename__ = "onnuri_staging_smoke_attempts"

    id = Column(Integer, primary_key=True, index=True)
    attempt_uuid = Column(
        String(36), nullable=False, unique=True, default=lambda: str(uuid.uuid4()),
        server_default=text("gen_random_uuid()::text")
    )
    envelope_id = Column(
        Integer, ForeignKey("onnuri_staging_smoke_envelopes.id", ondelete="RESTRICT"),
        nullable=False
    )
    proof_id = Column(
        Integer, ForeignKey("onnuri_staging_preflight_proofs.id", ondelete="RESTRICT"),
        nullable=False
    )
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False
    )
    inventory_id = Column(
        Integer, ForeignKey("telephony_number_inventory.id", ondelete="RESTRICT"),
        nullable=False
    )
    telephony_configuration_id = Column(
        Integer, ForeignKey("telephony_configurations.id", ondelete="RESTRICT"),
        nullable=False
    )
    workflow_id = Column(
        Integer, ForeignKey("workflows.id", ondelete="RESTRICT"), nullable=False
    )
    ordinal = Column(Integer, nullable=False)
    direction = Column(String(16), nullable=False)
    state = Column(String(64), nullable=False, default="allocated", server_default=text("'allocated'"))
    authenticated_operator_user_id = Column(
        Integer, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    workflow_owner_user_id = Column(
        Integer, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    idempotency_key = Column(String(128), nullable=False)
    allocation_request_digest = Column(String(128), nullable=False)
    manual_acknowledgement_digest = Column(String(128), nullable=True)
    manual_acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    dispatch_receipt_digest = Column(String(128), nullable=True)
    stock_call_id_digest = Column(String(128), nullable=True)
    bind_callback_nonce_digest = Column(String(128), nullable=True)
    inbound_tuple_digest = Column(String(64), nullable=True)
    stock_bound_at = Column(DateTime(timezone=True), nullable=True)
    authority_kind = Column(String(64), nullable=True)
    authority_wall_at = Column(DateTime(timezone=True), nullable=True)
    authority_deadline_at = Column(DateTime(timezone=True), nullable=True)
    authority_budget_seconds = Column(Integer, nullable=True)
    observed_carrier_answer_at = Column(DateTime(timezone=True), nullable=True)
    terminal_class = Column(String(64), nullable=True)
    terminal_reason = Column(String(128), nullable=True)
    allocated_at = Column(DateTime(timezone=True), nullable=False, server_default=text("now()"))
    terminal_at = Column(DateTime(timezone=True), nullable=True)
    contained_at = Column(DateTime(timezone=True), nullable=True)
    account_id = Column(String(255), nullable=True)
    application_id = Column(String(255), nullable=True)
    run_id = Column(String(255), nullable=True)

    __table_args__ = (
        UniqueConstraint("envelope_id", "ordinal", name="uq_onnuri_smoke_attempt_ordinal"),
        UniqueConstraint("envelope_id", "idempotency_key", name="uq_onnuri_smoke_attempt_idempotency"),
        UniqueConstraint("stock_call_id_digest", name="uq_onnuri_smoke_stock_binding"),
        CheckConstraint("ordinal BETWEEN 1 AND 3", name="ck_onnuri_smoke_attempt_ordinal"),
        CheckConstraint("direction IN ('inbound','outbound')", name="ck_onnuri_smoke_attempt_direction"),
        CheckConstraint(
            "direction = 'inbound' OR inbound_tuple_digest IS NULL",
            name="ck_onnuri_smoke_inbound_tuple_direction",
        ),
        CheckConstraint(
            "authority_budget_seconds IS NULL OR "
            "(authority_budget_seconds BETWEEN 1 AND 60)",
            name="ck_onnuri_smoke_authority_budget"
        ),
        CheckConstraint(
            "(manual_acknowledgement_digest IS NULL) = "
            "(manual_acknowledged_at IS NULL)",
            name="ck_onnuri_smoke_manual_ack_pair",
        ),
        CheckConstraint(
            "(account_id IS NULL AND application_id IS NULL AND run_id IS NULL) OR "
            "(account_id IS NOT NULL AND application_id IS NOT NULL AND run_id IS NOT NULL)",
            name="ck_onnuri_smoke_attempt_bound_context",
        ),
        Index(
            "ix_onnuri_smoke_attempt_stock_lookup",
            "organization_id",
            "account_id",
            "stock_call_id_digest",
        ),
        Index(
            "uq_onnuri_smoke_one_active_attempt", "envelope_id", unique=True,
            postgresql_where=text(
                "state NOT IN ('terminal','contained')"
            )
        ),
    )


class OnnuriOutboundDiagnosticCapabilityModel(Base):
    """One persisted F12 route capability, consumed only with a diagnostic reservation."""

    __tablename__ = "onnuri_outbound_diagnostic_capabilities"

    id = Column(Integer, primary_key=True, index=True)
    nonce_digest = Column(String(64), nullable=False, unique=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False)
    envelope_id = Column(Integer, ForeignKey("onnuri_staging_smoke_envelopes.id", ondelete="RESTRICT"), nullable=False)
    authorization_attempt_id = Column(Integer, ForeignKey("onnuri_staging_smoke_attempts.id", ondelete="RESTRICT"), nullable=False)
    authenticated_operator_user_id = Column(Integer, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    idempotency_key = Column(String(255), nullable=False)
    request_digest = Column(String(64), nullable=False)
    candidate_digest = Column(String(64), nullable=False)
    gate_envelope_digest = Column(String(64), nullable=False)
    route_profile_digest = Column(String(64), nullable=False)
    route_digest = Column(String(64), nullable=False)
    provider_digest = Column(String(64), nullable=False)
    keyset_digest = Column(String(64), nullable=False)
    token_digest = Column(String(64), nullable=False)
    signature_digest = Column(String(64), nullable=False)
    encrypted_capability_recovery = Column(Text, nullable=False)
    encrypted_consume_recovery = Column(Text, nullable=True)
    consume_response_digest = Column(String(64), nullable=True)

    issued_at = Column(DateTime(timezone=True), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
    diagnostic_attempt_id = Column(Integer, ForeignKey("onnuri_outbound_diagnostic_attempts.id", ondelete="RESTRICT"), nullable=True, unique=True)

    __table_args__ = (
        UniqueConstraint("authorization_attempt_id", "idempotency_key", name="uq_onnuri_outbound_diagnostic_capability_idempotency"),
        CheckConstraint("nonce_digest ~ '^[0-9a-f]{64}$' AND request_digest ~ '^[0-9a-f]{64}$' AND candidate_digest ~ '^[0-9a-f]{64}$' AND gate_envelope_digest ~ '^[0-9a-f]{64}$' AND route_profile_digest ~ '^[0-9a-f]{64}$' AND route_digest ~ '^[0-9a-f]{64}$' AND provider_digest ~ '^[0-9a-f]{64}$' AND keyset_digest ~ '^[0-9a-f]{64}$' AND token_digest ~ '^[0-9a-f]{64}$' AND signature_digest ~ '^[0-9a-f]{64}$' AND (consume_response_digest IS NULL OR consume_response_digest ~ '^[0-9a-f]{64}$')", name="ck_onnuri_outbound_diagnostic_capability_digests"),
        CheckConstraint("expires_at > issued_at", name="ck_onnuri_outbound_diagnostic_capability_expiry"),
        CheckConstraint(
            "(encrypted_consume_recovery IS NULL) = (consume_response_digest IS NULL) AND "
            "(consumed_at IS NULL) = (diagnostic_attempt_id IS NULL) AND "
            "(consumed_at IS NULL OR (encrypted_consume_recovery IS NOT NULL AND consume_response_digest IS NOT NULL))",
            name="ck_onnuri_outbound_diagnostic_capability_consume_recovery",
        ),
    )


class OnnuriRouteAdapterReplayModel(Base):
    """Durable one-use restricted-inventory adapter replay ledger."""

    __tablename__ = "onnuri_route_adapter_replays"

    id = Column(Integer, primary_key=True)
    key_id = Column(String(255), nullable=False)
    challenge_nonce = Column(String(43), nullable=False)
    audience = Column(String(128), nullable=False)
    signature_sha256 = Column(String(64), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)

    __table_args__ = (
        UniqueConstraint("key_id", "challenge_nonce", "audience", "signature_sha256", name="uq_onnuri_route_adapter_replay"),
        CheckConstraint("signature_sha256 ~ '^[0-9a-f]{64}$'", name="ck_onnuri_route_adapter_replay_signature"),
    )


class OnnuriOutboundDiagnosticAttemptModel(Base):
    """Isolated v1 outbound diagnostic state; legacy G008 rows are untouched."""

    __tablename__ = "onnuri_outbound_diagnostic_attempts"

    id = Column(Integer, primary_key=True, index=True)
    attempt_uuid = Column(String(36), nullable=False, unique=True, default=lambda: str(uuid.uuid4()))
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False)
    envelope_id = Column(Integer, ForeignKey("onnuri_staging_smoke_envelopes.id", ondelete="RESTRICT"), nullable=False)
    inventory_id = Column(Integer, ForeignKey("telephony_number_inventory.id", ondelete="RESTRICT"), nullable=False)
    telephony_configuration_id = Column(Integer, ForeignKey("telephony_configurations.id", ondelete="RESTRICT"), nullable=False)
    authenticated_operator_user_id = Column(Integer, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    ordinal = Column(Integer, nullable=False)
    idempotency_key = Column(String(255), nullable=False)
    fixture_digest = Column(String(64), nullable=False)
    destination_hmac_digest = Column(String(64), nullable=False)
    destination_hmac_key_version = Column(String(128), nullable=False)
    caller_digest = Column(String(64), nullable=False)
    operator_role = Column(String(64), nullable=False)
    operator_credential_digest = Column(String(64), nullable=False)
    candidate_digest = Column(String(64), nullable=False)
    provider_digest = Column(String(64), nullable=False)
    route_digest = Column(String(64), nullable=False)
    nat_firewall_digest = Column(String(64), nullable=False)
    keyset_digest = Column(String(64), nullable=False)
    request_digest = Column(String(64), nullable=False)
    dispatch = Column(String(32), nullable=False, default="not_submitted", server_default=text("'not_submitted'"))
    signaling = Column(String(32), nullable=False, default="unknown", server_default=text("'unknown'"))
    answer = Column(String(32), nullable=False, default="unknown", server_default=text("'unknown'"))
    media = Column(String(32), nullable=False, default="unknown", server_default=text("'unknown'"))
    terminal = Column(String(32), nullable=False, default="open", server_default=text("'open'"))
    reconciliation_cutoff_at = Column(DateTime(timezone=True), nullable=False)
    event_sequence = Column(Integer, nullable=False, default=0, server_default=text("0"))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=text("now()"))
    terminal_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint("envelope_id", "ordinal", name="uq_onnuri_outbound_diagnostic_ordinal"),
        UniqueConstraint("envelope_id", "idempotency_key", name="uq_onnuri_outbound_diagnostic_idempotency"),
        CheckConstraint("ordinal BETWEEN 1 AND 3", name="ck_onnuri_outbound_diagnostic_ordinal"),
        CheckConstraint("fixture_digest ~ '^[0-9a-f]{64}$'", name="ck_onnuri_outbound_diagnostic_fixture_digest"),
        CheckConstraint("destination_hmac_digest ~ '^[0-9a-f]{64}$' AND caller_digest ~ '^[0-9a-f]{64}$' AND operator_credential_digest ~ '^[0-9a-f]{64}$' AND candidate_digest ~ '^[0-9a-f]{64}$' AND provider_digest ~ '^[0-9a-f]{64}$' AND route_digest ~ '^[0-9a-f]{64}$' AND nat_firewall_digest ~ '^[0-9a-f]{64}$' AND keyset_digest ~ '^[0-9a-f]{64}$' AND request_digest ~ '^[0-9a-f]{64}$'", name="ck_onnuri_outbound_diagnostic_digests"),
        CheckConstraint(ONNURI_OUTBOUND_DIAGNOSTIC_PRODUCT_CHECK, name="ck_onnuri_outbound_diagnostic_product"),
        CheckConstraint("reconciliation_cutoff_at <= created_at + interval '60 seconds'", name="ck_onnuri_outbound_diagnostic_cutoff"),
        Index("uq_onnuri_outbound_diagnostic_active", "envelope_id", unique=True, postgresql_where=text("terminal = 'open'")),
    )


class OnnuriOutboundDiagnosticEventModel(Base):
    __tablename__ = "onnuri_outbound_diagnostic_events"
    id = Column(Integer, primary_key=True, index=True)
    attempt_id = Column(Integer, ForeignKey("onnuri_outbound_diagnostic_attempts.id", ondelete="RESTRICT"), nullable=False)
    sequence = Column(Integer, nullable=False)
    operation = Column(String(64), nullable=False)
    provenance_digest = Column(String(64), nullable=False)
    idempotency_key = Column(String(255), nullable=False)
    expected_dispatch = Column(String(32), nullable=False)
    expected_signaling = Column(String(32), nullable=False)
    expected_answer = Column(String(32), nullable=False)
    expected_media = Column(String(32), nullable=False)
    expected_terminal = Column(String(32), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=text("now()"))
    __table_args__ = (UniqueConstraint("attempt_id", "sequence", name="uq_onnuri_outbound_diagnostic_event_sequence"), UniqueConstraint("attempt_id", "idempotency_key", name="uq_onnuri_outbound_diagnostic_event_idempotency"), CheckConstraint("provenance_digest ~ '^[0-9a-f]{64}$'", name="ck_onnuri_outbound_diagnostic_event_digest"))


class OnnuriOutboundDiagnosticLateEvidenceModel(Base):
    __tablename__ = "onnuri_outbound_diagnostic_late_evidence"
    id = Column(Integer, primary_key=True, index=True)
    attempt_id = Column(Integer, ForeignKey("onnuri_outbound_diagnostic_attempts.id", ondelete="RESTRICT"), nullable=False)
    evidence_digest = Column(String(64), nullable=False)
    evidence_kind = Column(String(64), nullable=False)
    received_at = Column(DateTime(timezone=True), nullable=False, server_default=text("now()"))
    __table_args__ = (UniqueConstraint("attempt_id", "evidence_digest", name="uq_onnuri_outbound_diagnostic_late_evidence"), CheckConstraint("evidence_digest ~ '^[0-9a-f]{64}$'", name="ck_onnuri_outbound_diagnostic_late_evidence_digest"))


class OnnuriSmokeCallbackEventModel(Base):
    """Redacted, idempotent normalized stock callback accepted for an attempt."""

    __tablename__ = "onnuri_staging_smoke_callback_events"

    id = Column(Integer, primary_key=True, index=True)
    attempt_id = Column(
        Integer, ForeignKey("onnuri_staging_smoke_attempts.id", ondelete="RESTRICT"),
        nullable=False,
    )
    event_nonce_digest = Column(String(128), nullable=False)
    idempotency_key = Column(String(255), nullable=False)
    request_digest = Column(String(128), nullable=False)
    event_type = Column(String(16), nullable=False)
    normalized_status = Column(String(64), nullable=False)
    occurred_at = Column(DateTime(timezone=True), nullable=False)
    accepted_at = Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    duration_seconds = Column(Integer, nullable=True)
    redacted_cause_category = Column(String(64), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "attempt_id", "event_nonce_digest", name="uq_onnuri_smoke_callback_nonce"
        ),
        CheckConstraint(
            "event_type IN ('status','cdr')", name="ck_onnuri_smoke_callback_event_type"
        ),
        CheckConstraint(
            "duration_seconds IS NULL OR duration_seconds BETWEEN 0 AND 3600",
            name="ck_onnuri_smoke_callback_duration",
        ),
    )

class OnnuriSmokeCapabilityConsumptionModel(Base):
    __tablename__ = "onnuri_staging_capability_consumptions"

    id = Column(Integer, primary_key=True, index=True)
    attempt_id = Column(
        Integer, ForeignKey("onnuri_staging_smoke_attempts.id", ondelete="RESTRICT"),
        nullable=False
    )
    kind = Column(String(32), nullable=False)
    domain = Column(String(128), nullable=False)
    key_id = Column(String(255), nullable=False)
    algorithm_policy_id = Column(String(128), nullable=False)
    nonce_digest = Column(String(128), nullable=False)
    token_digest = Column(String(128), nullable=False)
    request_digest = Column(String(128), nullable=False)
    receipt_digest = Column(String(128), nullable=False)
    issued_at = Column(DateTime(timezone=True), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
    encrypted_issue_recovery = Column(Text, nullable=True)
    encrypted_consume_recovery = Column(Text, nullable=True)
    consume_response_digest = Column(String(128), nullable=True)
    recovery_erased_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint("kind", "key_id", "nonce_digest", name="uq_onnuri_smoke_cap_nonce"),
        UniqueConstraint("attempt_id", "kind", name="uq_onnuri_smoke_attempt_cap"),
        CheckConstraint("kind IN ('dispatch','media')", name="ck_onnuri_smoke_cap_kind"),
        CheckConstraint("issued_at < expires_at", name="ck_onnuri_smoke_cap_expiry"),
    )


class OnnuriSmokeAnswerAuthorizationModel(Base):
    __tablename__ = "onnuri_staging_answer_authorizations"

    id = Column(Integer, primary_key=True, index=True)
    attempt_id = Column(
        Integer, ForeignKey("onnuri_staging_smoke_attempts.id", ondelete="RESTRICT"),
        nullable=False, unique=True
    )
    direction = Column(String(16), nullable=False)
    authority_kind = Column(String(64), nullable=False)
    idempotency_key = Column(String(128), nullable=False, unique=True)
    callback_nonce_digest = Column(String(128), nullable=False, unique=True)
    canonical_request_digest = Column(String(128), nullable=False)
    canonical_response_digest = Column(String(128), nullable=False)
    encrypted_response_recovery = Column(Text, nullable=True)
    committed_at = Column(DateTime(timezone=True), nullable=False)
    deadline_at = Column(DateTime(timezone=True), nullable=False)
    budget_seconds = Column(Integer, nullable=False)
    approved_pause_milliseconds = Column(Integer, nullable=False, default=0, server_default=text("0"))
    observed_carrier_answer_at = Column(DateTime(timezone=True), nullable=True)
    recovery_erased_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "authority_kind IN ('outbound_observed_answer','inbound_preanswer_commit')",
            name="ck_onnuri_smoke_answer_kind"
        ),
        CheckConstraint("budget_seconds BETWEEN 1 AND 60", name="ck_onnuri_smoke_answer_budget"),
        CheckConstraint("approved_pause_milliseconds >= 0", name="ck_onnuri_smoke_answer_pause"),
    )


class OnnuriRegistrationGateModel(Base):
    __tablename__ = "onnuri_registration_gates"

    id = Column(Integer, primary_key=True, index=True)
    envelope_id = Column(
        Integer, ForeignKey("onnuri_staging_smoke_envelopes.id", ondelete="RESTRICT"),
        nullable=False
    )
    operation_uuid = Column(
        String(36), nullable=False, unique=True, default=lambda: str(uuid.uuid4()),
        server_default=text("gen_random_uuid()::text")
    )
    operation_kind = Column(String(16), nullable=False)
    unregisters_gate_id = Column(
        Integer, ForeignKey("onnuri_registration_gates.id", ondelete="RESTRICT"), nullable=True
    )
    execution_stage_id = Column(
        Integer,
        ForeignKey(
            "g008_execution_stages.id",
            ondelete="RESTRICT",
            name="fk_onnuri_reg_execution_stage",
        ),
        nullable=True,
    )
    state = Column(String(32), nullable=False)
    request_digest = Column(String(128), nullable=False)
    challenge_digest = Column(String(128), nullable=True)
    transaction_count = Column(Integer, nullable=False, default=0, server_default=text("0"))
    retransmission_count = Column(Integer, nullable=False, default=0, server_default=text("0"))
    requested_expires_seconds = Column(Integer, nullable=True)
    accepted_expires_at = Column(DateTime(timezone=True), nullable=True)
    failure_class = Column(String(64), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=text("now()"))
    terminal_at = Column(DateTime(timezone=True), nullable=True)
    execution_attestation_digest = Column(String(64), nullable=True)
    execution_attestation_signature_digest = Column(String(64), nullable=True)
    execution_attestation_key_digest = Column(String(64), nullable=True)
    execution_attestation_key_id = Column(String(128), nullable=True)
    execution_attested_at = Column(DateTime(timezone=True), nullable=True)
    unregister_required = Column(Boolean, nullable=False, default=False, server_default=text("false"))
    unregister_satisfied_at = Column(DateTime(timezone=True), nullable=True)
    wire_request_count = Column(Integer, nullable=True)

    __table_args__ = (
        CheckConstraint("operation_kind IN ('register','unregister')", name="ck_onnuri_reg_kind"),
        CheckConstraint(
            "state IN ('pending','challenged','completed','failed','contained')",
            name="ck_onnuri_reg_state"
        ),
        # Application transaction retries and protocol retransmissions are
        # independently bounded by the registration authority contract.
        CheckConstraint("transaction_count BETWEEN 0 AND 2", name="ck_onnuri_reg_transactions"),
        CheckConstraint("retransmission_count BETWEEN 0 AND 2", name="ck_onnuri_reg_retransmits"),
        CheckConstraint(
            "execution_attestation_digest IS NULL OR "
            "execution_attestation_digest ~ '^[0-9a-f]{64}$'",
            name="ck_onnuri_reg_execution_attestation_digest",
        ),
        CheckConstraint(
            "execution_attestation_signature_digest IS NULL OR "
            "execution_attestation_signature_digest ~ '^[0-9a-f]{64}$'",
            name="ck_onnuri_reg_execution_attestation_signature_digest",
        ),
        CheckConstraint(
            "execution_attestation_key_digest IS NULL OR "
            "execution_attestation_key_digest ~ '^[0-9a-f]{64}$'",
            name="ck_onnuri_reg_execution_attestation_key_digest",
        ),
        CheckConstraint(
            "execution_attestation_key_id IS NULL OR "
            "execution_attestation_key_id ~ '^[a-z0-9][a-z0-9._-]{0,127}$'",
            name="ck_onnuri_reg_execution_attestation_key_id",
        ),
        CheckConstraint(
            "(execution_attestation_digest IS NULL) = "
            "(execution_attestation_signature_digest IS NULL) AND "
            "(execution_attestation_digest IS NULL) = "
            "(execution_attestation_key_id IS NULL) AND "
            "(execution_attestation_digest IS NULL) = "
            "(execution_attestation_key_digest IS NULL) AND "
            "(execution_attestation_digest IS NULL) = "
            "(execution_attested_at IS NULL)",
            name="ck_onnuri_reg_execution_attestation_complete",
        ),
        CheckConstraint(
            "(state IN ('completed','failed','contained')) = "
            "(execution_attestation_digest IS NOT NULL AND "
            "execution_attestation_signature_digest IS NOT NULL AND "
            "execution_attestation_key_id IS NOT NULL AND "
            "execution_attestation_key_digest IS NOT NULL AND "
            "execution_attested_at IS NOT NULL)",
            name="ck_onnuri_reg_terminal_attested",
        ),
        CheckConstraint(
            "wire_request_count IS NULL OR wire_request_count BETWEEN 0 AND 2",
            name="ck_onnuri_reg_wire_request_count",
        ),
        CheckConstraint(
            "(state IN ('completed','failed','contained')) = "
            "(wire_request_count IS NOT NULL)",
            name="ck_onnuri_reg_terminal_wire_count",
        ),
        CheckConstraint(
            "(operation_kind = 'register' OR NOT unregister_required) AND "
            "(unregister_satisfied_at IS NULL OR "
            "(operation_kind = 'register' AND unregister_required))",
            name="ck_onnuri_reg_unregister_obligation",
        ),
        CheckConstraint(
            "operation_kind <> 'register' OR transaction_count = 0 "
            "OR unregister_required",
            name="ck_onnuri_reg_consumed_obligation",
        ),
        Index(
            "uq_onnuri_reg_execution_attestation_digest",
            "execution_attestation_digest",
            unique=True,
            postgresql_where=text("execution_attestation_digest IS NOT NULL"),
        ),
        Index(
            "uq_onnuri_reg_execution_stage",
            "execution_stage_id",
            unique=True,
            postgresql_where=text("execution_stage_id IS NOT NULL"),
        ),
        Index(
            "uq_onnuri_reg_one_register",
            "envelope_id",
            unique=True,
            postgresql_where=text("operation_kind = 'register'"),
        ),
        Index(
            "uq_onnuri_reg_one_unregister",
            "unregisters_gate_id",
            unique=True,
            postgresql_where=text(
                "operation_kind = 'unregister' AND unregisters_gate_id IS NOT NULL"
            ),
        ),
    )



class PhonePreviewVerificationModel(Base):
    __tablename__ = "phone_preview_verifications"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    phone_number_hash = Column(String(64), nullable=False)
    phone_number_masked = Column(String(32), nullable=False)
    code_hash = Column(String(128), nullable=False)
    code_salt = Column(String(64), nullable=False)
    status = Column(String(32), nullable=False, default="pending")
    attempts = Column(Integer, nullable=False, default=0, server_default=text("0"))
    expires_at = Column(DateTime(timezone=True), nullable=False)
    verified_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    organization = relationship("OrganizationModel")
    user = relationship("UserModel")
    sessions = relationship("PhonePreviewSessionModel", back_populates="verification")

    __table_args__ = (
        Index(
            "ix_phone_preview_verifications_lookup",
            "organization_id",
            "user_id",
            "phone_number_hash",
            "status",
        ),
        Index("ix_phone_preview_verifications_expires_at", "expires_at"),
    )


class PhonePreviewSessionModel(Base):
    __tablename__ = "phone_preview_sessions"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    workflow_id = Column(
        Integer, ForeignKey("workflows.id", ondelete="CASCADE"), nullable=False
    )
    workflow_run_id = Column(
        Integer, ForeignKey("workflow_runs.id", ondelete="SET NULL"), nullable=True
    )
    verification_id = Column(
        Integer,
        ForeignKey("phone_preview_verifications.id", ondelete="SET NULL"),
        nullable=True,
    )
    phone_number_hash = Column(String(64), nullable=False)
    phone_number_global_hash = Column(String(64), nullable=True)
    preview_telephony_configuration_id = Column(
        Integer,
        ForeignKey("telephony_configurations.id", ondelete="SET NULL"),
        nullable=True,
    )
    preview_from_phone_number_id = Column(
        Integer,
        ForeignKey("telephony_phone_numbers.id", ondelete="SET NULL"),
        nullable=True,
    )
    phone_number_masked = Column(String(32), nullable=False)
    destination_phone_encrypted = Column(Text, nullable=True)
    display_name = Column(String(120), nullable=True)
    status = Column(String(32), nullable=False, default="pending_verification")
    provider = Column(String(32), nullable=True)
    provider_call_id = Column(String(255), nullable=True)
    failure_reason = Column(String(255), nullable=True)
    max_duration_seconds = Column(Integer, nullable=False, default=300)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )
    completed_at = Column(DateTime(timezone=True), nullable=True)

    organization = relationship("OrganizationModel")
    user = relationship("UserModel")
    workflow = relationship("WorkflowModel")
    workflow_run = relationship("WorkflowRunModel")
    verification = relationship(
        "PhonePreviewVerificationModel", back_populates="sessions"
    )
    preview_telephony_configuration = relationship("TelephonyConfigurationModel")
    preview_from_phone_number = relationship("TelephonyPhoneNumberModel")

    __table_args__ = (
        Index(
            "ix_phone_preview_sessions_owner",
            "organization_id",
            "user_id",
            "status",
        ),
        Index("ix_phone_preview_sessions_workflow_run", "workflow_run_id"),
        Index(
            "ix_phone_preview_sessions_phone",
            "organization_id",
            "phone_number_hash",
            "created_at",
        ),
        Index(
            "ix_phone_preview_sessions_global_phone",
            "phone_number_global_hash",
            "created_at",
            postgresql_where=text("phone_number_global_hash IS NOT NULL"),
        ),
        Index(
            "ix_phone_preview_sessions_inbound_route",
            "phone_number_global_hash",
            "provider",
            "preview_telephony_configuration_id",
            "preview_from_phone_number_id",
            "updated_at",
            postgresql_where=text(
                "phone_number_global_hash IS NOT NULL "
                "AND preview_from_phone_number_id IS NOT NULL"
            ),
        ),
        Index("ix_phone_preview_sessions_expires_at", "expires_at"),
    )


class IntegrationModel(Base):
    __tablename__ = "integrations"

    id = Column(Integer, primary_key=True, index=True)
    integration_id = Column(
        String, nullable=False, index=True
    )  # External connection ID
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    provider = Column(String, nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"))
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    connection_details = Column(JSON, nullable=False, default=dict)
    action = Column(String, nullable=False, default=IntegrationAction.ALL_CALLS.value)

    # Relationships
    organization = relationship("OrganizationModel", back_populates="integrations")


class WorkflowDefinitionModel(Base):
    __tablename__ = "workflow_definitions"
    id = Column(Integer, primary_key=True, index=True)
    workflow_hash = Column(String, nullable=True)  # Legacy, no longer used
    workflow_json = Column(JSON, nullable=False, default=dict)
    workflow_id = Column(Integer, ForeignKey("workflows.id"), nullable=True)
    is_current = Column(
        Boolean, default=False, nullable=False, server_default=text("false")
    )
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    # Versioning columns
    status = Column(
        String,
        nullable=False,
        default="published",
        server_default=text("'published'"),
    )  # draft | published | archived
    version_number = Column(
        Integer, nullable=True
    )  # Sequential per workflow, display only
    published_at = Column(DateTime(timezone=True), nullable=True)

    # Full behavioral snapshot (moved from WorkflowModel to enable versioning)
    workflow_configurations = Column(
        JSON, nullable=False, default=dict, server_default=text("'{}'::json")
    )
    template_context_variables = Column(
        JSON, nullable=False, default=dict, server_default=text("'{}'::json")
    )

    # Table constraints and indexes — unique hash constraint removed (no more dedup)
    __table_args__ = (
        Index("ix_workflow_definitions_workflow_status", "workflow_id", "status"),
    )

    # Relationships
    workflow = relationship(
        "WorkflowModel",
        back_populates="definitions",
        foreign_keys=[workflow_id],
    )
    workflow_runs = relationship("WorkflowRunModel", back_populates="definition")


class FolderModel(Base):
    """A folder for grouping workflows (agents) within an organization.

    Folders are flat (no nesting) and org-scoped. A workflow belongs to at
    most one folder via ``WorkflowModel.folder_id``; a NULL folder_id means
    the workflow is "Uncategorized".
    """

    __tablename__ = "folders"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id"), nullable=False, index=True
    )
    organization = relationship("OrganizationModel")
    name = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    workflows = relationship("WorkflowModel", back_populates="folder")

    # Folder names must be unique within an organization.
    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="uq_folder_org_name"),
    )


class WorkflowModel(Base):
    __tablename__ = "workflows"
    id = Column(Integer, primary_key=True, index=True)
    workflow_uuid = Column(
        String(36),
        unique=True,
        nullable=False,
        index=True,
        default=lambda: str(uuid.uuid4()),
    )
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship("UserModel", back_populates="workflows")
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=True)
    organization = relationship("OrganizationModel")
    # Optional folder for grouping in the agents list. NULL = "Uncategorized".
    # ON DELETE SET NULL: deleting a folder un-files its agents, never deletes them.
    folder_id = Column(
        Integer,
        ForeignKey("folders.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    folder = relationship("FolderModel", back_populates="workflows")
    name = Column(String, index=True, nullable=False)
    status = Column(
        Enum(*[status.value for status in WorkflowStatus], name="workflow_status"),
        nullable=False,
        default=WorkflowStatus.ACTIVE.value,
        server_default=text("'active'::workflow_status"),
    )
    workflow_definition = Column(JSON, nullable=False, default=dict)
    template_context_variables = Column(JSON, nullable=False, default=dict)
    call_disposition_codes = Column(JSON, nullable=False, default=dict)
    workflow_configurations = Column(
        JSON, nullable=False, default=dict, server_default=text("'{}'::json")
    )
    runs = relationship("WorkflowRunModel", back_populates="workflow")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    # Pointer to the currently-live (published) version
    released_definition_id = Column(
        Integer,
        ForeignKey("workflow_definitions.id", use_alter=True),
        nullable=True,
    )
    released_definition = relationship(
        "WorkflowDefinitionModel",
        foreign_keys=[released_definition_id],
        uselist=False,
        viewonly=True,
    )

    # All versions / historical definitions of this workflow
    definitions = relationship(
        "WorkflowDefinitionModel",
        back_populates="workflow",
        foreign_keys="WorkflowDefinitionModel.workflow_id",
    )

    # Relationship to fetch the current (is_current=True) definition
    # Kept for backward compatibility during transition
    current_definition = relationship(
        "WorkflowDefinitionModel",
        primaryjoin=lambda: and_(
            WorkflowDefinitionModel.workflow_id == WorkflowModel.id,
            WorkflowDefinitionModel.is_current.is_(True),
        ),
        uselist=False,
        viewonly=True,
    )

    @property
    def current_definition_id(self):
        """Return ID of the current workflow definition (helper for backwards-compat)."""
        current_def = self.__dict__.get("current_definition")
        if current_def is not None:
            return current_def.id

        # If relationship is not loaded, we cannot safely access definitions without
        # risking an implicit lazy load on a detached instance. Return ``None`` in
        # that scenario so callers can handle the absence explicitly.
        return None


class WorkflowTemplates(Base):
    __tablename__ = "workflow_templates"
    id = Column(Integer, primary_key=True, index=True)
    template_name = Column(String, nullable=False, index=True)
    template_description = Column(String, nullable=False, index=True)
    template_json = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))


class WorkflowRunModel(Base):
    __tablename__ = "workflow_runs"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    workflow_id = Column(Integer, ForeignKey("workflows.id"), nullable=False)
    workflow = relationship("WorkflowModel", back_populates="runs")
    definition_id = Column(
        Integer, ForeignKey("workflow_definitions.id"), nullable=True
    )
    definition = relationship("WorkflowDefinitionModel", back_populates="workflow_runs")
    # Stored as VARCHAR (not a Postgres ENUM) so new telephony providers can
    # be added purely in application code without a database migration.
    # See WorkflowRunMode in api/enums.py for the canonical value set.
    mode = Column(String(64), nullable=False)
    call_type = Column(
        Enum(*[call_type.value for call_type in CallType], name="workflow_call_type"),
        nullable=False,
        default=CallType.OUTBOUND.value,
        server_default=text("'outbound'::workflow_call_type"),
    )
    state = Column(
        Enum(*[state.value for state in WorkflowRunState], name="workflow_run_state"),
        nullable=False,
        default=WorkflowRunState.INITIALIZED.value,
        server_default=text("'initialized'::workflow_run_state"),
    )
    is_completed = Column(Boolean, default=False)
    recording_url = Column(String, nullable=True)
    transcript_url = Column(String, nullable=True)
    # Store storage backend as string enum (s3, minio)
    storage_backend = Column(
        Enum("s3", "minio", name="storage_backend"),
        nullable=False,
        default="s3",
        server_default=text("'s3'::storage_backend"),
    )
    usage_info = Column(JSON, nullable=False, default=dict)
    cost_info = Column(JSON, nullable=False, default=dict)
    initial_context = Column(JSON, nullable=False, default=dict)
    gathered_context = Column(JSON, nullable=False, default=dict)
    logs = Column(JSON, nullable=False, default=dict, server_default=text("'{}'::json"))
    annotations = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    campaign_id = Column(Integer, ForeignKey("campaigns.id"), nullable=True)
    campaign = relationship("CampaignModel")
    queued_run_id = Column(Integer, ForeignKey("queued_runs.id"), nullable=True)
    queued_run = relationship("QueuedRunModel", foreign_keys=[queued_run_id])
    public_access_token = Column(String(36), nullable=True)
    text_session = relationship(
        "WorkflowRunTextSessionModel",
        back_populates="workflow_run",
        uselist=False,
        cascade="all, delete-orphan",
    )

    # Indexes
    __table_args__ = (
        Index(
            "idx_workflow_runs_public_access_token",
            "public_access_token",
            unique=True,
            postgresql_where=text("public_access_token IS NOT NULL"),
        ),
        Index(
            "idx_workflow_runs_call_id",
            text("(gathered_context->>'call_id')"),
            postgresql_where=text("gathered_context->>'call_id' IS NOT NULL"),
        ),
        Index("idx_workflow_runs_workflow_id", "workflow_id"),
        Index("idx_workflow_runs_campaign_id", "campaign_id"),
    )


class WorkflowRunTextSessionModel(Base):
    __tablename__ = "workflow_run_text_sessions"

    workflow_run_id = Column(
        Integer,
        ForeignKey("workflow_runs.id", ondelete="CASCADE"),
        primary_key=True,
    )
    workflow_run = relationship("WorkflowRunModel", back_populates="text_session")
    revision = Column(
        Integer,
        nullable=False,
        default=0,
        server_default=text("0"),
    )
    session_data = Column(
        JSON,
        nullable=False,
        default=dict,
        server_default=text("'{}'::json"),
    )
    checkpoint = Column(
        JSON,
        nullable=False,
        default=dict,
        server_default=text("'{}'::json"),
    )
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    __table_args__ = (Index("ix_workflow_run_text_sessions_updated_at", "updated_at"),)


class OrganizationUsageCycleModel(Base):
    """
    This model is used to track the usage of Dograh tokens for an organization for a given usage
    cycle.
    """

    __tablename__ = "organization_usage_cycles"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    period_start = Column(DateTime(timezone=True), nullable=False)
    period_end = Column(DateTime(timezone=True), nullable=False)
    quota_dograh_tokens = Column(Integer, nullable=False)
    used_dograh_tokens = Column(Float, nullable=False, default=0)
    total_duration_seconds = Column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    # New USD tracking fields
    used_amount_usd = Column(Float, nullable=True, default=0)
    quota_amount_usd = Column(Float, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    # Relationships
    organization = relationship("OrganizationModel", back_populates="usage_cycles")

    # Constraints and indexes
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "period_start", "period_end", name="unique_org_period"
        ),
        Index("idx_usage_cycles_org_period", "organization_id", "period_end"),
    )


class CampaignModel(Base):
    __tablename__ = "campaigns"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    workflow_id = Column(Integer, ForeignKey("workflows.id"), nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    # Nullable during the legacy → multi-config migration window. Backfilled to the
    # org's default config by the migration; will become NOT NULL in a follow-up.
    telephony_configuration_id = Column(
        Integer, ForeignKey("telephony_configurations.id"), nullable=True
    )

    # Source configuration
    source_type = Column(String, nullable=False, default="csv")
    source_id = Column(String, nullable=False)  # CSV file key

    # State management
    state = Column(
        Enum(
            "created",
            "syncing",
            "running",
            "paused",
            "completed",
            "failed",
            name="campaign_state",
        ),
        nullable=False,
        default="created",
    )

    # Progress tracking
    total_rows = Column(Integer, nullable=True)
    processed_rows = Column(Integer, nullable=False, default=0)
    failed_rows = Column(Integer, nullable=False, default=0)

    # Rate limiting and sync configuration
    rate_limit_per_second = Column(Integer, nullable=False, default=1)
    max_retries = Column(Integer, nullable=False, default=0)
    source_sync_status = Column(String, nullable=False, default="pending")
    source_last_synced_at = Column(DateTime(timezone=True), nullable=True)
    source_sync_error = Column(String, nullable=True)

    # Retry configuration for call failures
    retry_config = Column(
        JSON,
        nullable=False,
        default=DEFAULT_CAMPAIGN_RETRY_CONFIG,
        server_default=text(
            '\'{"enabled": true, "max_retries": 2, "retry_on_busy": true, "retry_on_no_answer": true, "retry_on_voicemail": true, "retry_delay_seconds": 120}\'::jsonb'
        ),
    )

    # Orchestrator tracking fields
    last_batch_scheduled_at = Column(DateTime(timezone=True), nullable=True)
    last_activity_at = Column(DateTime(timezone=True), nullable=True)
    orchestrator_metadata = Column(
        JSON, nullable=False, default=dict, server_default=text("'{}'::json")
    )

    # Append-only timestamped log entries for state transitions, failures,
    # and circuit-breaker events. Surfaced in the UI so operators can see
    # why a campaign moved to paused/failed without digging through logs.
    logs = Column(
        JSON,
        nullable=False,
        default=list,
        server_default=text("'[]'::json"),
    )

    # Timestamps
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    # Relationships
    organization = relationship("OrganizationModel")
    workflow = relationship("WorkflowModel")
    created_by_user = relationship("UserModel")

    # Indexes
    __table_args__ = (
        Index("ix_campaigns_org_id", "organization_id"),
        Index("ix_campaigns_state", "state"),
        Index("ix_campaigns_workflow_id", "workflow_id"),
        Index(
            "ix_campaigns_telephony_config",
            "telephony_configuration_id",
            postgresql_where=text("telephony_configuration_id IS NOT NULL"),
        ),
        # Index for efficient querying of active campaigns
        Index(
            "idx_campaigns_active_status",
            "state",
            postgresql_where=text("state IN ('syncing', 'running', 'paused')"),
        ),
    )


class QueuedRunModel(Base):
    __tablename__ = "queued_runs"

    id = Column(Integer, primary_key=True, index=True)
    campaign_id = Column(
        Integer, ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False
    )
    source_uuid = Column(String, nullable=False)
    context_variables = Column(JSON, nullable=False, default=dict)
    state = Column(
        Enum("queued", "processed", "processing", "failed", name="queued_run_state"),
        nullable=False,
        default="queued",
    )
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    processed_at = Column(DateTime(timezone=True), nullable=True)

    # New retry-related fields
    retry_count = Column(Integer, default=0, nullable=False, server_default=text("0"))
    parent_queued_run_id = Column(Integer, ForeignKey("queued_runs.id"), nullable=True)
    scheduled_for = Column(DateTime(timezone=True), nullable=True)
    retry_reason = Column(String, nullable=True)  # 'busy', 'no_answer', 'voicemail'

    # Relationships
    campaign = relationship("CampaignModel")
    parent_queued_run = relationship("QueuedRunModel", remote_side=[id])

    # Indexes
    __table_args__ = (
        Index("idx_queued_runs_campaign_state", "campaign_id", "state"),
        Index("idx_queued_runs_created", "created_at"),
        Index("idx_queued_runs_source_uuid", "source_uuid"),
        Index(
            "idx_queued_runs_scheduled", "scheduled_for"
        ),  # New index for scheduled retries
        # Optimized index for checking queued runs efficiently
        Index(
            "idx_queued_runs_campaign_state_optimized",
            "campaign_id",
            "state",
            postgresql_where=text("state = 'queued'"),
        ),
        # Optimized index for scheduled retries
        Index(
            "idx_queued_runs_scheduled_optimized",
            "campaign_id",
            "scheduled_for",
            postgresql_where=text("scheduled_for IS NOT NULL"),
        ),
        UniqueConstraint(
            "campaign_id",
            "source_uuid",
            "retry_count",
            name="unique_campaign_source_retry",
        ),
    )


class EmbedTokenModel(Base):
    """Model for storing workflow embed tokens"""

    __tablename__ = "embed_tokens"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String(255), unique=True, nullable=False, index=True)
    workflow_id = Column(
        Integer,
        ForeignKey("workflows.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    organization_id = Column(
        Integer,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    allowed_domains = Column(JSON, nullable=True)  # Array of whitelisted domains
    settings = Column(JSON, nullable=True)  # Widget customization settings
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    usage_limit = Column(Integer, nullable=True)  # Optional usage limit
    usage_count = Column(Integer, default=0, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    created_by = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    updated_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    workflow = relationship("WorkflowModel")
    organization = relationship("OrganizationModel")
    creator = relationship("UserModel")
    sessions = relationship(
        "EmbedSessionModel", back_populates="embed_token", cascade="all, delete-orphan"
    )


class EmbedSessionModel(Base):
    """Model for storing temporary embed sessions"""

    __tablename__ = "embed_sessions"

    id = Column(Integer, primary_key=True, index=True)
    session_token = Column(String(255), unique=True, nullable=False, index=True)
    embed_token_id = Column(
        Integer, ForeignKey("embed_tokens.id", ondelete="CASCADE"), nullable=False
    )
    workflow_run_id = Column(
        Integer, ForeignKey("workflow_runs.id", ondelete="CASCADE"), nullable=True
    )
    client_ip = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    origin = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)

    # Relationships
    embed_token = relationship("EmbedTokenModel", back_populates="sessions")
    workflow_run = relationship("WorkflowRunModel")


class AgentTriggerModel(Base):
    """Model for storing agent trigger mappings (UUID -> workflow_id).

    This is a minimal lookup table that maps trigger UUIDs to workflows.
    The trigger node in the workflow definition is the source of truth.
    """

    __tablename__ = "agent_triggers"

    id = Column(Integer, primary_key=True, index=True)

    # Globally unique trigger path (UUID format)
    trigger_path = Column(String(36), unique=True, nullable=False, index=True)

    # Link to workflow
    workflow_id = Column(
        Integer, ForeignKey("workflows.id", ondelete="CASCADE"), nullable=False
    )
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )

    # State management (active/archived)
    state = Column(
        Enum(*[state.value for state in TriggerState], name="trigger_state"),
        nullable=False,
        default=TriggerState.ACTIVE.value,
        server_default=text("'active'::trigger_state"),
    )

    # Audit
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    # Relationships
    workflow = relationship("WorkflowModel")
    organization = relationship("OrganizationModel")

    # Indexes for performance
    __table_args__ = (
        Index("ix_agent_triggers_workflow_id", "workflow_id"),
        Index("ix_agent_triggers_state", "state"),
    )


class ExternalCredentialModel(Base):
    """Model for storing external authentication credentials.

    Credentials are stored separately from webhook configurations to allow
    reuse across multiple workflows and secure storage of sensitive data.
    """

    __tablename__ = "external_credentials"

    id = Column(Integer, primary_key=True, index=True)

    # Public UUID reference (used in APIs and workflow definitions)
    # This prevents enumeration attacks and hides internal IDs
    credential_uuid = Column(
        String(36),
        unique=True,
        nullable=False,
        index=True,
        default=lambda: str(uuid.uuid4()),
    )

    # Organization scoping
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )

    # Credential metadata
    name = Column(String, nullable=False)  # Display name, e.g., "Salesforce API"
    description = Column(String, nullable=True)  # Optional description

    # Credential type - uses enum from api/enums.py
    credential_type = Column(
        Enum(
            *[t.value for t in WebhookCredentialType],
            name="webhook_credential_type",
        ),
        nullable=False,
        default=WebhookCredentialType.NONE.value,
    )

    # Encrypted credential data (JSON)
    # Structure depends on credential_type:
    # - api_key: {"header_name": "X-API-Key", "api_key": "value"}
    # - bearer_token: {"token": "value"}
    # - basic_auth: {"username": "user", "password": "value"}
    # - custom_header: {"header_name": "X-Custom", "header_value": "value"}
    credential_data = Column(JSON, nullable=False, default=dict)

    # Audit fields
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    # Soft delete for safety
    is_active = Column(Boolean, default=True, nullable=False)

    # Relationships
    organization = relationship("OrganizationModel")
    created_by_user = relationship("UserModel")

    # Indexes and constraints
    __table_args__ = (
        Index("ix_webhook_credentials_organization_id", "organization_id"),
        Index("ix_webhook_credentials_uuid", "credential_uuid"),
        UniqueConstraint("organization_id", "name", name="unique_org_credential_name"),
    )


class ToolModel(Base):
    """Model for storing reusable tools that can be invoked during workflows.

    Tools provide a standardized way to integrate external functionality - from
    HTTP API calls to native integrations.
    """

    __tablename__ = "tools"

    id = Column(Integer, primary_key=True, index=True)

    # Public identifier (used in APIs and workflow references)
    tool_uuid = Column(
        String(36),
        unique=True,
        nullable=False,
        index=True,
        default=lambda: str(uuid.uuid4()),
    )

    # Organization scoping
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )

    # Tool metadata
    name = Column(String(255), nullable=False)
    description = Column(String, nullable=True)

    # Tool category - uses enum from api/enums.py
    category = Column(
        Enum(
            *[c.value for c in ToolCategory],
            name="tool_category",
        ),
        nullable=False,
        default=ToolCategory.HTTP_API.value,
    )

    # Icon configuration (for UI display)
    icon = Column(String(50), nullable=True)  # Icon identifier
    icon_color = Column(String(7), nullable=True)  # Hex color code

    # Status management
    status = Column(
        Enum(
            *[s.value for s in ToolStatus],
            name="tool_status",
        ),
        nullable=False,
        default=ToolStatus.ACTIVE.value,
        server_default=text("'active'::tool_status"),
    )

    # The tool definition (JSONB) - contains schema_version for compatibility
    # Structure depends on category:
    # - http_api: {"schema_version": 1, "type": "http_api", "config": {...}}
    definition = Column(JSON, nullable=False, default=dict)

    # Audit fields
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    # Relationships
    organization = relationship("OrganizationModel")
    created_by_user = relationship("UserModel")

    # Indexes and constraints
    __table_args__ = (
        Index("ix_tools_organization_id", "organization_id"),
        Index("ix_tools_uuid", "tool_uuid"),
        Index("ix_tools_status", "status"),
        Index("ix_tools_category", "category"),
    )


class KnowledgeBaseDocumentModel(Base):
    """Model for storing document-level metadata in the knowledge base.

    Each document represents a source file (PDF, DOCX, etc.) that has been
    processed and chunked for retrieval.
    """

    __tablename__ = "knowledge_base_documents"

    id = Column(Integer, primary_key=True, index=True)

    # Public identifier for API references
    document_uuid = Column(
        String(36),
        unique=True,
        nullable=False,
        index=True,
        default=lambda: str(uuid.uuid4()),
    )

    # Organization scoping
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )

    # Document metadata
    filename = Column(String(500), nullable=False)
    file_size_bytes = Column(Integer, nullable=True)
    file_hash = Column(String(64), nullable=True)  # SHA-256 hash for deduplication
    mime_type = Column(String(100), nullable=True)

    # Retrieval mode: "chunked" (vector search) or "full_document" (return full text)
    retrieval_mode = Column(
        String(20), nullable=False, default="chunked", server_default="chunked"
    )
    full_text = Column(
        Text, nullable=True
    )  # Stored when retrieval_mode is "full_document"

    # Processing metadata
    source_url = Column(String, nullable=True)  # If document was fetched from URL
    total_chunks = Column(Integer, nullable=False, default=0)
    processing_status = Column(
        Enum(
            "pending",
            "processing",
            "completed",
            "failed",
            name="document_processing_status",
        ),
        nullable=False,
        default="pending",
        server_default=text("'pending'::document_processing_status"),
    )
    processing_error = Column(Text, nullable=True)

    # Docling conversion metadata
    docling_metadata = Column(
        JSON, nullable=False, default=dict
    )  # Store docling document metadata

    # Custom metadata (user-defined tags, categories, etc.)
    custom_metadata = Column(JSON, nullable=False, default=dict)

    # Audit fields
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    # Soft delete
    is_active = Column(Boolean, default=True, nullable=False)
    archived_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    organization = relationship("OrganizationModel")
    created_by_user = relationship("UserModel")
    chunks = relationship(
        "KnowledgeBaseChunkModel",
        back_populates="document",
        cascade="all, delete-orphan",
    )

    # Indexes and constraints
    __table_args__ = (
        Index("ix_kb_documents_organization_id", "organization_id"),
        Index("ix_kb_documents_uuid", "document_uuid"),
        Index("ix_kb_documents_status", "processing_status"),
        Index("ix_kb_documents_created_at", "created_at"),
    )


class WorkflowRecordingModel(Base):
    """Model for storing audio recordings scoped to an organization.

    Recordings are used in hybrid prompts where parts of the output are pre-recorded
    audio rather than dynamically generated TTS.
    """

    __tablename__ = "workflow_recordings"

    id = Column(Integer, primary_key=True, index=True)

    # Descriptive ID used in prompts (unique per organization)
    recording_id = Column(String(64), nullable=False, index=True)

    # Scoping
    workflow_id = Column(
        Integer, ForeignKey("workflows.id", ondelete="CASCADE"), nullable=True
    )
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )

    # TTS configuration metadata (optional, legacy)
    tts_provider = Column(String, nullable=True)
    tts_model = Column(String, nullable=True)
    tts_voice_id = Column(String, nullable=True)

    # Content
    transcript = Column(Text, nullable=False)

    # Storage
    storage_key = Column(String, nullable=False)
    storage_backend = Column(
        Enum("s3", "minio", name="recording_storage_backend"),
        nullable=False,
        default="s3",
        server_default=text("'s3'::recording_storage_backend"),
    )

    # Extra metadata (file_size_bytes, duration_seconds, original_filename, mime_type, etc.)
    recording_metadata = Column(
        JSON, nullable=False, default=dict, server_default=text("'{}'::json")
    )

    # Audit
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    # Soft delete
    is_active = Column(Boolean, default=True, nullable=False)

    # Relationships
    workflow = relationship("WorkflowModel")
    organization = relationship("OrganizationModel")
    created_by_user = relationship("UserModel")

    # Indexes
    __table_args__ = (
        UniqueConstraint(
            "recording_id",
            "organization_id",
            name="uq_workflow_recordings_recording_id_org",
        ),
        Index("ix_workflow_recordings_workflow_id", "workflow_id"),
        Index("ix_workflow_recordings_org_id", "organization_id"),
        Index("ix_workflow_recordings_recording_id", "recording_id"),
    )


class KnowledgeBaseChunkModel(Base):
    """Model for storing document chunks with vector embeddings.

    Each chunk represents a portion of a document that has been:
    1. Extracted and chunked by docling's HybridChunker
    2. Optionally contextualized with surrounding information
    3. Embedded into a vector representation for semantic search
    """

    __tablename__ = "knowledge_base_chunks"

    id = Column(Integer, primary_key=True, index=True)

    # Link to parent document
    document_id = Column(
        Integer,
        ForeignKey("knowledge_base_documents.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Organization scoping (denormalized for efficient querying)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )

    # Chunk content
    chunk_text = Column(Text, nullable=False)  # The actual chunk text
    contextualized_text = Column(
        Text, nullable=True
    )  # Enriched text from chunker.contextualize()

    # Chunk positioning and metadata
    chunk_index = Column(Integer, nullable=False)  # Position in document (0-based)

    # Docling chunk metadata
    chunk_metadata = Column(
        JSON, nullable=False, default=dict
    )  # Store chunk.meta if available

    # Embedding configuration
    embedding_model = Column(
        String(200), nullable=False
    )  # e.g., "sentence-transformers/all-MiniLM-L6-v2"
    embedding_dimension = Column(
        Integer, nullable=False
    )  # e.g., 384 for all-MiniLM-L6-v2

    # Vector embedding (pgvector column)
    # The dimension should match the embedding_dimension field
    # Default: 1536 dimensions for OpenAI text-embedding-3-small
    # SentenceTransformer (384-dim) also supported but stored as 384-dim vectors
    embedding = Column(Vector(1536), nullable=True)

    # Token count (useful for chunking strategy analysis)
    token_count = Column(Integer, nullable=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    # Relationships
    document = relationship("KnowledgeBaseDocumentModel", back_populates="chunks")
    organization = relationship("OrganizationModel")

    # Indexes and constraints
    __table_args__ = (
        Index("ix_kb_chunks_document_id", "document_id"),
        Index("ix_kb_chunks_organization_id", "organization_id"),
        Index("ix_kb_chunks_chunk_index", "chunk_index"),
        Index(
            "ix_kb_chunks_embedding_model", "embedding_model"
        ),  # For filtering by model
        # Vector similarity search index (using IVFFlat or HNSW)
        # IVFFlat is good for datasets with 10k-1M vectors
        # HNSW is better for larger datasets but uses more memory
        Index(
            "ix_kb_chunks_embedding_ivfflat",
            "embedding",
            postgresql_using="ivfflat",
            postgresql_with={"lists": 100},  # Adjust based on dataset size
            postgresql_ops={"embedding": "vector_cosine_ops"},
        ),
    )
