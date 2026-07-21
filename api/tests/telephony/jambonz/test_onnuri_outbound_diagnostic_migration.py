from __future__ import annotations

import importlib

from sqlalchemy import CheckConstraint, Index, UniqueConstraint

from api.db.models import (
    OnnuriOutboundDiagnosticAttemptModel,
    OnnuriOutboundDiagnosticCapabilityModel,
    OnnuriOutboundDiagnosticEventModel,
    OnnuriOutboundDiagnosticLateEvidenceModel,
)


MIGRATION = "api.alembic.versions.d0e1f2a3b4c5_add_onnuri_outbound_diagnostic_v1"
CONSUME_RECOVERY_MIGRATION = (
    "api.alembic.versions.f3a4b5c6d7e8_add_onnuri_route_consume_recovery"
)


def test_consume_recovery_migration_requires_paired_recovery_and_consumption(monkeypatch) -> None:
    migration = importlib.import_module(CONSUME_RECOVERY_MIGRATION)
    calls: list[tuple[str, tuple, dict]] = []
    monkeypatch.setattr(
        migration.op, "add_column", lambda *args, **kwargs: calls.append(("add", args, kwargs))
    )
    monkeypatch.setattr(
        migration.op, "execute", lambda *args, **kwargs: calls.append(("execute", args, kwargs))
    )

    migration.upgrade()

    sql = "\n".join(args[0] for kind, args, _ in calls if kind == "execute")
    assert "ck_onnuri_outbound_diagnostic_capability_consume_recovery" in sql
    assert "(encrypted_consume_recovery IS NULL) = (consume_response_digest IS NULL)" in sql
    assert "(consumed_at IS NULL) = (diagnostic_attempt_id IS NULL)" in sql


def test_model_requires_paired_recovery_and_consumption() -> None:
    constraints = {
        constraint.name: str(constraint.sqltext)
        for constraint in OnnuriOutboundDiagnosticCapabilityModel.__table__.constraints
        if isinstance(constraint, CheckConstraint)
    }
    contract = constraints["ck_onnuri_outbound_diagnostic_capability_consume_recovery"]
    assert "encrypted_consume_recovery IS NULL" in contract
    assert "consume_response_digest IS NULL" in contract
    assert "consumed_at IS NULL" in contract
    assert "diagnostic_attempt_id IS NULL" in contract


def test_contained_cleanup_migration_preserves_terminal_seal_and_authorizes_only_linked_stage() -> None:
    migration = importlib.import_module(
        "api.alembic.versions.g4a5b6c7d8e9_allow_contained_unregister_cleanup"
    )
    seal_guard = migration._seal_guard()
    stage_guard = migration._stage_guard(contained_cleanup=True)
    refused_stage_guard = migration._stage_guard(contained_cleanup=False)

    assert "OLD.state = 'contained' AND NEW.state = 'cleanup_required'" not in seal_guard
    assert "OLD.state IN ('contained','completed','failed','residue_blocked') THEN" in seal_guard
    assert "parent.state IN ('running','cleanup_required','contained')" in stage_guard
    assert "register_gate.operation_kind = 'register'" in stage_guard
    assert "register_gate.transaction_count = 1" in stage_guard
    assert "register_gate.unregister_required" in stage_guard
    assert "register_gate.unregister_satisfied_at IS NULL" in stage_guard
    assert "register_stage.organization_id = NEW.organization_id" in stage_guard
    assert "parent.state IN ('running','cleanup_required')" in refused_stage_guard


def test_contained_cleanup_migration_downgrade_revokes_contained_stage_authority(monkeypatch) -> None:
    migration = importlib.import_module(
        "api.alembic.versions.g4a5b6c7d8e9_allow_contained_unregister_cleanup"
    )
    calls: list[str] = []
    monkeypatch.setattr(migration.op, "execute", lambda sql: calls.append(sql))

    migration.downgrade()

    assert len(calls) == 2
    assert "OLD.state = 'contained' AND NEW.state = 'cleanup_required'" not in calls[0]
    assert "parent.state IN ('running','cleanup_required')" in calls[1]
    assert "'contained'" not in calls[1].split("parent.state IN", 1)[1].split(")", 1)[0]


def test_migration_upgrade_creates_closed_diagnostic_schema(monkeypatch) -> None:
    migration = importlib.import_module(MIGRATION)
    calls: list[tuple[str, tuple, dict]] = []

    monkeypatch.setattr(migration.op, "create_table", lambda *args, **kwargs: calls.append(("table", args, kwargs)))
    monkeypatch.setattr(migration.op, "create_index", lambda *args, **kwargs: calls.append(("index", args, kwargs)))

    migration.upgrade()

    tables = {args[0]: args[1:] for kind, args, _ in calls if kind == "table"}
    assert set(tables) == {
        "onnuri_outbound_diagnostic_attempts",
        "onnuri_outbound_diagnostic_capabilities",
        "onnuri_outbound_diagnostic_events",
        "onnuri_outbound_diagnostic_late_evidence",
    }
    attempts = tables["onnuri_outbound_diagnostic_attempts"]
    names = {item.name for item in attempts if hasattr(item, "name")}
    assert {
        "ck_onnuri_outbound_diagnostic_ordinal",
        "ck_onnuri_outbound_diagnostic_product",
        "ck_onnuri_outbound_diagnostic_cutoff",
    } <= names
    constraints = {item.name: str(item.sqltext) for item in attempts if isinstance(item, CheckConstraint)}
    assert "ordinal BETWEEN 1 AND 3" == constraints["ck_onnuri_outbound_diagnostic_ordinal"]
    assert "interval '60 seconds'" in constraints["ck_onnuri_outbound_diagnostic_cutoff"]
    assert "not_applicable" in constraints["ck_onnuri_outbound_diagnostic_product"]
    assert "none" in constraints["ck_onnuri_outbound_diagnostic_product"]
    capabilities = tables["onnuri_outbound_diagnostic_capabilities"]
    capability_columns = {item.name: item for item in capabilities if hasattr(item, "name")}
    capability_constraints = {
        item.name: str(item.sqltext)
        for item in capabilities
        if isinstance(item, CheckConstraint)
    }
    assert capability_columns["nonce_digest"].nullable is False
    assert capability_columns["nonce_digest"].unique is True
    assert capability_columns["diagnostic_attempt_id"].nullable is True
    assert capability_columns["diagnostic_attempt_id"].unique is True
    assert capability_columns["issued_at"].nullable is False
    assert capability_columns["expires_at"].nullable is False
    assert capability_columns["consumed_at"].nullable is True
    for binding in (
        "organization_id",
        "envelope_id",
        "authorization_attempt_id",
        "authenticated_operator_user_id",
        "idempotency_key",
        "request_digest",
        "candidate_digest",
        "gate_envelope_digest",
        "route_profile_digest",
        "route_digest",
        "provider_digest",
        "keyset_digest",
    ):
        assert capability_columns[binding].nullable is False
    assert {
        foreign.target_fullname.split(".", 1)[0]
        for item in capabilities
        if hasattr(item, "foreign_keys")
        for foreign in item.foreign_keys
    } == {
        "organizations",
        "onnuri_outbound_diagnostic_attempts",
        "onnuri_staging_smoke_attempts",
        "onnuri_staging_smoke_envelopes",
        "users",
    }
    assert "nonce_digest ~ '^[0-9a-f]{64}$'" in capability_constraints[
        "ck_onnuri_outbound_diagnostic_capability_digests"
    ]
    assert capability_constraints["ck_onnuri_outbound_diagnostic_capability_expiry"] == "expires_at > issued_at"
    assert any(
        getattr(item, "name", None)
        == "uq_onnuri_outbound_diagnostic_capability_idempotency"
        for item in capabilities
    )
    assert any(
        kind == "index" and args[0] == "uq_onnuri_outbound_diagnostic_active"
        and kwargs["unique"] is True and "terminal = 'open'" in str(kwargs["postgresql_where"])
        for kind, args, kwargs in calls
    )


def test_model_constraints_match_the_isolated_upgrade_contract() -> None:
    attempts = OnnuriOutboundDiagnosticAttemptModel.__table__
    capabilities = OnnuriOutboundDiagnosticCapabilityModel.__table__
    events = OnnuriOutboundDiagnosticEventModel.__table__
    late_evidence = OnnuriOutboundDiagnosticLateEvidenceModel.__table__

    attempt_constraints = {constraint.name: constraint for constraint in attempts.constraints}
    assert {"uq_onnuri_outbound_diagnostic_ordinal", "uq_onnuri_outbound_diagnostic_idempotency", "ck_onnuri_outbound_diagnostic_ordinal", "ck_onnuri_outbound_diagnostic_product", "ck_onnuri_outbound_diagnostic_cutoff"} <= set(attempt_constraints)
    assert any(
        isinstance(index, Index) and index.unique and index.name == "uq_onnuri_outbound_diagnostic_active"
        and "terminal = 'open'" in str(index.dialect_options["postgresql"]["where"])
        for index in attempts.indexes
    )
    assert {foreign.column.table.name for foreign in attempts.foreign_keys} == {
        "organizations", "onnuri_staging_smoke_envelopes", "telephony_number_inventory",
        "telephony_configurations", "users",
    }
    capability_constraints = {constraint.name: constraint for constraint in capabilities.constraints}
    assert {
        "uq_onnuri_outbound_diagnostic_capability_idempotency",
        "ck_onnuri_outbound_diagnostic_capability_digests",
        "ck_onnuri_outbound_diagnostic_capability_expiry",
    } <= set(capability_constraints)
    assert capabilities.c.nonce_digest.nullable is False
    assert capabilities.c.nonce_digest.unique is True
    assert capabilities.c.diagnostic_attempt_id.nullable is True
    assert capabilities.c.diagnostic_attempt_id.unique is True
    assert capabilities.c.issued_at.nullable is False
    assert capabilities.c.expires_at.nullable is False
    assert capabilities.c.consumed_at.nullable is True
    for binding in (
        "organization_id",
        "envelope_id",
        "authorization_attempt_id",
        "authenticated_operator_user_id",
        "idempotency_key",
        "request_digest",
        "candidate_digest",
        "gate_envelope_digest",
        "route_profile_digest",
        "route_digest",
        "provider_digest",
        "keyset_digest",
    ):
        assert capabilities.c[binding].nullable is False
    assert {foreign.column.table.name for foreign in capabilities.foreign_keys} == {
        "organizations",
        "onnuri_outbound_diagnostic_attempts",
        "onnuri_staging_smoke_attempts",
        "onnuri_staging_smoke_envelopes",
        "users",
    }
    assert all(foreign.ondelete == "RESTRICT" for foreign in capabilities.foreign_keys)
    assert {constraint.name for constraint in events.constraints if isinstance(constraint, UniqueConstraint)} == {
        "uq_onnuri_outbound_diagnostic_event_sequence", "uq_onnuri_outbound_diagnostic_event_idempotency"
    }
    assert {constraint.name for constraint in late_evidence.constraints if isinstance(constraint, UniqueConstraint)} == {
        "uq_onnuri_outbound_diagnostic_late_evidence"
    }
    assert all(
        foreign.ondelete == "RESTRICT"
        for table in (events, late_evidence)
        for foreign in table.foreign_keys
    )


def test_migration_downgrade_removes_children_before_attempts(monkeypatch) -> None:
    migration = importlib.import_module(MIGRATION)
    calls: list[tuple[str, tuple, dict]] = []
    monkeypatch.setattr(migration.op, "drop_table", lambda *args, **kwargs: calls.append(("table", args, kwargs)))
    monkeypatch.setattr(migration.op, "drop_index", lambda *args, **kwargs: calls.append(("index", args, kwargs)))

    migration.downgrade()

    assert calls == [
        ("table", ("onnuri_outbound_diagnostic_late_evidence",), {}),
        ("table", ("onnuri_outbound_diagnostic_events",), {}),
        ("table", ("onnuri_outbound_diagnostic_capabilities",), {}),
        ("index", ("uq_onnuri_outbound_diagnostic_active",), {"table_name": "onnuri_outbound_diagnostic_attempts"}),
        ("table", ("onnuri_outbound_diagnostic_attempts",), {}),
    ]


def test_wire_migration_refuses_preexisting_rows_before_enforcing_not_null(monkeypatch) -> None:
    migration = importlib.import_module(
        "api.alembic.versions.f2a3b4c5d6e7_persist_onnuri_route_capability_wire"
    )
    calls: list[tuple[str, tuple, dict]] = []
    monkeypatch.setattr(
        migration.op, "add_column", lambda *args, **kwargs: calls.append(("add", args, kwargs))
    )
    monkeypatch.setattr(
        migration.op, "execute", lambda *args, **kwargs: calls.append(("execute", args, kwargs))
    )
    monkeypatch.setattr(
        migration.op, "alter_column", lambda *args, **kwargs: calls.append(("alter", args, kwargs))
    )

    migration.upgrade()

    refusal = next(index for index, call in enumerate(calls) if call[0] == "execute")
    first_not_null = next(
        index
        for index, call in enumerate(calls)
        if call[0] == "alter" and call[2].get("nullable") is False
    )
    assert refusal < first_not_null
    assert "IF EXISTS (SELECT 1 FROM onnuri_outbound_diagnostic_capabilities)" in calls[refusal][1][0]
    assert "requires an empty table" in calls[refusal][1][0]


def test_wire_migration_empty_table_adds_digests_before_not_null(monkeypatch) -> None:
    migration = importlib.import_module(
        "api.alembic.versions.f2a3b4c5d6e7_persist_onnuri_route_capability_wire"
    )
    calls: list[tuple[str, tuple, dict]] = []
    monkeypatch.setattr(
        migration.op, "add_column", lambda *args, **kwargs: calls.append(("add", args, kwargs))
    )
    monkeypatch.setattr(
        migration.op, "execute", lambda *args, **kwargs: calls.append(("execute", args, kwargs))
    )
    monkeypatch.setattr(
        migration.op, "alter_column", lambda *args, **kwargs: calls.append(("alter", args, kwargs))
    )

    migration.upgrade()

    assert [call[1][1].name for call in calls if call[0] == "add"] == [
        "token_digest", "signature_digest", "encrypted_capability_recovery"
    ]
    assert [call[1][1] for call in calls if call[0] == "alter"] == [
        "token_digest", "signature_digest", "encrypted_capability_recovery"
    ]


def test_consume_recovery_migration_adds_a_paired_digest_constraint(monkeypatch) -> None:
    migration = importlib.import_module(
        "api.alembic.versions.f3a4b5c6d7e8_add_onnuri_route_consume_recovery"
    )
    calls: list[tuple[str, tuple, dict]] = []
    monkeypatch.setattr(
        migration.op, "add_column", lambda *args, **kwargs: calls.append(("add", args, kwargs))
    )
    monkeypatch.setattr(
        migration.op, "execute", lambda *args, **kwargs: calls.append(("execute", args, kwargs))
    )

    migration.upgrade()

    assert [call[1][1].name for call in calls if call[0] == "add"] == [
        "encrypted_consume_recovery",
        "consume_response_digest",
    ]
    constraint = next(call[1][0] for call in calls if call[0] == "execute")
    assert "consume_response_digest IS NULL" in constraint
    assert "consume_response_digest ~ '^[0-9a-f]{64}$'" in constraint


def test_model_keeps_consume_recovery_and_digest_as_an_optional_pair() -> None:
    capabilities = OnnuriOutboundDiagnosticCapabilityModel.__table__
    assert capabilities.c.encrypted_consume_recovery.nullable is True
    assert capabilities.c.consume_response_digest.nullable is True
