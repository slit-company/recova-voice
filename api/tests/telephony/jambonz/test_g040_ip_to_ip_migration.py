from __future__ import annotations

import importlib

from sqlalchemy import CheckConstraint

from api.db.models import G008ExecutionSealModel, G008ExecutionStageModel


MIGRATION = "api.alembic.versions.h5b6c7d8e9f0_add_g040_ip_to_ip_execution_mode"


def test_model_exposes_bounded_ip_to_ip_binding() -> None:
    columns = G008ExecutionSealModel.__table__.columns
    assert {
        "execution_mode",
        "owned_target_digest",
        "source_external_ipv4",
        "peer_signaling_ipv4_cidr",
        "peer_signaling_udp_port",
    } <= set(columns.keys())

    constraints = {
        item.name: str(item.sqltext)
        for item in G008ExecutionSealModel.__table__.constraints
        if isinstance(item, CheckConstraint)
    }
    assert "ip_to_ip_no_register" in constraints["ck_g008_execution_seal_mode"]
    binding = constraints["ck_g008_execution_seal_mode_binding"]
    assert "peer_signaling_udp_port = 5060" in binding
    assert "/32" in binding
    assert "owned_target_digest" in binding

    stage_constraints = {
        item.name: str(item.sqltext)
        for item in G008ExecutionStageModel.__table__.constraints
        if isinstance(item, CheckConstraint)
    }
    order = stage_constraints["ck_g008_execution_stage_order"]
    assert "peer_attach" in order
    assert "peer_detach" in order
    assert "register" in order
    assert "unregister" in order


def test_migration_adds_mode_binding_and_preserves_legacy(monkeypatch) -> None:
    migration = importlib.import_module(MIGRATION)
    calls: list[tuple[str, tuple, dict]] = []

    for name in (
        "add_column",
        "create_check_constraint",
        "drop_constraint",
        "drop_column",
    ):
        monkeypatch.setattr(
            migration.op,
            name,
            lambda *args, _name=name, **kwargs: calls.append((_name, args, kwargs)),
        )

    migration.upgrade()

    added = {
        args[1].name
        for kind, args, _ in calls
        if kind == "add_column" and args[0] == "g008_execution_seals"
    }
    assert added == {
        "execution_mode",
        "owned_target_digest",
        "source_external_ipv4",
        "peer_signaling_ipv4_cidr",
        "peer_signaling_udp_port",
    }
    sql = "\n".join(
        args[2]
        for kind, args, _ in calls
        if kind == "create_check_constraint"
    )
    assert "legacy_registration" in sql
    assert "ip_to_ip_no_register" in sql
    assert "peer_signaling_udp_port = 5060" in sql
    assert "peer_attach" in sql
    assert "peer_detach" in sql
