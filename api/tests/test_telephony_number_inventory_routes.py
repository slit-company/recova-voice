from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient
from api.routes.telephony_number_inventory import customer_router, operator_router
from api.services.auth.depends import get_superuser
from api.services.feature_gates import require_self_serve_telephony


NOW = datetime(2026, 7, 9, tzinfo=UTC)


def _inventory_row(**overrides):
    values = {
        "id": 101,
        "provider": "jambonz",
        "trunk_group": "kr-070",
        "organization_id": None,
        "telephony_configuration_id": None,
        "telephony_phone_number_id": None,
        "address_masked": "+82******4567",
        "address_type": "pstn",
        "country_code": "KR",
        "label": "Seoul demo",
        "status": "available",
        "reservation_expires_at": None,
        "quarantined_reason": None,
        "retired_reason": None,
        "extra_metadata": {},
        "created_at": NOW,
        "updated_at": NOW,
        # Sensitive persistence fields should be ignored by response models.
        "address_normalized": "+827012344567",
        "address_hash": "secret-hash",
        "address_encrypted_raw": "secret-ciphertext",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _phone_row(**overrides):
    values = {
        "id": 202,
        "inbound_workflow_id": 33,
        "label": "Support",
        "is_active": True,
        "is_default_caller_id": False,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _make_app():
    app = FastAPI()
    app.include_router(operator_router)
    app.include_router(customer_router)
    app.dependency_overrides[get_superuser] = lambda: SimpleNamespace(
        id=99,
        is_superuser=True,
        selected_organization_id=1,
    )
    app.dependency_overrides[require_self_serve_telephony] = lambda: SimpleNamespace(
        id=7,
        selected_organization_id=11,
        is_superuser=False,
    )
    return app


def test_operator_import_redacts_secure_inventory_fields():
    app = _make_app()
    client = TestClient(app)
    row = _inventory_row()

    with patch(
        "api.routes.telephony_number_inventory.import_inventory_numbers",
        new=AsyncMock(return_value=([row], [])),
    ) as import_mock:
        response = client.post(
            "/telephony-number-inventory/import",
            json={
                "numbers": [
                    {
                        "address": "07012344567",
                        "provider": "jambonz",
                        "country_code": "KR",
                    }
                ]
            },
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["imported"][0]["address_masked"] == "+82******4567"
    assert "address_normalized" not in payload["imported"][0]
    assert "address_hash" not in payload["imported"][0]
    assert "address_encrypted_raw" not in payload["imported"][0]
    import_mock.assert_awaited_once()
    assert import_mock.await_args.kwargs["actor_user_id"] == 99

def test_operator_inventory_response_exposes_only_safe_metadata():
    app = _make_app()
    client = TestClient(app)
    row = _inventory_row(
        id=101,
        status="assigned",
        organization_id=11,
        telephony_configuration_id=301,
        telephony_phone_number_id=202,
        extra_metadata={
            "recova_inventory_state": "assigned",
            "managed_by": "recova_number_inventory",
            "inventory_id": "101",
            "contract_version": "jambonz-v1",
            "is_contract_fixture": False,
            "live_trunk_validated": True,
            "live_validation_source": "operator_attestation",
            "live_validation_evidence_id": "cdr-123",
            "live_validation_trusted_writer": "recova_operator_live_validation_v1",
            "api_token": "secret",
            "address_hash": "hash",
            "nested": {"secret": "value"},
        },
    )

    with patch(
        "api.routes.telephony_number_inventory.list_inventory_numbers",
        new=AsyncMock(return_value=([row], 1)),
    ):
        response = client.get("/telephony-number-inventory?limit=1")

    assert response.status_code == 200
    number = response.json()["numbers"][0]
    assert number["extra_metadata"] == {
        "recova_inventory_state": "assigned",
        "managed_by": "recova_number_inventory",
        "inventory_id": "101",
        "contract_version": "jambonz-v1",
        "is_contract_fixture": False,
        "live_trunk_validated": True,
        "live_validation_source": "operator_attestation",
        "live_validation_evidence_id": "cdr-123",
    }
    assert number["assignment_metadata"] == {
        "managed_by": "recova_number_inventory",
        "recova_inventory_state": "assigned",
        "inventory_id": 101,
        "binding_metadata_consistent": True,
    }
    assert number["readiness_metadata"]["live_trunk_validated"] is True
    assert number["readiness_metadata"]["contract_version"] == "jambonz-v1"
    assert "api_token" not in number["extra_metadata"]
    assert "address_hash" not in number["extra_metadata"]


def test_untrusted_live_validation_metadata_does_not_render_ready():
    app = _make_app()
    client = TestClient(app)
    row = _inventory_row(
        status="assigned",
        telephony_configuration_id=301,
        telephony_phone_number_id=202,
        extra_metadata={
            "live_trunk_validated": True,
            "is_contract_fixture": False,
            "live_validation_source": "operator_attestation",
            "live_validation_evidence_id": "spoofed-proof",
        },
    )

    with patch(
        "api.routes.telephony_number_inventory.list_inventory_numbers",
        new=AsyncMock(return_value=([row], 1)),
    ):
        response = client.get("/telephony-number-inventory?limit=1")

    assert response.status_code == 200
    number = response.json()["numbers"][0]
    assert number["readiness_metadata"]["live_trunk_validated"] is False
    assert number["extra_metadata"]["live_trunk_validated"] is False


def test_contract_fixture_metadata_never_renders_live_ready():
    app = _make_app()
    client = TestClient(app)
    row = _inventory_row(
        status="assigned",
        telephony_configuration_id=301,
        telephony_phone_number_id=202,
        extra_metadata={
            "live_trunk_validated": True,
            "is_contract_fixture": True,
            "live_validation_source": "simulator",
            "live_validation_evidence_id": "fixture-1",
        },
    )

    with patch(
        "api.routes.telephony_number_inventory.list_inventory_numbers",
        new=AsyncMock(return_value=([row], 1)),
    ):
        response = client.get("/telephony-number-inventory?limit=1")

    assert response.status_code == 200
    readiness = response.json()["numbers"][0]["readiness_metadata"]
    assert readiness["is_contract_fixture"] is True
    assert readiness["live_trunk_validated"] is False


def test_operator_live_validation_attestation_uses_trusted_writer():
    app = _make_app()
    client = TestClient(app)
    row = _inventory_row(
        id=101,
        status="assigned",
        organization_id=11,
        telephony_configuration_id=301,
        telephony_phone_number_id=202,
        extra_metadata={
            "recova_inventory_state": "assigned",
            "managed_by": "recova_number_inventory",
            "inventory_id": 101,
            "contract_version": "jambonz_contract_v1",
            "is_contract_fixture": False,
            "live_trunk_validated": True,
            "live_validation_source": "operator_attestation",
            "live_validation_evidence_id": "real-route-cdr-001",
            "live_validation_trusted_writer": "recova_operator_live_validation_v1",
            "telephony_configuration_id": 301,
            "telephony_phone_number_id": 202,
            "call_attempt_id": "outbound:jambonz:real-route-001",
        },
    )

    with patch(
        "api.routes.telephony_number_inventory.attest_inventory_live_validation",
        new=AsyncMock(return_value=row),
    ) as attest_mock:
        response = client.post(
            "/telephony-number-inventory/101/live-validation",
            json={
                "live_validation_source": "operator_attestation",
                "live_validation_evidence_id": "real-route-cdr-001",
                "contract_version": "jambonz_contract_v1",
                "call_attempt_id": "outbound:jambonz:real-route-001",
                "note": "staging live route proof",
            },
        )

    assert response.status_code == 200
    readiness = response.json()["readiness_metadata"]
    assert readiness["live_trunk_validated"] is True
    assert readiness["is_contract_fixture"] is False
    assert readiness["telephony_configuration_id"] == 301
    assert readiness["telephony_phone_number_id"] == 202
    attest_mock.assert_awaited_once_with(
        101,
        actor_user_id=99,
        live_validation_source="operator_attestation",
        live_validation_evidence_id="real-route-cdr-001",
        contract_version="jambonz_contract_v1",
        call_attempt_id="outbound:jambonz:real-route-001",
        note="staging live route proof",
    )

def test_customer_bind_uses_selected_organization_scope():
    app = _make_app()
    client = TestClient(app)
    row = _inventory_row(
        status="assigned",
        organization_id=11,
        telephony_configuration_id=301,
        telephony_phone_number_id=202,
    )
    phone = _phone_row(inbound_workflow_id=33)

    with patch(
        "api.routes.telephony_number_inventory.bind_customer_assigned_number",
        new=AsyncMock(return_value=(row, phone, "Support Agent")),
    ) as bind_mock:
        response = client.post(
            "/organizations/telephony-numbers/assigned/101/bind",
            json={"workflow_id": 33},
        )

    assert response.status_code == 200
    assert response.json()["inbound_workflow_id"] == 33
    bind_mock.assert_awaited_once_with(
        101,
        organization_id=11,
        actor_user_id=7,
        workflow_id=33,
    )


def test_customer_unbind_uses_selected_organization_scope():
    app = _make_app()
    client = TestClient(app)
    row = _inventory_row(
        status="assigned",
        organization_id=11,
        telephony_configuration_id=301,
        telephony_phone_number_id=202,
    )
    phone = _phone_row(inbound_workflow_id=None)

    with patch(
        "api.routes.telephony_number_inventory.bind_customer_assigned_number",
        new=AsyncMock(return_value=(row, phone, None)),
    ) as bind_mock:
        response = client.delete("/organizations/telephony-numbers/assigned/101/bind")

    assert response.status_code == 200
    assert response.json()["inbound_workflow_id"] is None
    bind_mock.assert_awaited_once_with(
        101,
        organization_id=11,
        actor_user_id=7,
        workflow_id=None,
    )


def test_hidden_provider_crud_rejection_fails_closed_for_unknown_or_hidden_specs():
    source = (
        Path(__file__).resolve().parents[1] / "routes" / "organization.py"
    ).read_text()

    assert "return spec is not None and spec.visible_in_self_serve" in source
    assert "telephony_provider_not_supported_for_self_serve" in source
