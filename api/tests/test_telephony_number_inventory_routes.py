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
