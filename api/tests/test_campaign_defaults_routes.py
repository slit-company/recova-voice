from types import SimpleNamespace
from unittest.mock import AsyncMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.routes.organization import router as organization_router
from api.services.auth.depends import get_user


def _user():
    return SimpleNamespace(
        id=7,
        provider_id="stack-user-7",
        selected_organization_id=11,
        is_superuser=False,
    )


def _make_app():
    app = FastAPI()
    app.include_router(organization_router)
    app.dependency_overrides[get_user] = _user
    return app


def test_campaign_defaults_exposes_hidden_managed_default_calling_pool(monkeypatch):
    monkeypatch.setattr("api.services.feature_gates.AUTH_PROVIDER", "stack")
    monkeypatch.setattr("api.services.feature_gates.ENABLE_SELF_SERVE_CAMPAIGNS", False)

    async def get_configuration(_, key):
        if key == "SELF_SERVE_FEATURES":
            return SimpleNamespace(value={"self_serve_campaigns": True})
        return None

    monkeypatch.setattr(
        "api.routes.organization.db_client.get_configuration",
        AsyncMock(side_effect=get_configuration),
    )
    monkeypatch.setattr(
        "api.routes.organization.db_client.get_default_telephony_configuration",
        AsyncMock(
            return_value=SimpleNamespace(
                id=901,
                name="Recova Jambonz Managed",
                provider="jambonz",
            )
        ),
    )
    monkeypatch.setattr(
        "api.routes.organization.db_client.list_active_normalized_addresses_for_config",
        AsyncMock(return_value=["+827012345678", "+827087654321"]),
    )
    monkeypatch.setattr(
        "api.routes.organization.db_client.get_latest_campaign",
        AsyncMock(return_value=None),
    )

    client = TestClient(_make_app())

    response = client.get("/organizations/campaign-defaults")

    assert response.status_code == 200
    body = response.json()
    assert body["from_numbers_count"] == 2
    assert body["default_telephony_configuration_id"] == 901
    assert body["default_telephony_configuration_name"] == "Recova Jambonz Managed"
    assert body["default_telephony_configuration_provider"] == "jambonz"
