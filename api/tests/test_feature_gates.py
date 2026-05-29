from types import SimpleNamespace
from unittest.mock import AsyncMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.routes.campaign import router as campaign_router
from api.routes.organization import router as organization_router
from api.services.auth.depends import get_user


def _user(*, is_superuser: bool = False):
    return SimpleNamespace(
        id=7,
        provider_id="stack-user-7",
        selected_organization_id=11,
        is_superuser=is_superuser,
    )


def _make_app(router, user):
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_user] = lambda: user
    return app


def _force_saas_defaults(monkeypatch):
    monkeypatch.setattr("api.services.feature_gates.AUTH_PROVIDER", "stack")
    monkeypatch.setattr("api.services.feature_gates.ENABLE_SELF_SERVE_TELEPHONY", False)
    monkeypatch.setattr("api.services.feature_gates.ENABLE_SELF_SERVE_CAMPAIGNS", False)


def test_normal_saas_user_cannot_access_telephony_management(monkeypatch):
    _force_saas_defaults(monkeypatch)
    monkeypatch.setattr(
        "api.services.feature_gates.db_client.get_configuration",
        AsyncMock(return_value=None),
    )
    app = _make_app(organization_router, _user())
    client = TestClient(app)

    assert client.get("/organizations/telephony-configs").status_code == 403
    assert (
        client.post(
            "/organizations/telephony-configs",
            json={
                "name": "Twilio",
                "config": {
                    "provider": "twilio",
                    "account_sid": "AC123",
                    "auth_token": "secret",
                    "from_numbers": [],
                },
            },
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/organizations/telephony-configs/123/phone-numbers",
            json={"address": "+15551234567"},
        ).status_code
        == 403
    )


def test_superuser_can_access_telephony_management_when_default_disabled(monkeypatch):
    _force_saas_defaults(monkeypatch)
    monkeypatch.setattr(
        "api.routes.organization.db_client.list_telephony_configurations",
        AsyncMock(return_value=[]),
    )
    app = _make_app(organization_router, _user(is_superuser=True))
    client = TestClient(app)

    response = client.get("/organizations/telephony-configs")

    assert response.status_code == 200
    assert response.json() == {"configurations": []}


def test_org_override_can_access_telephony_management(monkeypatch):
    _force_saas_defaults(monkeypatch)
    monkeypatch.setattr(
        "api.services.feature_gates.db_client.get_configuration",
        AsyncMock(
            return_value=SimpleNamespace(value={"self_serve_telephony": True})
        ),
    )
    monkeypatch.setattr(
        "api.routes.organization.db_client.list_telephony_configurations",
        AsyncMock(return_value=[]),
    )
    app = _make_app(organization_router, _user())
    client = TestClient(app)

    response = client.get("/organizations/telephony-configs")

    assert response.status_code == 200
    assert response.json() == {"configurations": []}


def test_normal_saas_user_cannot_access_campaign_management(monkeypatch):
    _force_saas_defaults(monkeypatch)
    monkeypatch.setattr(
        "api.services.feature_gates.db_client.get_configuration",
        AsyncMock(return_value=None),
    )
    app = _make_app(campaign_router, _user())
    client = TestClient(app)

    assert client.get("/campaign/").status_code == 403
    assert (
        client.post(
            "/campaign/create",
            json={
                "name": "Campaign",
                "workflow_id": 1,
                "source_type": "csv",
                "source_id": "campaigns/11/source.csv",
            },
        ).status_code
        == 403
    )


def test_org_override_can_access_campaign_management(monkeypatch):
    _force_saas_defaults(monkeypatch)
    monkeypatch.setattr(
        "api.services.feature_gates.db_client.get_configuration",
        AsyncMock(
            return_value=SimpleNamespace(value={"self_serve_campaigns": True})
        ),
    )
    monkeypatch.setattr(
        "api.routes.campaign.db_client.get_campaigns",
        AsyncMock(return_value=[]),
    )
    monkeypatch.setattr(
        "api.routes.campaign.db_client.get_workflows_by_ids",
        AsyncMock(return_value=[]),
    )
    monkeypatch.setattr(
        "api.routes.campaign.db_client.get_queued_runs_stats_for_campaigns",
        AsyncMock(return_value={}),
    )
    monkeypatch.setattr(
        "api.routes.campaign.db_client.list_telephony_configurations",
        AsyncMock(return_value=[]),
    )
    app = _make_app(campaign_router, _user())
    client = TestClient(app)

    response = client.get("/campaign/")

    assert response.status_code == 200
    assert response.json() == {"campaigns": []}
