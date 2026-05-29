from types import SimpleNamespace
from unittest.mock import AsyncMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.routes.campaign import router as campaign_router
from api.routes.organization import router as organization_router
from api.routes.telephony import router as telephony_router
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


def test_normal_saas_user_cannot_access_legacy_initiate_call(monkeypatch):
    _force_saas_defaults(monkeypatch)
    monkeypatch.setattr(
        "api.services.feature_gates.db_client.get_configuration",
        AsyncMock(return_value=None),
    )
    app = _make_app(telephony_router, _user())
    client = TestClient(app)

    response = client.post(
        "/telephony/initiate-call",
        json={"workflow_id": 33, "phone_number": "+15551234567"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "self_serve_telephony_disabled"


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


def test_telephony_config_update_rejects_inbound_account_conflict(monkeypatch):
    _force_saas_defaults(monkeypatch)
    existing = SimpleNamespace(
        id=123,
        name="Twilio",
        provider="twilio",
        organization_id=11,
        credentials={"account_sid": "ACOLD", "auth_token": "old-secret"},
    )
    active_phone = SimpleNamespace(
        address="+15551234567",
        country_code="US",
        is_active=True,
    )
    conflict_config = SimpleNamespace(
        id=456,
        name="Other Twilio",
        organization_id=11,
    )
    conflict_phone = SimpleNamespace(address="+15551234567")

    monkeypatch.setattr(
        "api.routes.organization.db_client.get_telephony_configuration_for_org",
        AsyncMock(return_value=existing),
    )
    monkeypatch.setattr(
        "api.routes.organization.db_client.list_phone_numbers_for_config",
        AsyncMock(return_value=[active_phone]),
    )
    find_conflict = AsyncMock(return_value=(conflict_config, conflict_phone))
    monkeypatch.setattr(
        "api.routes.organization.db_client.find_inbound_routing_conflict",
        find_conflict,
    )
    update_config = AsyncMock()
    monkeypatch.setattr(
        "api.routes.organization.db_client.update_telephony_configuration",
        update_config,
    )
    app = _make_app(organization_router, _user(is_superuser=True))
    client = TestClient(app)

    response = client.put(
        "/organizations/telephony-configs/123",
        json={
            "config": {
                "provider": "twilio",
                "account_sid": "ACNEW",
                "auth_token": "new-secret",
                "from_numbers": [],
            },
        },
    )

    assert response.status_code == 409
    assert "ambiguous" in response.json()["detail"]
    update_config.assert_not_awaited()
    find_conflict.assert_awaited_once_with(
        provider="twilio",
        account_id_field="account_sid",
        account_id="ACNEW",
        address="+15551234567",
        country_hint="US",
        exclude_telephony_configuration_id=123,
    )


def test_legacy_telephony_config_rejects_update_inbound_account_conflict(
    monkeypatch,
):
    _force_saas_defaults(monkeypatch)
    default = SimpleNamespace(
        id=123,
        name="Twilio Default",
        provider="twilio",
        organization_id=11,
        credentials={"account_sid": "ACOLD", "auth_token": "old-secret"},
    )
    active_phone = SimpleNamespace(
        address="+15551234567",
        country_code="US",
        is_active=True,
    )
    conflict_config = SimpleNamespace(
        id=456,
        name="Other Twilio",
        organization_id=11,
    )
    conflict_phone = SimpleNamespace(address="+15551234567")

    monkeypatch.setattr(
        "api.routes.organization.db_client.get_default_telephony_configuration",
        AsyncMock(return_value=default),
    )
    monkeypatch.setattr(
        "api.routes.organization.db_client.list_phone_numbers_for_config",
        AsyncMock(return_value=[active_phone]),
    )
    find_conflict = AsyncMock(return_value=(conflict_config, conflict_phone))
    monkeypatch.setattr(
        "api.routes.organization.db_client.find_inbound_routing_conflict",
        find_conflict,
    )
    update_config = AsyncMock()
    monkeypatch.setattr(
        "api.routes.organization.db_client.update_telephony_configuration",
        update_config,
    )
    app = _make_app(organization_router, _user(is_superuser=True))
    client = TestClient(app)

    response = client.post(
        "/organizations/telephony-config",
        json={
            "provider": "twilio",
            "account_sid": "ACNEW",
            "auth_token": "new-secret",
            "from_numbers": ["+15551234567"],
        },
    )

    assert response.status_code == 409
    assert "ambiguous" in response.json()["detail"]
    update_config.assert_not_awaited()
    find_conflict.assert_awaited_once_with(
        provider="twilio",
        account_id_field="account_sid",
        account_id="ACNEW",
        address="+15551234567",
        country_hint="US",
        exclude_telephony_configuration_id=123,
    )


def test_legacy_telephony_config_rejects_new_number_routing_conflict(
    monkeypatch,
):
    _force_saas_defaults(monkeypatch)
    default = SimpleNamespace(
        id=123,
        name="Twilio Default",
        provider="twilio",
        organization_id=11,
        credentials={"account_sid": "AC123", "auth_token": "old-secret"},
    )
    conflict_config = SimpleNamespace(
        id=456,
        name="Other Twilio",
        organization_id=11,
    )
    conflict_phone = SimpleNamespace(address="+15557654321")

    monkeypatch.setattr(
        "api.routes.organization.db_client.get_default_telephony_configuration",
        AsyncMock(return_value=default),
    )
    monkeypatch.setattr(
        "api.routes.organization.db_client.list_phone_numbers_for_config",
        AsyncMock(return_value=[]),
    )
    find_conflict = AsyncMock(return_value=(conflict_config, conflict_phone))
    monkeypatch.setattr(
        "api.routes.organization.db_client.find_inbound_routing_conflict",
        find_conflict,
    )
    update_config = AsyncMock()
    create_phone_number = AsyncMock()
    monkeypatch.setattr(
        "api.routes.organization.db_client.update_telephony_configuration",
        update_config,
    )
    monkeypatch.setattr(
        "api.routes.organization.db_client.create_phone_number",
        create_phone_number,
    )
    app = _make_app(organization_router, _user(is_superuser=True))
    client = TestClient(app)

    response = client.post(
        "/organizations/telephony-config",
        json={
            "provider": "twilio",
            "account_sid": "AC123",
            "auth_token": "new-secret",
            "from_numbers": ["+15557654321"],
        },
    )

    assert response.status_code == 409
    assert "cannot be uniquely routed" in response.json()["detail"]
    update_config.assert_not_awaited()
    create_phone_number.assert_not_awaited()
    find_conflict.assert_awaited_once_with(
        provider="twilio",
        account_id_field="account_sid",
        account_id="AC123",
        address="+15557654321",
        country_hint=None,
        exclude_telephony_configuration_id=123,
        exclude_phone_number_id=None,
    )


def test_phone_number_update_rejects_reactivation_routing_conflict(monkeypatch):
    _force_saas_defaults(monkeypatch)
    cfg = SimpleNamespace(
        id=123,
        name="Twilio",
        provider="twilio",
        organization_id=11,
        credentials={"account_sid": "AC123", "auth_token": "secret"},
    )
    existing_phone = SimpleNamespace(
        id=321,
        telephony_configuration_id=123,
        address="+15551234567",
        country_code="US",
        is_active=False,
    )
    conflict_config = SimpleNamespace(
        id=456,
        name="Other Twilio",
        organization_id=22,
    )
    conflict_phone = SimpleNamespace(address="+15551234567")

    monkeypatch.setattr(
        "api.routes.organization.db_client.get_telephony_configuration_for_org",
        AsyncMock(return_value=cfg),
    )
    monkeypatch.setattr(
        "api.routes.organization.db_client.get_phone_number_for_config",
        AsyncMock(return_value=existing_phone),
    )
    find_conflict = AsyncMock(return_value=(conflict_config, conflict_phone))
    monkeypatch.setattr(
        "api.routes.organization.db_client.find_inbound_routing_conflict",
        find_conflict,
    )
    update_phone_number = AsyncMock()
    monkeypatch.setattr(
        "api.routes.organization.db_client.update_phone_number",
        update_phone_number,
    )
    app = _make_app(organization_router, _user(is_superuser=True))
    client = TestClient(app)

    response = client.put(
        "/organizations/telephony-configs/123/phone-numbers/321",
        json={"is_active": True},
    )

    assert response.status_code == 409
    assert "cannot be uniquely routed" in response.json()["detail"]
    update_phone_number.assert_not_awaited()
    find_conflict.assert_awaited_once_with(
        provider="twilio",
        account_id_field="account_sid",
        account_id="AC123",
        address="+15551234567",
        country_hint="US",
        exclude_telephony_configuration_id=None,
        exclude_phone_number_id=321,
    )


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
