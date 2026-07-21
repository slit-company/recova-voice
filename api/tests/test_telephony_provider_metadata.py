from types import SimpleNamespace

import pytest
from fastapi import HTTPException

import api.services.telephony.providers  # noqa: F401 - ensure provider registration
from api.routes.organization import (
    _ensure_self_serve_provider,
    get_telephony_providers_metadata,
)
from api.services.telephony.registry import get


@pytest.mark.asyncio
async def test_telephony_provider_metadata_hides_infrastructure_only_providers():
    result = await get_telephony_providers_metadata(
        user=SimpleNamespace(selected_organization_id=11)
    )

    provider_names = {provider.provider for provider in result.providers}
    assert "aws_connect" not in provider_names
    assert "clawops" not in provider_names
    assert "jambonz" not in provider_names


def test_self_serve_guard_rejects_infrastructure_only_aws_connect_provider():
    with pytest.raises(HTTPException) as exc:
        _ensure_self_serve_provider("aws_connect")

    assert exc.value.status_code == 400
    assert exc.value.detail == "telephony_provider_not_supported_for_self_serve"


def test_self_serve_guard_rejects_recova_owned_clawops_provider():
    with pytest.raises(HTTPException) as exc:
        _ensure_self_serve_provider("clawops")

    assert exc.value.status_code == 400
    assert exc.value.detail == "telephony_provider_not_supported_for_self_serve"


def test_self_serve_guard_rejects_operator_owned_jambonz_provider():
    with pytest.raises(HTTPException) as exc:
        _ensure_self_serve_provider("jambonz")

    assert exc.value.status_code == 400
    assert exc.value.detail == "telephony_provider_not_supported_for_self_serve"


def test_recova_owned_clawops_provider_allows_preview_smoke_only():
    spec = get("clawops")

    assert spec.visible_in_self_serve is False
    assert spec.supports_preview_smoke is True
    assert spec.supports_media_transport is True


def test_operator_owned_jambonz_provider_is_hidden_and_preview_smoke_bounded():
    spec = get("jambonz")

    assert spec.visible_in_self_serve is False
    assert spec.supports_public_calls is False
    assert spec.supports_preview_smoke is True
    assert spec.supports_media_transport is True
    assert spec.allowed_dispatch_purposes == frozenset({"phone_preview_smoke"})
    assert spec.account_id_credential_field == "account_id"
