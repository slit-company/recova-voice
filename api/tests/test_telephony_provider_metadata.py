from types import SimpleNamespace

import pytest
from fastapi import HTTPException

import api.services.telephony.providers  # noqa: F401 - ensure provider registration
from api.routes.organization import (
    _ensure_self_serve_provider,
    get_telephony_providers_metadata,
)


@pytest.mark.asyncio
async def test_telephony_provider_metadata_hides_infrastructure_only_providers():
    result = await get_telephony_providers_metadata(
        user=SimpleNamespace(selected_organization_id=11)
    )

    provider_names = {provider.provider for provider in result.providers}
    assert "aws_connect" not in provider_names


def test_self_serve_guard_rejects_infrastructure_only_aws_connect_provider():
    with pytest.raises(HTTPException) as exc:
        _ensure_self_serve_provider("aws_connect")

    assert exc.value.status_code == 400
    assert exc.value.detail == "telephony_provider_not_supported_for_self_serve"
