"""Jambonz telephony provider package."""

from typing import Any, Dict

from api.services.telephony.registry import (
    ProviderSpec,
    ProviderUIField,
    ProviderUIMetadata,
    register,
)

from .config import JambonzConfigurationRequest, JambonzConfigurationResponse
from .provider import JambonzProvider
from .transport import create_transport


def _config_loader(value: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "provider": "jambonz",
        "base_url": value.get("base_url"),
        "account_id": value.get("account_id"),
        "application_id": value.get("application_id"),
        "api_key": value.get("api_key"),
        "webhook_secret": value.get("webhook_secret"),
        "outbound_profile_id": value.get("outbound_profile_id"),
        "from_numbers": value.get("from_numbers", []),
    }


_UI_METADATA = ProviderUIMetadata(
    display_name="Recova Jambonz Contract Adapter",
    fields=[
        ProviderUIField(
            name="base_url",
            label="Recova Jambonz Adapter Base URL",
            type="text",
            sensitive=True,
        ),
        ProviderUIField(
            name="account_id",
            label="Account ID",
            type="text",
            sensitive=True,
        ),
        ProviderUIField(
            name="application_id",
            label="Application ID",
            type="text",
            sensitive=True,
        ),
        ProviderUIField(
            name="api_key",
            label="API Key",
            type="password",
            sensitive=True,
        ),
        ProviderUIField(
            name="webhook_secret",
            label="Webhook Secret",
            type="password",
            sensitive=True,
        ),
        ProviderUIField(
            name="outbound_profile_id",
            label="Outbound Profile ID",
            type="text",
            required=False,
            sensitive=True,
        ),
        ProviderUIField(
            name="from_numbers",
            label="Assigned Recova 070 Numbers",
            type="string-array",
            description="Operator-assigned Recova 070 caller IDs",
        ),
    ],
)


SPEC = ProviderSpec(
    name="jambonz",
    provider_cls=JambonzProvider,
    config_loader=_config_loader,
    transport_factory=create_transport,
    transport_sample_rate=8000,
    config_request_cls=JambonzConfigurationRequest,
    config_response_cls=JambonzConfigurationResponse,
    ui_metadata=_UI_METADATA,
    account_id_credential_field="account_id",
    visible_in_self_serve=False,
)


register(SPEC)


__all__ = [
    "SPEC",
    "JambonzConfigurationRequest",
    "JambonzConfigurationResponse",
    "JambonzProvider",
    "create_transport",
]
