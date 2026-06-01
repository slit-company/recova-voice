"""ClawOps telephony provider package."""

from typing import Any, Dict

from api.services.telephony.registry import (
    ProviderSpec,
    ProviderUIField,
    ProviderUIMetadata,
    register,
)

from .config import ClawOpsConfigurationRequest, ClawOpsConfigurationResponse
from .provider import ClawOpsProvider
from .transport import create_transport


def _config_loader(value: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "provider": "clawops",
        "account_id": value.get("account_id"),
        "api_key": value.get("api_key"),
        "signing_key": value.get("signing_key"),
        "from_numbers": value.get("from_numbers", []),
    }


_UI_METADATA = ProviderUIMetadata(
    display_name="ClawOps",
    docs_url="https://platform.claw-ops.com/docs",
    fields=[
        ProviderUIField(
            name="account_id",
            label="Account ID",
            type="text",
            sensitive=True,
            description="ClawOps Account ID",
        ),
        ProviderUIField(
            name="api_key",
            label="API Key",
            type="password",
            sensitive=True,
            description="Bearer API key for the ClawOps REST API",
        ),
        ProviderUIField(
            name="signing_key",
            label="Webhook Signing Key",
            type="password",
            sensitive=True,
            description="Signing key used to verify X-Signature on ClawOps webhooks",
        ),
        ProviderUIField(
            name="from_numbers",
            label="Phone Numbers",
            type="string-array",
            description="ClawOps-owned Korean 070 numbers used for calls",
        ),
    ],
)


SPEC = ProviderSpec(
    name="clawops",
    provider_cls=ClawOpsProvider,
    config_loader=_config_loader,
    transport_factory=create_transport,
    transport_sample_rate=8000,
    config_request_cls=ClawOpsConfigurationRequest,
    ui_metadata=_UI_METADATA,
    config_response_cls=ClawOpsConfigurationResponse,
    account_id_credential_field="account_id",
    visible_in_self_serve=False,
    supports_preview_smoke=True,
)


register(SPEC)


__all__ = [
    "SPEC",
    "ClawOpsConfigurationRequest",
    "ClawOpsConfigurationResponse",
    "ClawOpsProvider",
    "create_transport",
]
