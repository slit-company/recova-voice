"""Jambonz telephony provider package."""

from typing import Any, Dict

from api.services.telephony.registry import (
    ProviderSpec,
    ProviderUIField,
    ProviderUIMetadata,
    register,
)



def _config_loader(value: Dict[str, Any]) -> Dict[str, Any]:
    # Lazy import keeps provider registration independent of the facade/F12 graph.
    from api.services.onnuri_smoke_capabilities import get_smoke_authority_runtime

    runtime = get_smoke_authority_runtime()
    return {
        "provider": "jambonz",
        "base_url": value.get("base_url"),
        "account_id": value.get("account_id"),
        "application_id": value.get("application_id"),
        "api_key": value.get("api_key"),
        "webhook_secret": value.get("webhook_secret"),
        "outbound_profile_id": value.get("outbound_profile_id"),
        "from_numbers": value.get("from_numbers", []),
        "smoke_capability_issuer": runtime.issuer,
        "media_capability_verifier": runtime.issuer,
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


SPEC: ProviderSpec | None = None


def register_provider() -> None:
    """Register Jambonz without importing its runtime during package discovery."""

    global SPEC
    if SPEC is not None:
        register(SPEC)
        return

    from .config import JambonzConfigurationRequest, JambonzConfigurationResponse
    from .provider import JambonzProvider
    from .transport import create_transport

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
        supports_public_calls=False,
        supports_preview_smoke=True,
        allowed_dispatch_purposes=frozenset({"phone_preview_smoke"}),
    )
    register(SPEC)


__all__ = ["SPEC", "register_provider"]
