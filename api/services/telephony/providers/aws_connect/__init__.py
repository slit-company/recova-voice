"""Amazon Connect telephony provider package."""

from typing import Any, Dict

from api.services.telephony.registry import (
    ProviderSpec,
    ProviderUIField,
    ProviderUIMetadata,
    register,
)

from .config import AWSConnectConfigurationRequest, AWSConnectConfigurationResponse
from .provider import AWSConnectProvider
from .transport import create_transport


def _config_loader(value: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "provider": "aws_connect",
        "region": value.get("region"),
        "instance_id": value.get("instance_id"),
        "contact_flow_id": value.get("contact_flow_id"),
        "queue_id": value.get("queue_id"),
        "ring_timeout_seconds": value.get("ring_timeout_seconds"),
        "from_numbers": value.get("from_numbers", []),
    }


_UI_METADATA = ProviderUIMetadata(
    display_name="Amazon Connect",
    docs_url="https://docs.aws.amazon.com/connect/latest/APIReference/API_StartOutboundVoiceContact.html",
    fields=[
        ProviderUIField(name="region", label="AWS Region", type="text"),
        ProviderUIField(name="instance_id", label="Instance ID", type="text"),
        ProviderUIField(
            name="contact_flow_id",
            label="Outbound Contact Flow ID",
            type="text",
            description="Published CONTACT_FLOW ID used for StartOutboundVoiceContact.",
        ),
        ProviderUIField(
            name="queue_id",
            label="Queue ID",
            type="text",
            required=False,
            description="Optional queue used by Amazon Connect when SourcePhoneNumber is omitted.",
        ),
        ProviderUIField(
            name="ring_timeout_seconds",
            label="Ring timeout seconds",
            type="number",
            required=False,
            description=(
                "Optional 15-60 seconds. Leave blank for the Amazon Connect default; "
                "some accounts require CAMPAIGN traffic to set a custom timer."
            ),
        ),
        ProviderUIField(
            name="from_numbers",
            label="Amazon Connect phone numbers",
            type="string-array",
            description="E.164 source numbers such as +827040223234.",
        ),
    ],
)


SPEC = ProviderSpec(
    name="aws_connect",
    provider_cls=AWSConnectProvider,
    config_loader=_config_loader,
    transport_factory=create_transport,
    transport_sample_rate=8000,
    config_request_cls=AWSConnectConfigurationRequest,
    config_response_cls=AWSConnectConfigurationResponse,
    ui_metadata=_UI_METADATA,
    account_id_credential_field="instance_id",
    visible_in_self_serve=False,
    supports_media_transport=False,
    supports_preview_smoke=True,
)


register(SPEC)


__all__ = [
    "SPEC",
    "AWSConnectConfigurationRequest",
    "AWSConnectConfigurationResponse",
    "AWSConnectProvider",
    "create_transport",
]
