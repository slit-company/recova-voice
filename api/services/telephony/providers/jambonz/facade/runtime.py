"""Fail-closed deployment dependency composition for the Jambonz facade."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Mapping

from dataclasses import dataclass
from pydantic import SecretStr

from .auth import SignatureVerifier, VerificationPolicy
from .clients import (
    F12AuthorityHttpClient,
    F12TransportConfiguration,
    PrivatePemEs256Verifier,
    PrivateStockJambonzClient,
    StockJambonzConfiguration,
    StrictF12Transport,
    _private_service_url,
)
from .service import F12AuthorityClient, StockJambonzClient


class FacadeRuntimeConfigurationError(RuntimeError):
    """A non-sensitive startup failure that keeps traffic authority disabled."""


RUNTIME_CONFIGURATION_INVALID = "jambonz_facade_runtime_configuration_invalid"


@dataclass(frozen=True)
class RuntimeDependencies:
    """Complete explicit dependencies accepted by the facade composition root."""

    f12_client: F12AuthorityClient
    stock_client: StockJambonzClient
    signature_verifier: SignatureVerifier
    verification_policy: VerificationPolicy
    media_websocket_url: str


def compose_f12_transport(
    configuration: F12TransportConfiguration,
) -> StrictF12Transport:
    """Construct the strict transport from explicit opaque inputs."""

    return StrictF12Transport(configuration)


def load_deployment_dependencies(
    environ: Mapping[str, str] | None = None,
) -> RuntimeDependencies:
    """Resolve every private deployment dependency or fail without partial startup."""

    values = os.environ if environ is None else environ

    def required(name: str) -> str:
        value = values.get(name, "").strip()
        if not value:
            raise ValueError("required facade runtime setting is missing")
        return value

    def endpoint_credential() -> str:
        inline = values.get("RECOVA_F12_ENDPOINT_CREDENTIAL", "").strip()
        path_value = values.get("RECOVA_F12_ENDPOINT_CREDENTIAL_PATH", "").strip()
        if bool(inline) == bool(path_value):
            raise ValueError("exactly one F12 endpoint credential source is required")
        if inline:
            return inline
        descriptor = os.open(path_value, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
                raise ValueError("F12 endpoint credential file is not private")
            raw = os.read(descriptor, 4097)
        finally:
            os.close(descriptor)
        if not raw or len(raw) > 4096:
            raise ValueError("F12 endpoint credential file is invalid")
        try:
            value = raw.decode("utf-8").strip()
        except UnicodeDecodeError as exc:
            raise ValueError("F12 endpoint credential file is invalid") from exc
        if not value:
            raise ValueError("F12 endpoint credential file is invalid")
        return value

    try:
        f12_base_url = _private_service_url(
            required("RECOVA_F12_BASE_URL"), label="f12_base_url"
        )
        if not f12_base_url.startswith("https://"):
            raise ValueError("f12_base_url_must_use_https")
        f12_transport = StrictF12Transport(
            F12TransportConfiguration(
                base_url=f12_base_url,
                verified_identity=required("RECOVA_F12_VERIFIED_IDENTITY"),
                verified_issuer=required("RECOVA_F12_VERIFIED_ISSUER"),
                endpoint_credential=SecretStr(endpoint_credential()),
                client_certificate_path=Path(
                    required("RECOVA_F12_CLIENT_CERTIFICATE_PATH")
                ),
                client_key_path=Path(required("RECOVA_F12_CLIENT_KEY_PATH")),
                ca_certificate_path=Path(
                    required("RECOVA_F12_CA_CERTIFICATE_PATH")
                ),
                timeout_seconds=float(
                    values.get("RECOVA_F12_TIMEOUT_SECONDS", "5")
                ),
            )
        )
        dispatch_key_id = required("RECOVA_DISPATCH_KEY_ID")
        media_key_id = required("RECOVA_MEDIA_KEY_ID")
        policy = VerificationPolicy(
            dispatch_key_id=dispatch_key_id,
            media_key_id=media_key_id,
            maximum_clock_skew_seconds=int(
                values.get("RECOVA_MAXIMUM_CLOCK_SKEW_SECONDS", "30")
            ),
        )
        verifier = PrivatePemEs256Verifier(
            {
                dispatch_key_id: Path(
                    required("RECOVA_DISPATCH_PUBLIC_KEY_PATH")
                ),
                media_key_id: Path(required("RECOVA_MEDIA_PUBLIC_KEY_PATH")),
            }
        )
        stock_client = PrivateStockJambonzClient(
            StockJambonzConfiguration(
                base_url=required("RECOVA_STOCK_BASE_URL"),
                account_id=required("RECOVA_STOCK_ACCOUNT_ID"),
                api_token=SecretStr(required("RECOVA_STOCK_API_TOKEN")),
                timeout_seconds=float(
                    values.get("RECOVA_STOCK_TIMEOUT_SECONDS", "5")
                ),
            )
        )
        media_websocket_url = required("RECOVA_MEDIA_WEBSOCKET_URL")
        if not media_websocket_url.startswith("wss://"):
            raise ValueError("media_websocket_url_must_use_wss")
        _private_service_url(
            media_websocket_url.replace("wss://", "https://", 1),
            label="media_websocket_url",
            allow_path=True,
        )
    except (OSError, TypeError, ValueError):
        raise FacadeRuntimeConfigurationError(RUNTIME_CONFIGURATION_INVALID) from None

    return RuntimeDependencies(
        f12_client=F12AuthorityHttpClient(f12_transport),
        stock_client=stock_client,
        signature_verifier=verifier,
        verification_policy=policy,
        media_websocket_url=media_websocket_url,
    )
