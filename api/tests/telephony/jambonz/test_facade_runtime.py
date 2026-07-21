import traceback
import base64
from pathlib import Path
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel, ConfigDict, SecretStr
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

import api.services.telephony.providers.jambonz.facade as facade_package
import api.services.telephony.providers.jambonz.facade.app as app_module
import api.services.telephony.providers.jambonz.facade.clients as clients_module
import api.services.telephony.providers.jambonz.facade.runtime as runtime_module
from api.services.telephony.providers.jambonz.facade.app import create_facade_app
from api.services.telephony.providers.jambonz.facade.auth import VerificationPolicy
from api.schemas.onnuri_smoke import (
    CommitInboundAnswerIntentAndMintMediaRequest,
    FacadeAuthorityReadiness,
    FacadeBoundCallStatusResponse,
    RecordAnswerAndMintMediaRequest,
    SmokeReceipt,
)
from api.services.telephony.providers.jambonz.facade.clients import (
    F12AuthorityHttpClient,
    F12TransportConfiguration,
    F12TransportError,
    PrivatePemEs256Verifier,
    PrivateStockJambonzClient,
    StockJambonzConfiguration,
    StrictF12Transport,
)
from api.services.telephony.providers.jambonz.facade.models import (
    BoundCallContext,
    CallbackReceipt,
    CallStatus,
    ContainmentRequest,
    RouteChainCapability,
    RouteChainCapabilityRequest,
    DispatchConsumeReceipt,
    DispatchSubmission,
    Direction,
    FailureCategory,
    InboundInitialHookRequest,
    MediaAuthorityReceipt,
    NormalizedCallEvent,
    OutboundAnswerHookRequest,
    SignedCapability,
    StockCallCreateRequest,
)
from api.services.telephony.providers.jambonz.facade.service import (
    AuthorityClientError,
    StockClientError,
)


class _Request(BaseModel):
    operation_id: str


class _Response(BaseModel):
    model_config = ConfigDict(extra="forbid")

    accepted: bool


class _Verifier:
    def verify(self, **_kwargs: object) -> bool:
        return True


class _ReadyDependency:
    def __init__(self, ready: bool = True) -> None:
        self.ready = AsyncMock(return_value=ready)


class _FakeHTTPClient:
    def __init__(self) -> None:
        self.post = AsyncMock()
        self.aclose = AsyncMock()


def _injected_dependencies() -> dict[str, object]:
    return {
        "f12_client": _ReadyDependency(),
        "stock_client": _ReadyDependency(),
        "signature_verifier": _Verifier(),
        "verification_policy": VerificationPolicy(
            dispatch_key_id="dispatch-key", media_key_id="media-key"
        ),
        "media_websocket_url": "wss://media.invalid/calls",
    }


def _transport(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[StrictF12Transport, _FakeHTTPClient, object]:
    fake_client = _FakeHTTPClient()
    transport_marker = object()
    transport_constructor = Mock(return_value=transport_marker)
    client_constructor = Mock(return_value=fake_client)
    monkeypatch.setattr(clients_module.httpx, "AsyncHTTPTransport", transport_constructor)
    monkeypatch.setattr(clients_module.httpx, "AsyncClient", client_constructor)

    transport = StrictF12Transport(
        F12TransportConfiguration(
            base_url="https://f12.invalid/",
            verified_identity="facade-workload",
            verified_issuer="private-ca",
            endpoint_credential=SecretStr("opaque-endpoint-credential"),
            client_certificate_path=clients_module.Path("client.crt"),
            client_key_path=clients_module.Path("client.key"),
            ca_certificate_path=clients_module.Path("ca.crt"),
            timeout_seconds=3.0,
        )
    )
    return transport, fake_client, transport_marker


def test_zero_argument_startup_rejects_missing_runtime_configuration_before_transport_setup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_setup(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("invalid startup attempted transport setup")

    monkeypatch.setattr(runtime_module.os, "environ", {})
    monkeypatch.setattr(clients_module.httpx, "AsyncHTTPTransport", unexpected_setup)
    monkeypatch.setattr(clients_module.httpx, "AsyncClient", unexpected_setup)

    with pytest.raises(runtime_module.FacadeRuntimeConfigurationError) as exc_info:
        create_facade_app()

    assert str(exc_info.value) == runtime_module.RUNTIME_CONFIGURATION_INVALID
    assert str(exc_info.value) == "jambonz_facade_runtime_configuration_invalid"


def test_complete_runtime_configuration_composes_only_private_explicit_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    seen: dict[str, object] = {}
    f12_transport = object()
    verifier = object()
    stock = object()

    def build_f12(configuration: F12TransportConfiguration) -> object:
        seen["f12"] = configuration
        return f12_transport

    def build_verifier(paths: dict[str, Path]) -> object:
        seen["keys"] = paths
        return verifier

    def build_stock(configuration: StockJambonzConfiguration) -> object:
        seen["stock"] = configuration
        return stock

    monkeypatch.setattr(runtime_module, "StrictF12Transport", build_f12)
    monkeypatch.setattr(runtime_module, "PrivatePemEs256Verifier", build_verifier)
    monkeypatch.setattr(runtime_module, "PrivateStockJambonzClient", build_stock)
    endpoint_credential = tmp_path / "f12-endpoint-credential"
    endpoint_credential.write_text("opaque-f12-credential\n")
    endpoint_credential.chmod(0o400)
    environment = {
        "RECOVA_F12_BASE_URL": "https://f12.internal",
        "RECOVA_F12_VERIFIED_IDENTITY": "facade-workload",
        "RECOVA_F12_VERIFIED_ISSUER": "private-ca",
        "RECOVA_F12_ENDPOINT_CREDENTIAL_PATH": str(endpoint_credential),
        "RECOVA_F12_CLIENT_CERTIFICATE_PATH": "/run/secrets/client.crt",
        "RECOVA_F12_CLIENT_KEY_PATH": "/run/secrets/client.key",
        "RECOVA_F12_CA_CERTIFICATE_PATH": "/run/secrets/ca.crt",
        "RECOVA_DISPATCH_KEY_ID": "dispatch-key",
        "RECOVA_MEDIA_KEY_ID": "media-key",
        "RECOVA_DISPATCH_PUBLIC_KEY_PATH": "/run/config/dispatch.pem",
        "RECOVA_MEDIA_PUBLIC_KEY_PATH": "/run/config/media.pem",
        "RECOVA_STOCK_BASE_URL": "http://jambonz-api.default.svc",
        "RECOVA_STOCK_ACCOUNT_ID": "account-1",
        "RECOVA_STOCK_API_TOKEN": "opaque-stock-token",
        "RECOVA_MEDIA_WEBSOCKET_URL": "wss://facade.internal/media",
    }

    dependencies = runtime_module.load_deployment_dependencies(environment)

    assert dependencies.stock_client is stock
    assert dependencies.signature_verifier is verifier
    assert dependencies.verification_policy == VerificationPolicy(
        dispatch_key_id="dispatch-key", media_key_id="media-key"
    )
    assert dependencies.media_websocket_url == "wss://facade.internal/media"
    assert isinstance(dependencies.f12_client, F12AuthorityHttpClient)
    assert dependencies.f12_client._transport is f12_transport
    assert seen["keys"] == {
        "dispatch-key": Path("/run/config/dispatch.pem"),
        "media-key": Path("/run/config/media.pem"),
    }
    f12_configuration = seen["f12"]
    assert isinstance(f12_configuration, F12TransportConfiguration)
    assert f12_configuration.base_url == "https://f12.internal"
    assert (
        f12_configuration.endpoint_credential.get_secret_value()
        == "opaque-f12-credential"
    )
    stock_configuration = seen["stock"]
    assert isinstance(stock_configuration, StockJambonzConfiguration)
    assert stock_configuration.base_url == "http://jambonz-api.default.svc"
    assert stock_configuration.account_id == "account-1"
    assert stock_configuration.api_token.get_secret_value() == "opaque-stock-token"


def test_runtime_rejects_ambiguous_f12_endpoint_credential_sources(
    tmp_path: Path,
) -> None:
    endpoint_credential = tmp_path / "f12-endpoint-credential"
    endpoint_credential.write_text("opaque-file-credential\n")
    endpoint_credential.chmod(0o400)
    environment = {
        "RECOVA_F12_ENDPOINT_CREDENTIAL": "opaque-inline-credential",
        "RECOVA_F12_ENDPOINT_CREDENTIAL_PATH": str(endpoint_credential),
    }

    with pytest.raises(runtime_module.FacadeRuntimeConfigurationError):
        runtime_module.load_deployment_dependencies(environment)


@pytest.mark.parametrize("missing", tuple(_injected_dependencies()))
def test_partial_dependency_injection_is_rejected(missing: str) -> None:
    dependencies = _injected_dependencies()
    dependencies[missing] = None

    with pytest.raises(runtime_module.FacadeRuntimeConfigurationError) as exc_info:
        create_facade_app(**dependencies)

    assert str(exc_info.value) == "facade_partial_dependency_injection_rejected"


def test_complete_fake_injection_exposes_only_disabled_docs_and_facade_routes() -> None:
    app = create_facade_app(**_injected_dependencies())
    client = TestClient(app)

    assert app.docs_url is None
    assert app.redoc_url is None
    assert app.openapi_url is None
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/openapi.json").status_code == 404
    assert client.get("/healthz").json() == {"status": "alive"}
    assert client.get("/readyz").json() == {"status": "ready"}
    assert {route.path for route in app.routes} == {
        "/healthz",
        "/readyz",
        "/v1/g008/inbound/arm",
        "/v1/g008/calls/hangup",
        "/v1/jambonz-contract/accounts/{account_id}/calls",
        "/v1/jambonz-contract/accounts/{account_id}/calls/{stock_call_id}",
        "/v1/jambonz-contract/hooks/outbound/record-answer-and-mint-media",
        "/v1/jambonz-contract/hooks/inbound/commit-inbound-answer-intent-and-mint-media",
        "/v1/jambonz-contract/hooks/status",
        "/v1/jambonz-contract/hooks/cdr",
    }


def test_factory_has_no_application_or_alternate_factory_alias() -> None:
    assert create_facade_app.__module__ == app_module.__name__
    assert not hasattr(app_module, "app")
    assert not hasattr(app_module, "application")
    assert not hasattr(app_module, "create_app")
    assert facade_package.create_facade_app is create_facade_app


@pytest.mark.parametrize(
    "operation_path",
    [
        "/api/v1/internal/other/consume",
        "api/v1/internal/onnuri-smoke/consume",
        "/api/v1/internal/onnuri-smoke//consume",
        "/api/v1/internal/onnuri-smoke/../consume",
        "/api/v1/internal/onnuri-smoke/consume?retry=true",
        "/api/v1/internal/onnuri-smoke/consume#alternate",
        "https://outside.invalid/api/v1/internal/onnuri-smoke/consume",
    ],
)
@pytest.mark.asyncio
async def test_strict_transport_rejects_unapproved_paths_without_requesting(
    monkeypatch: pytest.MonkeyPatch, operation_path: str
) -> None:
    transport, fake_client, _ = _transport(monkeypatch)

    with pytest.raises(F12TransportError, match="^f12_operation_path_invalid$"):
        await transport.post_typed(
            operation_path=operation_path,
            request=_Request(operation_id="operation-1"),
            response_model=_Response,
        )

    fake_client.post.assert_not_awaited()


def test_strict_transport_disables_redirects_proxies_retries_and_general_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, transport_marker = _transport(monkeypatch)

    clients_module.httpx.AsyncHTTPTransport.assert_called_once_with(
        verify="ca.crt",
        cert=("client.crt", "client.key"),
        retries=0,
        trust_env=False,
    )
    clients_module.httpx.AsyncClient.assert_called_once()
    kwargs = clients_module.httpx.AsyncClient.call_args.kwargs
    assert kwargs["transport"] is transport_marker
    assert kwargs["follow_redirects"] is False
    assert kwargs["trust_env"] is False
    timeout = kwargs["timeout"]
    assert isinstance(timeout, httpx.Timeout)
    assert timeout.connect == timeout.read == timeout.write == timeout.pool == 3.0


@pytest.mark.parametrize("timeout", [None, 0, -1, 10.01, float("inf")])
def test_strict_transport_rejects_missing_or_unbounded_timeout(
    timeout: object,
) -> None:
    with pytest.raises((TypeError, ValueError)):
        F12TransportConfiguration(
            base_url="https://f12.invalid",
            verified_identity="facade-workload",
            verified_issuer="private-ca",
            endpoint_credential=SecretStr("opaque-endpoint-credential"),
            client_certificate_path=clients_module.Path("client.crt"),
            client_key_path=clients_module.Path("client.key"),
            ca_certificate_path=clients_module.Path("ca.crt"),
            timeout_seconds=timeout,  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
async def test_strict_transport_rejects_redirect_without_following_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport, fake_client, _ = _transport(monkeypatch)
    fake_client.post.return_value = SimpleNamespace(status_code=307)

    with pytest.raises(F12TransportError, match="^f12_operation_rejected$"):
        await transport.post_typed(
            operation_path="/api/v1/internal/onnuri-smoke/consume",
            request=_Request(operation_id="operation-1"),
            response_model=_Response,
        )

    fake_client.post.assert_awaited_once()


@pytest.mark.asyncio
async def test_strict_transport_sends_only_the_fixed_trusted_proxy_auth_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport, fake_client, _ = _transport(monkeypatch)
    fake_client.post.return_value = SimpleNamespace(
        status_code=200, json=lambda: {"accepted": True}
    )

    result = await transport.post_typed(
        operation_path="/api/v1/internal/onnuri-smoke/consume",
        request=_Request(operation_id="operation-1"),
        response_model=_Response,
    )

    assert result == _Response(accepted=True)
    headers = fake_client.post.await_args.kwargs["headers"]
    assert set(headers) == {
        "x-recova-verified-mtls-identity",
        "x-recova-verified-mtls-issuer",
        "x-recova-onnuri-endpoint-credential",
    }
    assert {header.lower() for header in headers}.isdisjoint(
        {"authorization", "cookie", "x-api-key"}
    )


@pytest.mark.asyncio
async def test_strict_transport_rejects_invalid_response_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport, fake_client, _ = _transport(monkeypatch)
    fake_client.post.return_value = SimpleNamespace(
        status_code=200, json=lambda: ["not", "a", "typed", "response"]
    )

    with pytest.raises(F12TransportError, match="^f12_response_contract_mismatch$"):
        await transport.post_typed(
            operation_path="/api/v1/internal/onnuri-smoke/consume",
            request=_Request(operation_id="operation-1"),
            response_model=_Response,
        )


@pytest.mark.asyncio
async def test_strict_transport_redacts_secret_bearing_transport_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport, fake_client, _ = _transport(monkeypatch)
    secret = "upstream-message-must-not-escape"
    fake_client.post.side_effect = httpx.ConnectError(f"connection failed: {secret}")

    with pytest.raises(F12TransportError) as exc_info:
        await transport.post_typed(
            operation_path="/api/v1/internal/onnuri-smoke/consume",
            request=_Request(operation_id="operation-1"),
            response_model=_Response,
        )

    assert str(exc_info.value) == "f12_transport_unavailable"
    assert secret not in str(exc_info.value)
    rendered_traceback = "".join(
        traceback.format_exception(
            type(exc_info.value),
            exc_info.value,
            exc_info.value.__traceback__,
        )
    )
    assert secret not in rendered_traceback
    fake_client.post.assert_awaited_once()


@pytest.mark.asyncio
async def test_authority_http_client_maps_tenant_bound_dispatch_models_and_opaque_secret() -> None:
    now = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)
    context = BoundCallContext(
        organization_id=7,
        account_id="account-1",
        application_id="application-1",
        run_id="run-1",
        attempt_id="attempt-1",
        direction="outbound",
        authority_deadline=now + timedelta(seconds=60),
        candidate_digest="b" * 64,
        gate_envelope_digest="c" * 64,
    )
    submission = DispatchSubmission(
        context=context,
        idempotency_key="idem-00000000001",
        request_digest="a" * 64,
        capability=SignedCapability(
            key_id="dispatch-key",
            issued_at=now,
            expires_at=now + timedelta(seconds=60),
            nonce="dispatch-nonce",
            claims={"organization_id": 7},
            signature=SecretStr("opaque-signature"),
        ),
    )
    receipt = DispatchConsumeReceipt(
        context=context,
        idempotency_key=submission.idempotency_key,
        request_digest=submission.request_digest,
        receipt_id="dispatch-receipt",
        consumed_at=now,
        dispatch_key_id="dispatch-key",
        signature=SecretStr("receipt-signature"),
    )
    transport = SimpleNamespace(
        post_typed=AsyncMock(return_value=receipt),
        aclose=AsyncMock(),
    )
    client = F12AuthorityHttpClient(transport)

    assert await client.consume_dispatch(submission) == receipt

    call = transport.post_typed.await_args.kwargs
    assert call["operation_path"] == "/api/v1/internal/onnuri-smoke/consume-dispatch"
    assert call["response_model"] is DispatchConsumeReceipt
    payload = call["request"]
    assert payload.organization_id == context.organization_id
    assert payload.attempt_uuid == context.attempt_id
    assert isinstance(payload.opaque_capability, SecretStr)
    assert json.loads(payload.opaque_capability.get_secret_value())["signature"] == (
        "opaque-signature"
    )


@pytest.mark.asyncio
async def test_authority_http_client_maps_tenant_bound_answer_requests() -> None:
    now = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)
    deadline = now + timedelta(seconds=60)
    outbound_context = BoundCallContext(
        organization_id=7,
        account_id="account-1",
        application_id="application-1",
        run_id="run-1",
        attempt_id="attempt-1",
        direction=Direction.OUTBOUND,
        stock_call_id="stock-call",
        authority_deadline=deadline,
        candidate_digest="b" * 64,
        gate_envelope_digest="c" * 64,
    )
    inbound_context = outbound_context.model_copy(
        update={"direction": Direction.INBOUND, "candidate_digest": "d" * 64}
    )
    outbound = OutboundAnswerHookRequest(
        organization_id=7,
        context=outbound_context,
        stock_call_id="stock-call",
        idempotency_key="idem-00000000001",
        request_digest="a" * 64,
        event_nonce="outbound-event",
        observed_wall_time=now,
        proposed_deadline=deadline,
        candidate_digest="b" * 64,
    )
    inbound = InboundInitialHookRequest(
        organization_id=7,
        context=inbound_context,
        stock_call_id="stock-call",
        idempotency_key="idem-00000000002",
        request_digest="c" * 64,
        event_nonce="inbound-event",
        observed_wall_time=now,
        proposed_deadline=deadline,
        candidate_digest="d" * 64,
        source_account_id="account-1",
        source_application_id="application-1",
        did_digest="e" * 64,
        caller_mobile_digest="f" * 64,
        optional_pause_milliseconds=0,
    )
    outbound_receipt = MediaAuthorityReceipt(
        context=outbound_context,
        stock_call_id="stock-call",
        idempotency_key=outbound.idempotency_key,
        request_digest=outbound.request_digest,
        authority_receipt_id="outbound-receipt",
        committed_at=now,
        authority_deadline=deadline,
        media_key_id="media-key",
        opaque_media_capability=SecretStr("outbound-media-capability"),
    )
    inbound_receipt = outbound_receipt.model_copy(
        update={
            "context": inbound_context,
            "idempotency_key": inbound.idempotency_key,
            "request_digest": inbound.request_digest,
            "authority_receipt_id": "inbound-receipt",
        }
    )
    transport = SimpleNamespace(
        post_typed=AsyncMock(side_effect=[outbound_receipt, inbound_receipt]),
        aclose=AsyncMock(),
    )
    client = F12AuthorityHttpClient(transport)

    assert await client.record_answer_and_mint_media(outbound) == outbound_receipt
    assert (
        await client.commit_inbound_answer_intent_and_mint_media(inbound)
        == inbound_receipt
    )

    outbound_payload = transport.post_typed.await_args_list[0].kwargs["request"]
    inbound_payload = transport.post_typed.await_args_list[1].kwargs["request"]
    assert isinstance(outbound_payload, RecordAnswerAndMintMediaRequest)
    assert outbound_payload.organization_id == outbound.context.organization_id
    assert outbound_payload.proposed_deadline == outbound.proposed_deadline
    assert isinstance(
        inbound_payload, CommitInboundAnswerIntentAndMintMediaRequest
    )
    assert inbound_payload.organization_id == inbound.context.organization_id
    assert inbound_payload.source_account_id == inbound.source_account_id
    assert (
        inbound_payload.approved_pause_milliseconds
        == inbound.optional_pause_milliseconds
    )


@pytest.mark.asyncio
async def test_authority_http_client_supports_ready_status_event_and_containment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)
    context = BoundCallContext(
        organization_id=7,
        account_id="account-a",
        application_id="application-a",
        run_id="run-a",
        attempt_id="attempt-a",
        direction=Direction.OUTBOUND,
        stock_call_id="stock-call-a",
        authority_deadline=now + timedelta(seconds=60),
        candidate_digest="b" * 64,
        gate_envelope_digest="c" * 64,
    )
    transport, _, _ = _transport(monkeypatch)
    transport.post_typed = AsyncMock(
        side_effect=[
            FacadeAuthorityReadiness(ready=True),
            FacadeAuthorityReadiness(ready=False),
            FacadeBoundCallStatusResponse(
                context=context.model_copy(update={"stock_call_id": None}),
                status=CallStatus.RUNNING,
                idempotency_key="idem-00000000001",
                request_digest="a" * 64,
                candidate_digest="b" * 64,
                allocated_at=now,
            ),
            CallbackReceipt(
                organization_id=7,
                event_nonce=clients_module.sha256_hex("event-a"),
                idempotency_key="idem-00000000001",
                request_digest="a" * 64,
                accepted_at=now,
                status=CallStatus.RUNNING,
            ),
            SmokeReceipt(attempt_uuid="attempt-a", state="contained"),
        ]
    )
    client = F12AuthorityHttpClient(transport)

    assert await client.ready() is True
    assert await client.ready() is False
    status = await client.get_call_status(
        organization_id=7, account_id="account-a", stock_call_id="stock-call-a"
    )
    event = NormalizedCallEvent(
        organization_id=7,
        context=context,
        stock_call_id="stock-call-a",
        event_type="status",
        normalized_status=CallStatus.RUNNING,
        occurred_at=now,
        event_nonce="event-a",
        idempotency_key="idem-00000000001",
        request_digest="a" * 64,
    )
    receipt = await client.submit_call_event(event)
    containment = ContainmentRequest(
        organization_id=7,
        context=context,
        stock_call_id="stock-call-a",
        category=FailureCategory.CONTAINMENT_REQUIRED,
    )
    assert await client.request_containment(containment) is None
    assert status.context.stock_call_id == "stock-call-a"
    assert status.status is CallStatus.RUNNING
    assert status.updated_at == now
    assert receipt.event_nonce == "event-a"
    assert transport.post_typed.await_args_list[2].kwargs["request"].stock_call_id_digest == (
        clients_module.sha256_hex("stock-call-a")
    )
    assert transport.post_typed.await_args_list[3].kwargs["request"].event_nonce_digest == (
        clients_module.sha256_hex("event-a")
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["ready", "status", "event", "containment"])
async def test_authority_http_client_fails_closed_without_retry_for_malformed_or_transport_response(
    monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    now = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)
    context = BoundCallContext(
        organization_id=7,
        account_id="account-a",
        application_id="application-a",
        run_id="run-a",
        attempt_id="attempt-a",
        direction=Direction.OUTBOUND,
        stock_call_id="stock-call-a",
        authority_deadline=now + timedelta(seconds=60),
        candidate_digest="b" * 64,
        gate_envelope_digest="c" * 64,
    )
    transport, _, _ = _transport(monkeypatch)
    transport.post_typed = AsyncMock(
        side_effect=F12TransportError("f12_response_contract_mismatch")
    )
    client = F12AuthorityHttpClient(transport)
    with pytest.raises(AuthorityClientError) as exc_info:
        if operation == "ready":
            await client.ready()
        elif operation == "status":
            await client.get_call_status(
                organization_id=7, account_id="account-a", stock_call_id="stock-call-a"
            )
        elif operation == "event":
            await client.submit_call_event(
                NormalizedCallEvent(
                    organization_id=7,
                    context=context,
                    stock_call_id="stock-call-a",
                    event_type="status",
                    normalized_status=CallStatus.RUNNING,
                    occurred_at=now,
                    event_nonce="event-a",
                    idempotency_key="idem-00000000001",
                    request_digest="a" * 64,
                )
            )
        else:
            await client.request_containment(
                ContainmentRequest(
                    organization_id=7,
                    context=context,
                    stock_call_id="stock-call-a",
                    category=FailureCategory.CONTAINMENT_REQUIRED,
                )
            )
    assert exc_info.value.category is FailureCategory.AUTHORITY_UNAVAILABLE
    assert exc_info.value.__cause__ is None
    transport.post_typed.assert_awaited_once()
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("operation_path", "response_model"),
    [
        ("/api/v1/internal/onnuri-smoke/ready", FacadeAuthorityReadiness),
        (
            "/api/v1/internal/onnuri-smoke/bound-call-status",
            FacadeBoundCallStatusResponse,
        ),
        ("/api/v1/internal/onnuri-smoke/normalized-event", CallbackReceipt),
        ("/api/v1/internal/onnuri-smoke/containment", SmokeReceipt),
    ],
)
async def test_strict_transport_rejects_each_new_authority_response_contract_without_retry(
    monkeypatch: pytest.MonkeyPatch,
    operation_path: str,
    response_model: type[BaseModel],
) -> None:
    transport, fake_client, _ = _transport(monkeypatch)
    fake_client.post.return_value = SimpleNamespace(
        status_code=200, json=lambda: {"malformed": True}
    )

    with pytest.raises(F12TransportError, match="^f12_response_contract_mismatch$"):
        await transport.post_typed(
            operation_path=operation_path,
            request=_Request(operation_id="operation-1"),
            response_model=response_model,
        )

    fake_client.post.assert_awaited_once()


@pytest.mark.asyncio
async def test_authority_http_client_redacts_transport_error_chaining() -> None:
    secret = "capability-value-must-not-escape"
    transport = SimpleNamespace(
        post_typed=AsyncMock(side_effect=F12TransportError(secret)),
        aclose=AsyncMock(),
    )
    client = F12AuthorityHttpClient(transport)
    now = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)
    context = BoundCallContext(
        organization_id=7,
        account_id="account-1",
        application_id="application-1",
        run_id="run-1",
        attempt_id="attempt-1",
        direction="outbound",
        authority_deadline=now + timedelta(seconds=60),
        candidate_digest="b" * 64,
        gate_envelope_digest="c" * 64,
    )
    submission = DispatchSubmission(
        context=context,
        idempotency_key="idem-00000000001",
        request_digest="a" * 64,
        capability=SignedCapability(
            key_id="dispatch-key",
            issued_at=now,
            expires_at=now + timedelta(seconds=60),
            nonce="dispatch-nonce",
            claims={"organization_id": 7},
            signature=SecretStr(secret),
        ),
    )

    with pytest.raises(AuthorityClientError) as exc_info:
        await client.consume_dispatch(submission)

    assert str(exc_info.value) == FailureCategory.AUTHORITY_UNAVAILABLE.value
    assert exc_info.value.__cause__ is None
    rendered = "".join(
        traceback.format_exception(
            type(exc_info.value),
            exc_info.value,
            exc_info.value.__traceback__,
        )
    )
    assert secret not in rendered


def _stock_create_request(**updates: object) -> StockCallCreateRequest:
    values: dict[str, object] = {
        "context": BoundCallContext(
            organization_id=7,
            account_id="account-1",
            application_id="application-1",
            run_id="run-1",
            attempt_id="attempt-1",
            direction=Direction.OUTBOUND,
            authority_deadline=datetime.now(UTC) + timedelta(seconds=60),
            candidate_digest="b" * 64,
            gate_envelope_digest="c" * 64,
        ),
        "idempotency_key": "idem-0000000000000001",
        "dispatch_receipt_id": "dispatch-receipt",
        "from_address": SecretStr("07000000000"),
        "to_address": SecretStr("01000000000"),
        "answer_hook_url": "https://facade.internal/hooks/answer",
        "status_hook_url": "https://facade.internal/hooks/status",
        "ring_timeout_seconds": 20,
        "time_limit_seconds": 60,
    }
    values.update(updates)
    return StockCallCreateRequest(**values)


@pytest.mark.asyncio
async def test_private_stock_client_emits_exact_upstream_payload_and_idempotent_result() -> None:
    captured: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/Accounts/account-1/Calls"
        assert request.headers["authorization"] == "Bearer opaque-api-token"
        payload = json.loads(request.content)
        captured.append(payload)
        return httpx.Response(
            201,
            json={"sid": "stock-call-1"},
        )

    client = PrivateStockJambonzClient(
        StockJambonzConfiguration(
            base_url="http://jambonz-api",
            account_id="account-1",
            api_token=SecretStr("opaque-api-token"),
        ),
        transport=httpx.MockTransport(handler),
    )
    request = _stock_create_request()
    first = await client.create_call(request)
    second = await client.create_call(request)

    assert first == second
    assert len(captured) == 1
    assert captured[0] == {
        "from": "07000000000",
        "to": {"type": "phone", "number": "01000000000"},
        "application_sid": "application-1",
        "call_hook": {
            "url": "https://facade.internal/hooks/answer",
            "method": "POST",
        },
        "call_status_hook": {
            "url": "https://facade.internal/hooks/status",
            "method": "POST",
        },
        "timeout": 20,
        "timeLimit": 60,
    }
    assert "07000000000" not in repr(client._idempotency)
    assert "01000000000" not in repr(client._idempotency)
    await client.aclose()


@pytest.mark.asyncio
async def test_private_stock_client_rejects_idempotency_mismatch_without_second_call() -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            201,
            json={"sid": "stock-call-1", "callId": "sip-call-1"},
        )

    client = PrivateStockJambonzClient(
        StockJambonzConfiguration(
            base_url="http://127.0.0.1:3000",
            account_id="account-1",
            api_token=SecretStr("opaque-api-token"),
        ),
        transport=httpx.MockTransport(handler),
    )
    await client.create_call(_stock_create_request())
    with pytest.raises(StockClientError) as exc_info:
        await client.create_call(
            _stock_create_request(to_address=SecretStr("01000000001"))
        )
    assert exc_info.value.category == FailureCategory.IDEMPOTENCY_MISMATCH
    assert calls == 1
    await client.aclose()


@pytest.mark.asyncio
async def test_private_stock_client_hangup_readiness_and_rejections() -> None:
    seen: list[tuple[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health":
            return httpx.Response(200)
        seen.append((request.url.path, json.loads(request.content)))
        return httpx.Response(202)

    client = PrivateStockJambonzClient(
        StockJambonzConfiguration(
            base_url="http://jambonz-api.default.svc",
            account_id="account-1",
            api_token=SecretStr("opaque-api-token"),
        ),
        transport=httpx.MockTransport(handler),
    )
    assert await client.ready() is True
    await client.request_bounded_hangup(
        stock_call_id="stock-call-1", timeout_seconds=2
    )
    assert seen == [
        (
            "/v1/Accounts/account-1/Calls/stock-call-1",
            {"call_status": "completed"},
        )
    ]
    client._client.post = AsyncMock(side_effect=TimeoutError)
    with pytest.raises(StockClientError) as exc_info:
        await client.request_bounded_hangup(
            stock_call_id="stock-call-2", timeout_seconds=1
        )
    assert exc_info.value.category == FailureCategory.STOCK_UNAVAILABLE
    await client.aclose()


@pytest.mark.parametrize(
    "url",
    [
        "https://public.example.com",
        "http://0.0.0.0",
        "file:///tmp/socket",
        "http://user:password@localhost",
        "http://localhost/?token=secret",
    ],
)
def test_stock_configuration_rejects_nonprivate_or_credentialed_urls(url: str) -> None:
    with pytest.raises(ValueError):
        StockJambonzConfiguration(
            base_url=url,
            account_id="account-1",
            api_token=SecretStr("opaque-api-token"),
        )


@pytest.mark.asyncio
async def test_stock_client_rejects_public_hook_before_network() -> None:
    client = PrivateStockJambonzClient(
        StockJambonzConfiguration(
            base_url="http://jambonz-api",
            account_id="account-1",
            api_token=SecretStr("opaque-api-token"),
        ),
        transport=httpx.MockTransport(
            lambda _request: pytest.fail("network must not be reached")
        ),
    )
    with pytest.raises(StockClientError) as exc_info:
        await client.create_call(
            _stock_create_request(
                answer_hook_url="https://public.example.com/hook"
            )
        )
    assert exc_info.value.category == FailureCategory.CONTRACT_MISMATCH
    await client.aclose()


def test_pem_es256_verifier_accepts_exact_raw_signature_and_rejects_confusion(
    tmp_path: Path,
) -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_path = tmp_path / "dispatch.pem"
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    verifier = PrivatePemEs256Verifier({"dispatch-key": public_path})
    message = b"domain-bound-canonical-message"
    der = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    signature = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    assert verifier.verify(
        key_id="dispatch-key",
        algorithm="ES256",
        verification_domain="recova.onnuri.smoke.dispatch.v1",
        message=message,
        signature=signature,
    )
    assert not verifier.verify(
        key_id="other-key",
        algorithm="ES256",
        verification_domain="recova.onnuri.smoke.dispatch.v1",
        message=message,
        signature=signature,
    )
    assert not verifier.verify(
        key_id="dispatch-key",
        algorithm="ES256",
        verification_domain="recova.onnuri.smoke.media.v1",
        message=message + b"-changed",
        signature=signature,
    )
    assert not verifier.verify(
        key_id="dispatch-key",
        algorithm="ES256",
        verification_domain="recova.onnuri.smoke.dispatch.v1",
        message=message,
        signature=signature + "=",
    )

@pytest.mark.asyncio
async def test_authority_http_client_posts_only_opaque_route_evidence_handle():
    now = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)
    context = BoundCallContext(
        organization_id=7,
        account_id="account-1",
        application_id="application-1",
        run_id="run-1",
        attempt_id="attempt-1",
        direction="outbound",
        authority_deadline=now + timedelta(seconds=60),
        candidate_digest="b" * 64,
        gate_envelope_digest="c" * 64,
    )
    request = RouteChainCapabilityRequest(
        context=context,
        idempotency_key="idem-00000000001",
        request_digest="a" * 64,
        route_profile_digest="d" * 64,
        route_evidence_handle="opaque-route-evidence-handle",
    )
    capability = RouteChainCapability(
        key_id="dispatch-key",
        issued_at=now,
        expires_at=now + timedelta(seconds=30),
        nonce="route-nonce",
        claims={},
        signature=SecretStr("opaque-route-capability"),
    )
    transport = SimpleNamespace(post_typed=AsyncMock(return_value=capability))

    assert await F12AuthorityHttpClient(transport).mint_route_chain_capability(request) == capability

    transport.post_typed.assert_awaited_once_with(
        operation_path="/api/v1/internal/onnuri-smoke/route-chain/capability",
        request=request,
        response_model=RouteChainCapability,
    )
    assert "packet" not in transport.post_typed.await_args.kwargs["request"].model_dump_json()
