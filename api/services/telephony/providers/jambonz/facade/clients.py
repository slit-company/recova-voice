"""Strict transport primitives for the internal Onnuri F12 boundary."""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import ipaddress
import re
from urllib.parse import quote, urlsplit

from dataclasses import dataclass
import json
from pathlib import Path
from typing import TYPE_CHECKING, TypeVar


import httpx
from pydantic import BaseModel, ConfigDict, SecretStr, ValidationError
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

if TYPE_CHECKING:
    from api.schemas.onnuri_smoke import (
        ClaimReservedInboundAndBindRequest,
        ClaimReservedInboundAndBindResponse,
    )


from .models import (
    CallStatusResponse,
    CallbackReceipt,
    ContainmentRequest,
    DispatchConsumeReceipt,
    DispatchSubmission,
    FailureCategory,
    InboundInitialHookRequest,
    MediaAuthorityReceipt,
    NormalizedCallEvent,
    OutboundAnswerHookRequest,
    RouteChainCapability,
    RouteChainCapabilityRequest,
    StockCallBindReceipt,
    StockCallBindRequest,
    StockCallCreateRequest,
    StockCallCreateResult,
)
from .service import (
    AuthorityClientError,
    StockClientError,
    canonical_model_digest,
)
_IDENTITY_HEADER = "x-recova-verified-mtls-identity"
_ISSUER_HEADER = "x-recova-verified-mtls-issuer"
_CREDENTIAL_HEADER = "x-recova-onnuri-endpoint-credential"
_FORBIDDEN_HEADERS = frozenset({"authorization", "cookie", "x-api-key"})
_ResponseModel = TypeVar("_ResponseModel", bound=BaseModel)

def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class F12TransportError(RuntimeError):
    """A non-sensitive F12 transport or response-contract failure."""


def _reveal_secrets(value: object) -> object:
    """Build an ephemeral wire value without changing secret-bearing model types."""

    if isinstance(value, SecretStr):
        return value.get_secret_value()
    if isinstance(value, dict):
        return {key: _reveal_secrets(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_reveal_secrets(item) for item in value]
    return value


def _opaque_dispatch_capability(submission: DispatchSubmission) -> SecretStr:
    payload = submission.capability.model_dump(
        mode="json", exclude={"signature"}, exclude_none=True
    )
    payload["signature"] = submission.capability.signature.get_secret_value()
    return SecretStr(
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    )


@dataclass(frozen=True)
class F12TransportConfiguration:
    """Opaque credentials and bounded transport settings for trusted-proxy F12."""

    base_url: str
    verified_identity: str
    verified_issuer: str
    endpoint_credential: SecretStr
    client_certificate_path: Path
    client_key_path: Path
    ca_certificate_path: Path
    timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        if not self.base_url.startswith("https://"):
            raise ValueError("f12_base_url_must_use_https")
        if not self.verified_identity or not self.verified_issuer:
            raise ValueError("f12_verified_identity_configuration_missing")
        if not self.endpoint_credential.get_secret_value():
            raise ValueError("f12_endpoint_credential_configuration_missing")
        if not 0 < self.timeout_seconds <= 10:
            raise ValueError("f12_timeout_out_of_bounds")


class StrictF12Transport:
    """No-retry mTLS transport with no ambient or general-purpose auth headers.

    Paths and authority model mappings are deliberately owned by the narrow
    adapter below.
    """

    def __init__(self, configuration: F12TransportConfiguration):
        self._base_url = configuration.base_url.rstrip("/")
        self._headers = {
            _IDENTITY_HEADER: configuration.verified_identity,
            _ISSUER_HEADER: configuration.verified_issuer,
            _CREDENTIAL_HEADER: (
                configuration.endpoint_credential.get_secret_value()
            ),
        }
        if _FORBIDDEN_HEADERS.intersection(self._headers):
            raise ValueError("f12_forbidden_auth_header")
        transport = httpx.AsyncHTTPTransport(
            verify=str(configuration.ca_certificate_path),
            cert=(
                str(configuration.client_certificate_path),
                str(configuration.client_key_path),
            ),
            retries=0,
            trust_env=False,
        )
        self._client = httpx.AsyncClient(
            transport=transport,
            timeout=httpx.Timeout(configuration.timeout_seconds),
            follow_redirects=False,
            trust_env=False,
        )

    async def post_typed(
        self,
        *,
        operation_path: str,
        request: BaseModel,
        response_model: type[_ResponseModel],
    ) -> _ResponseModel:
        """Send one adapter-selected operation and validate its strict model."""

        if (
            not operation_path.startswith("/api/v1/internal/onnuri-smoke/")
            or "//" in operation_path
            or "?" in operation_path
            or "#" in operation_path
            or ".." in operation_path
        ):
            raise F12TransportError("f12_operation_path_invalid")
        try:
            response = await self._client.post(
                f"{self._base_url}{operation_path}",
                headers=self._headers,
                json=_reveal_secrets(request.model_dump(mode="python")),
            )
        except httpx.HTTPError:
            raise F12TransportError("f12_transport_unavailable") from None
        if response.status_code != 200:
            raise F12TransportError("f12_operation_rejected")
        try:
            return response_model.model_validate(response.json())
        except (ValueError, ValidationError):
            raise F12TransportError("f12_response_contract_mismatch") from None

    async def aclose(self) -> None:
        await self._client.aclose()


class F12AuthorityHttpClient:
    """Strict facade-authority adapter over the no-retry internal transport."""

    def __init__(self, transport: StrictF12Transport):
        self._transport = transport

    async def _post(
        self,
        *,
        operation_path: str,
        request: BaseModel,
        response_model: type[_ResponseModel],
    ) -> _ResponseModel:
        try:
            return await self._transport.post_typed(
                operation_path=operation_path,
                request=request,
                response_model=response_model,
            )
        except F12TransportError:
            raise AuthorityClientError(FailureCategory.AUTHORITY_UNAVAILABLE) from None

    async def consume_dispatch(
        self, submission: DispatchSubmission
    ) -> DispatchConsumeReceipt:
        from api.schemas.onnuri_smoke import ConsumeDispatchRequest

        context = submission.context
        request = ConsumeDispatchRequest(
            organization_id=context.organization_id,
            account_id=context.account_id,
            application_id=context.application_id,
            run_id=context.run_id,
            attempt_uuid=context.attempt_id,
            idempotency_key=submission.idempotency_key,
            request_digest=submission.request_digest,
            opaque_capability=_opaque_dispatch_capability(submission),
        )
        return await self._post(
            operation_path="/api/v1/internal/onnuri-smoke/consume-dispatch",
            request=request,
            response_model=DispatchConsumeReceipt,
        )

    async def mint_route_chain_capability(
        self, request: RouteChainCapabilityRequest
    ) -> RouteChainCapability:
        return await self._post(
            operation_path="/api/v1/internal/onnuri-smoke/route-chain/capability",
            request=request,
            response_model=RouteChainCapability,
        )

    async def bind_stock_call(
        self, request: StockCallBindRequest
    ) -> StockCallBindReceipt:
        return await self._post(
            operation_path="/api/v1/internal/onnuri-smoke/bind-stock-call",
            request=request,
            response_model=StockCallBindReceipt,
        )

    async def claim_reserved_inbound_and_bind(
        self, request: ClaimReservedInboundAndBindRequest
    ) -> ClaimReservedInboundAndBindResponse:
        from api.schemas.onnuri_smoke import ClaimReservedInboundAndBindResponse

        return await self._post(
            operation_path=(
                "/api/v1/internal/onnuri-smoke/"
                "claim-reserved-inbound-and-bind"
            ),
            request=request,
            response_model=ClaimReservedInboundAndBindResponse,
        )

    async def record_answer_and_mint_media(
        self, request: OutboundAnswerHookRequest
    ) -> MediaAuthorityReceipt:
        from api.schemas.onnuri_smoke import RecordAnswerAndMintMediaRequest

        context = request.context
        payload = RecordAnswerAndMintMediaRequest(
            organization_id=request.organization_id,
            account_id=context.account_id,
            application_id=context.application_id,
            run_id=context.run_id,
            attempt_uuid=context.attempt_id,
            stock_call_id=request.stock_call_id,
            idempotency_key=request.idempotency_key,
            request_digest=request.request_digest,
            event_nonce=request.event_nonce,
            candidate_digest=request.candidate_digest,
            gate_envelope_digest=context.gate_envelope_digest,
            observed_wall_time=request.observed_wall_time,
            proposed_deadline=request.proposed_deadline,
            observed_answer=request.observed_answer,
        )
        return await self._post(
            operation_path="/api/v1/internal/onnuri-smoke/record-answer-and-mint-media",
            request=payload,
            response_model=MediaAuthorityReceipt,
        )

    async def commit_inbound_answer_intent_and_mint_media(
        self, request: InboundInitialHookRequest
    ) -> MediaAuthorityReceipt:
        from api.schemas.onnuri_smoke import (
            CommitInboundAnswerIntentAndMintMediaRequest,
        )
        context = request.context
        payload = CommitInboundAnswerIntentAndMintMediaRequest(
            organization_id=request.organization_id,
            account_id=context.account_id,
            application_id=context.application_id,
            run_id=context.run_id,
            attempt_uuid=context.attempt_id,
            stock_call_id=request.stock_call_id,
            idempotency_key=request.idempotency_key,
            request_digest=request.request_digest,
            event_nonce=request.event_nonce,
            candidate_digest=request.candidate_digest,
            gate_envelope_digest=context.gate_envelope_digest,
            observed_wall_time=request.observed_wall_time,
            proposed_deadline=request.proposed_deadline,
            source_account_id=request.source_account_id,
            source_application_id=request.source_application_id,
            did_digest=request.did_digest,
            caller_mobile_digest=request.caller_mobile_digest,
            approved_pause_milliseconds=request.optional_pause_milliseconds,
        )
        return await self._post(
            operation_path=(
                "/api/v1/internal/onnuri-smoke/"
                "commit-inbound-answer-intent-and-mint-media"
            ),
            request=payload,
            response_model=MediaAuthorityReceipt,
        )

    async def get_call_status(
        self,
        *,
        organization_id: int,
        account_id: str,
        stock_call_id: str,
    ) -> CallStatusResponse:
        from api.schemas.onnuri_smoke import (
            FacadeBoundCallStatusRequest,
            FacadeBoundCallStatusResponse,
        )

        response = await self._post(
            operation_path="/api/v1/internal/onnuri-smoke/bound-call-status",
            request=FacadeBoundCallStatusRequest(
                organization_id=organization_id,
                account_id=account_id,
                stock_call_id_digest=sha256_hex(stock_call_id),
            ),
            response_model=FacadeBoundCallStatusResponse,
        )
        return CallStatusResponse(
            context=response.context.model_copy(
                update={"stock_call_id": stock_call_id}
            ),
            status=response.status,
            updated_at=(
                response.contained_at
                or response.terminal_at
                or response.authority_deadline
                or response.stock_bound_at
                or response.allocated_at
            ),
            terminal=response.status.value
            in {"completed", "busy", "no_answer", "failed", "canceled", "contained"},
            failure_category=(
                FailureCategory.CONTAINMENT_REQUIRED
                if response.status.value == "contained"
                else None
            ),
            idempotency_key=getattr(response, "idempotency_key", None),
            request_digest=getattr(response, "request_digest", None),
            candidate_digest=getattr(response, "candidate_digest", None),
        )

    async def submit_call_event(
        self, event: NormalizedCallEvent
    ) -> CallbackReceipt:
        from api.schemas.onnuri_smoke import AcceptFacadeCallbackRequest

        response = await self._post(
            operation_path="/api/v1/internal/onnuri-smoke/normalized-event",
            request=AcceptFacadeCallbackRequest(
                context=event.context,
                event_nonce_digest=sha256_hex(event.event_nonce),
                idempotency_key=event.idempotency_key,
                request_digest=event.request_digest,
                event_type=event.event_type,
                normalized_status=event.normalized_status,
                occurred_at=event.occurred_at,
                duration_seconds=event.duration_seconds,
                redacted_cause_category=event.redacted_cause_category,
            ),
            response_model=CallbackReceipt,
        )
        if (
            response.organization_id != event.organization_id
            or response.event_nonce != sha256_hex(event.event_nonce)
            or response.idempotency_key != event.idempotency_key
            or response.request_digest != event.request_digest
            or response.status != event.normalized_status
        ):
            raise AuthorityClientError(FailureCategory.CONTRACT_MISMATCH)
        return response.model_copy(update={"event_nonce": event.event_nonce})

    async def request_containment(self, request: ContainmentRequest) -> None:
        from api.schemas.onnuri_smoke import RequestFacadeContainment, SmokeReceipt

        response = await self._post(
            operation_path="/api/v1/internal/onnuri-smoke/containment",
            request=RequestFacadeContainment(
                context=request.context,
                category=request.category,
            ),
            response_model=SmokeReceipt,
        )
        if response.attempt_uuid != request.context.attempt_id or response.state != "contained":
            raise AuthorityClientError(FailureCategory.CONTRACT_MISMATCH)

    async def ready(self) -> bool:
        from api.schemas.onnuri_smoke import FacadeAuthorityReadiness

        response = await self._post(
            operation_path="/api/v1/internal/onnuri-smoke/ready",
            request=FacadeAuthorityReadiness(ready=False),
            response_model=FacadeAuthorityReadiness,
        )
        return response.ready
    async def aclose(self) -> None:
        await self._transport.aclose()



_PRIVATE_SERVICE_NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def _private_service_url(
    value: str, *, label: str, allow_path: bool = False
) -> str:
    parsed = urlsplit(value)
    invalid_path = (
        parsed.path not in {"", "/"}
        if not allow_path
        else (
            not parsed.path.startswith("/")
            or "//" in parsed.path
            or any(part in {".", ".."} for part in parsed.path.split("/"))
        )
    )
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or invalid_path
    ):
        raise ValueError(f"{label}_must_be_private_service_url")
    hostname = parsed.hostname.lower().rstrip(".")
    allowed = hostname == "localhost" or bool(_PRIVATE_SERVICE_NAME.fullmatch(hostname))
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        allowed = allowed or hostname.endswith(
            (".internal", ".local", ".svc", ".svc.cluster.local")
        )
    else:
        allowed = (
            not address.is_unspecified
            and not address.is_multicast
            and (address.is_private or address.is_loopback)
        )
    if not allowed:
        raise ValueError(f"{label}_must_be_private_service_origin")
    return value.rstrip("/")


@dataclass(frozen=True)
class StockJambonzConfiguration:
    """Opaque account API credentials for one private OSS Jambonz deployment."""

    base_url: str
    account_id: str
    api_token: SecretStr
    timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "base_url",
            _private_service_url(self.base_url, label="stock_base_url"),
        )
        if not self.account_id or "/" in self.account_id:
            raise ValueError("stock_account_id_invalid")
        if not self.api_token.get_secret_value():
            raise ValueError("stock_api_token_missing")
        if not 0 < self.timeout_seconds <= 10:
            raise ValueError("stock_timeout_out_of_bounds")


class _StockCreateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    sid: str
    callId: str | None = None


class PrivatePemEs256Verifier:
    """Verify raw JWS ES256 signatures against pre-provisioned public keys."""

    def __init__(self, public_key_paths: dict[str, Path]):
        if not public_key_paths:
            raise ValueError("verification_public_keys_missing")
        loaded: dict[str, ec.EllipticCurvePublicKey] = {}
        loaded_fingerprints: dict[str, str] = {}
        for key_id, path in public_key_paths.items():
            if not key_id or not path.is_file() or path.is_symlink():
                raise ValueError("verification_public_key_invalid")
            try:
                key = serialization.load_pem_public_key(path.read_bytes())
            except (OSError, ValueError, TypeError):
                raise ValueError("verification_public_key_invalid") from None
            if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
                key.curve, ec.SECP256R1
            ):
                raise ValueError("verification_public_key_invalid")
            loaded[key_id] = key
            loaded_fingerprints[key_id] = hashlib.sha256(
                key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            ).hexdigest()
        self._keys = loaded
        self._key_fingerprints = loaded_fingerprints

    def key_fingerprint(self, key_id: str) -> str | None:
        """Return the configured public-key SPKI SHA256 without exposing key material."""

        return self._key_fingerprints.get(key_id)

    def verify(
        self,
        *,
        key_id: str,
        algorithm: str,
        verification_domain: str,
        message: bytes,
        signature: str,
    ) -> bool:
        del verification_domain
        key = self._keys.get(key_id)
        if key is None or algorithm != "ES256":
            return False
        try:
            encoded = signature.encode("ascii")
            if b"=" in encoded:
                return False
            raw = base64.urlsafe_b64decode(encoded + b"=" * (-len(encoded) % 4))
            if len(raw) != 64:
                return False
            r = int.from_bytes(raw[:32], "big")
            s = int.from_bytes(raw[32:], "big")
            key.verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
            return True
        except (UnicodeEncodeError, binascii.Error, InvalidSignature, ValueError):
            return False


class PrivateStockJambonzClient:
    """No-retry adapter for the public jambonz-api-server call API."""

    def __init__(
        self,
        configuration: StockJambonzConfiguration,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self._configuration = configuration
        self._headers = {
            "Authorization": f"Bearer {configuration.api_token.get_secret_value()}",
            "Content-Type": "application/json",
        }
        self._client = httpx.AsyncClient(
            base_url=configuration.base_url,
            headers=self._headers,
            transport=transport
            or httpx.AsyncHTTPTransport(retries=0, trust_env=False),
            timeout=httpx.Timeout(configuration.timeout_seconds),
            follow_redirects=False,
            trust_env=False,
        )
        self._create_lock = asyncio.Lock()
        self._idempotency: dict[
            str, tuple[str, StockCallCreateResult]
        ] = {}

    async def create_call(
        self, request: StockCallCreateRequest
    ) -> StockCallCreateResult:
        if request.context.account_id != self._configuration.account_id:
            raise StockClientError(FailureCategory.CONTRACT_MISMATCH)
        request_digest = canonical_model_digest(request)
        async with self._create_lock:
            existing = self._idempotency.get(request.idempotency_key)
            if existing is not None:
                existing_digest, existing_result = existing
                if existing_digest != request_digest:
                    raise StockClientError(FailureCategory.IDEMPOTENCY_MISMATCH)
                return existing_result
            result = await self._create_call_once(request, request_digest)
            self._idempotency[request.idempotency_key] = (request_digest, result)
            return result

    async def _create_call_once(
        self,
        request: StockCallCreateRequest,
        request_digest: str,
    ) -> StockCallCreateResult:
        try:
            answer_hook = _private_service_url(
                request.answer_hook_url,
                label="stock_answer_hook",
                allow_path=True,
            )
            status_hook = _private_service_url(
                request.status_hook_url,
                label="stock_status_hook",
                allow_path=True,
            )
        except ValueError:
            raise StockClientError(FailureCategory.CONTRACT_MISMATCH) from None
        payload = {
            "from": request.from_address.get_secret_value(),
            "to": {
                "type": "phone",
                "number": request.to_address.get_secret_value(),
            },
            "application_sid": request.context.application_id,
            "call_hook": {"url": answer_hook, "method": "POST"},
            "call_status_hook": {"url": status_hook, "method": "POST"},
            "timeout": request.ring_timeout_seconds,
            "timeLimit": request.time_limit_seconds,
        }
        path = (
            f"/v1/Accounts/{quote(self._configuration.account_id, safe='')}/Calls"
        )
        try:
            response = await self._client.post(path, json=payload)
        except httpx.HTTPError:
            raise StockClientError(FailureCategory.STOCK_UNAVAILABLE) from None
        if response.status_code != 201:
            raise StockClientError(FailureCategory.STOCK_REJECTED)
        try:
            upstream = _StockCreateResponse.model_validate(response.json())
        except (ValueError, ValidationError):
            raise StockClientError(FailureCategory.STOCK_REJECTED) from None
        if not upstream.sid:
            raise StockClientError(FailureCategory.STOCK_REJECTED)
        return StockCallCreateResult(
            organization_id=request.context.organization_id,
            stock_call_id=upstream.sid,
            stock_status="requested",
            idempotency_key=request.idempotency_key,
            request_digest=request_digest,
        )

    async def request_bounded_hangup(
        self,
        *,
        stock_call_id: str,
        timeout_seconds: int,
    ) -> None:
        if not stock_call_id or "/" in stock_call_id:
            raise StockClientError(FailureCategory.CONTRACT_MISMATCH)
        if not 0 < timeout_seconds <= 10:
            raise StockClientError(FailureCategory.CONTRACT_MISMATCH)
        path = (
            f"/v1/Accounts/{quote(self._configuration.account_id, safe='')}/Calls/"
            f"{quote(stock_call_id, safe='')}"
        )
        try:
            async with asyncio.timeout(timeout_seconds):
                response = await self._client.post(
                    path, json={"call_status": "completed"}
                )
        except (TimeoutError, httpx.HTTPError):
            raise StockClientError(FailureCategory.STOCK_UNAVAILABLE) from None
        if response.status_code not in {200, 202}:
            raise StockClientError(FailureCategory.STOCK_REJECTED)

    async def ready(self) -> bool:
        try:
            response = await self._client.get("/health")
        except httpx.HTTPError:
            return False
        return response.status_code == 200

    async def aclose(self) -> None:
        await self._client.aclose()
