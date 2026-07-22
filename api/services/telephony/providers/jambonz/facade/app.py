"""FastAPI composition root for the dependency-injected Jambonz facade."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .auth import SignatureVerifier, VerificationPolicy
from .models import (
    HookResponse,
    ListenVerb,
    OuterCallCreateRequest,
    StockCallWebhook,
    StockCdrWebhook,
)
from .service import (
    F12AuthorityClient,
    FacadeError,
    G008HangupRequest,
    G008PeerAttachRequest,
    G008PeerBinding,
    G008InboundArmRequest,
    FacadeService,
    StockJambonzClient,
)




def create_facade_app(
    *,
    f12_client: F12AuthorityClient | None = None,
    stock_client: StockJambonzClient | None = None,
    signature_verifier: SignatureVerifier | None = None,
    verification_policy: VerificationPolicy | None = None,
    media_websocket_url: str | None = None,
) -> FastAPI:
    """Build from complete injection, or enter fail-closed deployment composition."""

    supplied = (
        f12_client,
        stock_client,
        signature_verifier,
        verification_policy,
        media_websocket_url,
    )
    if all(value is None for value in supplied):
        from .runtime import load_deployment_dependencies

        dependencies = load_deployment_dependencies()
        f12_client = dependencies.f12_client
        stock_client = dependencies.stock_client
        signature_verifier = dependencies.signature_verifier
        verification_policy = dependencies.verification_policy
        media_websocket_url = dependencies.media_websocket_url
    elif any(value is None for value in supplied):
        from .runtime import FacadeRuntimeConfigurationError

        raise FacadeRuntimeConfigurationError(
            "facade_partial_dependency_injection_rejected"
        )

    assert f12_client is not None
    assert stock_client is not None
    assert signature_verifier is not None
    assert verification_policy is not None
    assert media_websocket_url is not None

    service = FacadeService(
        f12=f12_client,
        stock=stock_client,
        verifier=signature_verifier,
        verification_policy=verification_policy,
        media_websocket_url=media_websocket_url,
    )
    app = FastAPI(
        title="Recova Jambonz Facade",
        version="1",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.exception_handler(FacadeError)
    async def facade_error_handler(
        _request: Request, exc: FacadeError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=exc.http_status,
            content={
                "category": exc.category.value,
                "containment_requested": exc.containment_requested,
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        _request: Request, _exc: RequestValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={"category": "contract_mismatch"},
        )

    @app.get("/healthz", include_in_schema=False)
    async def health() -> dict[str, str]:
        return {"status": "alive"}

    @app.get("/readyz", include_in_schema=False)
    async def readiness() -> JSONResponse:
        ready = await service.ready()
        return JSONResponse(
            status_code=200 if ready else 503,
            content={"status": "ready" if ready else "unavailable"},
        )

    @app.post("/v1/g008/inbound/arm")
    async def arm_g008_inbound(request: G008InboundArmRequest) -> Any:
        return await service.arm_g008_inbound(
            request=request,
            now=datetime.now(timezone.utc),
        )

    @app.post("/v1/g008/calls/hangup")
    async def hangup_g008_call(request: G008HangupRequest) -> Any:
        return await service.hangup_g008(request=request)

    @app.post("/v1/g008/ip-peer/attach")
    async def attach_g008_ip_peer(request: G008PeerAttachRequest) -> Any:
        return await service.attach_g008_ip_peer(request)

    @app.post("/v1/g008/ip-peer/detach")
    async def detach_g008_ip_peer(request: G008PeerBinding) -> Any:
        return await service.detach_g008_ip_peer(request)

    @app.post("/v1/jambonz-contract/accounts/{account_id}/calls", status_code=201)
    async def create_call(
        account_id: str, request: OuterCallCreateRequest
    ) -> Any:
        return await service.create_outbound_call(
            account_id=account_id,
            request=request,
            now=datetime.now(timezone.utc),
        )

    @app.get(
        "/v1/jambonz-contract/accounts/{account_id}/calls/{stock_call_id}"
    )
    async def call_status(
        account_id: str,
        stock_call_id: str,
        organization_id: int = Query(gt=0),
    ) -> Any:
        return await service.get_call_status(
            organization_id=organization_id,
            account_id=account_id,
            stock_call_id=stock_call_id,
        )

    @app.post(
        "/v1/jambonz-contract/hooks/outbound/record-answer-and-mint-media"
    )
    async def outbound_answer(
        request: StockCallWebhook,
        organization_id: int = Query(gt=0),
    ) -> JSONResponse:
        response = await service.stock_outbound_answer(
            organization_id=organization_id,
            event=request,
            now=datetime.now(timezone.utc),
        )
        return JSONResponse(content=_jambonz_verbs(response))

    @app.post(
        "/v1/jambonz-contract/hooks/inbound/"
        "commit-inbound-answer-intent-and-mint-media"
    )
    async def inbound_initial(
        request: StockCallWebhook,
        organization_id: int = Query(gt=0),
    ) -> JSONResponse:
        response = await service.stock_inbound_initial(
            organization_id=organization_id,
            event=request,
            now=datetime.now(timezone.utc),
        )
        return JSONResponse(content=_jambonz_verbs(response))

    @app.post("/v1/jambonz-contract/hooks/status")
    async def status_callback(
        event: StockCallWebhook,
        organization_id: int = Query(gt=0),
    ) -> Any:
        return await service.stock_status(
            organization_id=organization_id,
            event=event,
            now=datetime.now(timezone.utc),
        )

    @app.post("/v1/jambonz-contract/hooks/cdr")
    async def cdr_callback(
        event: StockCdrWebhook,
        organization_id: int = Query(gt=0),
    ) -> Any:
        return await service.stock_cdr(
            organization_id=organization_id,
            event=event,
            now=datetime.now(timezone.utc),
        )

    return app


def _jambonz_verbs(response: HookResponse) -> list[dict[str, object]]:
    """Render official verb aliases while revealing only the opaque wsAuth token."""

    rendered: list[dict[str, object]] = []
    for verb in response.verbs:
        payload = verb.model_dump(mode="json", by_alias=True, exclude_none=True)
        if isinstance(verb, ListenVerb):
            ws_auth = payload["wsAuth"]
            if not isinstance(ws_auth, dict):
                raise RuntimeError("invalid wsAuth rendering")
            ws_auth["password"] = verb.ws_auth.password.get_secret_value()
        rendered.append(payload)
    return rendered
