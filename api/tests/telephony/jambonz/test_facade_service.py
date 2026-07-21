import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock
from fastapi.testclient import TestClient

import pytest
from pydantic import SecretStr

import api.services.telephony.providers.jambonz.facade.service as service_module
from api.services.telephony.providers.jambonz.facade.auth import VerificationPolicy
from api.services.telephony.providers.jambonz.facade.app import create_facade_app
from api.schemas.onnuri_smoke import (
    ClaimReservedInboundAndBindRequest,
    ClaimReservedInboundAndBindResponse,
)
from api.services.telephony.providers.jambonz.facade.clients import (
    F12AuthorityHttpClient,
)
from api.services.telephony.providers.jambonz.facade.models import (
    DISPATCH_VERIFICATION_DOMAIN,
    MEDIA_VERIFICATION_DOMAIN,
    BoundCallContext,
    CallbackReceipt,
    CallStatus,
    CallStatusResponse,
    ContainmentRequest,
    Direction,
    DispatchConsumeReceipt,
    FailureCategory,
    InboundInitialHookRequest,
    MediaAuthorityReceipt,
    OuterCallCreateRequest,
    OutboundAnswerHookRequest,
    RouteChainCapability,
    SignedCapability,
    StockCallBindReceipt,
    StockCallCreateResult,
    StockCallWebhook,
    StockCdrWebhook,
    StockStatusEvent,
)
from api.services.telephony.providers.jambonz.facade.service import (
    AuthorityClientError,
    FacadeError,
    FacadeService,
    G008HangupRequest,
    G008InboundArmRequest,
    canonical_model_digest,
    outbound_create_request_digest,
)

_NOW = datetime(2026, 7, 14, 12, 0, tzinfo=timezone.utc)
_DEADLINE = _NOW + timedelta(seconds=60)
_DIGEST = "a" * 64
_KEY = "idem-0000000000000001"


class _Verifier:
    def verify(self, **_kwargs):
        return True
    def key_fingerprint(self, _key_id):
        return "f" * 64


class _Authority:
    def __init__(self):
        self.calls = []
        self.media_receipt = None
        self.request_containment = AsyncMock()
        self.ready = AsyncMock(return_value=True)

    async def consume_dispatch(self, submission):
        self.calls.append(("consume", submission))
        return DispatchConsumeReceipt(
            context=submission.context,
            idempotency_key=submission.idempotency_key,
            request_digest=submission.request_digest,
            receipt_id="dispatch-receipt",
            consumed_at=_NOW,
            dispatch_key_id="dispatch-key",
            signature=SecretStr("signed-receipt"),
        )

    async def bind_stock_call(self, request):
        self.calls.append(("bind", request))
        return StockCallBindReceipt(
            context=request.context,
            stock_call_id=request.stock_call_id,
            idempotency_key=request.idempotency_key,
            request_digest=request.request_digest,
            bind_receipt_id="bind-receipt",
            bound_at=_NOW,
            media_capability_issued=False,
        )

    async def claim_reserved_inbound_and_bind(self, request):
        self.calls.append(("claim-inbound", request))
        bound_at = _NOW
        deadline = bound_at + timedelta(seconds=60)
        context = {
            "organization_id": request.organization_id,
            "execution_seal_uuid": "10000000-0000-4000-8000-000000000010",
            "stage_uuid": "10000000-0000-4000-8000-000000000011",
            "stage": "inbound_call",
            "ordinal": 3,
            "account_id": request.account_id,
            "application_id": request.application_id,
            "run_uuid": "10000000-0000-4000-8000-000000000012",
            "attempt_uuid": "10000000-0000-4000-8000-000000000013",
            "idempotency_key": "10000000-0000-4000-8000-000000000014",
            "bind_receipt_uuid": "10000000-0000-4000-8000-000000000015",
            "stock_call_id_digest": service_module._digest_text(str(request.stock_call_id)),
            "direction": "inbound",
            "authority_deadline_at": deadline,
            "did_digest": request.did_digest,
            "caller_digest": request.caller_digest,
            "request_digest": "4" * 64,
            "candidate_digest": "b" * 64,
            "gate_envelope_digest": "e" * 64,
            "bound_at": bound_at,
            "bind_receipt_digest": "0" * 64,
            "bind_receipt_signature_digest": service_module.hashlib.sha256(
                bytes(64)
            ).hexdigest(),
            "bind_receipt_key_fingerprint": "f" * 64,
            "bind_receipt_key_id": "dispatch-key",
        }
        claims = {
            "schema": "recova-g008-inbound-bind-receipt-v1",
            "domain": "recova.onnuri.smoke.g008.inbound-bind.v1",
            "algorithm": "ES256",
            "organization_id": context["organization_id"],
            "execution_seal_uuid": context["execution_seal_uuid"],
            "execution_stage_uuid": context["stage_uuid"],
            "account_uuid": context["account_id"],
            "application_uuid": context["application_id"],
            "stock_call_uuid": request.stock_call_id,
            "stock_call_id_digest": context["stock_call_id_digest"],
            "did_digest": context["did_digest"],
            "caller_digest": context["caller_digest"],
            "direction": "inbound",
            "run_uuid": context["run_uuid"],
            "attempt_uuid": context["attempt_uuid"],
            "idempotency_uuid": context["idempotency_key"],
            "bind_receipt_uuid": context["bind_receipt_uuid"],
            "request_digest": context["request_digest"],
            "candidate_digest": context["candidate_digest"],
            "gate_envelope_digest": context["gate_envelope_digest"],
            "issued_at": bound_at,
            "authority_deadline_at": deadline,
        }
        response = ClaimReservedInboundAndBindResponse.model_validate(
            {
                "context": context,
                "bind_receipt": {
                    "schema_version": "recova-g008-inbound-bind-receipt-v1",
                    "algorithm": "ES256",
                    "verification_domain": "recova.onnuri.smoke.g008.inbound-bind.v1",
                    "key_id": "dispatch-key",
                    "claims": claims,
                    "signature": "A" * 86,
                },
                "recovered": False,
            }
        )
        digest = service_module.hashlib.sha256(
            service_module.canonical_signing_bytes(
                response.bind_receipt, exclude={"signature"}
            )
        ).hexdigest()
        return response.model_copy(
            update={"context": response.context.model_copy(
                update={"bind_receipt_digest": digest}
            )}
        )

    async def record_answer_and_mint_media(self, request):
        self.calls.append(("outbound-media", request))
        return self._media(request)

    async def commit_inbound_answer_intent_and_mint_media(self, request):
        self.calls.append(("inbound-media", request))
        return self._media(request)

    def _media(self, request):
        if self.media_receipt is None:
            self.media_receipt = MediaAuthorityReceipt(
                context=request.context,
                stock_call_id=request.stock_call_id,
                idempotency_key=request.idempotency_key,
                request_digest=request.request_digest,
                authority_receipt_id="media-receipt",
                committed_at=_NOW,
                authority_deadline=request.proposed_deadline,
                media_key_id="media-key",
                opaque_media_capability=SecretStr("opaque-media-token"),
            )
        return self.media_receipt

    async def submit_call_event(self, event):
        self.calls.append(("callback", event))
        return CallbackReceipt(
            organization_id=event.organization_id,
            event_nonce=event.event_nonce,
            idempotency_key=event.idempotency_key,
            request_digest=event.request_digest,
            accepted_at=_NOW,
            status=event.normalized_status,
        )
    async def get_call_status(
        self, *, organization_id, account_id, stock_call_id
    ):
        self.calls.append(("lookup", (organization_id, account_id, stock_call_id)))
        return CallStatusResponse(
            context=_bound_context(),
            status=CallStatus.STOCK_BOUND,
            updated_at=_NOW,
            terminal=False,
            idempotency_key=_KEY,
            request_digest=_DIGEST,
            candidate_digest="b" * 64,
        )



class _Stock:
    def __init__(self):
        self.calls = []
        self.request_bounded_hangup = AsyncMock()
        self.ready = AsyncMock(return_value=True)

    async def create_call(self, request):
        self.calls.append(request)
        return StockCallCreateResult(
            organization_id=request.context.organization_id,
            stock_call_id="stock-call",
            stock_status="created",
            idempotency_key=request.idempotency_key,
            request_digest=canonical_model_digest(request),
        )



def _service(authority=None, stock=None):
    return FacadeService(
        f12=authority or _Authority(),
        stock=stock or _Stock(),
        verifier=_Verifier(),
        verification_policy=VerificationPolicy(
            dispatch_key_id="dispatch-key", media_key_id="media-key"
        ),
        media_websocket_url="wss://media.recova.invalid/calls",
    )


async def _arm_inbound(service, **updates):
    event = _inbound_stock_fixture()
    values = {
        "organization_id": 7,
        "execution_seal_uuid": "10000000-0000-4000-8000-000000000010",
        "execution_nonce_digest": "a" * 64,
        "candidate_digest": "b" * 64,
        "gate_envelope_digest": "e" * 64,
        "execution_stage_uuid": "10000000-0000-4000-8000-000000000011",
        "destination_hmac_digest": "d" * 64,
        "reserved_inbound_did_digest": service_module._digest_text(
            event.to_address.get_secret_value()
        ),
        "reserved_inbound_caller_digest": service_module._digest_text(
            event.from_address.get_secret_value()
        ),
        "retry_count": 0,
        "concurrency_count": 1,
        "call_deadline_seconds": 60,
    }
    values.update(updates)
    return await service.arm_g008_inbound(
        request=G008InboundArmRequest(**values),
        now=_NOW,
    )


def _outbound_create(**updates):
    capability = SignedCapability(
        key_id="dispatch-key",
        issued_at=_NOW - timedelta(seconds=1),
        expires_at=_DEADLINE,
        nonce="dispatch-nonce",
        claims={"pending": True},
        signature=SecretStr("raw-dispatch-capability"),
    )
    values = dict(
        organization_id=7,
        application_id="application-1",
        run_id="run-1",
        attempt_id="attempt-1",
        authority_deadline=_DEADLINE,
        idempotency_key=_KEY,
        candidate_digest="b" * 64,
        gate_envelope_digest="e" * 64,
        dispatch_capability=capability,
        from_address=SecretStr("+827012345678"),
        to_address=SecretStr("+821012345678"),
        answer_hook_url="https://facade.invalid/answer",
        status_hook_url="https://facade.invalid/status",
    )
    values.update(updates)
    request = OuterCallCreateRequest(**values)
    digest = outbound_create_request_digest("account-1", request)
    context = BoundCallContext(
        organization_id=request.organization_id,
        account_id="account-1",
        application_id=request.application_id,
        run_id=request.run_id,
        attempt_id=request.attempt_id,
        direction=Direction.OUTBOUND,
        authority_deadline=request.authority_deadline,
        candidate_digest=request.candidate_digest,
        gate_envelope_digest=request.gate_envelope_digest,
    )
    claims = {
        "organization_id": context.organization_id,
        "account_id": context.account_id,
        "application_id": context.application_id,
        "run_id": context.run_id,
        "attempt_id": context.attempt_id,
        "direction": context.direction.value,
        "authority_deadline": context.authority_deadline.isoformat(),
        "idempotency_key": request.idempotency_key,
        "request_digest": digest,
        "candidate_digest": context.candidate_digest,
        "gate_envelope_digest": context.gate_envelope_digest,
        "contract_version": context.contract_version,
    }
    return request.model_copy(
        update={"dispatch_capability": capability.model_copy(update={"claims": claims})}
    )


def _bound_context(direction=Direction.OUTBOUND, **updates):
    values = dict(
        organization_id=7,
        account_id="account-1",
        application_id="application-1",
        run_id="run-1",
        attempt_id="attempt-1",
        direction=direction,
        stock_call_id="stock-call",
        authority_deadline=_DEADLINE,
        candidate_digest="b" * 64,
        gate_envelope_digest="e" * 64,
    )
    values.update(updates)
    return BoundCallContext(**values)


def _with_digest(request):
    digest = service_module._digest_payload(
        service_module._model_payload(request, exclude={"request_digest"})
    )
    return request.model_copy(update={"request_digest": digest})


def _outbound_hook(**updates):
    values = dict(
        organization_id=7,
        context=_bound_context(),
        stock_call_id="stock-call",
        idempotency_key=_KEY,
        request_digest=_DIGEST,
        event_nonce="answer-nonce",
        observed_wall_time=_NOW,
        proposed_deadline=_DEADLINE,
        candidate_digest="b" * 64,
    )
    values.update(updates)
    return _with_digest(OutboundAnswerHookRequest(**values))


def _inbound_hook(**updates):
    values = dict(
        organization_id=7,
        context=_bound_context(Direction.INBOUND),
        stock_call_id="stock-call",
        idempotency_key=_KEY,
        request_digest=_DIGEST,
        event_nonce="inbound-nonce",
        observed_wall_time=_NOW,
        proposed_deadline=_DEADLINE,
        candidate_digest="b" * 64,
        source_account_id="account-1",
        source_application_id="application-1",
        did_digest="c" * 64,
        caller_mobile_digest="d" * 64,
    )
    values.update(updates)
    return _with_digest(InboundInitialHookRequest(**values))

@pytest.mark.parametrize(
    "mutation",
    [
        {},
        {"route_profile_digest": None},
        {"route_evidence_handle": "a" * 64},
        {"route_chain": {"packet": "raw-route-material"}},
        {"dispatch_capability": {"raw": "legacy-capability"}},
        {"request_mode": "legacy"},
    ],
)
def test_diagnostic_request_rejections_precede_authority_and_stock_networks(mutation):
    authority, stock = _Authority(), _Stock()
    app = create_facade_app(
        f12_client=authority,
        stock_client=stock,
        signature_verifier=_Verifier(),
        verification_policy=VerificationPolicy(
            dispatch_key_id="dispatch-key", media_key_id="media-key"
        ),
        media_websocket_url="wss://media.recova.invalid/calls",
    )
    payload = {
        "contract_version": "recova-jambonz-facade-v1",
        "organization_id": 7,
        "application_id": "application-1",
        "run_id": "run-1",
        "attempt_id": "attempt-1",
        "direction": "outbound",
        "authority_deadline": _DEADLINE.isoformat(),
        "idempotency_key": _KEY,
        "candidate_digest": "b" * 64,
        "gate_envelope_digest": "e" * 64,
        "request_mode": "diagnostic",
        "route_evidence_handle": "route-evidence-handle-v1",
        "route_profile_digest": "9" * 64,
        "from_address": "+827012345678",
        "to_address": "+821012345678",
        "answer_hook_url": "https://facade.invalid/answer",
        "status_hook_url": "https://facade.invalid/status",
        "ring_timeout_seconds": 30,
        "time_limit_seconds": 60,
    }
    if not mutation:
        del payload["route_evidence_handle"]
    else:
        for key, value in mutation.items():
            if value is None:
                del payload[key]
            else:
                payload[key] = value

    response = TestClient(app).post(
        "/v1/jambonz-contract/accounts/account-1/calls", json=payload
    )

    assert response.status_code == 422
    assert authority.calls == []
    assert stock.calls == []
    assert "raw-route-material" not in response.text


@pytest.mark.asyncio
async def test_stock_create_occurs_only_after_verified_dispatch_receipt_and_bind_is_not_media_mint():
    authority, stock = _Authority(), _Stock()
    result = await _service(authority, stock).create_outbound_call(
        account_id="account-1", request=_outbound_create(), now=_NOW
    )

    assert [name for name, _ in authority.calls] == ["consume", "bind"]
    assert len(stock.calls) == 1
    assert stock.calls[0].dispatch_receipt_id == "dispatch-receipt"
    assert result.context.organization_id == stock.calls[0].context.organization_id == 7
    bind = authority.calls[1][1]
    assert bind.context.stock_call_id == "stock-call"
    assert result.bind_receipt_id == "bind-receipt"
    assert "media" not in json.dumps(result.model_dump(mode="json"))


@pytest.mark.asyncio
async def test_dispatch_receipt_failure_rejects_before_stock_network_boundary():
    authority, stock = _Authority(), _Stock()
    authority.consume_dispatch = AsyncMock(
        side_effect=AuthorityClientError(FailureCategory.REPLAY)
    )

    with pytest.raises(FacadeError) as exc_info:
        await _service(authority, stock).create_outbound_call(
            account_id="account-1", request=_outbound_create(), now=_NOW
        )

    assert exc_info.value.category == FailureCategory.REPLAY
    assert stock.calls == []
    assert "raw-dispatch-capability" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_missing_bind_receipt_contains_stock_call_and_never_returns_authority():
    authority, stock = _Authority(), _Stock()
    authority.bind_stock_call = AsyncMock(
        side_effect=AuthorityClientError(FailureCategory.CONTRACT_MISMATCH)
    )

    with pytest.raises(FacadeError) as exc_info:
        await _service(authority, stock).create_outbound_call(
            account_id="account-1", request=_outbound_create(), now=_NOW
        )

    assert exc_info.value.containment_requested is True
    assert len(stock.calls) == 1
    assert authority.request_containment.await_count >= 1
    assert stock.request_bounded_hangup.await_count >= 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "capability_change",
    [
        {"verification_domain": MEDIA_VERIFICATION_DOMAIN},
        {"key_id": "media-key"},
    ],
)
async def test_dispatch_domain_or_key_confusion_rejects_before_stock(
    capability_change,
):
    authority, stock = _Authority(), _Stock()
    request = _outbound_create()
    request = request.model_copy(
        update={
            "dispatch_capability": request.dispatch_capability.model_copy(
                update=capability_change
            )
        }
    )

    with pytest.raises(FacadeError) as exc_info:
        await _service(authority, stock).create_outbound_call(
            account_id="account-1", request=request, now=_NOW
        )

    assert exc_info.value.category in {
        FailureCategory.CONTRACT_MISMATCH,
        FailureCategory.AUTHENTICATION_REJECTED,
    }
    assert stock.calls == []
    assert "raw-dispatch-capability" not in str(exc_info.value)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "request_change",
    [
        {"to_address": SecretStr("+821055500000")},
        {"idempotency_key": "idem-0000000000000002"},
        {"run_id": "changed-run"},
        {"attempt_id": "changed-attempt"},
        {"application_id": "changed-application"},
        {"organization_id": 8},
    ],
)
async def test_changed_signed_dispatch_request_or_binding_rejects_before_stock(
    request_change,
):
    authority, stock = _Authority(), _Stock()
    request = _outbound_create().model_copy(update=request_change)

    with pytest.raises(FacadeError) as exc_info:
        await _service(authority, stock).create_outbound_call(
            account_id="account-1", request=request, now=_NOW
        )

    assert exc_info.value.category == FailureCategory.CONTRACT_MISMATCH
    assert stock.calls == []


@pytest.mark.asyncio
async def test_outbound_answer_mints_only_after_bound_observed_answer_and_duplicate_keeps_token_and_deadline():
    authority = _Authority()
    service = _service(authority)
    request = _outbound_hook()
    await service.create_outbound_call(
        account_id="account-1", request=_outbound_create(), now=_NOW
    )

    first = await service.outbound_answer_hook(request)
    second = await service.outbound_answer_hook(request)

    assert [name for name, _ in authority.calls] == [
        "consume",
        "bind",
        "outbound-media",
        "outbound-media",
    ]
    assert first.organization_id == second.organization_id == 7
    assert first.verbs[0].verb == "listen"
    assert all(verb.verb != "answer" for verb in first.verbs)
    assert first.authority_receipt_id == second.authority_receipt_id == "media-receipt"
    assert first.verbs[0].ws_auth.password.get_secret_value() == second.verbs[0].ws_auth.password.get_secret_value()
    assert authority.media_receipt.authority_deadline == _DEADLINE


@pytest.mark.asyncio
async def test_initial_inbound_claims_without_lookup_or_raw_phone_before_media():
    authority = _Authority()
    service = _service(authority)
    await _arm_inbound(service)
    response = await service.stock_inbound_initial(
        organization_id=7,
        event=_inbound_stock_fixture(),
        now=_NOW,
    )

    assert [name for name, _ in authority.calls] == [
        "claim-inbound",
        "inbound-media",
    ]
    claim_request = authority.calls[0][1]
    assert set(claim_request.model_dump(mode="json")) == {
        "organization_id",
        "account_id",
        "application_id",
        "stock_call_id",
        "did_digest",
        "caller_digest",
    }
    assert "+82" not in claim_request.model_dump_json()
    media_request = authority.calls[1][1]
    assert media_request.event_nonce == media_request.request_digest == "4" * 64
    assert media_request.observed_wall_time == _NOW
    assert media_request.proposed_deadline == _DEADLINE
    assert [verb.verb for verb in response.verbs] == ["answer", "listen"]

def test_inbound_pause_is_rejected_before_any_authority_transition():
    with pytest.raises(ValueError, match="optional_pause_milliseconds"):
        _inbound_hook(optional_pause_milliseconds=1)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,value",
    [
        ("event_nonce", "changed-nonce"),
        ("idempotency_key", "idem-0000000000000002"),
        ("candidate_digest", "e" * 64),
        ("context", _bound_context(run_id="other-run")),
        ("context", _bound_context(account_id="other-tenant")),
        ("context", _bound_context(application_id="other-application")),
        ("context", _bound_context(attempt_id="other-attempt")),
    ],
)
async def test_changed_replay_nonce_digest_key_tenant_or_binding_is_rejected(field, value):
    authority = _Authority()
    authority.record_answer_and_mint_media = AsyncMock(
        side_effect=[
            authority._media(_outbound_hook()),
            AuthorityClientError(FailureCategory.IDEMPOTENCY_MISMATCH),
        ]
    )
    service = _service(authority)
    await service.outbound_answer_hook(_outbound_hook())
    changed = _outbound_hook(**{field: value})

    with pytest.raises(FacadeError) as exc_info:
        await service.outbound_answer_hook(changed)

    assert exc_info.value.containment_requested is True
    assert exc_info.value.category == FailureCategory.IDEMPOTENCY_MISMATCH


@pytest.mark.asyncio
async def test_invalid_initial_status_rejects_without_claim_lookup_or_containment():
    authority, stock = _Authority(), _Stock()
    response = await _service(authority, stock).stock_inbound_initial(
        organization_id=7,
        event=_inbound_stock_fixture(call_status="ringing", sip_status=180),
        now=_NOW,
    )

    assert response.verbs == ()
    assert response.containment_requested is False
    assert authority.calls == []
    assert authority.request_containment.await_count == 0
    assert stock.request_bounded_hangup.await_count == 0


@pytest.mark.asyncio
async def test_post_claim_media_failure_contains_with_persisted_context():
    authority, stock = _Authority(), _Stock()
    service = _service(authority, stock)
    await _arm_inbound(service)
    original_media = authority.commit_inbound_answer_intent_and_mint_media

    async def wrong_media_domain(request):
        receipt = await original_media(request)
        return receipt.model_copy(
            update={"media_verification_domain": DISPATCH_VERIFICATION_DOMAIN}
        )

    authority.commit_inbound_answer_intent_and_mint_media = wrong_media_domain
    response = await service.stock_inbound_initial(
        organization_id=7,
        event=_inbound_stock_fixture(),
        now=_NOW,
    )

    assert response.verbs == ()
    assert response.containment_requested is True
    containment = authority.request_containment.await_args.args[0]
    assert containment.context.run_id == "10000000-0000-4000-8000-000000000012"
    assert authority.request_containment.await_count == 1
    assert stock.request_bounded_hangup.await_count == 1


@pytest.mark.asyncio
async def test_callback_is_bound_to_nonce_digest_account_application_run_attempt_call_and_direction():
    authority = _Authority()
    event = _with_digest(
        StockStatusEvent(
            organization_id=7,
            context=_bound_context(),
            stock_call_id="stock-call",
            status="answered",
            event_time=_NOW,
            event_nonce="status-nonce",
            idempotency_key=_KEY,
            request_digest=_DIGEST,
        )
    )

    receipt = await _service(authority).accept_status(event)

    submitted = authority.calls[-1][1]
    assert submitted.event_nonce == receipt.event_nonce == "status-nonce"
    assert submitted.request_digest == receipt.request_digest == event.request_digest
    assert submitted.idempotency_key == receipt.idempotency_key == _KEY
    assert submitted.stock_call_id == submitted.context.stock_call_id == "stock-call"
    assert (
        submitted.context.account_id,
        submitted.context.application_id,
        submitted.context.run_id,
        submitted.context.attempt_id,
        submitted.context.direction,
    ) == (
        "account-1",
        "application-1",
        "run-1",
        "attempt-1",
        Direction.OUTBOUND,
    )
    assert receipt.status == CallStatus.ANSWER_AUTHORITY_COMMITTED
    assert receipt.organization_id == submitted.organization_id == 7


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "receipt_change",
    [
        {"event_nonce": "other-nonce"},
        {"idempotency_key": "idem-0000000000000002"},
        {"request_digest": "f" * 64},
        {"organization_id": 8},
    ],
)
async def test_changed_callback_receipt_nonce_key_or_digest_rejects(receipt_change):
    authority = _Authority()
    event = _with_digest(
        StockStatusEvent(
            organization_id=7,
            context=_bound_context(),
            stock_call_id="stock-call",
            status="answered",
            event_time=_NOW,
            event_nonce="status-nonce",
            idempotency_key=_KEY,
            request_digest=_DIGEST,
        )
    )
    valid = await authority.submit_call_event(
        service_module.normalize_stock_status(event)
    )
    authority.submit_call_event = AsyncMock(
        return_value=valid.model_copy(update=receipt_change)
    )

    with pytest.raises(FacadeError) as exc_info:
        await _service(authority).accept_status(event)

    assert exc_info.value.category == FailureCategory.CONTRACT_MISMATCH
    assert "opaque-media-token" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_dispatch_receipt_context_swap_rejects_before_stock_without_identifier_leak():
    authority, stock = _Authority(), _Stock()
    request = _outbound_create()

    async def swapped_receipt(submission):
        return DispatchConsumeReceipt(
            context=submission.context.model_copy(update={"organization_id": 8}),
            idempotency_key=submission.idempotency_key,
            request_digest=submission.request_digest,
            receipt_id="other-org-receipt",
            consumed_at=_NOW,
            dispatch_key_id="dispatch-key",
            signature=SecretStr("other-org-signature"),
        )

    authority.consume_dispatch = swapped_receipt

    with pytest.raises(FacadeError) as exc_info:
        await _service(authority, stock).create_outbound_call(
            account_id="account-1", request=request, now=_NOW
        )

    assert exc_info.value.category == FailureCategory.CONTRACT_MISMATCH
    assert stock.calls == []
    assert "other-org" not in str(exc_info.value)
    assert "raw-dispatch-capability" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_stock_bind_context_swap_contains_and_reveals_no_tenant_identifier():
    authority, stock = _Authority(), _Stock()

    async def swapped_bind(request):
        return StockCallBindReceipt(
            context=request.context.model_copy(update={"organization_id": 8}),
            stock_call_id=request.stock_call_id,
            idempotency_key=request.idempotency_key,
            request_digest=request.request_digest,
            bind_receipt_id="other-org-bind",
            bound_at=_NOW,
            media_capability_issued=False,
        )

    authority.bind_stock_call = swapped_bind

    with pytest.raises(FacadeError) as exc_info:
        await _service(authority, stock).create_outbound_call(
            account_id="account-1", request=_outbound_create(), now=_NOW
        )

    assert exc_info.value.category == FailureCategory.CONTRACT_MISMATCH
    assert exc_info.value.containment_requested is True
    assert authority.request_containment.await_count >= 1
    assert stock.request_bounded_hangup.await_count >= 1
    assert "other-org" not in str(exc_info.value)


def test_hook_event_and_containment_reject_cross_organization_tuples():
    with pytest.raises(ValueError):
        _outbound_hook(organization_id=8)
    with pytest.raises(ValueError):
        StockStatusEvent(
            organization_id=8,
            context=_bound_context(),
            stock_call_id="stock-call",
            status="answered",
            event_time=_NOW,
            event_nonce="status-nonce",
            idempotency_key=_KEY,
            request_digest=_DIGEST,
        )
    with pytest.raises(ValueError):
        ContainmentRequest(
            organization_id=8,
            context=_bound_context(),
            stock_call_id="stock-call",
            category=FailureCategory.CONTAINMENT_REQUIRED,
        )


def test_canonical_outbound_digest_binds_exact_organization():
    first = _outbound_create()
    second = first.model_copy(update={"organization_id": 8})

    assert outbound_create_request_digest(
        "account-1", first
    ) != outbound_create_request_digest("account-1", second)


@pytest.mark.parametrize("organization_id", [0, -1])
def test_facade_tenant_models_require_positive_organization(organization_id):
    with pytest.raises(ValueError):
        _outbound_create(organization_id=organization_id)
    with pytest.raises(ValueError):
        _bound_context(organization_id=organization_id)


def _stock_call_fixture(**updates):
    values = {
        "call_sid": "stock-call",
        "call_id": "sip-call-id",
        "application_sid": "application-1",
        "account_sid": "account-1",
        "direction": "outbound",
        "from": "+827012345678",
        "to": "+821012345678",
        "caller_name": "Recova",
        "sip_status": 200,
        "sip_reason": "OK",
        "call_status": "in-progress",
        "trace_id": "public-trace-id",
    }
    values.update(updates)
    return StockCallWebhook.model_validate(values)


def _inbound_stock_fixture(**updates):
    values = {
        "call_sid": "10000000-0000-4000-8000-000000000006",
        "call_id": "inbound-sip-call-id",
        "application_sid": "10000000-0000-4000-8000-000000000003",
        "account_sid": "10000000-0000-4000-8000-000000000002",
        "direction": "inbound",
        "call_status": "trying",
        "sip_status": 100,
        "sip_reason": "Trying",
    }
    values.update(updates)
    return _stock_call_fixture(**values)


@pytest.mark.asyncio
async def test_raw_stock_answer_resolves_f12_binding_and_uses_only_persisted_authority():
    authority = _Authority()
    event = _stock_call_fixture()

    first = await _service(authority).stock_outbound_answer(
        organization_id=7, event=event, now=_NOW
    )

    assert authority.calls[0] == ("lookup", (7, "account-1", "stock-call"))
    submitted = authority.calls[1][1]
    assert submitted.context == _bound_context()
    assert submitted.idempotency_key == _KEY
    assert submitted.request_digest == _DIGEST
    assert submitted.candidate_digest == "b" * 64
    assert first.verbs[0].url == "wss://media.recova.invalid/calls"
    assert first.verbs[0].ws_auth.password.get_secret_value() == (
        "opaque-media-token"
    )

@pytest.mark.asyncio
async def test_raw_stock_answer_replay_is_rejected_and_contained():
    authority, stock = _Authority(), _Stock()
    original = authority.record_answer_and_mint_media
    calls = 0

    async def reject_replay(request):
        nonlocal calls
        calls += 1
        if calls > 1:
            raise AuthorityClientError(FailureCategory.REPLAY)
        return await original(request)

    authority.record_answer_and_mint_media = reject_replay
    service = _service(authority, stock)
    event = _stock_call_fixture()
    await service.stock_outbound_answer(
        organization_id=7, event=event, now=_NOW
    )

    with pytest.raises(FacadeError) as exc_info:
        await service.stock_outbound_answer(
            organization_id=7, event=event, now=_NOW
        )

    assert exc_info.value.category == FailureCategory.REPLAY
    assert exc_info.value.containment_requested is True
    assert authority.request_containment.await_count >= 1
    assert stock.request_bounded_hangup.await_count >= 1



@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tamper",
    [
        "tenant",
        "application",
        "call",
        "did_digest",
        "signature",
        "malformed_signature",
    ],
)
async def test_tampered_inbound_claim_rejects_before_media(tamper):
    authority = _Authority()
    original_claim = authority.claim_reserved_inbound_and_bind

    async def tampered_claim(request):
        response = await original_claim(request)
        if tamper == "tenant":
            return response.model_copy(
                update={"context": response.context.model_copy(
                    update={"organization_id": 8}
                )}
            )
        if tamper == "application":
            return response.model_copy(
                update={"context": response.context.model_copy(
                    update={"application_id": "10000000-0000-4000-8000-000000000099"}
                )}
            )
        if tamper == "call":
            return response.model_copy(
                update={"context": response.context.model_copy(
                    update={"stock_call_id_digest": "9" * 64}
                )}
            )
        if tamper == "did_digest":
            return response.model_copy(
                update={"context": response.context.model_copy(
                    update={"did_digest": "9" * 64}
                )}
            )
        signature = "B" * 85 + "Q"
        if tamper == "malformed_signature":
            signature = "A" * 85 + "B"
            signature_text_digest = service_module._digest_text(signature)
            return response.model_copy(
                update={
                    "context": response.context.model_copy(
                        update={
                            "bind_receipt_signature_digest": signature_text_digest
                        }
                    ),
                    "bind_receipt": response.bind_receipt.model_copy(
                        update={"signature": signature}
                    ),
                }
            )
        return response.model_copy(
            update={"bind_receipt": response.bind_receipt.model_copy(
                update={"signature": signature}
            )}
        )

    authority.claim_reserved_inbound_and_bind = tampered_claim
    service = _service(authority)
    await _arm_inbound(service)
    response = await service.stock_inbound_initial(
        organization_id=7,
        event=_inbound_stock_fixture(),
        now=_NOW,
    )

    assert response.verbs == ()
    assert [name for name, _ in authority.calls] == ["claim-inbound"]
    assert all(name != "lookup" for name, _ in authority.calls)
@pytest.mark.asyncio
async def test_raw_stock_callback_mismatch_contains_persisted_call():
    authority, stock = _Authority(), _Stock()

    with pytest.raises(FacadeError) as exc_info:
        await _service(authority, stock).stock_outbound_answer(
            organization_id=7,
            event=_stock_call_fixture(application_sid="wrong-application"),
            now=_NOW,
        )

    assert exc_info.value.category == FailureCategory.CONTRACT_MISMATCH
    assert exc_info.value.containment_requested is True
    assert authority.request_containment.await_count >= 1
    assert stock.request_bounded_hangup.await_count >= 1


@pytest.mark.asyncio
async def test_raw_status_uses_exact_f12_call_correlation_and_persisted_envelope():
    authority = _Authority()
    receipt = await _service(authority).stock_status(
        organization_id=7,
        event=_stock_call_fixture(call_status="completed"),
        now=_NOW,
    )

    assert authority.calls[0] == ("lookup", (7, "account-1", "stock-call"))
    normalized = authority.calls[1][1]
    assert normalized.context == _bound_context()
    assert normalized.idempotency_key == _KEY
    assert normalized.request_digest == _DIGEST
    assert normalized.normalized_status == receipt.status == CallStatus.COMPLETED


def test_public_stock_shape_rejects_caller_supplied_authority():
    fixture = _stock_call_fixture().model_dump(mode="json", by_alias=True)
    assert "organization_id" not in fixture
    assert "context" not in fixture

    with pytest.raises(ValueError):
        StockCallWebhook.model_validate(
            {
                **fixture,
                "organization_id": 7,
                "context": _bound_context().model_dump(mode="json"),
                "idempotency_key": _KEY,
                "request_digest": _DIGEST,
                "candidate_digest": "b" * 64,
            }
        )


def test_stock_webhook_route_requires_positive_organization_binding():
    authority = _Authority()
    app = create_facade_app(
        f12_client=authority,
        stock_client=_Stock(),
        signature_verifier=_Verifier(),
        verification_policy=VerificationPolicy(
            dispatch_key_id="dispatch-key", media_key_id="media-key"
        ),
        media_websocket_url="wss://media.recova.invalid/calls",
    )
    client = TestClient(app)
    payload = _stock_call_fixture().model_dump(mode="json", by_alias=True)

    missing = client.post(
        "/v1/jambonz-contract/hooks/outbound/record-answer-and-mint-media",
        json=payload,
    )
    non_positive = client.post(
        "/v1/jambonz-contract/hooks/outbound/"
        "record-answer-and-mint-media?organization_id=0",
        json=payload,
    )

    assert missing.status_code == non_positive.status_code == 422
    assert authority.calls == []


@pytest.mark.asyncio
async def test_raw_cdr_rejects_terminal_mutation():
    authority = _Authority()
    cdr = StockCdrWebhook.model_validate(
        {
            "call_sid": "stock-call",
            "call_id": "sip-call-id",
            "application_sid": "application-1",
            "account_sid": "account-1",
            "direction": "outbound",
            "from": "+827012345678",
            "to": "+821012345678",
            "call_status": "completed",
            "duration": 42,
            "sip_status": 200,
            "sip_reason": "OK",
        }
    )
    receipt = await _service(authority).stock_cdr(
        organization_id=7, event=cdr, now=_NOW
    )
    assert receipt.status == CallStatus.COMPLETED
    assert authority.calls[-1][1].duration_seconds == 42

    async def terminal_lookup(**_kwargs):
        return CallStatusResponse(
            context=_bound_context(),
            status=CallStatus.COMPLETED,
            updated_at=_NOW,
            terminal=True,
            idempotency_key=_KEY,
            request_digest=_DIGEST,
            candidate_digest="b" * 64,
        )

    authority.get_call_status = terminal_lookup
    with pytest.raises(FacadeError) as exc_info:
        await _service(authority).stock_cdr(
            organization_id=7, event=cdr, now=_NOW
        )
    assert exc_info.value.category == FailureCategory.CONTRACT_MISMATCH


@pytest.mark.asyncio
async def test_f12_client_posts_exact_atomic_inbound_claim_contract():
    request = ClaimReservedInboundAndBindRequest(
        organization_id=7,
        account_id="10000000-0000-4000-8000-000000000002",
        application_id="10000000-0000-4000-8000-000000000003",
        stock_call_id="10000000-0000-4000-8000-000000000006",
        did_digest="5" * 64,
        caller_digest="6" * 64,
    )
    assert set(request.model_dump(mode="json")) == {
        "organization_id",
        "account_id",
        "application_id",
        "stock_call_id",
        "did_digest",
        "caller_digest",
    }
    response = await _Authority().claim_reserved_inbound_and_bind(request)
    transport = SimpleNamespace(post_typed=AsyncMock(return_value=response))

    assert (
        await F12AuthorityHttpClient(
            transport
        ).claim_reserved_inbound_and_bind(request)
        == response
    )
    transport.post_typed.assert_awaited_once_with(
        operation_path=(
            "/api/v1/internal/onnuri-smoke/"
            "claim-reserved-inbound-and-bind"
        ),
        request=request,
        response_model=ClaimReservedInboundAndBindResponse,
    )


@pytest.mark.asyncio
async def test_g008_inbound_wrong_order_rejects_without_authority_or_stock_side_effects():
    authority, stock = _Authority(), _Stock()
    response = await _service(authority, stock).stock_inbound_initial(
        organization_id=7,
        event=_inbound_stock_fixture(),
        now=_NOW,
    )

    assert response.verbs == ()
    assert authority.calls == []
    authority.request_containment.assert_not_awaited()
    stock.request_bounded_hangup.assert_not_awaited()


@pytest.mark.asyncio
async def test_g008_inbound_arm_is_one_shot_and_replay_is_rejected():
    service = _service()
    first = await _arm_inbound(service)

    with pytest.raises(FacadeError) as exc_info:
        await _arm_inbound(service)

    assert first.state == "armed"
    assert exc_info.value.category == FailureCategory.REPLAY


@pytest.mark.asyncio
async def test_g008_inbound_hangup_before_arm_consumption_has_no_side_effect():
    authority, stock = _Authority(), _Stock()
    service = _service(authority, stock)
    armed = await _arm_inbound(service)
    request = G008HangupRequest(
        organization_id=7,
        execution_seal_uuid="10000000-0000-4000-8000-000000000010",
        execution_nonce_digest="a" * 64,
        candidate_digest="b" * 64,
        gate_envelope_digest="e" * 64,
        context=armed.context.model_dump(mode="json"),
        deadline_seconds=5,
    )

    with pytest.raises(FacadeError) as exc_info:
        await service.hangup_g008(request=request)

    assert exc_info.value.category == FailureCategory.CONTRACT_MISMATCH
    assert authority.calls == []
    authority.request_containment.assert_not_awaited()
    stock.request_bounded_hangup.assert_not_awaited()


@pytest.mark.asyncio
async def test_g008_inbound_cross_tenant_and_wrong_binding_do_not_consume_arm():
    authority, stock = _Authority(), _Stock()
    service = _service(authority, stock)
    await _arm_inbound(service)

    cross_tenant = await service.stock_inbound_initial(
        organization_id=8,
        event=_inbound_stock_fixture(),
        now=_NOW,
    )
    wrong_binding = await service.stock_inbound_initial(
        organization_id=7,
        event=_inbound_stock_fixture(**{"from": "+821099999999"}),
        now=_NOW,
    )
    accepted = await service.stock_inbound_initial(
        organization_id=7,
        event=_inbound_stock_fixture(),
        now=_NOW,
    )

    assert cross_tenant.verbs == ()
    assert wrong_binding.verbs == ()
    assert [verb.verb for verb in accepted.verbs] == ["answer", "listen"]
    assert [name for name, _ in authority.calls] == [
        "claim-inbound",
        "inbound-media",
    ]
    authority.request_containment.assert_not_awaited()
    stock.request_bounded_hangup.assert_not_awaited()


@pytest.mark.asyncio
async def test_g008_terminal_hangup_is_idempotent_and_has_no_containment_side_effect():
    authority, stock = _Authority(), _Stock()
    service = _service(authority, stock)
    seal = "10000000-0000-4000-8000-000000000010"
    created = await service.create_outbound_call(
        account_id="account-1",
        request=_outbound_create(run_id=seal),
        now=_NOW,
    )
    authority.get_call_status = AsyncMock(
        return_value=CallStatusResponse(
            context=created.context,
            status=CallStatus.COMPLETED,
            updated_at=_NOW,
            terminal=True,
            idempotency_key=created.idempotency_key,
            request_digest=created.request_digest,
            candidate_digest=created.context.candidate_digest,
        )
    )
    request = G008HangupRequest(
        organization_id=7,
        execution_seal_uuid=seal,
        execution_nonce_digest=service_module._digest_text("dispatch-nonce"),
        candidate_digest="b" * 64,
        gate_envelope_digest="e" * 64,
        context=created.context.model_dump(mode="json"),
        deadline_seconds=5,
    )

    first = await service.hangup_g008(request=request)
    second = await service.hangup_g008(request=request)

    assert first == second
    assert first.model_dump() == {
        "context_digest": service_module._digest(created.context),
        "state": "terminated",
        "containment_requested": False,
    }
    authority.get_call_status.assert_awaited_once()
    authority.request_containment.assert_not_awaited()
    stock.request_bounded_hangup.assert_not_awaited()


@pytest.mark.asyncio
async def test_g008_hangup_wrong_binding_is_rejected_before_lookup_or_containment():
    authority, stock = _Authority(), _Stock()
    service = _service(authority, stock)
    seal = "10000000-0000-4000-8000-000000000010"
    created = await service.create_outbound_call(
        account_id="account-1",
        request=_outbound_create(run_id=seal),
        now=_NOW,
    )
    calls_before = list(authority.calls)
    request = G008HangupRequest(
        organization_id=7,
        execution_seal_uuid=seal,
        execution_nonce_digest=service_module._digest_text("dispatch-nonce"),
        candidate_digest="c" * 64,
        gate_envelope_digest="e" * 64,
        context=created.context.model_dump(mode="json"),
        deadline_seconds=5,
    )

    with pytest.raises(FacadeError) as exc_info:
        await service.hangup_g008(request=request)

    assert exc_info.value.category == FailureCategory.CONTRACT_MISMATCH
    assert authority.calls == calls_before
    authority.request_containment.assert_not_awaited()
    stock.request_bounded_hangup.assert_not_awaited()


@pytest.mark.asyncio
async def test_g008_active_hangup_invokes_stock_and_f12_once_and_recovers_receipt():
    authority, stock = _Authority(), _Stock()
    service = _service(authority, stock)
    seal = "10000000-0000-4000-8000-000000000010"
    created = await service.create_outbound_call(
        account_id="account-1",
        request=_outbound_create(run_id=seal),
        now=_NOW,
    )
    authority.get_call_status = AsyncMock(
        return_value=CallStatusResponse(
            context=created.context,
            status=CallStatus.RUNNING,
            updated_at=_NOW,
            terminal=False,
            idempotency_key=created.idempotency_key,
            request_digest=created.request_digest,
            candidate_digest=created.context.candidate_digest,
        )
    )
    request = G008HangupRequest(
        organization_id=7,
        execution_seal_uuid=seal,
        execution_nonce_digest=service_module._digest_text("dispatch-nonce"),
        candidate_digest="b" * 64,
        gate_envelope_digest="e" * 64,
        context=created.context.model_dump(mode="json"),
        deadline_seconds=5,
    )

    first = await service.hangup_g008(request=request)
    second = await service.hangup_g008(request=request)

    assert first == second
    assert first.containment_requested is True
    authority.request_containment.assert_awaited_once()
    stock.request_bounded_hangup.assert_awaited_once_with(
        stock_call_id="stock-call",
        timeout_seconds=5,
    )

@pytest.mark.asyncio
async def test_diagnostic_facade_mints_opaque_route_capability_before_dispatch_without_route_authority():
    authority, stock = _Authority(), _Stock()
    request = _outbound_create(
        request_mode="diagnostic",
        dispatch_capability=None,
        route_profile_digest="9" * 64,
        route_evidence_handle="opaque-route-evidence-handle",
    )
    request_digest = outbound_create_request_digest("account-1", request)
    claims = {
        "organization_id": 7,
        "account_id": "account-1",
        "application_id": "application-1",
        "run_id": "run-1",
        "attempt_id": "attempt-1",
        "direction": "outbound",
        "authority_deadline": _DEADLINE.isoformat(),
        "idempotency_key": _KEY,
        "request_digest": request_digest,
        "candidate_digest": "b" * 64,
        "gate_envelope_digest": "e" * 64,
        "contract_version": "recova-jambonz-facade-v1",
        "route_profile_digest": "9" * 64,
        "provider_fact_packet_id": "packet-1",
        "provider_fact_packet_sha256": "1" * 64,
        "route_decision_id": "decision-1",
        "route_decision_sha256": "2" * 64,
        "route_conformance_id": "conformance-1",
        "route_conformance_sha256": "3" * 64,
        "adapter_entries_digest": "4" * 64,
        "keyset_sha256": "5" * 64,
        "revocations_sha256": "6" * 64,
    }
    authority.mint_route_chain_capability = AsyncMock(
        return_value=RouteChainCapability(
            key_id="dispatch-key",
            issued_at=_NOW,
            expires_at=_DEADLINE,
            nonce="route-nonce",
            claims=claims,
            signature=SecretStr("opaque-route-capability"),
        )
    )

    await _service(authority, stock).create_outbound_call(
        account_id="account-1", request=request, now=_NOW
    )

    minted_request = authority.mint_route_chain_capability.await_args.args[0]
    assert minted_request.route_evidence_handle == "opaque-route-evidence-handle"
    assert minted_request.route_profile_digest == "9" * 64
    assert "packet" not in minted_request.model_dump_json()
    assert authority.calls[0][0] == "consume"
    assert authority.calls[0][1].capability.signature.get_secret_value() == (
        "opaque-route-capability"
    )
    assert "opaque-route-evidence-handle" not in authority.calls[0][1].model_dump_json()
