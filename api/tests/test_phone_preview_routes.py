from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.routes.phone_preview import get_phone_preview_user, router


def _make_test_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_phone_preview_user] = lambda: SimpleNamespace(
        id=7,
        selected_organization_id=11,
    )
    return app


@pytest.mark.parametrize(
    ("method", "path", "json_body", "service_method"),
    [
        (
            "post",
            "/phone-preview/start",
            {"workflow_id": 33, "phone_number": "01012345678"},
            "start",
        ),
        (
            "post",
            "/phone-preview/verify",
            {"session_id": 123, "otp_code": "123456"},
            "verify",
        ),
        ("post", "/phone-preview/call", {"session_id": 123}, "call"),
        (
            "post",
            "/phone-preview/wait-inbound",
            {"session_id": 123},
            "wait_for_inbound",
        ),
        ("get", "/phone-preview/status/123", None, "status"),
        ("get", "/phone-preview/123", None, "status"),
    ],
)
def test_phone_preview_rejects_api_key_auth_before_service_call(
    method, path, json_body, service_method
):
    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)

    with patch(
        f"api.routes.phone_preview.phone_preview_service.{service_method}",
        new=AsyncMock(),
    ) as service_call:
        request = getattr(client, method)
        if json_body is None:
            response = request(path, headers={"X-API-Key": "dgr_test_key"})
        else:
            response = request(
                path, json=json_body, headers={"X-API-Key": "dgr_test_key"}
            )

    assert response.status_code == 403
    assert response.json()["detail"] == "phone_preview_requires_user_session"
    service_call.assert_not_awaited()


def test_start_route_returns_preview_session():
    app = _make_test_app()
    client = TestClient(app)
    expires_at = datetime.now(UTC) + timedelta(minutes=5)

    with patch(
        "api.routes.phone_preview.phone_preview_service.start",
        new=AsyncMock(
            return_value=SimpleNamespace(
                as_dict=lambda: {
                    "session_id": 123,
                    "status": "pending_verification",
                    "otp_required": True,
                    "masked_phone": "+82****5678",
                    "expires_at": expires_at,
                    "workflow_run_id": None,
                    "provider_call_id": None,
                    "failure_reason": None,
                    "dev_otp_code": "123456",
                }
            )
        ),
    ) as start:
        response = client.post(
            "/phone-preview/start",
            json={"workflow_id": 33, "phone_number": "01012345678"},
        )

    assert response.status_code == 200
    assert response.json()["session_id"] == 123
    assert response.json()["otp_required"] is True
    assert response.json()["dev_otp_code"] == "123456"
    start.assert_awaited_once()


def test_start_route_rejects_oversized_payload_before_service_call():
    app = _make_test_app()
    client = TestClient(app)

    with patch(
        "api.routes.phone_preview.phone_preview_service.start",
        new=AsyncMock(),
    ) as start:
        response = client.post(
            "/phone-preview/start",
            json={
                "workflow_id": 33,
                "phone_number": "0" * 41,
                "display_name": "x" * 121,
            },
        )

    assert response.status_code == 422
    start.assert_not_awaited()


def test_call_route_delegates_to_preview_service():
    app = _make_test_app()
    client = TestClient(app)
    expires_at = datetime.now(UTC) + timedelta(minutes=5)

    with patch(
        "api.routes.phone_preview.phone_preview_service.call",
        new=AsyncMock(
            return_value=SimpleNamespace(
                as_dict=lambda: {
                    "session_id": 123,
                    "status": "calling",
                    "otp_required": False,
                    "masked_phone": "+82****5678",
                    "expires_at": expires_at,
                    "workflow_run_id": 501,
                    "provider_call_id": "call-123",
                    "failure_reason": None,
                }
            )
        ),
    ) as call:
        response = client.post("/phone-preview/call", json={"session_id": 123})

    assert response.status_code == 200
    assert response.json()["workflow_run_id"] == 501
    assert "provider_call_id" not in response.json()
    call.assert_awaited_once()


def test_wait_inbound_route_delegates_to_preview_service():
    app = _make_test_app()
    client = TestClient(app)
    expires_at = datetime.now(UTC) + timedelta(minutes=5)

    with patch(
        "api.routes.phone_preview.phone_preview_service.wait_for_inbound",
        new=AsyncMock(
            return_value=SimpleNamespace(
                as_dict=lambda: {
                    "session_id": 123,
                    "status": "awaiting_inbound",
                    "otp_required": False,
                    "masked_phone": "+82****5678",
                    "expires_at": expires_at,
                    "workflow_run_id": None,
                    "provider_call_id": None,
                    "failure_reason": None,
                    "inbound_phone_number": "070-0000-0000",
                }
            )
        ),
    ) as wait_for_inbound:
        response = client.post("/phone-preview/wait-inbound", json={"session_id": 123})

    assert response.status_code == 200
    assert response.json()["status"] == "awaiting_inbound"
    assert response.json()["inbound_phone_number"] == "070-0000-0000"
    assert "provider_call_id" not in response.json()
    wait_for_inbound.assert_awaited_once()


def test_status_route_delegates_to_preview_service():
    app = _make_test_app()
    client = TestClient(app)
    expires_at = datetime.now(UTC) + timedelta(minutes=5)

    with patch(
        "api.routes.phone_preview.phone_preview_service.status",
        new=AsyncMock(
            return_value=SimpleNamespace(
                as_dict=lambda: {
                    "session_id": 123,
                    "status": "completed",
                    "otp_required": False,
                    "masked_phone": "+82****5678",
                    "expires_at": expires_at,
                    "workflow_run_id": 501,
                    "provider_call_id": "call-123",
                    "failure_reason": None,
                }
            )
        ),
    ) as status:
        response = client.get("/phone-preview/status/123")

    assert response.status_code == 200
    assert response.json()["status"] == "completed"
    assert "provider_call_id" not in response.json()
    status.assert_awaited_once()


def test_phone_preview_status_returns_latency_summary_without_raw_logs():
    app = _make_test_app()
    client = TestClient(app)
    expires_at = datetime.now(UTC) + timedelta(minutes=5)
    updated_at = datetime.now(UTC).isoformat()

    with patch(
        "api.routes.phone_preview.phone_preview_service.status",
        new=AsyncMock(
            return_value=SimpleNamespace(
                as_dict=lambda: {
                    "session_id": 123,
                    "status": "calling",
                    "otp_required": False,
                    "masked_phone": "+82****5678",
                    "expires_at": expires_at,
                    "workflow_run_id": 501,
                    "provider_call_id": "call-123",
                    "failure_reason": None,
                    "logs": {
                        "realtime_feedback_events": [
                            {"payload": {"secret": "must-not-leak"}}
                        ]
                    },
                    "latency_summary": {
                        "workflow_run_id": 501,
                        "latency_profile": "speed_demo",
                        "user_stop_to_bot_started_ms": 321.0,
                        "stt_final_ms": 120.0,
                        "llm_ttfb_ms": 80.0,
                        "tts_ttfb_ms": 70.0,
                        "first_response_ms": 450.0,
                        "updated_at": updated_at,
                    },
                }
            )
        ),
    ):
        response = client.get("/phone-preview/status/123")

    assert response.status_code == 200
    payload = response.json()
    assert payload["latency_summary"] == {
        "workflow_run_id": 501,
        "latency_profile": "speed_demo",
        "user_stop_to_bot_started_ms": 321.0,
        "stt_final_ms": 120.0,
        "llm_ttfb_ms": 80.0,
        "tts_ttfb_ms": 70.0,
        "first_response_ms": 450.0,
        "updated_at": updated_at,
    }
    assert "logs" not in payload
    assert "realtime_feedback_events" not in str(payload)
    assert "provider_call_id" not in payload
