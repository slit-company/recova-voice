from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.routes.phone_preview import router
from api.services.auth.depends import get_user


def _make_test_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_user] = lambda: SimpleNamespace(
        id=7,
        selected_organization_id=11,
    )
    return app


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
    assert response.json()["provider_call_id"] == "call-123"
    call.assert_awaited_once()


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
    status.assert_awaited_once()
