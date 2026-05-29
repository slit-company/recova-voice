from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.routes.organization_usage import router
from api.services.auth.depends import get_user


def _make_test_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_user] = lambda: SimpleNamespace(
        id=1,
        selected_organization_id=11,
    )
    return app


def test_usage_history_sanitizes_preview_provider_context():
    app = _make_test_app()
    client = TestClient(app)
    preview_run = {
        "id": 501,
        "workflow_id": 33,
        "workflow_name": "Preview Agent",
        "name": "WR-PREVIEW-00000501",
        "created_at": "2026-05-22T10:30:00+00:00",
        "dograh_token_usage": 1.5,
        "call_duration_seconds": 42,
        "recording_url": None,
        "transcript_url": None,
        "public_access_token": None,
        "phone_number": "+82****5678",
        "caller_number": None,
        "called_number": "+82****5678",
        "call_type": "outbound",
        "mode": "twilio",
        "disposition": None,
        "initial_context": {
            "telephony_preview": True,
            "preview_session_id": 123,
            "provider": "twilio",
            "preview_user_id": 1,
            "telephony_configuration_id": 901,
            "phone_number": "+82****5678",
        },
        "gathered_context": {
            "provider": "twilio",
            "call_id": "CA123",
            "provider_call_id": "CA123",
            "safe": "ok",
        },
    }

    with patch("api.routes.organization_usage.db_client") as mock_db:
        mock_db.get_usage_history = AsyncMock(return_value=([preview_run], 1, 1.5, 42))

        response = client.get("/organizations/usage/runs")

    assert response.status_code == 200
    listed = response.json()["runs"][0]
    assert listed["initial_context"] == {
        "telephony_preview": True,
        "preview_session_id": 123,
        "phone_number": "+82****5678",
    }
    assert listed["gathered_context"] == {"safe": "ok"}
