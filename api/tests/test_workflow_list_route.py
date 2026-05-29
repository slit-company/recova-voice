from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.schemas.workflow import WorkflowRunResponseSchema
from api.routes.workflow import router
from api.services.auth.depends import get_user


def _make_test_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_user] = lambda: SimpleNamespace(
        id=1,
        selected_organization_id=11,
    )
    return app


def test_workflow_fetch_list_includes_workflow_uuid():
    app = _make_test_app()
    client = TestClient(app)

    workflow = SimpleNamespace(
        id=5,
        name="Sales Agent",
        status="active",
        created_at=datetime(2026, 5, 22, 10, 30, tzinfo=timezone.utc),
        folder_id=3,
        workflow_uuid="workflow-uuid-123",
    )

    with patch("api.routes.workflow.db_client") as mock_db:
        mock_db.get_all_workflows_for_listing = AsyncMock(return_value=[workflow])
        mock_db.get_workflow_run_counts = AsyncMock(return_value={workflow.id: 9})

        response = client.get("/workflow/fetch")

    assert response.status_code == 200
    assert response.json() == [
        {
            "id": workflow.id,
            "name": workflow.name,
            "status": workflow.status,
            "created_at": "2026-05-22T10:30:00Z",
            "total_runs": 9,
            "folder_id": workflow.folder_id,
            "workflow_uuid": workflow.workflow_uuid,
        }
    ]


def test_workflow_run_detail_sanitizes_preview_provider_context():
    app = _make_test_app()
    client = TestClient(app)
    run = SimpleNamespace(
        id=501,
        workflow_id=33,
        name="WR-PREVIEW-00000501",
        mode="twilio",
        is_completed=False,
        transcript_url=None,
        recording_url=None,
        public_access_token=None,
        cost_info=None,
        created_at=datetime(2026, 5, 22, 10, 30, tzinfo=timezone.utc),
        definition_id=44,
        initial_context={
            "telephony_preview": True,
            "preview_session_id": 123,
            "provider": "twilio",
            "preview_user_id": 1,
            "telephony_configuration_id": 901,
            "telephony_configuration_organization_id": 900,
            "phone_number": "+82****5678",
        },
        gathered_context={
            "provider": "twilio",
            "call_id": "CA123",
            "nested": {"provider_call_id": "CA123", "safe": "ok"},
        },
        call_type="outbound",
        logs={
            "telephony_status_callbacks": [
                {
                    "status": "ringing",
                    "call_id": "CA123",
                    "CallSid": "CA123",
                    "account_sid": "ACSECRET",
                    "To": "+821012345678",
                    "nested": {"provider_call_id": "CA123", "safe": "ok"},
                }
            ]
        },
        annotations={},
    )

    with patch("api.routes.workflow.db_client") as mock_db:
        mock_db.get_workflow_run = AsyncMock(return_value=run)

        response = client.get("/workflow/33/runs/501")

    assert response.status_code == 200
    body = response.json()
    assert body["initial_context"] == {
        "telephony_preview": True,
        "preview_session_id": 123,
        "phone_number": "+82****5678",
    }
    assert body["gathered_context"] == {"nested": {"safe": "ok"}}
    assert body["logs"] == {
        "telephony_status_callbacks": [
            {
                "status": "ringing",
                "nested": {"safe": "ok"},
            }
        ]
    }


def test_workflow_runs_list_sanitizes_preview_provider_context():
    app = _make_test_app()
    client = TestClient(app)
    run = WorkflowRunResponseSchema.model_validate(
        {
            "id": 501,
            "workflow_id": 33,
            "name": "WR-PREVIEW-00000501",
            "mode": "twilio",
            "created_at": datetime(2026, 5, 22, 10, 30, tzinfo=timezone.utc),
            "is_completed": False,
            "transcript_url": None,
            "recording_url": None,
            "cost_info": None,
            "definition_id": 44,
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
                "safe": "ok",
            },
            "call_type": "outbound",
            "logs": {
                "telephony_status_callbacks": [
                    {
                        "status": "ringing",
                        "call_id": "CA123",
                        "account_sid": "ACSECRET",
                    }
                ]
            },
        }
    )

    with patch("api.routes.workflow.db_client") as mock_db:
        mock_db.get_workflow_runs_by_workflow_id = AsyncMock(return_value=([run], 1))

        response = client.get("/workflow/33/runs")

    assert response.status_code == 200
    listed = response.json()["runs"][0]
    assert listed["initial_context"] == {
        "telephony_preview": True,
        "preview_session_id": 123,
        "phone_number": "+82****5678",
    }
    assert listed["gathered_context"] == {"safe": "ok"}
    assert listed["logs"] == {"telephony_status_callbacks": [{"status": "ringing"}]}
