from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from api.enums import WorkflowRunState
from api.routes.telephony import _handle_telephony_websocket


class FakeWebSocket:
    def __init__(self):
        self.close_calls: list[dict] = []

    async def close(self, code: int, reason: str):
        self.close_calls.append({"code": code, "reason": reason})


@pytest.mark.asyncio
async def test_telephony_websocket_rejects_workflow_run_path_mismatch():
    websocket = FakeWebSocket()
    workflow_run = SimpleNamespace(
        id=501,
        workflow_id=33,
        state=WorkflowRunState.INITIALIZED.value,
        initial_context={"telephony_preview": True, "preview_session_id": 123},
        gathered_context={},
        mode="twilio",
    )
    workflow = SimpleNamespace(id=34, user_id=7, organization_id=11)

    with (
        patch("api.routes.telephony.db_client") as mock_db,
        patch(
            "api.routes.telephony.get_telephony_provider_for_run",
            new=AsyncMock(),
        ) as get_provider,
    ):
        mock_db.get_workflow_run = AsyncMock(return_value=workflow_run)
        mock_db.get_workflow_by_id = AsyncMock(return_value=workflow)
        mock_db.update_workflow_run = AsyncMock()

        await _handle_telephony_websocket(
            websocket,
            workflow_id=34,
            user_id=7,
            workflow_run_id=501,
        )

    assert websocket.close_calls == [{"code": 4403, "reason": "Workflow run mismatch"}]
    get_provider.assert_not_awaited()
    mock_db.update_workflow_run.assert_not_awaited()


@pytest.mark.asyncio
async def test_telephony_websocket_rejects_workflow_owner_path_mismatch():
    websocket = FakeWebSocket()
    workflow_run = SimpleNamespace(
        id=501,
        workflow_id=33,
        state=WorkflowRunState.INITIALIZED.value,
        initial_context={"telephony_preview": True, "preview_session_id": 123},
        gathered_context={},
        mode="twilio",
    )
    workflow = SimpleNamespace(id=33, user_id=7, organization_id=11)

    with (
        patch("api.routes.telephony.db_client") as mock_db,
        patch(
            "api.routes.telephony.get_telephony_provider_for_run",
            new=AsyncMock(),
        ) as get_provider,
    ):
        mock_db.get_workflow_run = AsyncMock(return_value=workflow_run)
        mock_db.get_workflow_by_id = AsyncMock(return_value=workflow)
        mock_db.update_workflow_run = AsyncMock()

        await _handle_telephony_websocket(
            websocket,
            workflow_id=33,
            user_id=99,
            workflow_run_id=501,
        )

    assert websocket.close_calls == [
        {"code": 4403, "reason": "Workflow owner mismatch"}
    ]
    get_provider.assert_not_awaited()
    mock_db.update_workflow_run.assert_not_awaited()
