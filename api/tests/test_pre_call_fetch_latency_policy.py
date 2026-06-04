from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from api.services.pipecat.event_handlers import _merge_pre_call_fetch_result


@pytest.mark.asyncio
async def test_late_pre_call_fetch_preserves_existing_context_keys():
    # Given
    engine = SimpleNamespace(
        _call_context_vars={
            "customer_name": "Existing Customer",
            "lead_id": "lead-123",
        }
    )
    fetch_result = {
        "customer_name": "Fetched Customer",
        "account_tier": "enterprise",
    }
    # When
    with patch(
        "api.services.pipecat.event_handlers.db_client.update_workflow_run",
        new_callable=AsyncMock,
    ) as update_workflow_run:
        merged_keys, conflict_keys = await _merge_pre_call_fetch_result(
            workflow_run_id=1,
            engine=engine,
            fetch_result=fetch_result,
            overwrite_existing=False,
        )
    # Then
    assert engine._call_context_vars["customer_name"] == "Existing Customer"
    assert engine._call_context_vars["account_tier"] == "enterprise"
    assert merged_keys == ["account_tier"]
    assert conflict_keys == ["customer_name"]
    update_workflow_run.assert_awaited_once()
