from unittest.mock import AsyncMock, patch

import pytest

from api.services.workflow.dto import ReactFlowDTO
from api.services.workflow.pipecat_engine import PipecatEngine
from api.services.workflow.workflow_graph import WorkflowGraph


def _workflow_with_delayed_start() -> WorkflowGraph:
    return WorkflowGraph(
        ReactFlowDTO.model_validate(
            {
                "nodes": [
                    {
                        "id": "start",
                        "type": "startCall",
                        "position": {"x": 0, "y": 0},
                        "data": {
                            "name": "Start",
                            "prompt": "Greet the caller.",
                            "is_start": True,
                            "allow_interrupt": False,
                            "add_global_prompt": False,
                            "delayed_start": True,
                            "delayed_start_duration": 0.4,
                        },
                    }
                ],
                "edges": [],
            }
        )
    )


@pytest.mark.asyncio
async def test_speed_demo_skips_delayed_start_by_default():
    # Given
    engine = PipecatEngine(
        workflow=_workflow_with_delayed_start(),
        call_context_vars={},
        workflow_run_id=1,
        skip_start_node_delayed_start=True,
    )
    start_node = engine.workflow.nodes[engine.workflow.start_node_id]
    engine._setup_llm_context = AsyncMock()
    # When
    with patch(
        "api.services.workflow.pipecat_engine.asyncio.sleep", new_callable=AsyncMock
    ) as sleep_mock:
        await engine._handle_start_node(start_node)
    # Then
    sleep_mock.assert_not_awaited()
    engine._setup_llm_context.assert_awaited_once_with(start_node)
