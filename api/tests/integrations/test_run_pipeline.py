"""Integration tests for ``api.services.pipecat.run_pipeline._run_pipeline``.

Drives the actual ``_run_pipeline`` against the test database with real
DB rows (organization, user, user configuration, workflow, workflow run)
and pipecat's real ``MockTransport`` / ``Pipeline`` / ``PipelineTask``.
The only patches are for things that talk to genuinely external systems;
those are applied via ``patch_run_pipeline_externals`` from the shared
helpers module.

Verifies that the wiring done by ``_run_pipeline`` (in particular
``register_event_handlers``) produces the right behaviour end-to-end:
``maybe_trigger_initial_response`` fires (``engine.set_node`` runs), and
on shutdown the workflow run is persisted with the expected state,
completion flag, and ``gathered_context`` entries.
"""

import asyncio
from unittest.mock import patch

import pytest
from pipecat.tests.mock_transport import MockTransport
from pipecat.transports.base_transport import TransportParams
from pipecat.utils.enums import RealtimeFeedbackType

from api.enums import WorkflowRunMode, WorkflowRunState
from api.services.pipecat.audio_config import create_audio_config
from api.services.pipecat.run_pipeline import _run_pipeline
from api.services.workflow.pipecat_engine import PipecatEngine
from api.tests.integrations._run_pipeline_helpers import (
    create_workflow_run_rows,
    PassthroughProcessor,
    patch_run_pipeline_externals,
)

WORKFLOW_DEFINITION = {
    "nodes": [
        {
            "id": "start",
            "type": "startCall",
            "position": {"x": 0, "y": 0},
            "data": {
                "name": "Start",
                "prompt": "You are a helpful assistant. Greet the user briefly.",
                "is_start": True,
                "allow_interrupt": False,
                "add_global_prompt": False,
            },
        },
        {
            "id": "end",
            "type": "endCall",
            "position": {"x": 0, "y": 200},
            "data": {
                "name": "End",
                "prompt": "End the call politely.",
                "is_end": True,
                "allow_interrupt": False,
                "add_global_prompt": False,
            },
        },
    ],
    "edges": [
        {
            "id": "start-end",
            "source": "start",
            "target": "end",
            "data": {"label": "End", "condition": "When the user wants to end."},
        }
    ],
}

PRE_CALL_FETCH_WORKFLOW_DEFINITION = {
    "nodes": [
        {
            "id": "start",
            "type": "startCall",
            "position": {"x": 0, "y": 0},
            "data": {
                "name": "Start",
                "prompt": "You are a helpful assistant. Greet the user briefly.",
                "is_start": True,
                "allow_interrupt": False,
                "add_global_prompt": False,
                "pre_call_fetch_enabled": True,
                "pre_call_fetch_url": "https://example.test/pre-call",
            },
        },
        {
            "id": "end",
            "type": "endCall",
            "position": {"x": 0, "y": 200},
            "data": {
                "name": "End",
                "prompt": "End the call politely.",
                "is_end": True,
                "allow_interrupt": False,
                "add_global_prompt": False,
            },
        },
    ],
    "edges": [
        {
            "id": "start-end",
            "source": "start",
            "target": "end",
            "data": {"label": "End", "condition": "When the user wants to end."},
        }
    ],
}


async def _wait_for_latency_handler(pipeline_task, run_task) -> None:
    for _ in range(60):
        if run_task.done():
            run_task.result()
        observer = pipeline_task.user_bot_latency_observer
        handler = (
            observer._event_handlers.get("on_latency_measured")
            if observer is not None
            else None
        )
        if handler and handler.handlers:
            return
        await asyncio.sleep(0.05)
    raise AssertionError("latency observer handler was never registered")


@pytest.fixture
async def workflow_run_setup(db_session, async_session):
    """Create org/user/user_configuration/workflow/workflow_run rows in the
    test database. Returns (workflow_run, user, workflow)."""
    return await create_workflow_run_rows(
        db_session,
        async_session,
        workflow_definition=WORKFLOW_DEFINITION,
        name_prefix="Event Handler Integration",
        provider_id_suffix="event-handlers",
    )


async def _wait_for_captured_pipeline_task(captured_task: list, run_task) -> None:
    for _ in range(60):
        if captured_task or run_task.done():
            break
        await asyncio.sleep(0.05)
    if run_task.done() and not captured_task:
        run_task.result()
    assert captured_task, "create_pipeline_task was never invoked"


@pytest.mark.asyncio
async def test_run_pipeline_fires_initial_response_and_completes_run(
    workflow_run_setup, db_session
):
    """End-to-end: _run_pipeline boots, register_event_handlers wires up,
    on_pipeline_started + on_client_connected both fire, the initial
    response is triggered (set_node), and on_pipeline_finished updates
    the workflow_run row to COMPLETED."""
    workflow_run, user, workflow = workflow_run_setup
    transport = MockTransport(
        TransportParams(audio_in_enabled=True, audio_out_enabled=True)
    )

    captured_task: list = []
    audio_config = create_audio_config(WorkflowRunMode.SMALLWEBRTC.value)
    with patch_run_pipeline_externals(captured_task):
        run_coro = _run_pipeline(
            transport=transport,
            workflow_id=workflow.id,
            workflow_run_id=workflow_run.id,
            user_id=user.id,
            audio_config=audio_config,
            user_provider_id=user.provider_id,
        )
        run_task = asyncio.create_task(run_coro)

        # Wait until create_pipeline_task is invoked. Surface any
        # exception from _run_pipeline immediately rather than swallowing
        # it during the wait loop.
        for _ in range(60):
            if captured_task or run_task.done():
                break
            await asyncio.sleep(0.05)
        if run_task.done() and not captured_task:
            run_task.result()  # re-raise the failure
        assert captured_task, "create_pipeline_task was never invoked"
        pipeline_task = captured_task[0]
        await asyncio.sleep(0.2)
        # Let the initial response handler (set_node, queue LLMContextFrame)
        # complete before tearing things down.
        await pipeline_task.cancel()
        await asyncio.wait_for(run_task, timeout=5.0)

    # Verify the run was completed end-to-end via the real on_pipeline_finished
    # handler — DB side effects, not mock assertions.
    refreshed = await db_session.get_workflow_run_by_id(workflow_run.id)
    assert refreshed.is_completed is True
    assert refreshed.state == WorkflowRunState.COMPLETED.value
    # set_node("start") populates "nodes_visited" via _gathered_context, and
    # on_pipeline_finished merges call_tags into gathered_context.
    assert "Start" in refreshed.gathered_context.get("nodes_visited", [])
    assert "call_tags" in refreshed.gathered_context


@pytest.mark.asyncio
async def test_run_pipeline_persists_latency_breakdown_event(
    workflow_run_setup, db_session
):
    workflow_run, user, workflow = workflow_run_setup
    transport = MockTransport(
        TransportParams(audio_in_enabled=True, audio_out_enabled=True)
    )

    captured_task: list = []
    audio_config = create_audio_config(WorkflowRunMode.SMALLWEBRTC.value)
    with patch_run_pipeline_externals(captured_task):
        run_coro = _run_pipeline(
            transport=transport,
            workflow_id=workflow.id,
            workflow_run_id=workflow_run.id,
            user_id=user.id,
            audio_config=audio_config,
            user_provider_id=user.provider_id,
        )
        run_task = asyncio.create_task(run_coro)

        for _ in range(60):
            if captured_task or run_task.done():
                break
            await asyncio.sleep(0.05)
        if run_task.done() and not captured_task:
            run_task.result()
        assert captured_task, "create_pipeline_task was never invoked"

        pipeline_task = captured_task[0]
        assert pipeline_task.user_bot_latency_observer is not None
        await _wait_for_latency_handler(pipeline_task, run_task)

        await pipeline_task.user_bot_latency_observer._call_event_handler(
            "on_latency_measured", 0.321
        )

        await pipeline_task.cancel()
        await asyncio.wait_for(run_task, timeout=5.0)

    refreshed = await db_session.get_workflow_run_by_id(workflow_run.id)
    events = (refreshed.logs or {}).get("realtime_feedback_events") or []
    latency_events = [
        event
        for event in events
        if event.get("type") == RealtimeFeedbackType.LATENCY_MEASURED.value
    ]

    assert latency_events, "expected persisted latency feedback event"
    payload = latency_events[-1]["payload"]
    assert payload["kind"] == "voice_latency_breakdown"
    assert payload["workflow_run_id"] == workflow_run.id
    assert payload["user_stop_to_bot_started_ms"] == 321.0
    assert "client_secret" not in str(payload)


@pytest.mark.asyncio
async def test_run_pipeline_surfaces_returnzero_latency_timings_in_canonical_event(
    workflow_run_setup, db_session
):
    workflow_run, user, workflow = workflow_run_setup
    transport = MockTransport(
        TransportParams(audio_in_enabled=True, audio_out_enabled=True)
    )

    captured_task: list = []
    captured_stt_kwargs: list[dict[str, object]] = []
    audio_config = create_audio_config(WorkflowRunMode.SMALLWEBRTC.value)

    def _capture_stt_factory(*_args, **kwargs):
        captured_stt_kwargs.append(kwargs)
        latency_timings = kwargs["latency_timings"]
        latency_timings["returnzero_auth_ms"] = 12.5
        latency_timings["returnzero_ws_connect_ms"] = 34.75
        return PassthroughProcessor()

    with patch_run_pipeline_externals(
        captured_task,
        stt_factory=_capture_stt_factory,
    ):
        run_coro = _run_pipeline(
            transport=transport,
            workflow_id=workflow.id,
            workflow_run_id=workflow_run.id,
            user_id=user.id,
            audio_config=audio_config,
            user_provider_id=user.provider_id,
        )
        run_task = asyncio.create_task(run_coro)

        for _ in range(60):
            if captured_task or run_task.done():
                break
            await asyncio.sleep(0.05)
        if run_task.done() and not captured_task:
            run_task.result()
        assert captured_task, "create_pipeline_task was never invoked"
        assert captured_stt_kwargs, "create_stt_service was never invoked"

        pipeline_task = captured_task[0]
        await _wait_for_latency_handler(pipeline_task, run_task)

        await pipeline_task.user_bot_latency_observer._call_event_handler(
            "on_latency_measured", 0.111
        )

        await pipeline_task.cancel()
        await asyncio.wait_for(run_task, timeout=5.0)

    refreshed = await db_session.get_workflow_run_by_id(workflow_run.id)
    events = (refreshed.logs or {}).get("realtime_feedback_events") or []
    latency_events = [
        event
        for event in events
        if event.get("type") == RealtimeFeedbackType.LATENCY_MEASURED.value
    ]

    assert latency_events, "expected persisted latency feedback event"
    payload = latency_events[-1]["payload"]
    assert payload["returnzero_auth_ms"] == 12.5
    assert payload["returnzero_ws_connect_ms"] == 34.75


@pytest.mark.asyncio
async def test_speed_demo_does_not_block_initial_response_on_optional_pre_call_fetch(
    db_session, async_session
):
    # Given
    workflow_run, user, workflow = await create_workflow_run_rows(
        db_session,
        async_session,
        workflow_definition=PRE_CALL_FETCH_WORKFLOW_DEFINITION,
        workflow_configurations={"latency_profile": "speed_demo"},
        name_prefix="Optional Pre Call Fetch",
        provider_id_suffix="optional-pre-call-fetch",
    )
    transport = MockTransport(
        TransportParams(audio_in_enabled=True, audio_out_enabled=True)
    )
    captured_task: list = []
    fetch_result = asyncio.Future()
    set_node_started = asyncio.Event()
    original_set_node = PipecatEngine.set_node

    async def _fetch_late(**_kwargs):
        return await fetch_result

    async def _observed_set_node(
        self, node_id: str, emit_transition_event: bool = True
    ):
        set_node_started.set()
        return await original_set_node(self, node_id, emit_transition_event)

    audio_config = create_audio_config(WorkflowRunMode.SMALLWEBRTC.value)
    with (
        patch(
            "api.services.pipecat.run_pipeline.execute_pre_call_fetch",
            side_effect=_fetch_late,
        ),
        patch.object(PipecatEngine, "set_node", new=_observed_set_node),
        patch_run_pipeline_externals(captured_task),
    ):
        run_task = None
        try:
            # When
            run_task = asyncio.create_task(
                _run_pipeline(
                    transport=transport,
                    workflow_id=workflow.id,
                    workflow_run_id=workflow_run.id,
                    user_id=user.id,
                    audio_config=audio_config,
                    user_provider_id=user.provider_id,
                )
            )
            await _wait_for_captured_pipeline_task(captured_task, run_task)
            await asyncio.wait_for(set_node_started.wait(), timeout=1.2)
            # Then
            assert fetch_result.done() is False
        finally:
            if not fetch_result.done():
                fetch_result.cancel()
            if captured_task:
                await captured_task[0].cancel()
            if run_task is not None:
                await asyncio.wait_for(run_task, timeout=5.0)


@pytest.mark.asyncio
async def test_required_pre_call_fetch_still_blocks_until_timeout_or_result(
    db_session, async_session
):
    # Given
    workflow_run, user, workflow = await create_workflow_run_rows(
        db_session,
        async_session,
        workflow_definition=PRE_CALL_FETCH_WORKFLOW_DEFINITION,
        workflow_configurations={
            "latency_profile": "custom",
            "pre_call_fetch_required": True,
            "pre_call_fetch_timeout_seconds": 0.1,
        },
        name_prefix="Required Pre Call Fetch",
        provider_id_suffix="required-pre-call-fetch",
    )
    transport = MockTransport(
        TransportParams(audio_in_enabled=True, audio_out_enabled=True)
    )
    captured_task: list = []
    fetch_result = asyncio.Future()
    set_node_started = asyncio.Event()
    original_set_node = PipecatEngine.set_node

    async def _fetch_never_finishes(**_kwargs):
        return await fetch_result

    async def _observed_set_node(
        self, node_id: str, emit_transition_event: bool = True
    ):
        set_node_started.set()
        return await original_set_node(self, node_id, emit_transition_event)

    audio_config = create_audio_config(WorkflowRunMode.SMALLWEBRTC.value)
    started_at = asyncio.get_running_loop().time()
    with (
        patch(
            "api.services.pipecat.run_pipeline.execute_pre_call_fetch",
            side_effect=_fetch_never_finishes,
        ),
        patch.object(PipecatEngine, "set_node", new=_observed_set_node),
        patch_run_pipeline_externals(captured_task),
    ):
        run_task = None
        try:
            # When
            run_task = asyncio.create_task(
                _run_pipeline(
                    transport=transport,
                    workflow_id=workflow.id,
                    workflow_run_id=workflow_run.id,
                    user_id=user.id,
                    audio_config=audio_config,
                    user_provider_id=user.provider_id,
                )
            )
            await _wait_for_captured_pipeline_task(captured_task, run_task)
            await asyncio.wait_for(set_node_started.wait(), timeout=0.8)
            # Then
            assert asyncio.get_running_loop().time() - started_at >= 0.1
        finally:
            if not fetch_result.done():
                fetch_result.set_result({})
            if captured_task:
                await captured_task[0].cancel()
            if run_task is not None:
                await asyncio.wait_for(run_task, timeout=5.0)
