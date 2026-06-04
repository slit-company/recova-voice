# ReturnZero Latency Optimization Plan

## TL;DR
> **Summary**: Optimize Recova's standard STT -> LLM -> TTS phone path for Korean B2B demo calls with ReturnZero as the fixed STT provider, starting with latency observability and then reducing avoidable wait in ReturnZero connect, turn stopping, TTS aggregation, and first-response startup.
> **Deliverables**:
> - Persisted per-stage latency breakdown for phone preview and telephony runs.
> - ReturnZero STT latency hardening: token cache, connection timings, measured TTFS P99 support.
> - Workflow-level latency profile with `balanced`, `speed_demo`, and `custom`.
> - Configurable turn-stop timeout and TTS aggregation silence.
> - Speed-demo defaults for phone preview and Korean demo workflows.
> - Repeatable benchmark and manual QA evidence path.
> **Effort**: Large
> **Parallel**: YES - 5 waves
> **Critical Path**: Tasks 1/2/3 -> Tasks 4/5/6/7 -> Task 8 -> Task 9 -> Task 10 -> Final Verification

## Context
### Original Request
The user said ReturnZero STT has been added and is intended to be fixed going forward, then asked for a source-code-grounded, external-research-backed plan to reduce latency aggressively.

### Interview Summary
No blocking product questions remain. Defaults applied:
- Optimize the self-serve Korean B2B demo/test-call path first.
- Keep campaign/production safety behavior configurable instead of globally removing safeguards.
- Treat ReturnZero as the default target STT provider for the Recova demo path, while preserving existing configs unless explicitly migrated.
- Use measured baseline improvement as the main success criterion because current live latency is not yet captured.

### Metis Review
Gaps addressed in this plan:
- Scope is fixed to standard non-realtime phone preview and telephony calls first. Realtime is out of scope except regression checks.
- New config values live in `workflow_configurations`, with UI preservation fixes so old dialogs do not drop unknown keys.
- Speed profile is rollbackable by switching `latency_profile` from `speed_demo` to `balanced`.
- ReturnZero `ttfs_p99_latency` is not guessed permanently. The implementation must benchmark it and set a measured value using the algorithm in Task 2.
- Pre-call fetch has explicit strict vs fast fallback behavior.
- Manual QA has concrete tmux/HTTP/browser scenarios.

## Work Objectives
### Core Objective
Reduce Recova Korean demo-call latency in the standard STT + LLM + TTS path without losing debuggability, transcripts, reports, or tenant isolation.

### Deliverables
- Backend event schema and persisted latency breakdown.
- ReturnZero STT service timing and token-cache improvements.
- Workflow latency profile config and UI controls.
- Faster turn-stop and TTS aggregation defaults for demo calls.
- First-response startup policy for pre-call fetch, greeting, delayed start, and barge-in.
- Benchmarks and QA artifacts under `evidence/returnzero-latency/`.

### Definition of Done
- `source venv/bin/activate && set -a && source api/.env.test && set +a && python -m pytest api/tests/test_returnzero_stt.py api/tests/test_run_pipeline_latency_config.py api/tests/integrations/test_run_pipeline.py api/tests/test_user_muting_during_bot_speech.py api/tests/test_phone_preview_service.py`
- `cd ui && npm run build`
- `git diff --check`
- A benchmark artifact exists at `evidence/returnzero-latency/final-benchmark.json` showing `speed_demo` improves deterministic mocked `user_stop_to_bot_started_ms` by at least 400ms versus `balanced`.
- If ReturnZero credentials are available in the environment, a real ReturnZero benchmark artifact exists. If credentials are absent, the evidence file must explicitly record `skipped_real_returnzero=true`.

### Must Have
- All organization-scoped reads/writes must preserve `organization_id` checks.
- Existing workflows remain `balanced` unless explicitly set to `speed_demo` or `custom`.
- Phone preview can use `speed_demo` defaults without mutating a user's saved workflow unless the user saves.
- Every latency metric is tied to `workflow_run_id`.
- ReturnZero credentials remain masked and are never logged.

### Must NOT Have
- No blind Realtime migration.
- No global search-and-replace rebrand.
- No hardcoded shared ReturnZero credentials.
- No silent fallback from ReturnZero to another STT provider during demo calls; surface a clear pipeline error instead.
- No blanket TTS behavior change for providers that do not accept the same aggregator parameter.

## Verification Strategy
> ZERO HUMAN INTERVENTION - all verification is agent-executed.
- Test decision: TDD for every production code change, using existing `pytest` and `npm run build`.
- QA policy: Every task has at least one agent-run scenario.
- Evidence root: `evidence/returnzero-latency/`.
- Manual QA channels: tmux for benchmark/CLI scenarios, HTTP for backend routes, Browser for phone-preview UI.

## External References
- ReturnZero streaming docs: `https://developers.rtzr.ai/docs/en/stt-streaming/websocket/`
- ReturnZero auth docs: `https://developers.rtzr.ai/docs/en/authentications/`
- ReturnZero pricing/concurrency docs: `https://developers.rtzr.ai/docs/en/pricing/`, `https://developers.rtzr.ai/docs/en/rate_limit/`
- ReturnZero Python samples: `https://github.com/vito-ai/python-tutorial/tree/16ef85c9d61edcb65cbe92a527b1ddb817fbf298/python-stt-sample/src`
- Pipecat STT latency model: `https://github.com/pipecat-ai/pipecat/blob/a27d2132b5857106785d6f2774ceda714999b54c/src/pipecat/services/stt_latency.py`
- Pipecat speech timeout strategy: `https://github.com/pipecat-ai/pipecat/blob/a27d2132b5857106785d6f2774ceda714999b54c/src/pipecat/turns/user_stop/speech_timeout_user_turn_stop_strategy.py`
- Pipecat latency observer example: `https://github.com/pipecat-ai/pipecat/blob/a27d2132b5857106785d6f2774ceda714999b54c/examples/turn-management/turn-management-turn-tracking-observer.py`
- LiveKit multilingual turn detector: `https://github.com/livekit/agents/blob/04567b9acfa5e90a442c3fbd366dcf3cd24ccbf2/livekit-plugins/livekit-plugins-turn-detector/README.md`
- Vapi voice pipeline configuration: `https://docs.vapi.ai/customization/voice-pipeline-configuration`

## Execution Strategy
### Parallel Execution Waves
Wave 1: Tasks 1, 2, 3
Wave 2: Tasks 4, 5, 6, 7
Wave 3: Task 8
Wave 4: Task 9
Wave 5: Task 10 and Final Verification

### Dependency Matrix
- Task 1 blocks Tasks 8, 10, Final Verification.
- Task 2 blocks Task 4 and Task 8.
- Task 3 blocks Tasks 4, 5, 6, 7, 8.
- Task 4 and Task 5 block Task 8.
- Task 6 blocks Task 8.
- Task 7 blocks Task 8.
- Task 8 creates the importable `api.scripts` package and blocks Task 9.
- Task 9 blocks Task 10 and Final Verification.
- Task 10 waits for all implementation tasks.

## Execution Tasks
- [x] 1. Add Canonical Latency Breakdown Events

  **What to do**: Add a single latency-event schema and collector for standard voice runs. Reuse existing frame/observer hooks instead of inventing a second telemetry system. Persist the canonical event through `api/services/pipecat/in_memory_buffers.py::InMemoryLogsBuffer.append()` as `{"type": RealtimeFeedbackType.LATENCY_MEASURED.value, "payload": {"kind": "voice_latency_breakdown", ...}}`; `api/services/pipecat/event_handlers.py::on_pipeline_finished()` must then save it to `workflow_runs.logs.realtime_feedback_events` via `db_client.update_workflow_run(logs={"realtime_feedback_events": feedback_events})`, following the current save path at `api/services/pipecat/event_handlers.py:356-375`. Include at least: `workflow_run_id`, `latency_profile`, `pipeline_started_at`, `client_connected_at`, `initial_response_triggered_at`, `pre_call_fetch_wait_ms`, `returnzero_auth_ms`, `returnzero_ws_connect_ms`, `stt_first_interim_ms`, `stt_final_ms`, `vad_stop_to_final_ms`, `user_turn_stopped_at`, `llm_ttfb_ms`, `tts_ttfb_ms`, `bot_started_speaking_at`, `first_response_ms`, `user_stop_to_bot_started_ms`, and Pipecat `on_latency_breakdown` payload when available. Define `first_response_ms` as the first observed `bot_started_speaking_at - client_connected_at` for the run; if `client_connected_at` is unavailable, fall back to `bot_started_speaking_at - pipeline_started_at` and add `first_response_ms_fallback="pipeline_started_at"`.

  **Must NOT do**: Do not log audio, raw credentials, or unmasked phone numbers. Do not remove existing `RealtimeFeedbackType.LATENCY_MEASURED` events.

  **Parallelization**: Can Parallel: YES | Wave 1 | Blocks: 8, 10 | Blocked By: none

  **References**:
  - Pattern: `api/services/pipecat/run_pipeline.py:783` - existing user-bot latency append path.
  - Persistence target: `api/services/pipecat/in_memory_buffers.py:79` - app-level logs buffer.
  - Persistence target: `api/services/pipecat/event_handlers.py:356` - saves `realtime_feedback_events` to `workflow_runs.logs`.
  - Persistence target: `api/db/workflow_run_client.py:351` - `update_workflow_run(logs=...)` merges log keys.
  - Pattern: `api/services/pipecat/realtime_feedback_observer.py:294` - existing TTFB frame observer.
  - Pattern: `api/services/integrations/tuner/collector.py:108` - already attaches `on_latency_breakdown`.
  - Pattern: `api/services/pipecat/pipeline_metrics_aggregator.py:45` - current metrics frame aggregation point.
  - API: `pipecat/src/pipecat/pipeline/task.py:289` - `UserBotLatencyObserver` is created when turn tracking is enabled.

  **Acceptance Criteria**:
  - [ ] New unit test fails red first and passes green: `api/tests/test_latency_events.py::test_latency_breakdown_event_redacts_sensitive_fields`.
  - [ ] Integration test fails red first and passes green: `api/tests/integrations/test_run_pipeline.py::test_run_pipeline_persists_latency_breakdown_event`.
  - [ ] Latency events are present in logs buffer with `workflow_run_id` and no secrets.

  **QA Scenarios**:
  ```
  Scenario: Mock pipeline emits persisted latency breakdown
    Tool: tmux
    Steps: tmux new-session -d -s ulw-qa-latency-events 'cd /Users/slit/projects/dograh && source venv/bin/activate && set -a && source api/.env.test && set +a && python -m pytest api/tests/integrations/test_run_pipeline.py::test_run_pipeline_persists_latency_breakdown_event -q | tee evidence/returnzero-latency/task-1-latency-events.txt'
    Expected: command exits 0 and evidence file contains 1 passed
    Evidence: evidence/returnzero-latency/task-1-latency-events.txt

  Scenario: Sensitive fields are redacted
    Tool: tmux
    Steps: tmux new-session -d -s ulw-qa-latency-redaction 'cd /Users/slit/projects/dograh && source venv/bin/activate && set -a && source api/.env.test && set +a && python -m pytest api/tests/test_latency_events.py::test_latency_breakdown_event_redacts_sensitive_fields -q | tee evidence/returnzero-latency/task-1-redaction.txt'
    Expected: command exits 0 and evidence file contains no client_secret, Authorization, or phone number literal
    Evidence: evidence/returnzero-latency/task-1-redaction.txt
  ```

  **Commit**: YES | Message: `feat(voice): persist latency breakdown events` | Files: `api/services/pipecat/*`, `api/tests/test_latency_events.py`, `api/tests/integrations/test_run_pipeline.py`

- [x] 2. Harden ReturnZero STT Startup Latency

  **What to do**: Add a module-level ReturnZero token cache keyed by `(api_base_url, sha256(client_id), sha256(client_secret))`, guarded by an async lock. Reuse tokens until `expire_at - 300s`. Record auth and websocket connection duration into the latency collector from Task 1. Add `ttfs_p99_latency` support to `ReturnZeroSTTService`. Initial default algorithm: if `workflow_configurations.returnzero_ttfs_p99_latency_seconds` is set, use it; else if `RETURNZERO_TTFS_P99_SECONDS` env is set, use it; else use `None` and let Pipecat default to 1.0 until Task 8 benchmarks a measured value.

  **Must NOT do**: Do not cache plaintext secrets in event payloads or logs. Do not share websocket connections across calls. Do not change ReturnZero WebSocket query parameter names.

  **Parallelization**: Can Parallel: YES | Wave 1 | Blocks: 4, 8 | Blocked By: none

  **References**:
  - Current implementation: `api/services/pipecat/returnzero_stt.py:123` - connect path.
  - Current auth: `api/services/pipecat/returnzero_stt.py:206` - token fetch.
  - Current service factory: `api/services/pipecat/service_factory.py:218` - ReturnZero branch.
  - Pipecat metadata: `pipecat/src/pipecat/services/stt_service.py:471` - missing TTFS falls back to default.
  - Test pattern: `api/tests/test_returnzero_stt.py:154` - URL/query tests.
  - External: ReturnZero auth docs and WebSocket docs above.

  **Acceptance Criteria**:
  - [ ] `api/tests/test_returnzero_stt.py::test_returnzero_token_cache_reuses_valid_token` RED->GREEN.
  - [ ] `api/tests/test_returnzero_stt.py::test_returnzero_service_passes_configured_ttfs_p99_latency` RED->GREEN.
  - [ ] `api/tests/test_returnzero_stt.py::test_returnzero_connect_records_auth_and_websocket_timings` RED->GREEN.

  **QA Scenarios**:
  ```
  Scenario: Local fake ReturnZero auth is called once for two service connects
    Tool: tmux
    Steps: tmux new-session -d -s ulw-qa-returnzero-cache 'cd /Users/slit/projects/dograh && source venv/bin/activate && set -a && source api/.env.test && set +a && python -m pytest api/tests/test_returnzero_stt.py::test_returnzero_token_cache_reuses_valid_token -q | tee evidence/returnzero-latency/task-2-token-cache.txt'
    Expected: command exits 0 and assertion shows one auth call
    Evidence: evidence/returnzero-latency/task-2-token-cache.txt

  Scenario: ReturnZero TTFS metadata is configurable
    Tool: tmux
    Steps: tmux new-session -d -s ulw-qa-returnzero-ttfs 'cd /Users/slit/projects/dograh && source venv/bin/activate && set -a && source api/.env.test && set +a && python -m pytest api/tests/test_returnzero_stt.py::test_returnzero_service_passes_configured_ttfs_p99_latency -q | tee evidence/returnzero-latency/task-2-ttfs.txt'
    Expected: command exits 0 and service constructor stores the configured TTFS value
    Evidence: evidence/returnzero-latency/task-2-ttfs.txt
  ```

  **Commit**: YES | Message: `perf(stt): cache returnzero auth and expose ttfs` | Files: `api/services/pipecat/returnzero_stt.py`, `api/services/pipecat/service_factory.py`, `api/tests/test_returnzero_stt.py`

- [x] 3. Add Workflow Latency Profile Configuration

  **What to do**: Add workflow config keys:
  - `latency_profile`: `"balanced" | "speed_demo" | "custom"`, default `"balanced"`.
  - `user_speech_timeout_seconds`: optional float, valid `0.25..1.5`.
  - `tts_aggregation_silence_seconds`: optional float, valid `0.2..1.5`.
  - `pre_call_fetch_timeout_seconds`: optional float, valid `0.1..10`.
  - `pre_call_fetch_required`: optional bool, default `true` for `balanced`, `false` for `speed_demo`.
  - `returnzero_ttfs_p99_latency_seconds`: optional float, valid `0.2..3.0`.
  - `speed_profile_respect_delayed_start`: optional bool, default `false`.
  Backend helper must resolve effective values with this order:
  - First, if `workflow_run.initial_context.runtime_latency_profile` is one of `"balanced" | "speed_demo" | "custom"`, use it as a transient runtime override. This field is allowed only for phone-preview/demo runs and must not be written back to workflow definitions.
  - Second, use `workflow_configurations.latency_profile` from the pinned workflow definition.
  - Third, fall back to `"balanced"`.
  - `balanced`: current behavior, `user_speech_timeout=0.6`, TTS existing provider default, pre-call fetch waits up to current timeout.
  - `speed_demo`: `user_speech_timeout=0.35`, `tts_aggregation_silence_seconds=0.35`, `pre_call_fetch_timeout_seconds=0.5`, `pre_call_fetch_required=false`, delayed start skipped unless `speed_profile_respect_delayed_start=true`.
  - `custom`: explicit values only; missing values fall back to `balanced`.

  **Must NOT do**: Do not drop existing unknown `workflow_configurations` keys. Do not migrate existing workflows to speed mode automatically.

  **Parallelization**: Can Parallel: YES | Wave 1 | Blocks: 4, 5, 6, 7, 8 | Blocked By: none

  **References**:
  - Current config read: `api/services/pipecat/run_pipeline.py:365`.
  - UI types: `ui/src/types/workflow-configurations.ts:57`.
  - Settings dialog currently drops keys: `ui/src/app/workflow/[workflowId]/components/ConfigurationsDialog.tsx:55`.
  - Settings page preserves spread pattern: `ui/src/app/workflow/[workflowId]/settings/page.tsx:353`.
  - Workflow config save path: `ui/src/app/workflow/[workflowId]/hooks/useWorkflowState.ts:468`.

  **Acceptance Criteria**:
  - [ ] `api/tests/test_latency_profile_config.py::test_speed_demo_profile_resolves_expected_defaults` RED->GREEN.
  - [ ] `api/tests/test_latency_profile_config.py::test_runtime_initial_context_profile_overrides_workflow_config_for_preview` RED->GREEN.
  - [ ] `api/tests/test_latency_profile_config.py::test_custom_profile_validates_bounds` RED->GREEN.
  - [ ] UI build succeeds after adding TypeScript keys and controls.
  - [ ] `ConfigurationsDialog` saves by spreading existing configuration before overriding known fields.

  **QA Scenarios**:
  ```
  Scenario: Speed profile resolves deterministic defaults
    Tool: tmux
    Steps: tmux new-session -d -s ulw-qa-profile-defaults 'cd /Users/slit/projects/dograh && source venv/bin/activate && set -a && source api/.env.test && set +a && python -m pytest api/tests/test_latency_profile_config.py::test_speed_demo_profile_resolves_expected_defaults -q | tee evidence/returnzero-latency/task-3-profile.txt'
    Expected: command exits 0 and output contains 1 passed
    Evidence: evidence/returnzero-latency/task-3-profile.txt

  Scenario: Frontend accepts latency profile keys
    Tool: tmux
    Steps: tmux new-session -d -s ulw-qa-profile-ui 'cd /Users/slit/projects/dograh/ui && npm run build | tee ../evidence/returnzero-latency/task-3-ui-build.txt'
    Expected: command exits 0
    Evidence: evidence/returnzero-latency/task-3-ui-build.txt
  ```

  **Commit**: YES | Message: `feat(config): add voice latency profiles` | Files: `api/services/pipecat/latency_config.py`, `api/tests/test_latency_profile_config.py`, `ui/src/types/workflow-configurations.ts`, `ui/src/app/workflow/[workflowId]/components/ConfigurationsDialog.tsx`, `ui/src/app/workflow/[workflowId]/settings/page.tsx`

- [x] 4. Apply Configurable Turn Stop Timing

  **What to do**: In `run_pipeline.py`, resolve latency config from Task 3 and pass `SpeechTimeoutUserTurnStopStrategy(user_speech_timeout=resolved.user_speech_timeout_seconds)` for standard non-realtime transcription mode. Apply the same resolved value only to realtime providers that still use local VAD + speech-timeout (`GOOGLE_REALTIME`, `GOOGLE_VERTEX_REALTIME`, unknown local-VAD realtime); do not apply it to OpenAI/Grok external-turn providers.

  **Must NOT do**: Do not lower `VADParams(stop_secs=0.2)` in this task. Pipecat's built-in TTFS values assume 0.2.

  **Parallelization**: Can Parallel: YES | Wave 2 | Blocks: 8 | Blocked By: 2, 3

  **References**:
  - Current hardcode: `api/services/pipecat/run_pipeline.py:620`.
  - Realtime helper tests: `api/tests/test_run_pipeline_realtime_turn_config.py:17`.
  - Pipecat strategy default: `pipecat/src/pipecat/turns/user_stop/speech_timeout_user_turn_stop_strategy.py:48`.
  - Pipecat STT latency warning: `pipecat/src/pipecat/services/stt_latency.py:16`.

  **Acceptance Criteria**:
  - [ ] `api/tests/test_run_pipeline_latency_config.py::test_standard_speed_demo_uses_350ms_user_speech_timeout` RED->GREEN.
  - [ ] `api/tests/test_run_pipeline_latency_config.py::test_balanced_profile_keeps_600ms_user_speech_timeout` RED->GREEN.
  - [ ] Existing realtime turn-config tests still pass.

  **QA Scenarios**:
  ```
  Scenario: Standard speed profile uses 350ms speech timeout
    Tool: tmux
    Steps: tmux new-session -d -s ulw-qa-turn-speed 'cd /Users/slit/projects/dograh && source venv/bin/activate && set -a && source api/.env.test && set +a && python -m pytest api/tests/test_run_pipeline_latency_config.py::test_standard_speed_demo_uses_350ms_user_speech_timeout -q | tee evidence/returnzero-latency/task-4-turn-speed.txt'
    Expected: command exits 0 and assertion observes 0.35
    Evidence: evidence/returnzero-latency/task-4-turn-speed.txt

  Scenario: Realtime external-turn providers are unchanged
    Tool: tmux
    Steps: tmux new-session -d -s ulw-qa-turn-realtime 'cd /Users/slit/projects/dograh && source venv/bin/activate && set -a && source api/.env.test && set +a && python -m pytest api/tests/test_run_pipeline_realtime_turn_config.py -q | tee evidence/returnzero-latency/task-4-realtime.txt'
    Expected: command exits 0
    Evidence: evidence/returnzero-latency/task-4-realtime.txt
  ```

  **Commit**: YES | Message: `perf(voice): make turn stop timeout configurable` | Files: `api/services/pipecat/run_pipeline.py`, `api/services/pipecat/latency_config.py`, `api/tests/test_run_pipeline_latency_config.py`, `api/tests/test_run_pipeline_realtime_turn_config.py`

- [x] 5. Apply Low-Latency TTS Aggregation Per Provider

  **What to do**: Change `create_tts_service` to accept `aggregation_silence_seconds: float | None`. In `run_pipeline.py`, pass the resolved profile value. For providers that already pass `silence_time_s`, use the override. For providers that do not currently pass `silence_time_s` (for example CAMB), leave them unchanged and add a comment/test documenting unsupported override. Keep OpenAI default at 0.35 when no override is supplied.

  **Must NOT do**: Do not force a single text aggregation mode across all provider SDKs. Do not alter voice/model/speed semantics.

  **Parallelization**: Can Parallel: YES | Wave 2 | Blocks: 8 | Blocked By: 3

  **References**:
  - Current Deepgram TTS: `api/services/pipecat/service_factory.py:286`.
  - Current OpenAI TTS constant: `api/services/pipecat/service_factory.py:65`.
  - Current ElevenLabs TTS: `api/services/pipecat/service_factory.py:332`.
  - Pipecat OpenAI streaming pattern: external GitHub `src/pipecat/services/openai/tts.py`.

  **Acceptance Criteria**:
  - [ ] `api/tests/test_tts_latency_config.py::test_speed_demo_overrides_elevenlabs_aggregation_silence` RED->GREEN.
  - [ ] `api/tests/test_tts_latency_config.py::test_openai_keeps_035_default_when_no_override` RED->GREEN.
  - [ ] `api/tests/test_tts_latency_config.py::test_unsupported_tts_provider_ignores_override_explicitly` RED->GREEN.

  **QA Scenarios**:
  ```
  Scenario: ElevenLabs TTS gets 350ms aggregation in speed profile
    Tool: tmux
    Steps: tmux new-session -d -s ulw-qa-tts-speed 'cd /Users/slit/projects/dograh && source venv/bin/activate && set -a && source api/.env.test && set +a && python -m pytest api/tests/test_tts_latency_config.py::test_speed_demo_overrides_elevenlabs_aggregation_silence -q | tee evidence/returnzero-latency/task-5-tts-speed.txt'
    Expected: command exits 0 and mock service receives silence_time_s=0.35
    Evidence: evidence/returnzero-latency/task-5-tts-speed.txt

  Scenario: Existing OpenAI default remains 350ms
    Tool: tmux
    Steps: tmux new-session -d -s ulw-qa-tts-openai 'cd /Users/slit/projects/dograh && source venv/bin/activate && set -a && source api/.env.test && set +a && python -m pytest api/tests/test_tts_latency_config.py::test_openai_keeps_035_default_when_no_override -q | tee evidence/returnzero-latency/task-5-openai.txt'
    Expected: command exits 0
    Evidence: evidence/returnzero-latency/task-5-openai.txt
  ```

  **Commit**: YES | Message: `perf(tts): honor latency profile aggregation silence` | Files: `api/services/pipecat/service_factory.py`, `api/services/pipecat/run_pipeline.py`, `api/tests/test_tts_latency_config.py`

- [x] 6. Reduce First-Response Startup Blocking

  **What to do**: Implement fast optional pre-call fetch. In `speed_demo`, wait at most `pre_call_fetch_timeout_seconds=0.5`. If `pre_call_fetch_required=false` and the task is still pending, start the node/greeting immediately. When the late fetch completes, merge only non-conflicting keys into `engine._call_context_vars` and `workflow_runs.initial_context`; if a fetched key already exists, preserve the existing value, do not overwrite it, and record the key name under `pre_call_fetch_late_conflict_keys`. Late values are available only for future template renders, node transitions, and custom-tool payloads; they are never retroactively injected into a greeting or LLM context that was already rendered. Persist latency/log payload fields `pre_call_fetch_late=true`, `pre_call_fetch_late_keys`, and `pre_call_fetch_late_conflict_keys`. If `pre_call_fetch_required=true`, preserve current strict behavior except apply the configured timeout and fail cleanly on timeout. In `speed_demo`, skip `delayed_start` unless `speed_profile_respect_delayed_start=true`. Emit latency events for skipped/waited paths.

  **Must NOT do**: Do not break templated greeting correctness for strict pre-call fetch workflows. Do not mutate saved workflow node data at runtime; apply policy to the runtime `WorkflowGraph`/engine instance only.

  **Parallelization**: Can Parallel: YES | Wave 2 | Blocks: 8 | Blocked By: 3

  **References**:
  - Current pre-call task creation: `api/services/pipecat/run_pipeline.py:456`.
  - Current startup wait: `api/services/pipecat/event_handlers.py:118`.
  - Current node start: `api/services/pipecat/event_handlers.py:155`.
  - Current strict merge target: `api/services/pipecat/event_handlers.py:144` - pre-call fetch updates `engine._call_context_vars` and `workflow_runs.initial_context`.
  - Current delayed start sleep: `api/services/workflow/pipecat_engine.py:591`.
  - Start node config: `api/services/workflow/dto.py:287`.

  **Acceptance Criteria**:
  - [ ] `api/tests/integrations/test_run_pipeline.py::test_speed_demo_does_not_block_initial_response_on_optional_pre_call_fetch` RED->GREEN.
  - [ ] `api/tests/integrations/test_run_pipeline.py::test_required_pre_call_fetch_still_blocks_until_timeout_or_result` RED->GREEN.
  - [ ] `api/tests/test_pipecat_engine_latency_startup.py::test_speed_demo_skips_delayed_start_by_default` RED->GREEN.

  **QA Scenarios**:
  ```
  Scenario: Optional slow pre-call fetch does not delay first response
    Tool: tmux
    Steps: tmux new-session -d -s ulw-qa-prefetch-fast 'cd /Users/slit/projects/dograh && source venv/bin/activate && set -a && source api/.env.test && set +a && python -m pytest api/tests/integrations/test_run_pipeline.py::test_speed_demo_does_not_block_initial_response_on_optional_pre_call_fetch -q | tee evidence/returnzero-latency/task-6-prefetch-fast.txt'
    Expected: command exits 0 and assertion shows initial response before fake fetch completion
    Evidence: evidence/returnzero-latency/task-6-prefetch-fast.txt

  Scenario: Strict pre-call fetch preserves old behavior
    Tool: tmux
    Steps: tmux new-session -d -s ulw-qa-prefetch-strict 'cd /Users/slit/projects/dograh && source venv/bin/activate && set -a && source api/.env.test && set +a && python -m pytest api/tests/integrations/test_run_pipeline.py::test_required_pre_call_fetch_still_blocks_until_timeout_or_result -q | tee evidence/returnzero-latency/task-6-prefetch-strict.txt'
    Expected: command exits 0
    Evidence: evidence/returnzero-latency/task-6-prefetch-strict.txt
  ```

  **Commit**: YES | Message: `perf(voice): timebox demo pre-call startup work` | Files: `api/services/pipecat/event_handlers.py`, `api/services/pipecat/run_pipeline.py`, `api/services/workflow/pipecat_engine.py`, `api/tests/integrations/test_run_pipeline.py`, `api/tests/test_pipecat_engine_latency_startup.py`

- [x] 7. Set Demo Defaults For Greeting And Barge-In

  **What to do**: For new Recova demo workflows and phone-preview-only runtime overrides, default start/agent nodes to `allow_interrupt=true`, `delayed_start=false`, and this exact short Korean text greeting when no greeting exists: `안녕하세요, Recova 데모 상담원입니다. 무엇을 도와드릴까요?`. For saved new blank workflows, update `ui/src/components/workflow/CreateWorkflowButton.tsx` start node `data` with `greeting_type="text"`, `greeting` set to the exact string above, `allow_interrupt=true`, and `delayed_start=false`. For phone-preview-only runtime overrides, add `apply_speed_demo_node_overrides(workflow_graph: WorkflowGraph)` in `api/services/pipecat/latency_config.py`; call it in `api/services/pipecat/run_pipeline.py` after `WorkflowGraph(...)` creation and before `PipecatEngine(...)` creation, only when effective `latency_profile == "speed_demo"` and the run is a phone-preview/demo run. The runtime override may mutate the in-memory `WorkflowGraph` instance, but must not persist node changes to draft or active workflow definitions. Add a non-blocking UI/backend warning when a speed-demo workflow lacks a greeting, because no greeting causes initial LLM generation.

  **Must NOT do**: Do not force all existing nodes to allow interruption. Do not require audio recordings for MVP; audio greeting cache optimization can be a later enhancement.

  **Parallelization**: Can Parallel: YES | Wave 2 | Blocks: 8 | Blocked By: 3

  **References**:
  - Current create workflow defaults: `ui/src/components/workflow/CreateWorkflowButton.tsx:29`.
  - Start node example already uses interruption: `api/services/workflow/dto.py:188`.
  - Runtime muting: `api/services/workflow/pipecat_engine.py:800`.
  - No-greeting LLM generation: `api/services/workflow/pipecat_engine.py:685`.

  **Acceptance Criteria**:
  - [ ] `api/tests/test_latency_profile_config.py::test_speed_demo_warns_when_start_node_has_no_greeting` RED->GREEN.
  - [ ] UI build succeeds with new demo defaults.
  - [ ] Existing mute tests still prove `allow_interrupt=false` behavior is available.

  **QA Scenarios**:
  ```
  Scenario: Speed demo workflow without greeting emits warning but still runs
    Tool: tmux
    Steps: tmux new-session -d -s ulw-qa-greeting-warning 'cd /Users/slit/projects/dograh && source venv/bin/activate && set -a && source api/.env.test && set +a && python -m pytest api/tests/test_latency_profile_config.py::test_speed_demo_warns_when_start_node_has_no_greeting -q | tee evidence/returnzero-latency/task-7-greeting-warning.txt'
    Expected: command exits 0 and warning event is asserted
    Evidence: evidence/returnzero-latency/task-7-greeting-warning.txt

  Scenario: Existing user-mute behavior remains available
    Tool: tmux
    Steps: tmux new-session -d -s ulw-qa-barge-regression 'cd /Users/slit/projects/dograh && source venv/bin/activate && set -a && source api/.env.test && set +a && python -m pytest api/tests/test_user_muting_during_bot_speech.py -q | tee evidence/returnzero-latency/task-7-mute-regression.txt'
    Expected: command exits 0
    Evidence: evidence/returnzero-latency/task-7-mute-regression.txt
  ```

  **Commit**: YES | Message: `feat(demo): prefer interruptible low-latency starts` | Files: `api/services/pipecat/latency_config.py`, `ui/src/components/workflow/CreateWorkflowButton.tsx`, `api/tests/test_latency_profile_config.py`, `api/tests/test_user_muting_during_bot_speech.py`

- [x] 8. Add Deterministic And Optional Real ReturnZero Benchmarks

  **What to do**: Add an importable benchmark script at `api/scripts/benchmark_voice_latency.py` and create `api/scripts/__init__.py` in the same commit so `python -m api.scripts.benchmark_voice_latency` works. The script runs two profiles against the same mocked phone pipeline: `balanced` and `speed_demo`. It must output JSON with p50/p95 for `user_stop_to_bot_started_ms`, `stt_final_ms`, `llm_ttfb_ms`, `tts_ttfb_ms`, and `first_response_ms`. Include an optional ReturnZero real-WS benchmark path that runs only when `RETURNZERO_CLIENT_ID`, `RETURNZERO_CLIENT_SECRET`, and `RETURNZERO_BENCHMARK_AUDIO` are set. Measured ReturnZero TTFS P99 algorithm: sort `vad_stop_to_final_ms`, take p99, divide by 1000, round up to 2 decimals, clamp to `0.2..3.0`, then write the value into benchmark output; do not auto-edit source defaults.

  **Must NOT do**: Do not require paid ReturnZero credentials for CI. Do not place benchmark audio or credentials in git unless the fixture is explicitly non-sensitive test audio.

  **Parallelization**: Can Parallel: NO | Wave 3 | Blocks: Final Verification | Blocked By: 1, 2, 4, 5, 6, 7

  **References**:
  - Integration harness: `api/tests/integrations/_run_pipeline_helpers.py:79`.
  - ReturnZero service tests: `api/tests/test_returnzero_stt.py:190`.
  - Pipecat benchmark guidance: `pipecat/src/pipecat/services/stt_latency.py:20`.

  **Acceptance Criteria**:
  - [ ] `api/tests/test_voice_latency_benchmark.py::test_benchmark_reports_required_latency_fields` RED->GREEN.
  - [ ] `api/tests/test_voice_latency_benchmark.py::test_speed_demo_mock_benchmark_improves_by_at_least_400ms` RED->GREEN.
  - [ ] `python -m api.scripts.benchmark_voice_latency --help` exits 0, proving `api/scripts/__init__.py` made the module importable.
  - [ ] Running the script writes `evidence/returnzero-latency/final-benchmark.json`.

  **QA Scenarios**:
  ```
  Scenario: Deterministic benchmark proves speed profile improvement
    Tool: tmux
    Steps: tmux new-session -d -s ulw-qa-benchmark 'cd /Users/slit/projects/dograh && source venv/bin/activate && set -a && source api/.env.test && set +a && python -m api.scripts.benchmark_voice_latency --profiles balanced,speed_demo --iterations 20 --output evidence/returnzero-latency/final-benchmark.json | tee evidence/returnzero-latency/task-8-benchmark.txt'
    Expected: command exits 0 and JSON shows speed_demo user_stop_to_bot_started_ms p50 at least 400ms lower than balanced
    Evidence: evidence/returnzero-latency/final-benchmark.json

  Scenario: Real ReturnZero benchmark is run or explicitly skipped
    Tool: tmux
    Steps: tmux new-session -d -s ulw-qa-returnzero-real 'cd /Users/slit/projects/dograh && source venv/bin/activate && set -a && source api/.env.test && set +a && python -m api.scripts.benchmark_voice_latency --returnzero-real --output evidence/returnzero-latency/returnzero-real.json | tee evidence/returnzero-latency/task-8-returnzero-real.txt'
    Expected: command exits 0 and output JSON contains either measured returnzero_ttfs_p99_latency_seconds or skipped_real_returnzero=true
    Evidence: evidence/returnzero-latency/returnzero-real.json
  ```

  **Commit**: YES | Message: `test(voice): add latency benchmark harness` | Files: `api/scripts/__init__.py`, `api/scripts/benchmark_voice_latency.py`, `api/tests/test_voice_latency_benchmark.py`, `evidence/returnzero-latency/.gitkeep`

- [x] 9. Update Phone Preview UX Responsiveness Without Masking Call Latency

  **What to do**: Reduce `PhoneCallDialog` status polling while `calling` from 3000ms to 1000ms, but only after a session starts. When `PhonePreviewService` creates a workflow run for outbound or inbound preview, set `initial_context["runtime_latency_profile"] = "speed_demo"` alongside the existing `telephony_preview=True` marker; `api/services/pipecat/run_pipeline.py` must pass merged call context into the Task 3 latency resolver so this transient value wins over saved `workflow_configurations.latency_profile` without mutating draft or active workflow configuration. Add a typed phone-preview latency contract instead of making the UI fetch workflow-run logs directly:
  - Backend: add `PhonePreviewLatencySummary` in `api/routes/phone_preview.py` with fields `workflow_run_id: int`, `latency_profile: str | None`, `user_stop_to_bot_started_ms: float | None`, `stt_final_ms: float | None`, `llm_ttfb_ms: float | None`, `tts_ttfb_ms: float | None`, `first_response_ms: float | None`, `updated_at: str | None`.
  - Backend: add `latency_summary: PhonePreviewLatencySummary | None = None` to `PhonePreviewResponse`.
  - Backend service: in `api/services/phone_preview/service.py::status()`, when a `workflow_run` is already loaded for the session, extract the latest `workflow_run.logs["realtime_feedback_events"]` item where `type == "rtf-latency-measured"` and `payload.kind == "voice_latency_breakdown"`, then map only the fields above into `latency_summary`. `start`, `verify`, and `call` responses may return `latency_summary=None`.
  - Frontend: display the latency block only when `latency_summary` is present. Add exact i18n labels in `ui/src/lib/i18n.ts`: `phoneCall.latencyTitle` = EN `Pipeline latency`, KO `파이프라인 지연`; `phoneCall.latencyProfile` = EN `Profile`, KO `프로필`; `phoneCall.latencyResponse` = EN `Response`, KO `응답`; `phoneCall.latencyStt` = EN `STT final`, KO `STT 확정`; `phoneCall.latencyLlm` = EN `LLM first token`, KO `LLM 첫 토큰`; `phoneCall.latencyTts` = EN `TTS first audio`, KO `TTS 첫 오디오`; `phoneCall.latencyPending` = EN `Latency appears after the first turn.`, KO `첫 턴 이후 지연 시간이 표시됩니다.`
  Ensure phone preview start can request `speed_demo` runtime behavior without mutating saved workflow configuration. Add `api/scripts/create_phone_preview_qa_fixture.py` to create a test org/user/workflow/session and write `{ "workflow_id": number, "session_id": number, "auth_token": string | null, "url": string }` to `evidence/returnzero-latency/task-9-fixture.json` for browser QA.

  **Must NOT do**: Do not claim polling improvement as actual voice latency improvement. Do not bypass OTP/security checks. Do not expose raw `workflow_run.logs` or full phone numbers through the preview status response.

  **Parallelization**: Can Parallel: NO | Wave 4 | Blocks: 10, Final Verification | Blocked By: 3, 8

  **References**:
  - Current polling: `ui/src/app/workflow/[workflowId]/components/PhoneCallDialog.tsx:266`.
  - Start preview call: `ui/src/app/workflow/[workflowId]/components/PhoneCallDialog.tsx:215`.
  - Status response model: `api/routes/phone_preview.py:36`.
  - Status service path: `api/services/phone_preview/service.py:484`.
  - Current logs source: `api/services/pipecat/event_handlers.py:356`.
  - i18n labels: `ui/src/lib/i18n.ts:653` and `ui/src/lib/i18n.ts:1406`.
  - Backend preview tests: `api/tests/test_phone_preview_service.py`.
  - Route tests: `api/tests/test_phone_preview_routes.py`.

  **Acceptance Criteria**:
  - [x] `api/tests/test_phone_preview_service.py::test_phone_preview_uses_speed_demo_latency_profile_without_persisting_workflow` RED->GREEN.
  - [x] `api/tests/test_phone_preview_service.py::test_phone_preview_workflow_run_initial_context_carries_runtime_latency_profile` RED->GREEN.
  - [x] `api/tests/test_phone_preview_routes.py::test_phone_preview_status_returns_latency_summary_without_raw_logs` RED->GREEN.
  - [x] `api/tests/test_phone_preview_service.py::test_phone_preview_qa_fixture_outputs_workflow_url` RED->GREEN.
  - [x] `cd ui && npm run build` passes.
  - [x] Browser QA shows status refresh faster than 3s after call starts.

  **QA Scenarios**:
  ```
  Scenario: Preview service applies transient speed profile
    Tool: tmux
    Steps: tmux new-session -d -s ulw-qa-preview-speed 'cd /Users/slit/projects/dograh && source venv/bin/activate && set -a && source api/.env.test && set +a && python -m pytest api/tests/test_phone_preview_service.py::test_phone_preview_uses_speed_demo_latency_profile_without_persisting_workflow -q | tee evidence/returnzero-latency/task-9-preview-speed.txt'
    Expected: command exits 0 and saved workflow config remains unchanged
    Evidence: evidence/returnzero-latency/task-9-preview-speed.txt

  Scenario: Browser preview polling is 1s while calling
    Tool: Browser use
    Steps: run `python -m api.scripts.create_phone_preview_qa_fixture --output evidence/returnzero-latency/task-9-fixture.json`, start API with `uvicorn api.app:app --host 0.0.0.0 --port 8000`, start UI with `cd ui && npm run dev -- --host 0.0.0.0 --port 3000`, open the `url` from the fixture JSON, click `전화로 프리뷰` (or `Call me preview` if locale is English), enter `01012345678`, click `전화 프리뷰 시작` (or `Start call-me preview`), and record `/api/v1/phone-preview/status/{session_id}` request timestamps from browser action log
    Expected: screenshot and action log show status requests spaced 900-1300ms apart while calling; no OTP bypass; the UI still displays the phone-call dialog
    Evidence: evidence/returnzero-latency/task-9-browser-preview.png and task-9-browser-preview.json
  ```

  **Commit**: YES | Message: `feat(preview): use speed profile for demo calls` | Files: `api/routes/phone_preview.py`, `api/services/phone_preview/service.py`, `api/scripts/create_phone_preview_qa_fixture.py`, `api/tests/test_phone_preview_service.py`, `api/tests/test_phone_preview_routes.py`, `ui/src/app/workflow/[workflowId]/components/PhoneCallDialog.tsx`, `ui/src/lib/i18n.ts`

- [x] 10. Document Rollout, Defaults, And Operational Guardrails

  **What to do**: Document the latency strategy in `docs/product/returnzero-latency-optimization.md` and link it from `AGENTS.md` or the product docs index if appropriate. Include: ReturnZero as Recova demo STT direction, metric definitions, speed profile defaults, rollback to balanced, concurrency/channel-limit handling, what is intentionally not optimized yet, and how to run the benchmark. Update pricing/cost notes only if STT usage collection is implemented; otherwise state that ReturnZero cost attribution is a follow-up.

  **Must NOT do**: Do not claim live latency numbers unless Task 8 captured real ReturnZero evidence. Do not publish Recova marketing claims before domains/screenshots are true.

  **Parallelization**: Can Parallel: NO | Wave 5 | Blocks: Final Verification | Blocked By: 1-9

  **References**:
  - Current product runtime doc: `docs/product/realtime-development-direction.md`.
  - Root policy: `AGENTS.md`.
  - Pricing gap: `api/services/pricing/stt.py:15` and `api/services/pipecat/pipeline_metrics_aggregator.py:28`.

  **Acceptance Criteria**:
  - [x] New docs file truthfully describes measured vs planned latency.
  - [x] Docs include exact benchmark command and rollback instructions.
  - [x] `git diff --check` passes.

  **QA Scenarios**:
  ```
  Scenario: Docs mention no unmeasured live latency claims
    Tool: tmux
    Steps: tmux new-session -d -s ulw-qa-docs-latency 'cd /Users/slit/projects/dograh && rg -n \"p50|p95|ms|ReturnZero|speed_demo|balanced\" docs/product/returnzero-latency-optimization.md AGENTS.md | tee evidence/returnzero-latency/task-10-docs.txt'
    Expected: output includes benchmark-backed caveat and rollback instructions
    Evidence: evidence/returnzero-latency/task-10-docs.txt

  Scenario: Diff whitespace clean
    Tool: tmux
    Steps: tmux new-session -d -s ulw-qa-diff-check 'cd /Users/slit/projects/dograh && git diff --check | tee evidence/returnzero-latency/task-10-diff-check.txt'
    Expected: command exits 0
    Evidence: evidence/returnzero-latency/task-10-diff-check.txt
  ```

  **Commit**: YES | Message: `docs(product): document returnzero latency rollout` | Files: `docs/product/returnzero-latency-optimization.md`, `AGENTS.md`

## Final Verification Wave
> ALL must pass before staging or proposing commits.

- [x] F1. Plan Compliance Audit
  - Command: `cd /Users/slit/projects/dograh && source venv/bin/activate && set -a && source api/.env.test && set +a && python -m pytest api/tests/test_returnzero_stt.py api/tests/test_latency_profile_config.py api/tests/test_run_pipeline_latency_config.py api/tests/test_tts_latency_config.py api/tests/test_voice_latency_benchmark.py -q`
  - Evidence: `evidence/returnzero-latency/final-targeted-pytest.txt`

- [x] F2. Integration Regression
  - Command: `python -m pytest api/tests/integrations/test_run_pipeline.py api/tests/test_phone_preview_service.py api/tests/test_user_muting_during_bot_speech.py api/tests/test_run_pipeline_realtime_turn_config.py -q`
  - Evidence: `evidence/returnzero-latency/final-integration-pytest.txt`

- [x] F3. Frontend Build
  - Command: `cd ui && npm run build | tee ../evidence/returnzero-latency/final-ui-build.txt`
  - Evidence: `evidence/returnzero-latency/final-ui-build.txt`

- [x] F4. Benchmark Proof
  - Command: `python -m api.scripts.benchmark_voice_latency --profiles balanced,speed_demo --iterations 20 --output evidence/returnzero-latency/final-benchmark.json`
  - Pass: `speed_demo.user_stop_to_bot_started_ms.p50 <= balanced.user_stop_to_bot_started_ms.p50 - 400`
  - Evidence: `evidence/returnzero-latency/final-benchmark.json`

- [x] F5. Real Manual QA
  - Channel: Browser use for PhoneCallDialog plus tmux for benchmark.
  - Invocation: run `python -m api.scripts.create_phone_preview_qa_fixture --output evidence/returnzero-latency/final-browser-fixture.json`, start API on `http://localhost:8000`, start UI on `http://localhost:3000`, open fixture `url`, click `전화로 프리뷰` (or `Call me preview` if locale is English), enter `01012345678`, start outbound preview with `전화 프리뷰 시작` (or `Start call-me preview`), and capture browser action log plus screenshot.
  - Pass: Browser preview flow reaches calling state, polling interval is 900-1300ms, no OTP/security bypass, and backend logs include `latency_profile=speed_demo`.
  - Evidence: `evidence/returnzero-latency/final-browser-preview.png`, `evidence/returnzero-latency/final-browser-preview.json`

- [x] F6. Scope Fidelity Check
  - Verify no Realtime default switch, no shared ReturnZero credential, no existing workflow migration to speed mode, and no global campaign behavior change without config.
  - Evidence: `evidence/returnzero-latency/final-scope-audit.txt`

## Commit Strategy
- Use one commit per task if executed independently.
- Do not auto-commit unless the user explicitly requests it.
- Commit messages must follow the repo's detailed conventional format in `AGENTS.md`.
- If multiple tasks are implemented in one verified unit, use a single commit only when all evidence files and tests cover that unit.

## Success Criteria
- ReturnZero remains the STT target for the Recova demo path.
- Demo calls have persisted latency breakdowns by stage.
- Deterministic benchmark proves at least 400ms p50 improvement from profile/config changes.
- Real ReturnZero benchmark is captured when credentials are available, otherwise explicitly skipped without failing CI.
- Users can rollback by selecting `balanced`.
- UI, phone preview, and existing realtime turn config do not regress.
