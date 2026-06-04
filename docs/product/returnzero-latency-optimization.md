# ReturnZero Latency Optimization Rollout

Last updated: 2026-06-04

## Decision

Recova's default B2B demo-call path remains the standard STT + LLM + TTS
pipeline. For the self-serve phone preview, Recova now uses ReturnZero as the
intended STT direction and applies a transient `speed_demo` latency profile at
runtime. This is scoped to demo/test calls and does not mutate the saved
workflow configuration.

Realtime remains an opt-in low-latency runtime. The standard pipeline stays the
default because B2B evaluation needs transcripts, reports, tool-call traces,
provider replaceability, cost visibility, and debuggable failures.

## What Is Measured

The committed benchmark harness currently has two modes:

- deterministic mock benchmark, used for repeatable regression proof
- optional real ReturnZero benchmark, used only when credentials and a local
  benchmark audio file are provided

Current evidence in `evidence/returnzero-latency/final-benchmark.json` is
deterministic mock evidence, not a live ReturnZero production measurement.

The latest optional real ReturnZero artifact,
`evidence/returnzero-latency/returnzero-real.json`, was captured on
2026-06-04 with credentials from `api/.env` and a generated Korean macOS Yuna
WAV fixture at `evidence/returnzero-latency/returnzero-benchmark-ko.wav`.
That run produced `skipped_real_returnzero=false`, `iterations=5`,
`vad_stop_to_final_ms.p50=56.186`, `vad_stop_to_final_ms.p95=61.127`, and
`returnzero_ttfs_p99_latency_seconds=0.2`.

Treat this as a provider websocket smoke benchmark, not as a customer-facing
PSTN latency number. The audio is synthetic and local, so it does not measure
mobile network quality, telephony jitter, microphone input, or real user speech.

Do not quote the deterministic numbers as customer-facing live latency. Use
them only to prove that the code path and profile defaults produce the expected
relative regression signal.

## Metrics

- `user_stop_to_bot_started_ms`: elapsed time from detected end of user speech
  to assistant audio start. This is the primary perceived turn latency metric.
- `stt_final_ms`: elapsed time to final STT text after user speech stop.
- `llm_ttfb_ms`: elapsed time to first LLM token after the LLM request starts.
- `tts_ttfb_ms`: elapsed time to first TTS audio after the TTS request starts.
- `first_response_ms`: elapsed time from pipeline/client readiness to first
  assistant response audio where that can be measured.

Phone preview exposes only the summary fields above through
`PhonePreviewLatencySummary`. It must not expose raw `workflow_run.logs`,
provider call IDs, full phone numbers, or provider secrets.

## Speed Profile Defaults

`speed_demo` currently resolves to:

- `user_speech_timeout_seconds`: `0.35`
- `tts_aggregation_silence_seconds`: `0.35`
- `pre_call_fetch_timeout_seconds`: `0.5`
- `pre_call_fetch_required`: `false`
- `speed_profile_respect_delayed_start`: `false` unless explicitly configured

For phone preview runs, `PhonePreviewService` sets
`initial_context["runtime_latency_profile"] = "speed_demo"` alongside
`telephony_preview = True`. `run_pipeline` allows that runtime profile override
only for preview context, so a saved workflow with `latency_profile: "balanced"`
can still run as `speed_demo` for the demo call.

`speed_demo` also applies runtime-only node defaults:

- start and agent nodes allow interruption
- start and agent nodes do not delay start
- a missing start greeting gets the Recova Korean demo greeting and a warning
  event

These overrides are applied to the in-memory workflow graph and must not be
persisted back to draft or published workflow configuration.

## Benchmark Commands

Run deterministic benchmark evidence:

```bash
source venv/bin/activate && set -a && source api/.env.test && set +a && python -m api.scripts.benchmark_voice_latency --profiles balanced,speed_demo --iterations 20 --output evidence/returnzero-latency/final-benchmark.json
```

Run optional real ReturnZero evidence:

```bash
source venv/bin/activate && set -a && source api/.env.test && set +a && RETURNZERO_CLIENT_ID=... RETURNZERO_CLIENT_SECRET=... RETURNZERO_BENCHMARK_AUDIO=/absolute/path/to/sample.wav python -m api.scripts.benchmark_voice_latency --returnzero-real --output evidence/returnzero-latency/returnzero-real.json
```

Use real evidence only when `skipped_real_returnzero` is `false` and
`returnzero_ttfs_p99_latency_seconds` is present.

## Rollback

To roll a workflow back to conservative behavior, remove its saved
`latency_profile` or set it to `balanced`. Balanced restores:

- `user_speech_timeout_seconds`: `0.6`
- no TTS aggregation override
- `pre_call_fetch_timeout_seconds`: `10.0`
- `pre_call_fetch_required`: `true`

To roll phone preview itself back from speed mode, remove or change the
`runtime_latency_profile: "speed_demo"` values created in
`api/services/phone_preview/service.py` for outbound and inbound preview
workflow runs. Prefer setting the saved or runtime profile to `balanced` before
changing provider-level code.

If a provider regresses under `speed_demo`, use a custom profile rather than
globally weakening the profile. Keep the custom values inside the bounds in
`WorkflowLatencyConfiguration`.

## Concurrency And Channel Limits

The speed profile reduces per-turn waiting inside a connected call. It does not
increase provider channel limits, ReturnZero websocket capacity, telephony
concurrency, outbound campaign safety limits, or organization quotas.

Operational handling should remain conservative:

- keep phone-preview OTP, session TTL, daily user/org/phone limits, and
  destination clearing intact
- fail or defer calls when telephony or STT providers return capacity errors
- measure provider disconnects and websocket failures separately from latency
- avoid lowering VAD or pre-call waits as a workaround for channel saturation

Active ReturnZero session counting and provider-specific 429/close-code
reporting are follow-up work.

## Cost Notes

Do not update customer-facing cost claims from this rollout. The current STT
pricing registry covers Deepgram and OpenAI defaults, and ReturnZero cost
attribution is not implemented in usage collection yet.

ReturnZero pricing and per-call STT seconds should be wired into the existing
usage/cost pipeline before Recova reports ReturnZero cost per minute.

## Not Optimized Yet

This rollout does not yet optimize or prove:

- live Korean PSTN latency under real mobile network conditions
- real ReturnZero TTFS without benchmark credentials and a fixed audio corpus
- LLM provider streaming latency beyond first-token timing
- TTS provider cold starts and voice-specific latency
- packet loss, jitter buffer behavior, carrier route quality, or SIP trunk load
- campaign-scale concurrency and provider backpressure
- Realtime provider parity
- final business outcome metrics such as booking rate or qualification rate

Treat this as a measured engineering rollout for the standard pipeline, not as
a finished latency marketing claim.
