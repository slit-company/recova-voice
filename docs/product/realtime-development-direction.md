# Recova Realtime Voice Direction

Last updated: 2026-06-02

## Executive Decision

Realtime should be treated as a first-class Recova runtime, but not yet the
default runtime for the self-serve B2B demo funnel.

The current product default should remain the standard STT + LLM + TTS path.
Realtime should be developed as an opt-in low-latency mode for selected demo
agents, premium pilots, and latency-sensitive workflows. Promote it to the
default only after Recova has measured Korean B2B calls showing that Realtime
wins on:

- first response latency and barge-in quality
- node-transition correctness
- tool-call correctness and timing
- transcript/report quality
- call drop and reconnect behavior
- cost per connected minute
- debugging and customer-support operability

## Current Implementation Map

Recova already has a real Realtime path, not just a UI toggle.

- `api/schemas/user_configuration.py` supports `llm`, `stt`, `tts`,
  `realtime`, and `is_realtime`.
- `ui/src/components/ServiceConfigurationForm.tsx` exposes a Realtime Mode
  toggle. In Realtime mode, overrides are `realtime` + `llm`; in standard mode,
  they are `llm` + `tts` + `stt`.
- `api/services/phone_preview/service.py` preflights model configuration before
  dialing. Realtime preview requires `realtime` and `llm`; standard preview
  requires `stt`, `tts`, and `llm`.
- `api/services/pipecat/run_pipeline.py` resolves `is_realtime` and chooses
  between `create_realtime_llm_service` and separate STT/TTS/LLM services.
- `api/services/pipecat/pipeline_builder.py` builds two different pipelines:
  - standard: transport input -> STT -> workflow/user context -> LLM -> callback
    processor -> TTS -> transport output
  - Realtime: transport input -> workflow/user context -> realtime LLM ->
    callback processor -> transport output
- `api/services/workflow/pipecat_engine.py` is still the workflow authority.
  It builds prompts/functions per canvas node, registers edge transition
  functions, registers custom tools and knowledge retrieval, emits node
  transition events, and queues node openings.

This means Realtime does follow the canvas graph. The risk is not that it
ignores the canvas. The risk is that the speech-to-speech provider owns more of
the audio and conversation lifecycle than the standard pipeline.

## Provider-Specific Runtime Behavior

The current provider wrappers show that Realtime support is already adapting to
provider-specific limitations.

- OpenAI Realtime can update instructions/tools during a session, so the wrapper
  focuses on Dograh/Recova engine integration: user mute gating, greeting
  triggers, one-off appended prompts, transcript parity, and deferred function
  calls while the bot is speaking.
- Gemini Live cannot update `system_instruction` mid-session in the same way,
  so node transitions can require reconnect behavior. The wrapper defers
  reconnects until bot speech ends and defers tool calls emitted mid-turn.
- Ultravox binds prompt/tool configuration to call creation, so its wrapper
  recreates the call across node transitions and reconstructs initial messages.
  This makes it more fragile for graph-heavy workflows than a provider with
  in-session prompt/tool updates.

## Current Product Gaps

These are the gaps that matter before Realtime becomes a default Recova demo
runtime.

1. **Graph-flow confidence**
   Realtime follows the graph, but Recova needs automated scenario coverage for
   node transitions, edge functions, static greetings, end nodes, and tool
   result driven transitions across every supported realtime provider.

2. **Observability parity**
   The standard path has explicit STT text, LLM text, TTS text/audio, and usage
   boundaries. Realtime has provider-specific event streams. Recova needs a
   normalized event contract for user transcript, assistant transcript,
   function-call start/end, node transition, interruption, reconnect, and
   provider error events.

3. **Korean call-quality proof**
   Realtime models are improving quickly, but Recova needs its own Korean B2B
   evaluation set: names, phone numbers, company names, dates, appointment
   slots, pricing questions, consent phrases, and noisy mobile/PSTN audio.

4. **Feature parity**
   Current code disables or limits some features in Realtime:
   - context compaction is disabled because the speech-to-speech service owns
     conversation state.
   - voicemail detection is disabled for Realtime runs.
   - recording router is only used in non-Realtime mode because Realtime models
     produce audio directly.

5. **Provider abstraction**
   OpenAI, Gemini, and Ultravox need different strategies for prompt/tool
   updates. Recova should expose a capability matrix instead of treating all
   realtime providers as equivalent.

## External Research Snapshot

Verified on 2026-06-02 from official/primary sources.

OpenAI positions Realtime as a production voice-agent surface with direct
speech-to-speech processing, lower latency, better naturalness, function
calling improvements, MCP support, image input, SIP phone calling, reusable
prompts, and explicit cost controls:

- https://openai.com/index/introducing-gpt-realtime/
- https://developers.openai.com/api/docs/guides/voice-agents
- https://developers.openai.com/api/docs/guides/realtime-models-prompting

OpenAI's own architecture guidance separates the use cases clearly:
speech-to-speech is best for natural low-latency conversations, while chained
voice pipelines are better for predictable workflows or extending existing text
agents.

OpenAI's current voice-agent docs are especially aligned with Recova's product
tradeoff. They describe speech-to-speech sessions as best for barge-in, low
first-audio latency, natural turn-taking, and realtime tool use. They describe
chained voice pipelines as the better fit when each stage needs to be visible
or replaceable, including cases where the product must store transcripts, run
policy checks, call internal systems, or generate speech only after an approved
workflow answer.

OpenAI Realtime also has concrete runtime constraints that matter for Recova:
sessions are stateful; most session fields can be updated, but the output voice
cannot be changed after the model has emitted audio; Realtime supports session
and response-level tools; WebRTC/SIP can handle interruption buffering better
than WebSocket playback; and audio truncation does not give a perfectly aligned
truncated transcript. These details reinforce the need for Recova-owned
observability instead of relying on provider events as-is.

Google Gemini Live supports low-latency voice/video sessions, multilingual
conversation, barge-in, tool use, audio transcription, proactive audio, and
session resumption in Vertex AI:

- https://ai.google.dev/gemini-api/docs/live-api
- https://docs.cloud.google.com/vertex-ai/generative-ai/docs/live-api/start-manage-session

Gemini Live's session-management docs also matter operationally: Google
documents context-window compression, session resumption, resumption tokens,
generation-complete signals, and connection lifecycle events. This maps to the
Reconnect-on-node-transition behavior already present in Recova's
`DograhGeminiLiveLLMService` wrapper and supports the provider-capability-gate
recommendation.

Ultravox markets a hosted realtime voice-agent platform with multilingual
support, tools/function calling, knowledge, call stages, conversation history,
telephony integrations, and webhooks:

- https://docs.ultravox.ai/overview
- https://docs.ultravox.ai/agents/call-stages

Ultravox's Call Stages docs are relevant because they are close to Recova's
canvas nodes: stages allow prompt/tool/voice/history changes, but require a
stage-change tool and explicit planning. This matches the current Recova
Ultravox wrapper, which recreates calls or reconstructs initial messages across
node transitions instead of relying on simple in-session updates.

Recent research is mixed rather than one-sided:

- Full-Duplex-Bench-v3 evaluates GPT-Realtime, Gemini Live, Grok, Ultravox, and
  a cascaded Whisper -> GPT-4o -> TTS baseline across accuracy, latency, and
  turn-taking. It reports Realtime strengths, but also that self-correction and
  hard multi-step reasoning remain consistent failure modes.
  https://arxiv.org/abs/2604.04847
- An enterprise realtime voice-agent tutorial argues that cascaded streaming
  STT -> LLM -> TTS remains practical for self-hosted enterprise agents, while
  native speech-to-speech is attractive when a hosted provider can meet latency
  and capability needs. https://arxiv.org/abs/2603.05413

## Recommended Development Direction

The first implementation priority is not "switch the default." It is to make
Realtime falsifiable. Recova should be able to answer, from its own logs, which
runtime handled a prospect's Korean B2B demo call better and why.

### Phase 1: Make Realtime Measurable

Build an internal Realtime evaluation harness before changing product defaults.
It should replay the same scripted Korean B2B scenarios against standard and
Realtime modes:

- simple qualification call
- appointment scheduling
- pricing objection
- user interruption/barge-in
- noisy phone-number capture
- custom tool lookup
- node transition after tool result
- end-node call disposition

Minimum metrics:

- time to first assistant audio
- time from user stop to assistant start
- interruption recovery time
- transition function chosen
- tool call arguments
- transcript word/slot accuracy
- call disposition
- provider error/reconnect count
- cost per minute

### Phase 2: Normalize Realtime Observability

Add a provider-neutral event model for Realtime runs. Reports and QA should not
need to know whether a transcript came from OpenAI, Gemini, Ultravox, or a
standard STT provider.

Target event contract:

- `user_transcript.final`
- `assistant_transcript.final`
- `assistant_audio.started`
- `assistant_audio.stopped`
- `barge_in.detected`
- `function_call.started`
- `function_call.completed`
- `node_transition.completed`
- `provider_reconnect.started`
- `provider_reconnect.completed`
- `provider_error`
- `cost_sample`

### Phase 3: Capability-Gate Providers

Treat Realtime providers as capability profiles, not interchangeable backends.

Suggested capability fields:

- can update instructions mid-session
- can update tools mid-session
- supports async function calls
- supports session resumption
- emits user transcripts
- emits assistant transcripts
- supports SIP directly
- supports Korean with measured slot accuracy
- supports recording/history export
- supports configurable turn detection

Use these gates to decide which providers can power:

- self-serve demo default
- premium low-latency demo
- production campaign calls
- inbound support calls
- regulated/compliance-sensitive calls

### Phase 4: Productize as a Controlled Toggle

Realtime should not be a raw model-config checkbox for the demo funnel. It
should become a product-level mode:

- Standard mode: "Reliable operations"
  - default
  - STT + LLM + TTS
  - best for transcripts, reports, QA, cost control, and predictable workflows
- Realtime mode: "Low-latency conversation"
  - opt-in
  - provider-gated
  - shows a warning if transcripts, voicemail detection, or recording playback
    parity is weaker for the selected provider

### Phase 5: Promotion Criteria

Make Realtime the default only if a Korean B2B benchmark shows:

- at least 25% lower median response latency than the standard pipeline
- no worse node-transition accuracy
- no worse tool-call argument accuracy
- no worse final call disposition accuracy
- transcript/report quality good enough for sales/support review
- cost per minute within the target demo margin
- no provider-specific reconnect or dropped-call rate that hurts the demo

## Near-Term Recommendation

Keep the product default as STT + LLM + TTS. Invest in Realtime as a serious
parallel runtime by adding evaluation, observability normalization, and
provider capability gates. Use Realtime for curated wow demos only after the
selected provider passes the graph-flow and Korean B2B benchmark.
