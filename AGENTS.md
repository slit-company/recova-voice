# Recova / Dograh Fork - Project Overview

Recova is a Korean B2B voice AI product built from a fork of Dograh. Dograh's
core platform remains the technical base: workflow-based voice agents,
telephony/WebRTC runtime, campaigns, reporting, generated SDKs, and OSS
deployment scripts. New product work should be Recova-first while preserving
Dograh compatibility where names are tied to upstream packages, image names,
protocols, or unfinished migration work.

Current state: this repo is mid-migration. `api/app.py` and the Next.js metadata
already identify the product as Recova, while most docs, setup scripts,
screenshots, public links, package names, and deployment images still say
Dograh. Do not perform a blind search-and-replace; rebrand only when the
corresponding runtime, docs, links, screenshots, and deployment artifacts are
true.

## Product Priorities
- Canonical internal product planning lives in `product/README.md`. Before product
  work, read its product definition, journeys, capability map, priorities, and
  metrics. A change that alters product definition, behavior, journey/capability
  state, priority, metric/gate, or decision status MUST update the relevant
  `product/` document in the same verified change. Keep the official product
  state only in `product/03-capability-map.md`, decision rationale in `context/`,
  implementation plans in `plans/`, and truthful public guidance in `docs/`; do
  not duplicate their detailed content into product planning.

- Korean B2B operators are the target users: sales/support teams, call-center
  style operations, admin/superadmin workflows, organization-level controls,
  Korean-language call behavior, and measurable call outcomes.
- Recova's near-term sales motion is a self-serve B2B demo funnel. Prospects
  should be able to enter the product, create their own voice agent, input their
  own phone number for a test call, experience inbound and outbound calling, and
  then evaluate adopting Recova for their company. Treat this as a product
  direction, not a one-off demo script.
- Current demo-call method recommendation: default the self-serve B2B
  demo/test-call path to the standard STT + LLM + TTS pipeline, not Realtime.
  The reason is adoption evaluation: prospects need dependable transcripts,
  reports, tool-call traces, provider flexibility, cost-per-minute visibility,
  and debuggable failures more than the lowest possible first-turn latency.
  Keep Realtime available as an opt-in low-latency/premium showcase path, but
  do not make it the default until measured call data shows it wins on latency,
  interruption quality, drop rate, tool-call correctness, transcript/report
  quality, and cost per minute for Korean B2B scenarios. See
  `docs/product/realtime-development-direction.md` for the current Realtime
  implementation analysis and development roadmap. See
  `docs/product/returnzero-latency-optimization.md` for the current ReturnZero
  STT + LLM + TTS latency rollout, `speed_demo` defaults, benchmark command,
  and rollback guidance.
- Treat campaigns, telephony configuration, reports, usage/cost, recordings,
  API keys, organizations, and superadmin as production surfaces.
- Keep tenant isolation as a hard security invariant. Any organization-scoped
  resource read/write must filter or validate by `organization_id`.

## Project Structure

```
dograh/
├── api/              # Backend - FastAPI application
├── ui/               # Frontend - Next.js application
├── product/          # Canonical internal product planning
├── context/          # Decision rationale and handoff context
├── plans/            # Implementation execution plans
├── docs/             # Mintlify/public and operational documentation
├── scripts/          # Helper scripts for local development
├── pipecat/          # Pipecat framework (git submodule)
├── docker-compose.yaml       # Production/OSS deployment
├── docker-compose-local.yaml # Local development services
```

## Tech Stack

- **Backend**: Python with FastAPI
- **Frontend**: Next.js 15 with React 19, TypeScript, Tailwind CSS
- **Database**: PostgreSQL with SQLAlchemy (async)
- **Cache/Queue**: Redis with ARQ for background tasks
- **Storage**: MinIO (S3-compatible) for audio files

## Current Migration Map

| Area | Current state | Agent guidance |
| ---- | ------------- | -------------- |
| Backend API | FastAPI app metadata says Recova; many modules still Dograh-named | Prefer Recova in user-facing metadata, preserve stable internal identifiers unless migration is explicit |
| Frontend | Next.js metadata says Recova; UI copy is mixed | New B2B product copy should say Recova; keep generated client files untouched |
| Docs | Mintlify docs are mostly upstream Dograh | Keep docs truthful; do not publish Recova claims before screenshots, domains, and commands are valid |
| Deployment | Compose/scripts/images are Dograh-oriented | Read `scripts/AGENTS.md`; image/registry naming changes must be coordinated |
| Telephony | Registry-driven multi-provider subsystem | Read nested telephony `AGENTS.md` files before edits |
| Pipecat | Submodule/vendor framework | Avoid modifying unless the task is explicitly Pipecat-level |

## Where To Look

| Task | Location | Notes |
| ---- | -------- | ----- |
| Product planning | `product/README.md` | Canonical product definition, journeys, status, priorities, and metrics |
| API entrypoint | `api/app.py` | App metadata, `/api/v1`, MCP mount, worker sync startup |
| Route composition | `api/routes/main.py` | Main router aggregation and health response |
| Workflow builder/runtime | `api/services/workflow/` | Graph, node data/specs, tools, QA, text chat |
| Live voice pipeline | `api/services/pipecat/` | Pipeline, audio, realtime adapters, event handling |
| Telephony providers | `api/services/telephony/` | Provider registry; nested instructions apply |
| Campaigns | `api/services/campaign/`, `ui/src/app/campaigns/` | B2B outbound calling and scheduling |
| Reports/usage/cost | `api/services/reports/`, `api/services/pricing/`, `ui/src/app/reports/`, `ui/src/app/usage/` | B2B analytics and billing-adjacent surfaces |
| Frontend shell/pages | `ui/src/app/`, `ui/src/components/` | Next.js App Router and dashboard UI |
| API client | `ui/src/client/` | Generated; use `npm run generate-client` |
| Docs navigation | `docs/docs.json` | Mintlify structure and navigation |
| Startup/deployment | `scripts/`, `docker-compose*.yaml` | Scripts are coupled; read `scripts/AGENTS.md` |

## Local Development

Contributor setup and service startup are documented in `docs/contribution/setup.mdx`.

## Environment Configuration

- `api/.env` - Backend environment variables. Source this when running diagnostic scripts or one-off services against the dev DB (e.g. `python -m api.services.admin_utils.local_exec`).
- `api/.env.test` - Test-only environment variables. Source this when running pytest so tests hit the test DB and never the dev/prod credentials in `api/.env`.
- `ui/.env` - Frontend environment variables

Typical invocation:

```bash
# Tests
source venv/bin/activate && set -a && source api/.env.test && set +a && python -m pytest api/tests/...

# Diagnostics / scripts
source venv/bin/activate && set -a && source api/.env && set +a && python -m api.services.admin_utils.local_exec
```

## Commit and Push Discipline

This repository is operated as `cosmosjeon/recova-v1` on `origin`, with the
original Dograh project kept as `upstream`. Version history must stay useful to
humans reconstructing what changed and why.

Before committing, agents must run the relevant verification gates for the
changed areas and include the commands/results in the commit body whenever the
change is more than a trivial typo.

Minimum gates for normal UI/backend changes:

```bash
git diff --check
cd ui && npm run build
source venv/bin/activate && set -a && source api/.env.test && set +a && python -m pytest api/tests/...
```

For narrower backend-only changes, a targeted pytest path is acceptable, but the
commit body must say that the gate was targeted. For frontend-only changes, run
`cd ui && npm run build` at minimum.

Commit messages must use a detailed conventional format:

```text
type(scope): concise summary

Why:
- User/product reason for the change.

What changed:
- Concrete implementation bullets.

Verification:
- `command` — result.

Notes:
- Any intentional limitations, follow-up work, or non-obvious tradeoffs.
```

Rules:
- Prefer one coherent commit per verified unit of work.
- Do not use vague messages such as `fix stuff`, `update`, or `wip`.
- Do not commit secrets, `.env` files, local logs, build caches, or one-off test
  accounts.
- Before pushing, verify the target with `git remote -v` and
  `git status --short --branch`; push to `origin main` unless the user says
  otherwise.
- After pushing, verify remote parity with
  `git rev-list --left-right --count origin/main...HEAD` and report whether CI
  is observable. If `gh run list` returns no runs, say no GitHub Actions run was
  found instead of claiming CI passed.

Agent/OMX workers must treat this section as deterministic project policy, not
as a preference from memory. If an OMX prompt asks for implementation that will
be committed, include these commit/push rules or point the worker at this file.
