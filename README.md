# Recova

Recova is a Korean B2B voice AI product built from the open-source Dograh
platform. The fork keeps Dograh's core workflow builder, telephony runtime,
WebRTC test calls, campaign engine, and self-hostable deployment model, while
the product direction is Recova-first: Korean business operators, Korean call
flows, tenant-safe administration, and production integrations for local B2B
sales/support workflows.

This repository still contains a large amount of upstream Dograh branding and
documentation. Treat the codebase as a transition-state fork, not a clean-room
Recova app. Some runtime surfaces already say Recova, including the FastAPI
OpenAPI metadata and the Next.js page metadata; many docs, setup scripts, image
names, and community links still say Dograh and should be migrated deliberately.

## Current State

| Area | Status | Notes |
| --- | --- | --- |
| Backend API | Recova-facing metadata with Dograh internals | `api/app.py` exposes `Recova API`; routes still follow Dograh domain names. |
| Frontend | Recova shell on Dograh workflow UI | `ui/src/app/layout.tsx` uses `Recova`; most UI terminology still says workflow/agent from Dograh. |
| Docs | Mostly upstream Dograh | Mintlify docs still use Dograh navigation, screenshots, and public links. |
| Deployment | Dograh OSS model | Compose files, images, and scripts still assume Dograh naming and registries. |
| Telephony | Multi-provider voice stack | Twilio, Vonage, Plivo, Telnyx, Cloudonix, Vobiz, ARI, and other providers are registry-driven. |
| B2B operations | Partially present | Campaigns, reports, usage, pricing, organizations, API keys, and superadmin surfaces exist. |

## Repository Map

```text
dograh/
├── api/              # FastAPI backend, DB models, services, ARQ tasks
├── ui/               # Next.js 15 app, generated API client, dashboard
├── product/          # Canonical internal product planning
├── context/          # Decision rationale and handoff context
├── plans/            # Implementation execution plans
├── docs/             # Mintlify documentation, mostly upstream Dograh today
├── scripts/          # Local/dev/deployment helpers; many have .sh/.ps1 pairs
├── sdk/              # Python and TypeScript SDK packages
├── examples/         # SDK examples
├── evals/            # Evaluation and visualizer tooling
├── pipecat/          # Pipecat submodule/vendor framework
├── docker-compose.yaml
└── docker-compose-local.yaml
```

## Where To Look

| Task | Start here | Notes |
| --- | --- | --- |
| Product planning | `product/README.md` | Canonical product definition, journeys, status, priorities, and metrics. |
| API routes | `api/routes/main.py` | Routers are mounted under `/api/v1`. Keep handlers thin. |
| Product/workflow logic | `api/services/workflow/` | Agent graph, node data, QA, tool execution, text chat. |
| Live voice runtime | `api/services/pipecat/` | Pipeline construction, events, audio, realtime model adapters. |
| Telephony | `api/services/telephony/` | Read nested `AGENTS.md` files before provider work. |
| Campaigns | `api/services/campaign/` and `ui/src/app/campaigns/` | Core B2B outbound calling surface. |
| Reports/usage/cost | `api/services/reports/`, `api/services/pricing/`, `ui/src/app/reports/`, `ui/src/app/usage/` | Key for Korean B2B operator/admin flows. |
| Organizations/auth | `api/routes/organization.py`, `api/services/auth/`, `ui/src/lib/auth/` | Tenant isolation is mandatory. |
| Frontend pages | `ui/src/app/` | Next.js App Router. |
| Generated client | `ui/src/client/` | Regenerate from OpenAPI; do not hand-edit generated files. |
| Documentation | `docs/docs.json` and `docs/**/*.mdx` | Still Dograh-heavy; migrate carefully and truthfully. |
| Startup/deploy scripts | `scripts/AGENTS.md` | Script coupling is non-obvious. Read it first. |

## Product Direction For Agents

- Recova is the product name for new work. Preserve Dograh names only where they
  are protocol identifiers, package names, upstream compatibility points, image
  names, or migration work not yet completed.
- The intended go-to-market demo flow is self-serve and B2B-focused: a prospect
  lands in Recova, creates their own agent, enters their own phone number for a
  test call, experiences inbound and outbound calling, and uses that hands-on
  trial to decide whether to adopt Recova for their company.
- Optimize product decisions for Korean B2B usage: call centers, sales/support
  teams, Korean phone-number behavior, Korean-language prompts, auditability,
  organization-level administration, and clear operational reporting.
- Do not blindly rebrand public docs or deployment commands unless the backing
  images, domains, package names, and screenshots are also correct.
- Prioritize tenant isolation. Every organization-scoped API read/write must
  filter or validate by `organization_id`.
- Treat campaigns, telephony configuration, reports, usage, recordings, and API
  keys as production B2B surfaces, not demo-only features.

## Product Planning

Canonical internal product planning lives in [`product/README.md`](product/README.md).
It separates the product definition, end-to-end journeys, current capability
status, priorities, and metrics from decision history in `context/`, executable
implementation plans in `plans/`, and public guidance in `docs/`. Changes to
product definition, behavior, journey/capability status, priorities, metrics, or
decision status must update the relevant `product/` document in the same change.

## Local Development

Contributor setup and service startup are documented in
`docs/contribution/setup.mdx`.

Common commands:

```bash
# Backend tests
source venv/bin/activate
set -a && source api/.env.test && set +a
python -m pytest api/tests/...

# Backend diagnostics / one-off scripts against the dev DB
source venv/bin/activate
set -a && source api/.env && set +a
python -m api.services.admin_utils.local_exec

# Frontend
cd ui
npm run dev
npm run build
```

## Environment Files

- `api/.env` - backend development and diagnostics. Do not use it for pytest.
- `api/.env.test` - backend test environment. Source this before pytest.
- `ui/.env` - frontend environment.

Do not commit `.env` files, local logs, generated caches, or one-off test
accounts.

## Verification Policy

Before committing normal UI/backend changes, run the relevant gates:

```bash
git diff --check
cd ui && npm run build
source venv/bin/activate && set -a && source api/.env.test && set +a && python -m pytest api/tests/...
```

For frontend-only changes, `cd ui && npm run build` is the minimum. For
backend-only changes, a targeted pytest path is acceptable when the commit body
states that the gate was targeted.

## Git Remotes

This fork is operated as `cosmosjeon/recova-v1` on `origin`. The original
Dograh project is kept as `upstream`.

Before pushing, verify:

```bash
git remote -v
git status --short --branch
```

Push to `origin main` unless the user asks for another target. After pushing,
verify remote parity:

```bash
git rev-list --left-right --count origin/main...HEAD
```

If `gh run list` shows no GitHub Actions runs, report that no run was found
instead of claiming CI passed.

## License

This fork inherits Dograh's BSD 2-Clause license. Keep upstream license and
attribution requirements intact while changing product-facing Recova materials.
