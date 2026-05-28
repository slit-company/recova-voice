# Dograh - Project Overview

Dograh is a voice AI platform for building and deploying conversational AI agents with telephony and WebRTC support.

## Project Structure

```
dograh/
├── api/              # Backend - FastAPI application
├── ui/               # Frontend - Next.js application
├── scripts/          # Helper scripts for local development
├── docs/             # Mintlify documentation
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
