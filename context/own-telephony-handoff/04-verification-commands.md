# 04 — 검증 명령 모음

이 문서는 다음 작업자가 실행해야 할 검증 명령과 알려진 제약을 정리한다.

## 현재 마지막 검증 상태

기준 커밋 전 주요 검증:

- Jambonz smoke/test suite: passed.
- UI build: passed.
- `git diff --check`: passed.
- `Release Please` GitHub Actions run for `a28fc26`: success.

주의: 전체 DB-backed pytest는 로컬 Postgres test credential 상태에 따라 실패할 수 있다. 이전에는 로컬 Postgres가 `postgres` password auth를 거절해서 DB-backed test가 시작 전 실패한 적이 있다.

## Supplier-independent smoke

공급자 스펙이 없어도 항상 실행 가능한 smoke다.

```bash
PYTHONPATH=.:pipecat/src api/.venv/bin/python -m api.scripts.jambonz_contract_smoke
```

기대:

- JSON에 `"passed": true`.
- Pipecat import 때문에 INFO banner가 먼저 출력될 수 있다.

의미:

- signed fixture 검증.
- replay rejection.
- expired/malformed signature rejection.
- simulator/live marker 분리.
- trusted operator attestation marker 처리.
- CDR fixture 검증.
- canonical JSON 안정성.

의미하지 않는 것:

- 실제 SIP/070 routing 성공.
- 실제 carrier 품질.
- live readiness.

## Focused backend tests

```bash
PYTHONPATH=.:pipecat/src \
ENVIRONMENT=test \
LOG_LEVEL=DEBUG \
UI_APP_URL=http://localhost:3000 \
DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/test_db \
REDIS_URL=redis://:redissecret@localhost:6379/0 \
MINIO_PUBLIC_ENDPOINT=http://localhost:9000 \
api/.venv/bin/python -m pytest \
  api/tests/telephony/jambonz/test_simulator_smoke.py \
  api/tests/test_telephony_number_inventory_routes.py \
  api/tests/test_telephony_lane_c.py
```

마지막 관측 결과:

- 17 passed, 1 warning.

## Backend compile check

```bash
api/.venv/bin/python -m py_compile \
  api/services/telephony/providers/jambonz/simulator_smoke.py \
  api/scripts/jambonz_contract_smoke.py \
  api/tests/telephony/jambonz/test_simulator_smoke.py
```

## UI lint/build

Inventory page만 고친 경우:

```bash
cd ui && npx eslint --fix src/app/superadmin/telephony-number-inventory/page.tsx
```

Frontend 변경 후 최소 gate:

```bash
cd ui && npm run build
```

알려진 warning:

- Sentry auth token 없으면 release/source maps upload가 skip/warn 될 수 있다.
- Node `[DEP0205] module.register()` deprecation warning이 보일 수 있다.

## Full project policy gates

일반 UI/backend change 후 최소 권장:

```bash
git diff --check
cd ui && npm run build
source venv/bin/activate && set -a && source api/.env.test && set +a && python -m pytest api/tests/...
```

현재 repo에서는 backend venv가 `api/.venv`인 경우가 있으므로 실제 환경에 맞춰 사용한다.

## Git/CI 확인

push 전:

```bash
git remote -v
git status --short --branch
git diff --check
```

push 후:

```bash
git rev-list --left-right --count origin/main...HEAD
gh run list --limit 5 --json databaseId,status,conclusion,headSha,displayTitle,workflowName,event,url
```

성공 기준:

- remote parity: `0 0`.
- GitHub Actions run이 있으면 결론을 확인한다.
- run이 없으면 “CI가 없었다/관측되지 않았다”고 말한다.

## Live carrier verification commands/actions

실제 carrier 접근 후에는 자동 명령만으로 끝나지 않는다. 다음 evidence를 운영자가 확인해야 한다.

1. 실제 휴대폰/유선에서 070 번호로 inbound call.
2. Recova workflow 실행 여부 확인.
3. Recova outbound call을 실제 휴대폰으로 발신.
4. 상대방 화면 caller ID가 할당된 070 번호인지 확인.
5. CDR/status/failure/recording/transcript 저장 확인.
6. superadmin inventory에서 `Attest live` 입력.
7. staging soak 지표 수집.

## Local DB 문제 대응

DB-backed tests가 `password authentication failed for user "postgres"` 류로 실패하면 코드 실패로 단정하지 않는다.

확인할 것:

- local Postgres 실행 여부.
- `test_db` 존재 여부.
- `api/.env.test`와 실제 local Postgres credential 일치 여부.
- Docker/local service startup 상태.

그래도 실패하면 실패 원인을 commit body/보고에 명시한다.
