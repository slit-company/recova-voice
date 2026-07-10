# 01 — 현재 상태 스냅샷

- 작성일: 2026-07-10
- 기준 브랜치: `main`
- 기준 커밋: `a28fc26 docs(context): add SIP 070 supplier playbooks`
- 원격 상태 확인: `origin/main...HEAD = 0 0`
- 마지막 관측 CI: `Release Please` run `29020254364` success
- 작업트리 특이사항: `.gjc/` 런타임 상태만 untracked였음. 커밋 대상 아님.

## 제품 방향

Recova는 Callva, Vox.ai, 채널톡 ALF처럼 **전화선에 직접 연결된 한국 B2B AI 전화 서비스**를 만든다.

V1 방향:

- ClawOps는 V1 core 런타임/폴백에서 제외.
- Jambonz 기반 `jambonz_contract_v1` contract-first core가 production basis.
- Asterisk/ARI는 reference only.
- 공급자 matrix를 기다리지 않고 simulator/fixture로 미리 구현 완료.
- 실제 SIP/070 공급자 payload와 통화 품질은 cutover/staging gate에서 검증.

## 이미 끝난 코드베이스 작업

### Backend core

- Hidden Jambonz provider 구현.
- `jambonz_contract_v1` 계약 모델/서명/fixture/simulator/smoke 구현.
- Jambonz inbound/outbound runtime policy가 assigned Recova 070 번호만 core 경로로 사용하도록 제한.
- campaign 발신 풀도 Recova-managed assigned number 기준으로 제한.
- admission, CDR/failure event, ops alert 흐름 추가.
- trusted-only live validation attestation 추가.

### Number inventory / assignment

- 운영자 중심 번호 inventory 도입.
- import/list/reserve/assign/quarantine/retire/audit API 구현.
- full managed-inventory assignment tuple 유지:
  - `recova_inventory_state="assigned"`
  - `managed_by="recova_number_inventory"`
  - `inventory_id`
  - `telephony_phone_number_id`
  - `telephony_configuration_id`
- 고객은 assigned number 목록만 보고 workflow에 bind/unbind.
- 고객에게 carrier credential, Jambonz credential, arbitrary phone CRUD 노출 안 함.

### Trust boundary

- simulator/fixture evidence는 live readiness로 인정하지 않음.
- `live_trunk_validated=true`만으로는 live-ready 처리하지 않음.
- trusted writer marker `recova_operator_live_validation_v1`가 있어야 live validation evidence로 인정.
- live validation metadata는 import/assign/quarantine/retire 경계에서 strip/재스탬프.

### UI

- Superadmin number inventory page에서 import/reserve/assign/quarantine/retire/audit/live attestation 가능.
- Customer assigned numbers page `/telephony-numbers` 구현.
- Workflow settings에 assigned number binder 결합.
- Campaign UI에서 Recova-managed assigned caller ID pool/concurrency 안내.

### Docs/context

- `context/001-own-telephony-infra.md`: 자체 전화 인프라 방향.
- `context/002-korean-sip070-contract-guide.md`: 공급자 계약/질문/후보 리스트.
- `context/003-sip070-phone-call-playbook.md`: 전화 문의 스크립트와 상사 보고용 설명.
- `docs/integrations/telephony/own-infra-readiness.mdx`: readiness 기준.
- `docs/integrations/telephony/own-infra-runbook.mdx`: operator/customer flow.
- `docs/integrations/telephony/sip-070-cutover-checklist.mdx`: cutover checklist.

## 아직 남은 것

남은 것은 대부분 코드가 아니라 외부 스펙/계약/실통화 검증이다.

1. 한국 SIP/070 공급자 계약 또는 테스트 계정 확보.
2. 공급자 기술 스펙 확보:
   - SIP endpoint/proxy/registrar
   - 인증 방식: IP-auth 또는 REGISTER
   - inbound DID 라우팅 방식
   - outbound caller ID 정책
   - codec/DTMF/early media
   - CDR/장애 로그 제공 방식
   - 동시콜/CPS/요금/차단 정책
3. GCP Seoul staging 환경에 실제 trunk 설정.
4. 실제 번호로 inbound/outbound/campaign smoke.
5. operator `Attest live` 기록.
6. 24h staging soak.
7. 법무/규제/사업 launch 판단.

## 지금 당장 코딩을 더 하면 안 되는 이유

공급자 스펙 없이 아래를 상상으로 구현하면 위험하다.

- 특정 SIP header mapping.
- 특정 provider response code 해석.
- codec/DTMF 강제값.
- CDR field mapping.
- caller ID 사전등록 flow.
- live trunk validated 자동 판정.

현재는 contract simulator로 안전하게 멈춰둔 상태다. 다음 코드는 실제 공급자 문서가 들어온 뒤 작성한다.

## 하면 안 되는 것

- ClawOps를 V1 runtime/fallback으로 되살리지 않는다.
- phone preview 성공을 own-infra readiness로 인정하지 않는다.
- simulator/fixture call을 live readiness denominator에 넣지 않는다.
- customer에게 SIP credential, provider credential, raw trunk 설정을 노출하지 않는다.
- 법무/규제 결론을 기술 코드나 문서에서 단정하지 않는다.
- tenant isolation 없이 organization-scoped resource를 조회/변경하지 않는다.

## 다음 사람이 시작할 때 첫 액션

1. `context/002-korean-sip070-contract-guide.md`와 `context/003-sip070-phone-call-playbook.md`에서 공급자 후보와 질문을 확인한다.
2. 공급자 답변을 `05-supplier-intake-template.md` 형식으로 정리한다.
3. 공급자 스펙이 충분하면 `03-next-coding-after-supplier.md` 순서로 구현한다.
4. 구현 후 `04-verification-commands.md`의 smoke/test/build를 실행한다.
