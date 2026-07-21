# 제품 역량 지도

- 문서 상태: active
- 마지막 검토: 2026-07-21

이 표는 기능 존재 여부와 종단 사용자 가치 완성을 구분한다. 상태 정의는 [`README.md`](./README.md)를 따른다.

- 전체 셀프서브 종단 여정: **Partial**
- 자체 한국 070 trunk: **Waiting**

| 영역 | 상태 | 현재 근거 | 핵심 공백 또는 조건 |
|---|---|---|---|
| 계정 가입과 인증 | Partial | `ui/src/app/auth/signup/page.tsx`, `ui/src/app/after-sign-in/page.tsx` | 신규 상태와 인증/조회 실패 구분, 회사·역할·약관 안내 |
| 조직·권한·API 키 | Partial | `ui/src/app/settings/page.tsx`, `ui/src/app/api-keys/page.tsx`, `AGENTS.md` | 코어 표면은 있으나 역할·권한·오류 상태 감사와 tenant isolation 지속 검증이 필요함 |
| 첫 에이전트 생성 | Partial | `ui/src/app/workflow/create/page.tsx` | 업무 목표·성공 지표·안전 규칙까지 받는 생성 경험이 불완전함 |
| 에이전트 목록·폴더·보관 | Current | `ui/src/app/workflow/page.tsx` | 첫 가치와 운영 현황을 보여주는 허브 역할 보완 필요 |
| 시각적 워크플로 빌더 | Partial | `ui/src/app/workflow/[workflowId]/RenderWorkflow.tsx`, `ui/src/components/flow/` | 코어 편집은 있으나 초보자 가이드, readiness와 업무 KPI 설계가 불완전함 |
| 도구·파일·녹음 연결 | Partial | `ui/src/app/tools/`, `ui/src/app/files/`, `ui/src/app/recordings/` | 기능은 있으나 생성·시험·결과 여정 안의 발견성과 연결성이 검증되지 않음 |
| 웹 음성·텍스트 시험 | Partial | `ui/src/app/workflow/[workflowId]/components/WorkflowTesterPanel.tsx` | 시험은 가능하나 결과→문제 노드→재시험의 개선 루프가 불완전함 |
| 실제 전화 프리뷰 | Partial | `ui/src/app/workflow/[workflowId]/components/PhoneCallDialog.tsx`, `docs/product/returnzero-latency-optimization.md` | 통화는 가능하나 첫 성공과 전사·도구·비용 확인이 하나의 흐름으로 검증되지 않음 |
| 표준 STT + LLM + TTS | Current | `AGENTS.md`, `docs/product/returnzero-latency-optimization.md` | 현재 demo 기본값이며 실제 PSTN 품질·비용 근거를 계속 축적해야 함 |
| Realtime 런타임 | Current | `docs/product/realtime-development-direction.md` | opt-in 경로이며 한국 B2B benchmark gate 전 기본값 승격 금지 |
| 다중 telephony provider | Current | `ui/src/app/telephony-configurations/page.tsx`, `api/services/telephony/` | 셀프서브 빌더 흐름 안에서 설정 복잡도 완화 필요 |
| Recova 배정 번호 UX | Partial | `ui/src/app/telephony-numbers/page.tsx`, `ui/src/components/telephony/AssignedNumbersBinder.tsx`, `context/own-telephony-handoff/01-current-state.md` | 전화번호 탭의 한·영 전환은 완료했으나 실공급자 번호와 live attestation 전 production-ready 아님 |
| 자체 한국 070 trunk | Waiting | `context/004-onnuri-staging-no-traffic-checkpoint.md`, `context/007-onnuri-bounded-live-smoke-foundation.md`, `context/008-onnuri-outbound-route-remediation.md`, `deploy/onnuri-jambonz-oss/`, `infra/onnuri-seoul-staging-phase-b/`, `infra/onnuri-seoul-staging-phase-c-smoke/` | 공개 소스 후보와 서울 disabled staging에 더해 provider-fact route decision/conformance, F12 전용 one-use route capability, 최대 3회·수동 승인·무자동재시도 진단 권한, 닫힌 signaling/answer/media 상태 그래프를 offline/default-disabled로 검증했다. 기존 로컬 UDP 발신 경로는 승인 대상에서 제외했다. 공급자 권위 outbound route/caller-ID/dial-format/CDR 사실, 새 immutable candidate와 packet-present preflight, 서울 실경로 outbound·inbound·양방향 media·비용·teardown 증거가 없으므로 계속 `Waiting`이며 production-ready 또는 `Current`가 아님 |
| 인바운드 종단 운영 | Partial | workflow call type, telephony routing, assigned number binder | 신규 사용자가 계약 전 경험할 정확한 UX 미결정 |
| 단건 아웃바운드 종단 운영 | Partial | phone preview와 telephony runtime | 시험→실운영 전환과 운영 결과 연결 보완 필요 |
| 캠페인 | Partial | `ui/src/app/campaigns/` | 코어 운영은 있으나 빌더→캠페인, 캠페인→성과·실패·수정 연결이 불완전함 |
| 실행 상세와 전사 | Partial | `ui/src/app/workflow/[workflowId]/run/[runId]/page.tsx`, `ui/src/app/usage/page.tsx` | 에이전트 식별과 결과 조회는 가능하나 문제 원인 설명과 수정할 워크플로 연결이 불완전함 |
| 리포트와 disposition | Partial | `ui/src/app/reports/page.tsx` | 코어 리포트는 있으나 캠페인·목표 대비 성과와 개선 행동 연결이 불완전함 |
| 사용량과 비용 | Partial | `ui/src/app/usage/page.tsx`, pricing services | ReturnZero STT 비용 귀속과 도입 평가용 비용 요약 미완 |
| 한국어 제품 UX | Partial | locale context와 번역 테이블, 전화번호 탭 번역, `plans/korean-locale-fallback-audit.md` | 전화번호 탭은 화면·빈 상태·작업 피드백까지 전환되며, 나머지 영어 fallback 감사 계획은 아직 완료 표시되지 않음 |
| Recova 브랜드와 공개 문서 | Partial | `README.md`, `docs/` | Dograh 링크·스크린샷·명령을 실제 준비 상태에 맞춰 점진 이관 |
| 회사 도입 평가와 전환 | Unknown | `product/02-end-to-end-journeys.md` | 인바운드·아웃바운드 경험, 품질·비용·보안 검토와 상업 전환 흐름 미확인 |
| 조직·superadmin 운영 | Partial | `ui/src/app/settings/page.tsx`, `ui/src/app/superadmin/page.tsx` | 역할·권한·오류 상태와 고객 도입·launch gate 연결 감사 필요 |
| 녹음·개인정보·보존 정책 | Unknown | `product/01-product-definition.md` | 제품 정책과 업종별 규제 gate 미확정 |
| 종단 제품 분석 | Planned | `product/05-metrics.md` | 퍼널 이벤트, baseline과 목표값 확정 필요 |

## 절대 상태를 올리면 안 되는 경우

- simulator·fixture 성공만으로 자체 전화 인프라를 `Current` production-ready로 변경하지 않는다.
- synthetic/local benchmark를 실제 PSTN 품질로 기록하지 않는다.
- 화면이나 API가 존재한다는 이유만으로 종단 여정을 `Current`로 변경하지 않는다.
- 보안·권한·오류·빈 상태 검증 없이 B2B 운영 표면을 완료로 처리하지 않는다.

## 상태 변경 시 필요한 근거

- 사용자 여정 변경: 실제 UI 경로와 빈·오류·권한 상태 확인
- API/런타임 변경: 조직 격리와 실패 분기 테스트
- 전화 인프라 변경: 실제 번호 CDR/status/call attempt와 trusted operator attestation
- 품질 주장: 측정 환경, 표본, baseline과 raw evidence 위치
- 완료 처리: 구현 계획의 acceptance criteria와 최종 verification 결과
