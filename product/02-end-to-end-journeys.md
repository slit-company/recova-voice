# 종단 사용자 여정

- 문서 상태: active
- 마지막 검토: 2026-07-13

## 기준 여정

Recova의 기준 여정은 다음 순환을 끊김 없이 만드는 것이다.

> 가입·조직 준비 → 에이전트 생성 → 업무 대화 구성 → 시험 통화 → 실제 채널 연결 → 운영 → 결과 확인 → 수정·재시험

현재 코드에 화면이나 기능이 존재하는 것과 이 여정이 제품적으로 연결된 것은 다르다.

## 1. 가입과 조직 준비
- **제품 상태:** Partial

**사용자 결과**

- 계정을 만들고 자신이 속한 회사와 역할을 이해한다.
- 첫 에이전트를 만들 준비가 됐는지 명확히 안다.

**현재 확인된 동작**

- 이메일·비밀번호 가입 후 세션을 만들고 `/after-sign-in`으로 이동한다.
- 활성 워크플로가 없으면 `/workflow/create`, 있으면 `/workflow`로 이동한다.

근거: `ui/src/app/auth/signup/page.tsx`, `ui/src/app/after-sign-in/page.tsx`

**현재 공백**

- 세션 생성 실패와 신규 사용자 상태가 명확히 구분되지 않는다.
- 회사·팀·역할·이용 목적, 약관·개인정보 안내가 첫 흐름에서 드러나지 않는다.
- `/overview`의 안내가 신규 사용자 기본 흐름과 연결되지 않는다.

## 2. 첫 에이전트 생성
- **제품 상태:** Partial

**사용자 결과**

- 전화 업무와 성공 기준을 설명해 실행 가능한 첫 초안을 만든다.

**현재 확인된 동작**

- 인바운드/아웃바운드 유형, 사용 사례, 활동 설명으로 템플릿 워크플로를 생성한다.
- 성공 후 에디터를 열고 웹콜 온보딩으로 연결한다.

근거: `ui/src/app/workflow/create/page.tsx`

**현재 공백**

- 이름, 대상 고객, 언어·음성, 업무 목표, 성공 지표, 금지 행동을 한 흐름에서 정하지 않는다.
- ID 없는 성공 응답이나 성공 모달을 닫은 뒤의 복구 경로가 불명확하다.

## 3. 업무 대화 구성
- **제품 상태:** Partial

**사용자 결과**

- 시작·종료, 대화 노드, 분기, 도구, 지식, 녹음과 설정을 이해하며 수정한다.
- 배포 전에 누락된 필수 조건과 위험을 발견한다.

**현재 확인된 동작**

- React Flow 기반 워크플로 빌더와 노드·엣지 편집, 버전, 도구·문서·녹음 연결이 존재한다.
- 에이전트는 활성·보관 상태와 폴더로 관리된다.

근거: `ui/src/app/workflow/[workflowId]/page.tsx`, `ui/src/app/workflow/[workflowId]/RenderWorkflow.tsx`, `ui/src/app/workflow/page.tsx`

**현재 공백**

- 초보 운영자가 “통화 가능한 상태”를 판단할 제품 수준 체크리스트가 확인되지 않았다.
- 한국어 fallback과 일부 Dograh 중심 문구가 남아 있다.
- 빌더 안에서 업무 KPI와 통화 후 판정을 설계하는 흐름이 약하다.

## 4. 시험과 디버깅
- **제품 상태:** Partial

**사용자 결과**

- 웹, 텍스트 또는 자신의 전화번호로 실제 대화를 시험한다.
- 실패 시 어느 단계가 문제인지 이해하고 바로 수정한다.

**현재 확인된 동작**

- 웹 음성 테스터, 수동 텍스트 채팅, 전화 프리뷰 흐름이 존재한다.
- 기본 전화 프리뷰는 표준 STT + LLM + TTS의 `speed_demo` 런타임 프로필을 사용하며 저장된 워크플로를 바꾸지 않는다.

근거: `ui/src/app/workflow/[workflowId]/components/WorkflowTesterPanel.tsx`, `ui/src/app/workflow/[workflowId]/components/PhoneCallDialog.tsx`, `docs/product/returnzero-latency-optimization.md`

**현재 공백**

- 첫 통화 성공, 전사 확인, 도구 호출 확인, 실패 해결을 하나의 완료 흐름으로 묶은 근거가 없다.
- 테스트 결과에서 수정해야 할 노드로 바로 돌아가는 연결이 약하다.

## 5. 실제 채널 연결과 배포
- **제품 상태:** Partial

**사용자 결과**

- 검증된 에이전트를 인바운드 번호, 단건 아웃바운드 또는 캠페인에 안전하게 연결한다.
- 전화번호, 발신자 ID, 동시콜과 권한을 이해한다.

**현재 확인된 동작**

- 다중 telephony provider 설정과 배정된 Recova 번호 binding 표면이 존재한다.
- 자체 070 inventory·assignment·trusted live attestation 코어가 구현돼 있다.

근거: `ui/src/app/telephony-configurations/page.tsx`, `ui/src/app/telephony-numbers/page.tsx`, `context/own-telephony-handoff/01-current-state.md`

**현재 공백**

- 빌더에서 테스트 성공 후 전화 연결·단건 발신·캠페인으로 이어지는 통합 전환이 약하다.
- [Waiting] 자체 070은 공급자 계약과 실제 인바운드·아웃바운드 검증을 기다린다. 기술 단계는 전화 인프라 handoff 문서에서 관리한다.

## 6. 운영
- **제품 상태:** Partial

**사용자 결과**

- 인바운드와 아웃바운드 업무를 반복 운영하고, 진행·실패·재시도를 관리한다.

**현재 확인된 동작**

- 캠페인 생성과 상태, 연결 워크플로, 실행 수와 대기 수를 관리한다.
- 워크플로별 실행 목록과 상세 진입점이 존재한다.

근거: `ui/src/app/campaigns/page.tsx`, `ui/src/app/workflow/[workflowId]/runs/page.tsx`

**현재 공백**

- 캠페인 진행 화면에서 결과·전환·실패 원인·후속 조치로 이어지는 연결이 약하다.
- [Unknown] 인바운드 큐와 단건 아웃바운드 운영 여정은 추가 감사가 필요하다.

## 7. 측정과 개선
- **제품 상태:** Partial

**사용자 결과**

- 업무 성과, 통화 품질, 실패 원인과 비용을 보고 개선할 에이전트와 대화를 고른다.
- 수정 후 같은 기준으로 다시 시험해 개선 여부를 확인한다.

**현재 확인된 동작**

- 일간 실행·전환·disposition·통화시간 리포트와 CSV가 있다.
- 사용량 화면에서 실행 필터, 녹음·전사, 토큰·비용, 상세 링크를 제공한다.
- 실행 상세에서 실행을 만든 에이전트 이름을 함께 확인할 수 있다.

근거: `ui/src/app/reports/page.tsx`, `ui/src/app/usage/page.tsx`, `ui/src/app/workflow/[workflowId]/run/[runId]/page.tsx`

**현재 공백**

- 캠페인 단위 성과와 목표 대비 결과가 명확히 연결되지 않는다.
- 리포트·실행 상세에서 해당 워크플로 수정과 재시험으로 돌아가는 개선 루프가 약하다.
- “회사 도입 평가 성공”을 판단할 제품 지표와 화면이 아직 확정되지 않았다.

## 8. 회사 도입 평가와 전환

- **제품 상태:** Unknown

**사용자 결과**

- 자신의 번호로 아웃바운드를 시험하고 인바운드와 아웃바운드의 업무 가치를 모두 경험한다.
- 통화 품질, 업무 결과, 비용, 보안과 운영 조건을 검토해 파일럿·계약·중단을 결정한다.

**현재 확인된 동작**

- 전화 프리뷰, 실행 상세, 리포트와 사용량·비용 화면은 각각 존재한다.

근거: `ui/src/app/workflow/[workflowId]/components/PhoneCallDialog.tsx`, `ui/src/app/reports/page.tsx`, `ui/src/app/usage/page.tsx`

**현재 공백**

- 인바운드와 아웃바운드 체험, 품질·비용·보안 검토를 하나의 도입 평가로 묶은 흐름이 확인되지 않았다.
- 무료 시험·크레딧·과금 전환과 영업 handoff 기준이 확정되지 않았다.
- 자체 070 계약 전 인바운드 체험을 제공할 정확한 방식이 미정이다.

## 9. 조직과 superadmin 운영

- **제품 상태:** Partial

**사용자 결과**

- 조직 관리자가 구성원·권한·API 키·전화 설정·사용량을 통제한다.
- Recova 운영자가 조직과 전화번호 inventory를 tenant-safe하게 운영하고 장애와 감사를 처리한다.
- 녹음 동의, 개인정보, 보존·삭제와 abuse/fraud 조건을 확인한 뒤 production 사용을 허용한다.

**현재 확인된 동작**

- 설정, API 키, telephony configuration, 사용량과 superadmin 화면이 존재한다.
- 전화번호 inventory의 import·reserve·assign·quarantine·retire·audit 경로가 존재한다.

근거: `ui/src/app/settings/page.tsx`, `ui/src/app/api-keys/page.tsx`, `ui/src/app/telephony-configurations/page.tsx`, `ui/src/app/usage/page.tsx`, `ui/src/app/superadmin/page.tsx`

**현재 공백**

- 역할·권한별 빈·오류·금지 상태의 종단 감사가 필요하다.
- 녹음 동의, 개인정보, 보존·삭제와 업종별 규제 gate가 확정되지 않았다.
- superadmin 운영은 고객의 도입 평가와 분리하되, 실제 launch의 필수 조건으로 연결해야 한다.

## 완료 판단

종단 여정은 각 기능이 존재한다고 완료되지 않는다. 잠재고객과 조직 관리자가 별도 설명 없이 다음을 수행하고 결과를 이해할 때 완료로 본다.

1. 조직과 역할이 준비된 상태에서 첫 에이전트를 만든다.
2. 자신의 번호로 의미 있는 아웃바운드 시험 통화를 완료하고 인바운드 가치를 경험한다.
3. 전사·도구 호출·통화 결과를 확인한다.
4. 에이전트를 실제 운영 채널에 연결한다.
5. 운영 결과, 통화 품질과 비용을 확인한다.
6. 권한, 보안, 녹음·개인정보와 운영 조건을 검토한다.
7. 파일럿·계약·중단 중 다음 상업 단계를 결정한다.
8. 문제를 수정하고 다시 시험한다.
