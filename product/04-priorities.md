# 제품 우선순위

- 문서 상태: active
- 마지막 검토: 2026-07-16
- 기준: 전화 공급자 계약은 기다리되, 콜 빌더 제품 개선은 멈추지 않는다.

이 문서는 구현 작업 목록이 아니라 제품 문제의 우선순위다. 파일 단위 변경과 검증은 실행 전에 `plans/` 문서로 구체화한다.

## P0 — 셀프서브 첫 가치 완성

**목표:** 신규 사용자가 설명 없이 가입해 첫 에이전트를 만들고 의미 있는 통화를 완료한 뒤 결과를 이해한다.

- 가입·세션·조직 준비의 실패와 신규 상태를 명확히 구분한다.
- 빈 대시보드와 첫 생성 흐름이 사용자의 다음 행동을 한 가지로 안내한다.
- 첫 생성에서 업무 목적, 대상, 성공 기준과 필수 안전 규칙을 이해시킨다.
- 생성 → 자신의 번호를 사용한 아웃바운드 시험 → 인바운드 가치 확인 → 전사·도구 호출·통화 결과 확인을 한 흐름으로 연결한다.
- 첫 통화 실패 시 인증, 모델, 워크플로, STT/LLM/TTS, 전화 단계 중 어디가 문제인지 알려준다.
- 품질·비용·보안 조건을 요약하고 파일럿·계약·중단 중 다음 단계를 안내한다.

**완료 신호:** 신규 사용자가 가입부터 자신의 번호를 사용한 시험, 인바운드·아웃바운드 가치 확인, 결과 검토와 다음 도입 단계 선택까지 운영자 도움 없이 완료하며, 단계별 전환과 실패 원인이 측정된다.

## P0 — 제품 측정 기반 만들기

**목표:** 느낌이 아니라 실제 사용자 여정과 통화 결과로 우선순위를 정한다.

- 가입, 첫 생성, 첫 시험 시작·성공, 결과 확인, 재편집의 퍼널을 정의한다.
- 웹콜, 전화 프리뷰, 실제 PSTN과 synthetic evidence를 분리한다.
- 지연뿐 아니라 통화 완료, interruption, 도구 호출, 전사·리포트 품질, drop과 비용을 함께 본다.
- 민감한 번호, raw logs, provider ID와 credential을 제품 분석에 노출하지 않는다.

**완료 신호:** 각 P0/P1 개선이 baseline 대비 어떤 사용자·통화 지표를 바꿨는지 설명할 수 있다.

## P1 — 한국 B2B 빌더 품질

**목표:** 비개발 운영자가 복잡한 워크플로를 안전하게 만들고 반복 수정한다.

- 한국어 fallback과 Dograh 중심 문구를 실제 화면 단위로 정리한다.
- 노드·분기·도구·지식·녹음 설정의 목적과 오류를 쉽게 설명한다.
- 통화 전 readiness, 필수값, 충돌과 위험한 설정을 저장·실행 전에 보여준다.
- 버전, draft/active 상태와 변경 영향이 운영자에게 명확해야 한다.
- 템플릿을 업종 이름이 아니라 검증 가능한 업무 목표와 결과 중심으로 평가한다.

연결 계획: [`../plans/korean-locale-fallback-audit.md`](../plans/korean-locale-fallback-audit.md)

## P1 — 시험에서 운영과 성과까지 연결

**목표:** 테스트한 에이전트를 실제 업무에 적용하고 결과로 다시 개선한다.

- 빌더에서 인바운드 번호, 단건 아웃바운드, 캠페인으로 이어지는 경로를 명확히 한다.
- 캠페인에서 진행률뿐 아니라 전환, disposition, 실패 원인과 후속 행동을 본다.
- 리포트·사용량·실행 상세에서 해당 워크플로와 문제 노드로 돌아갈 수 있게 한다.
- 업무 KPI, 캠페인 결과, 통화 품질과 비용을 같은 운영 맥락에서 비교한다.

**완료 신호:** 운영자가 문제 캠페인이나 통화를 발견해 원인을 확인하고, 에이전트를 수정·재시험하는 순환을 끊김 없이 완료한다.

## 상태 트랙 — 우선순위와 별개

### Waiting — 자체 한국 전화 인프라

- **제품 상태:** Waiting
- 공개 소스·라이선스 키 비의존 후보와 서울 비공개 disabled staging은 검증했지만 live readiness는 검증되지 않았다.
- 최신 시작 잔액·통화, 공급자 권위 RTP CIDR/포트와 실제 Recova F12/media 경로가 확인되기 전에는 REGISTER·RTP·실통화 gate를 열지 않는다.
- 이 대기는 위 P0/P1 콜 빌더 개선을 막지 않는다.

결정·기술 handoff: [`../context/own-telephony-handoff/01-current-state.md`](../context/own-telephony-handoff/01-current-state.md), [`../context/own-telephony-handoff/03-next-coding-after-supplier.md`](../context/own-telephony-handoff/03-next-coding-after-supplier.md)

### Current — Realtime opt-in

- **제품 상태:** Current
- 기본값 승격 결정은 실제 한국 B2B 통화 근거를 기다리는 `Planned` 상태다.
- 지연, interruption, 통화 완료, 도구·그래프 정확도, 전사·리포트 품질과 분당 비용을 표준 파이프라인과 비교한다.

기술 방향: [`../docs/product/realtime-development-direction.md`](../docs/product/realtime-development-direction.md)

## 보류·미결정

- **Planned / 우선순위 미정:** 실제 도메인·패키지·이미지·스크린샷과 함께하는 전면 Recova 리브랜딩
- **현재 범위 밖:** 고객 self-serve 번호 marketplace와 raw carrier credential 노출
- **Unknown:** 첫 wedge 근거가 필요한 업종별 전용 제품화
- **Unknown:** 공급자 정책과 abuse/fraud 근거가 필요한 대규모 캠페인 한도
