# 제품 지표와 검증 기준

- 문서 상태: draft
- 마지막 검토: 2026-07-10

현재 저장소에는 종단 제품 지표의 확정 baseline과 목표값이 없다. 이 문서는 먼저 정의를 고정하며, 수치는 실제 계측 후 결정한다.

## 제안 지표 체계

### Core activation rate

신규 조직이 다음을 모두 완료한 비율이다.

1. 에이전트를 생성한다.
2. 의미 있는 웹·텍스트 또는 전화 시험을 완료한다.
3. 전사·도구 호출·통화 결과를 확인한다.
4. 에이전트를 수정하고 다시 시험한다.

이 지표는 빌더의 첫 가치만 측정한다. 회사 도입 평가 성공으로 표현하지 않는다.

### Qualified telephony demo success rate

신규 조직이 다음을 모두 완료한 비율이다.

1. Core activation을 완료한다.
2. 자신의 전화번호로 아웃바운드 시험 통화를 완료한다.
3. 인바운드와 아웃바운드의 업무 가치를 모두 경험한다.
4. 전사, 도구 호출, 통화 결과, 품질·비용·보안 조건을 확인한다.
5. 파일럿·계약·중단 중 다음 상업 단계를 선택한다.

웹콜만 성공한 조직은 이 지표에 포함하지 않는다. 현재 인바운드 체험 방식, 상업 전환 이벤트, baseline과 목표값은 `Unknown`이며 제품 책임자 결정이 필요하다.

## 퍼널

| 단계 | 정의 | 지표 구분 | 아직 필요한 것 |
|---|---|---|---|
| 가입 완료 | 유효 세션과 조직 컨텍스트가 생성됨 | 공통 | 세션 실패와 신규 상태 분리 |
| 첫 에이전트 생성 | 워크플로 ID와 유효 draft 생성 | Core activation | 이름·업무 목표·성공 기준 정의 |
| 첫 시험 시작 | 웹·텍스트·전화 시험 세션 시작 | Core activation | 채널별 이벤트 규격 |
| 첫 시험 성공 | 대화가 정상 종료되고 결과가 저장됨 | Core activation | “의미 있는 통화” 최소 조건 |
| 결과 확인 | 전사·도구 호출·disposition 화면 확인 | Core activation | 개인정보 없는 분석 이벤트 |
| 첫 개선 | 워크플로 수정 후 재시험 | Core activation | 변경 버전과 시험 결과 연결 |
| 자기 번호 아웃바운드 성공 | 사용자가 입력한 번호로 전화가 연결되고 결과가 저장됨 | Qualified telephony demo | OTP·번호 마스킹을 유지한 이벤트 |
| 인바운드 가치 경험 | 인바운드 업무 흐름과 결과를 사용자가 확인함 | Qualified telephony demo | 계약 전 제공 방식과 성공 기준 |
| 도입 조건 검토 | 품질·비용·보안과 운영 조건을 확인함 | Qualified telephony demo | 평가 요약과 확인 이벤트 |
| 상업 단계 선택 | 파일럿·계약·중단 상태가 기록됨 | Qualified telephony demo | CRM/영업 handoff와 상태 정의 |
| 운영 진입 | 번호 binding, 단건 발신 또는 캠페인 생성 | Adoption/operation | 채널별 진입 기준 |

반드시 볼 보조 지표:

- 가입 → Core activation 전환율
- Core activation → Qualified telephony demo 전환율
- 자기 번호 아웃바운드와 인바운드 가치 경험의 개별 성공률
- 첫 성공 통화와 도입 단계 선택까지 걸린 시간
- 단계별 이탈률과 오류 원인 분포

## 통화 품질

웹, phone preview, staging PSTN, production PSTN을 분리해 측정한다.

- call completion rate와 drop rate
- user stop → bot audio 시작 지연
- STT final, LLM first token, TTS first audio
- interruption/barge-in 성공률과 false interruption
- 도구 호출 성공·실패·timeout
- workflow node transition 정확도
- 전사 완전성·오류율
- report/disposition 생성 완전성
- provider reconnect와 terminal failure 원인 포착률

지연 정의와 benchmark 명령은 [`../docs/product/returnzero-latency-optimization.md`](../docs/product/returnzero-latency-optimization.md)에만 둔다.

## 운영 성과

- 인바운드 응답률과 정상 라우팅률
- 아웃바운드 연결·응답·완료율
- 캠페인 진행률, 성공·실패·재시도율
- 업무별 disposition과 전환 결과
- 실패 원인 미분류 비율
- 운영자가 실패를 발견해 수정·재시험하기까지 걸린 시간
- 조직·워크플로·캠페인별 사용량과 비용

“전환”의 업무 의미는 업종과 사용 사례별로 정의해야 한다. 단일 `xfer_count`를 모든 고객의 비즈니스 성과로 간주하지 않는다.

## 경제성

- 분당 STT, LLM, TTS, telephony 비용
- 성공 통화당 비용
- 도구 호출과 재시도로 인한 추가 비용
- 캠페인별 비용과 유효 결과당 비용
- 공급자 quota·동시콜·CPS 제한 사용률

ReturnZero STT 비용 귀속이 구현되기 전에는 전체 비용 가시성이 완성됐다고 표시하지 않는다.

## 안전과 신뢰

다음은 평균이 아니라 hard gate다.

- cross-tenant read/write/routing 0건
- credential, 전체 전화번호, raw provider ID의 비인가 노출 0건
- retired/quarantined/unassigned/wrong-org 번호 발신 0건
- simulator evidence의 live readiness 승격 0건
- OTP·quota·abuse/fraud 제한 우회 0건
- 녹음·전사 보존과 삭제 정책 위반 0건

## 증거 등급

1. **Unit/fixture:** 계약과 분기 검증용. 실제 통화 품질 증거가 아니다.
2. **Synthetic/local:** pipeline 비교와 회귀 검증용. 실제 PSTN 수치가 아니다.
3. **Phone preview:** 실제 목적지 전화 경험이지만 production inbound/campaign 증거와 구분한다.
4. **Staging PSTN:** 공급자 trunk와 실제 번호를 사용한 cutover 증거다.
5. **Production:** 고객·조직·업무 맥락의 장기 지표다.

모든 품질 주장은 환경, 표본 수, 기간과 증거 등급을 함께 기록한다.

## 목표값 결정 전 필요한 작업

- 퍼널 이벤트 이름과 개인정보 최소화 규칙 확정
- 현재 신규 사용자 baseline 계측
- Core activation과 자기 번호 아웃바운드·인바운드 경험의 성공 정의 확정
- 첫 우선 업무의 disposition·전환 정의
- 파일럿·계약·중단 상업 단계 이벤트 정의
- 비용 attribution 공백 확인
- 제품 지표 owner와 주간 검토 방식 결정
