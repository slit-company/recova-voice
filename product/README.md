# Recova 제품 기획

- 문서 상태: active
- 마지막 검토: 2026-07-10
- 목적: Recova가 누구를 위해 어떤 제품을 만들고 있으며, 현재 어디까지 왔고 무엇을 우선할지 한곳에서 확인한다.

## 한 줄 정의

Recova는 한국 B2B 팀이 AI 전화 에이전트를 직접 만들고 시험한 뒤, 인바운드·아웃바운드·캠페인으로 운영하고 결과를 측정해 개선하는 셀프서브 콜 빌더다.

070 번호 발급과 자체 전화 인프라는 이 제품을 실제 한국 전화망에 연결하는 하위 시스템이다. 전화 인프라 작업이 전체 제품 기획을 대신하지 않는다.

## 문서 목차

| 문서 | 소유하는 내용 |
|---|---|
| [01-product-definition.md](./01-product-definition.md) | 고객, 문제, 제품 약속, 원칙, 범위 |
| [02-end-to-end-journeys.md](./02-end-to-end-journeys.md) | 가입부터 운영·성과 개선까지의 목표 여정과 현재 공백 |
| [03-capability-map.md](./03-capability-map.md) | 제품 영역별 현재 상태와 코드·문서 근거 |
| [04-priorities.md](./04-priorities.md) | 현재 우선순위, 대기 트랙, 후순위 |
| [05-metrics.md](./05-metrics.md) | 활성화·통화 품질·운영 성과·안전 지표 |

## 원본 경계

문서마다 같은 내용을 복사하지 않는다.

| 위치 | 원본으로 관리하는 내용 |
|---|---|
| `product/` | 현재 제품 정의, 사용자 여정, 역량 상태, 우선순위, 제품 지표 |
| `context/` | 왜 그런 결정을 했는지에 대한 조사 근거와 결정 이력 |
| `plans/` | 승인된 범위를 구현하기 위한 파일 단위 실행 계획과 검증 방법 |
| `docs/` | 실제 사용자가 사용할 수 있는 기능에 대한 공개 문서와 운영 문서 |
| `AGENTS.md` | 저장소 작업 규칙, 보안 불변식, 코드 탐색 안내 |
| `README.md` | 신규 기여자를 위한 짧은 저장소 개요 |

세부 수치, 명령, 공급자 payload, 코드 구현 설명은 해당 기술 문서에 둔다. 이 폴더에서는 결론과 상태만 적고 원본을 링크한다.

## 상태 표기

- **Current**: 현재 코드나 운영 절차로 확인되는 역량.
- **Partial**: 구성 요소는 있으나 사용자 여정이 끊기거나 품질·운영 조건이 부족한 상태.
- **Waiting**: 외부 계약, 공급자 정보, 법무 판단처럼 코드 밖의 입력을 기다리는 상태.
- **Planned**: 방향은 정했지만 구현 또는 검증이 끝나지 않은 상태.
- **Unknown**: 현재 근거로 판단할 수 없어 조사해야 하는 상태.

`Current`는 “제품적으로 충분하다”는 뜻이 아니다. 기능 존재와 사용자 가치 완성을 구분한다.

## 동기화 규칙

제품 정의·동작·여정, 역량 상태, 우선순위, 지표·gate 또는 결정 상태를 바꾸는 사람은 반드시 같은 verified change 안에서 아래 제품 기획 문서를 갱신한다. 이 동기화는 해당 변경의 완료 조건이다.

1. 목표 고객, 제품 약속, 기본 런타임 또는 비타협 원칙이 바뀌면 `01-product-definition.md`를 갱신한다.
2. 가입·생성·시험·배포·운영·측정 흐름이 바뀌면 `02-end-to-end-journeys.md`를 갱신한다.
3. 기능이 출시·중단·대기 상태로 바뀌면 `03-capability-map.md`의 상태와 근거를 갱신한다.
4. 우선순위가 바뀌거나 작업이 끝나면 `04-priorities.md`를 갱신한다.
5. 측정 정의나 출시 gate가 바뀌면 `05-metrics.md`를 갱신한다.
6. 결정 이유가 새로 생기거나 뒤집히면 `context/`에 순번 문서를 추가하고 여기서 링크한다.
7. 구현에 들어가는 일은 `plans/`에 실행 계획을 두고, 검증 근거가 생긴 뒤에만 `03-capability-map.md`의 제품 상태를 변경한다.
8. 공개 동작이 바뀌면 실제 제품과 일치하는 범위에서 `docs/`도 함께 갱신한다.

모든 제품 문서는 상단의 `마지막 검토` 날짜를 갱신한다. 근거 없는 완료 표시와 미래 기능을 현재 기능처럼 쓰는 것은 금지한다.

영역별 공식 제품 상태는 `03-capability-map.md`에서만 변경한다. 다른 문서는 필요한 상태를 링크하거나 요약할 수 있지만 서로 다른 상태를 별도로 선언하지 않는다.

## 현재 연결 문서

- 제품·저장소 방향: [`../AGENTS.md`](../AGENTS.md), [`../README.md`](../README.md)
- Realtime 방향: [`../docs/product/realtime-development-direction.md`](../docs/product/realtime-development-direction.md)
- 기본 ReturnZero 파이프라인: [`../docs/product/returnzero-latency-optimization.md`](../docs/product/returnzero-latency-optimization.md)
- 자체 전화 인프라 결정: [`../context/001-own-telephony-infra.md`](../context/001-own-telephony-infra.md)
- 전화 인프라 현재 상태: [`../context/own-telephony-handoff/01-current-state.md`](../context/own-telephony-handoff/01-current-state.md)
- 한국어 UI 감사 계획: [`../plans/korean-locale-fallback-audit.md`](../plans/korean-locale-fallback-audit.md)
