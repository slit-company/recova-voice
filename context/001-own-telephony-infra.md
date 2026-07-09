# 001 — Recova 자체 한국 전화 인프라: Contract-First Jambonz Core

- 작성일: 2026-07-08
- 갱신일: 2026-07-09
- 상태: approved execution in progress
- 기준 계획: `.gjc/_session-019f4039-d524-7000-9976-acc8884c25ec/plans/ralplan/019f4039-d524-7000-9976-acc8884c25ec/pending-approval.md`

## 미션

Recova는 Callva, Vox.ai, 채널톡 ALF와 같은 **전화선에 직접 연결된 한국 B2B AI 전화 서비스**를 만든다. 시장 검증은 완료된 것으로 전제한다.

핵심은 외부 CPaaS에 종속되지 않고 Recova가 직접 운영하는 한국 070 기반 텔레포니 레이어를 갖는 것이다. 이것은 공개 API를 파는 CPaaS 사업이 아니라 **Recova 자가 소비용 전화 인프라**다.

## 최종 V1 방향

V1은 **jambonz 기반 contract-first core**로 간다.

- ClawOps는 V1 core 런타임/폴백에서 제외한다.
- jambonz가 직접 검증 및 production basis다.
- Asterisk/ARI는 reference only다.
- 외부 SIP/070 supplier matrix를 기다리지 않는다.
- 먼저 `jambonz_contract_v1` fixture/simulator로 구현하고, 실제 supplier/jambonz payload 검증은 cutover/staging gate로 둔다.
- 코드상 `jambonz` provider의 `base_url`은 public jambonz REST API가 아니라 Recova-owned `jambonz_contract_v1` adapter endpoint다. 이 adapter가 jambonz deployment와 Recova backend 사이에서 native payload를 계약 payload로 변환한다.
- GCP Seoul multi-zone + 2개 이상 jambonz 노드가 production target이다.
- 법/규제 판단은 기술 스펙 밖의 별도 business/legal launch risk다.

## 번호/고객 UX 정책

V1의 번호 UX는 운영자 중심이다.

1. 운영자가 Recova-owned 070 번호를 inventory에 import/register한다.
2. 운영자가 특정 조직에 번호를 assign한다.
3. 고객은 할당된 번호 목록만 보고 workflow에 bind/unbind한다.
4. 고객은 jambonz credential, SIP trunk, arbitrary phone-number CRUD를 직접 만지지 않는다.

Customer self-serve number marketplace, customer-owned caller ID, 발신번호 사전등록 workflow, forwarding onboarding은 V1 밖이다.

## Phone preview 정책

Phone preview는 V1 own-infra launch gate에서 제외한다.

- 기존 ClawOps-backed preview는 current-product path로 남을 수 있다.
- preview 성공은 own-infra readiness evidence가 아니다.
- preview의 ClawOps 의존 제거는 별도 follow-up plan이다.

## Contract-first 구현 원칙

`jambonz_contract_v1`은 다음을 fixture/simulator로 고정한다.

- inbound answer/control webhook
- media WebSocket start frame
- outbound create-call request/response
- status sequence: initiated/ringing/answered/completed
- terminal failures: busy/no-answer/failed/canceled/media-error
- CDR event with duration/timestamps/direction/provider call id
- malformed/unsigned/replayed callbacks
- capacity-denied/system-unavailable responses
- KR number variants: `070...`, domestic `0XX`, `+82...`

Simulator evidence는 **contract validation**일 뿐이며 live trunk readiness가 아니다. Live readiness dashboard와 soak denominator에서 fixture/simulator call과 phone preview call은 제외한다.

## Core architecture components

| Component | Direction |
|---|---|
| Jambonz provider | Hidden `api/services/telephony/providers/jambonz/`, `visible_in_self_serve=False` |
| Number inventory | Global `telephony_number_inventory` before org assignment |
| Operator APIs | import/list/reserve/assign/quarantine/retire/audit |
| Customer APIs/UI | assigned-number list + workflow bind/unbind only |
| Runtime entrypoints | `/telephony/inbound/run`, `/telephony/initiate-call`, campaign dispatch |
| Admission | atomic idempotent acquire/release by global/provider/org/direction/profile |
| CDR/failure persistence | first-class call event/CDR tables separate from workflow JSON logs |
| Alerts | `TelephonyOpsAlertSink` with typed taxonomy/dedupe/escalation |

## Launch evidence gates

V1 core launch requires:

- 24h real-number staging soak
- 10 concurrent calls
- at least 20 inbound + 20 outbound
- status/recording/CDR normal ≥99%
- zero cross-tenant routing
- zero ClawOps runtime dependency for assigned-number V1 core

Supplier behavior that cannot map to Recova's contract blocks cutover, not initial implementation.

## Current implementation lanes

- Lane A: `jambonz_contract_v1`, hidden jambonz provider, runtime policy hooks.
- Lane B: number inventory, operator assignment APIs, customer bind-only API/UI.
- Lane C: admission, CDR/failure events, ops alerts, integration verification.
