# 007 — Onnuri 제한형 live smoke 기반 결정

- 작성일: 2026-07-16
- 상태: **Waiting** — 공개 소스 G009 후보와 서울 비공개 G007 disabled staging은 검증했지만 REGISTER·RTP·실통화는 실행하지 않았다.
- 기준: 승인된 실행 기준 `.gjc/_session-019f60d4-9b29-7000-aa51-e0537c6352a2/plans/ralplan/019f60d4-9b29-7000-aa51-e0537c6352a2/pending-approval.md` (SHA `55a188fbdfd3fdf798f7d07a446235aa4530d708c008a3dbed865746677309fa`)

## 배경

[`004-onnuri-staging-no-traffic-checkpoint.md`](./004-onnuri-staging-no-traffic-checkpoint.md), [`005-onnuri-seoul-staging-phase-a-operator-contract.md`](./005-onnuri-seoul-staging-phase-a-operator-contract.md), [`006-onnuri-seoul-staging-phase-b-foundation-decision.md`](./006-onnuri-seoul-staging-phase-b-foundation-decision.md)의 no-traffic·fail-closed 경계를 유지하면서 실제 공급자 traffic 전에 정확한 공개 소스 런타임과 비공개 서울 staging을 검증해야 했다. 이 기반의 존재는 자체 한국 070 역량을 출시·운영 가능 상태로 만들지 않는다. 공식 제품 상태는 [`../product/03-capability-map.md`](../product/03-capability-map.md)의 **Waiting**이다.

## 현재 근거

- `deploy/onnuri-jambonz-oss/`와 승인 후보 manifest: Jambonz 공개 저장소와 선언된 공개 의존성만으로 만든 G009 후보를 불변 digest·SBOM·license·provenance·취약점 증거로 봉인했다. 런타임 라이선스 키, activation service, trial 또는 유료 entitlement를 요구하는 구성요소는 후보에서 제외했다.
- `infra/onnuri-seoul-staging-phase-b/`: 서울 VPC·private Google access·flow logging·기본 deny 기반을 적용했고, 서명된 dependency receipt로 Phase B 동일성을 검증했다.
- `infra/onnuri-seoul-staging-phase-c-smoke/`: 별도 Terraform state와 최소 권한 identity로 G009 파생 이미지를 외부 IP 없이 부팅했다. dispatch·registration·media·inbound·outbound gate는 모두 `false`이며 실제 상태에 대한 최종 plan은 `No changes`였다.
- disabled-runtime evidence bundle: exact candidate manifest, GCE image와 facade digest, private-only NIC, numeric secret references, effective firewall, zero SIP/RTP/REGISTER/call counters, containment stop drill, Phase B before/after, 32개 Phase C 리소스만 삭제하는 destroy plan과 durable scheduler를 Ed25519 서명 receipt에 결합했다. 검증기는 고정 파일의 실제 SHA-256을 다시 계산하고 G009 compute receipt 서명을 교차 검증한다.
- 비공개 부팅 검증에서는 13개 base service와 registration profile 부재를 확인했다. provider REGISTER, SIP/SDP/RTP, WebSocket media, 인바운드·아웃바운드 통화는 실행하지 않았다.
- 공급자 기존 서신은 REGISTER 방식, UDP 5060 signaling과 배정 DID 용도를 확인하지만 최신 시작 잔액·통화와 정확한 RTP/RTCP CIDR·포트 범위를 제공하지 않는다. 공식 지원 채널에 이 누락 정보를 요청했다.
- 실제 G008 실행에는 placeholder가 아닌 Recova F12/status/event와 media adapter의 private runtime 경로가 추가로 필요하다.

## 결정

G007을 **공개 소스·라이선스 키 비의존 후보에 고정된 서울 비공개 disabled staging**으로 인정한다. 이는 cloud 기반과 zero-traffic·containment·destroy readiness만 증명한다.

다음 동작은 계속 금지한다.

- 공급자 권위 잔액·통화와 RTP/RTCP network 범위 없이 REGISTER 또는 media gate 열기
- raw secret, 전화번호, DID, endpoint 또는 protocol/media payload를 증거에 기록하기
- 자동 재시도, 동시 통화, soak, 소유하지 않은 번호 또는 60초 초과 시도
- public·production 공개나 제품 상태를 `Current`로 승격하기
- 라이선스 키, activation, trial 또는 유료 entitlement가 필요한 런타임으로 대체하기

## 남은 G008 gate

아래 항목은 독립 gate이며 앞 단계 통과가 다음 단계의 자동 승인을 뜻하지 않는다.

1. **공급자 권위 근거:** 최신 시작 잔액·통화, registrar/proxy/realm, signaling과 정확한 RTP/RTCP CIDR·포트 범위, CPS·동시성 제한을 최신 답변으로 고정한다.
2. **Recova runtime:** tenant-bound F12 status/event와 bidirectional mono 8 kHz L16 media 경로를 실제 private endpoint로 연결하고 fail-closed 검증한다.
3. **제한 실행:** 한 번의 논리적 REGISTER, 소유 모바일 outbound 한 번과 inbound 한 번, 전체에서 contingency 최대 한 번만 허용한다. 각 시도는 60초 이내이며 자동 재시도와 동시 실행은 금지한다.
4. **증거:** redacted status/CDR/cost, 사람의 양방향 audio 확인과 provider counters를 서명된 closure receipt로 결합한다.
5. **종료:** dispatch·REGISTER·RTP를 먼저 닫고 credential/rule을 회수한 뒤 Phase C state와 ephemeral data를 파괴하며 Phase B deny-only 동일성과 제품 `Waiting`을 다시 확인한다.

이 gate가 모두 통과해도 비공개 진단 범위만 닫힌다. public, production-ready 또는 `Current` 전환은 별도의 제품 결정 전까지 금지된다.
