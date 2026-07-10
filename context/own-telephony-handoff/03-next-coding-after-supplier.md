# 03 — 공급자 스펙 받은 뒤 다음 코딩 순서

이 문서는 실제 한국 SIP/070 공급자 기술 스펙을 받은 뒤 개발을 재개하는 순서를 정리한다.

## 시작 조건

아래 중 최소 Green 조건을 만족해야 코딩을 시작한다.

### Green — 코딩 시작 가능

- 070 DID를 Recova/Jambonz/SBC SIP endpoint로 inbound routing 가능.
- Recova/Jambonz/SBC에서 outbound SIP 발신 가능.
- Recova에 배정된 070 번호를 outbound caller ID로 표시 가능.
- 인증 방식이 명확함: IP-auth 또는 SIP REGISTER.
- codec/DTMF/포트/SBC IP/장애 로그/요금 조건이 문서 또는 메일로 확인됨.

### Yellow — 설계 보완 필요

- SIP는 가능하지만 최소 채널이 크거나 테스트 번호가 없음.
- CDR/실패 로그가 부족함.
- caller ID 정책이 애매함.
- 공급자가 PBX/SI 경유만 가능하다고 함.

### Red — 코딩하지 말 것

- 전화기/Centrex 설치형만 가능.
- 외부 IP-PBX/SIP trunk 불가.
- inbound 또는 outbound 중 하나만 가능.
- 발신번호가 보장되지 않음.
- CDR/장애 원인 확인이 전혀 안 됨.

## 입력 받아야 하는 공급자 정보

`05-supplier-intake-template.md`를 채운 뒤 코딩한다.

필수값:

```text
supplier_name
trunk_type: ip_auth | register | gateway | unknown
sip_proxy_or_registrar
outbound_proxy
inbound_source_ips
rtp_ip_ranges
rtp_port_range
supported_codecs
supported_dtmf_modes
caller_id_policy
cdr_source
failure_code_mapping
concurrency_limit
cps_limit
billing_unit
emergency/fraud/spam restrictions
```

## 구현 단계

### 1단계 — supplier spec을 contract adapter에 매핑

목표:

- 공급자 native SIP/Jambonz payload가 `jambonz_contract_v1`로 변환되는지 확인.
- 기존 simulator contract를 깨지 않는다.

주요 파일:

- `api/services/telephony/providers/jambonz/contract.py`
- `api/services/telephony/providers/jambonz/serializers.py`
- `api/services/telephony/providers/jambonz/routes.py`
- `api/services/telephony/providers/jambonz/transport.py`

해야 할 일:

1. 공급자 inbound INVITE에서 called number를 어느 header로 받는지 결정.
2. provider call id, account id, application id, direction, timestamps mapping 확정.
3. status/failure code를 Recova terminal statuses로 매핑.
4. CDR payload field mapping 추가.
5. signature/auth/replay protection을 실제 ingress 방식에 맞게 점검.

하면 안 되는 일:

- `jambonz_contract_v1`을 공급자별로 무너뜨리지 않는다.
- 공급자 native payload를 workflow runtime 전체에 퍼뜨리지 않는다.
- simulator fixture를 live evidence처럼 취급하지 않는다.

### 2단계 — runtime config/secrets 주입 방식 확정

목표:

- carrier credential은 operator/infra secret으로만 관리.
- customer organization에는 credential 노출 없음.

주요 파일:

- `api/services/telephony/providers/jambonz/config.py`
- `api/services/telephony/providers/jambonz/provider.py`
- `api/db/telephony_configuration_client.py`
- deployment/env secret files or cloud secret manager config

확인할 것:

- IP-auth라면 GCP Seoul static egress IP를 공급자 allowlist에 넣는다.
- REGISTER라면 SIP ID/password rotation 정책이 필요하다.
- trunk 설정은 hidden `jambonz` provider config로 유지한다.

### 3단계 — 실제 번호 inventory import/assignment path 점검

목표:

- 공급자에게 받은 테스트 070 번호를 Recova inventory에 넣고 조직에 assign.
- 고객은 assigned number만 workflow에 bind.

주요 파일:

- `api/db/telephony_number_inventory_client.py`
- `api/services/telephony_number_inventory.py`
- `api/routes/telephony_number_inventory.py`
- `ui/src/app/superadmin/telephony-number-inventory/page.tsx`
- `ui/src/components/telephony/AssignedNumbersBinder.tsx`

실행 순서:

1. 테스트 번호 1~5개 import.
2. 테스트 organization에 reserve/assign.
3. workflow에 bind.
4. readiness metadata가 fixture-only가 아닌지 확인.

### 4단계 — inbound live call smoke

목표:

- 외부 전화 → 공급자 → Recova/Jambonz/SBC → `/telephony/inbound/run` → workflow 실행.

확인할 것:

- called number가 assigned inventory와 정확히 매칭됨.
- wrong org/wrong number는 reject됨.
- workflow 미바인딩 number는 reject + ops alert.
- CDR/status/failure event가 저장됨.
- 녹취/전사/리포트 path가 기존 Recova pipeline과 맞음.

### 5단계 — outbound live call smoke

목표:

- Recova → Jambonz/SIP trunk → 국내 번호 발신.
- caller ID가 assigned Recova 070으로 표시됨.

확인할 것:

- explicit/default caller ID policy가 assigned inventory만 허용.
- unassigned/retired/quarantined/wrong-org number는 발신 불가.
- status sequence가 initiated/ringing/answered/completed 또는 terminal failure로 들어옴.
- CDR duration/cost/failure reason 저장.

### 6단계 — campaign live smoke

목표:

- campaign dispatch가 assigned caller-ID pool과 admission limit을 지킨다.

확인할 것:

- campaign from-number pool은 assigned Recova 070만 포함.
- 동시콜 limit이 inventory/campaign UI copy와 맞음.
- CPS/concurrency가 supplier policy를 넘지 않음.
- 실패 시 retry/alert가 과발신을 만들지 않음.

### 7단계 — operator live attestation

목표:

- 실제 route proof가 생긴 뒤 operator가 live validation evidence를 기록.

주요 route/UI:

```text
POST /api/v1/telephony-number-inventory/{inventory_id}/live-validation
ui/src/app/superadmin/telephony-number-inventory/page.tsx — Attest live
```

입력해야 하는 evidence:

- `live_validation_source`: `operator_attestation` 또는 approved tooling.
- `live_validation_evidence_id`: 실제 CDR/status/call attempt reference.
- `call_attempt_id`: 가능하면 inbound/outbound 실제 attempt id.
- `contract_version`: `jambonz_contract_v1`.

주의:

- attestation은 기술 증거 기록일 뿐, 법무/사업 launch approval이 아니다.

### 8단계 — staging soak / launch gate

V1 launch gate:

- 24h real-number staging soak.
- 10 concurrent calls.
- 최소 20 inbound + 20 outbound real calls.
- status/recording/CDR normal ≥99%.
- zero cross-tenant routing.
- zero ClawOps runtime dependency for assigned-number V1 core.

## 필요한 테스트 추가 후보

공급자 스펙을 받은 뒤 추가하면 좋은 테스트:

- provider-native inbound payload/header fixture → `jambonz_contract_v1` mapping test.
- provider-native status/failure code mapping test.
- provider CDR payload mapping test.
- IP-auth/REGISTER config validation test.
- wrong caller ID rejection test using real supplier number formats.
- inbound wrong org / unassigned route rejection test with supplier header fixture.
- live attestation cannot be set from supplier callback metadata alone.

## PR/커밋 기준

공급자 스펙 반영은 최소 2개 커밋으로 나누는 것이 좋다.

1. `feat(telephony): map <supplier> trunk contract`
   - provider mapping/config/tests.
2. `feat(telephony): validate <supplier> live cutover path`
   - live smoke docs/checklist/attestation evidence updates.

단, 작은 PoC이면 하나의 coherent commit도 가능하다.
