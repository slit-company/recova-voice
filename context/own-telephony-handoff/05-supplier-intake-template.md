# 05 — 공급자 정보 입력 템플릿

공급자 통화/메일 후 이 파일을 복사해서 `context/own-telephony-handoff/suppliers/<YYYYMMDD>-<vendor>.md` 형태로 저장한다.

예:

```text
context/own-telephony-handoff/suppliers/20260710-onnuri070.md
```

## 복사해서 쓸 템플릿

```markdown
# 공급자 검토 — <업체명>

- 작성일:
- 작성자:
- 업체명:
- 담당자:
- 연락처:
- 이메일:
- 웹사이트:
- 통화/메일 일시:
- 현재 판정: Green / Yellow / Red / Unknown

## 1. 한 줄 요약

예: 070 DID 1개 테스트는 가능하지만, inbound SIP routing은 전화기/앱으로만 가능해서 Recova V1에는 부적합.

## 2. 우리가 요청한 구성

```text
070 번호
  → 공급자 SIP trunk / DID routing
  → Recova Jambonz/SBC SIP endpoint
  → Recova AI workflow
```

## 3. 핵심 질문 답변

| 항목 | 답변 | 근거/메모 |
|---|---|---|
| 070 신규 번호 발급 가능 | 가능 / 불가 / 모름 |  |
| 테스트 번호 1~5개 가능 | 가능 / 불가 / 모름 |  |
| inbound DID → Recova SIP endpoint | 가능 / 불가 / 모름 |  |
| outbound SIP 발신 | 가능 / 불가 / 모름 |  |
| 070 caller ID 표시 | 가능 / 불가 / 모름 |  |
| Asterisk/FreePBX/Jambonz 연동 경험 | 있음 / 없음 / 모름 |  |
| 인증 방식 | IP-auth / REGISTER / gateway / 모름 |  |
| 최소 회선/채널 |  |  |
| 동시콜 limit |  |  |
| CPS limit |  |  |
| codec |  |  |
| DTMF | RFC2833/RFC4733 / SIP INFO / In-band / 모름 |  |
| early media | 지원 / 미지원 / 모름 |  |
| CDR 제공 | 가능 / 불가 / 모름 |  |
| 실패 로그/장애 코드 | 가능 / 불가 / 모름 |  |
| 장애 대응 채널 |  |  |
| 요금/과금 단위 |  |  |
| 약정/설치비/보증금 |  |  |
| 법/규제/발신번호 요구사항 |  |  |

## 4. 받은 기술 정보

```text
SIP proxy/registrar:
Outbound proxy:
Inbound source IPs:
RTP IP ranges:
RTP port range:
Transport: UDP / TCP / TLS
Auth: IP-auth / REGISTER
Username:
Password handling:
Caller ID header/policy:
Inbound called-number header:
CDR source/API/file:
Failure code mapping:
```

비밀번호/credential 원문은 이 문서에 저장하지 않는다. Secret manager 또는 별도 보안 채널에 둔다.

## 5. Recova 매핑 판단

| Recova requirement | 상태 | 메모 |
|---|---|---|
| Hidden Jambonz provider로 수용 가능 | 가능 / 불가 / 미정 |  |
| `jambonz_contract_v1`로 payload mapping 가능 | 가능 / 불가 / 미정 |  |
| number inventory assignment와 충돌 없음 | 가능 / 불가 / 미정 |  |
| customer bind-only UX 유지 가능 | 가능 / 불가 / 미정 |  |
| CDR/failure persistence 가능 | 가능 / 불가 / 미정 |  |
| trusted live attestation evidence 생성 가능 | 가능 / 불가 / 미정 |  |

## 6. 리스크

- 리스크 1:
- 리스크 2:
- 리스크 3:

## 7. 다음 액션

- [ ] 공급자에게 추가 질문 보내기
- [ ] 기술 문서/요금표 받기
- [ ] 테스트 번호 신청
- [ ] GCP Seoul static IP 전달
- [ ] Recova staging SIP endpoint 전달
- [ ] PoC 일정 잡기
- [ ] 법무/규제 검토에 넘길 항목 정리

## 8. 최종 판정

### Green

아래가 모두 가능하면 Green:

- inbound SIP routing 가능.
- outbound SIP 발신 가능.
- assigned 070 caller ID 표시 가능.
- CDR/failure evidence 가능.
- 테스트 번호/PoC 가능.

### Yellow

가능은 하지만 조건이 크거나 애매하면 Yellow:

- 최소 30/50회선부터 가능.
- PBX/SI 경유 필요.
- CDR 부족.
- 문서 부족.

### Red

아래면 Red:

- 전화기/Centrex만 가능.
- 외부 IP-PBX 불가.
- inbound 또는 outbound 중 하나만 가능.
- 발신번호 보장 안 됨.
- 장애/통화기록 제공 불가.
```

## 저장 규칙

- credential, password, API key는 이 폴더에 저장하지 않는다.
- 공급자가 보낸 PDF/견적서는 repo에 넣지 않는다. 필요한 요약만 적고 파일 위치/보안 저장소 링크를 기록한다.
- 법무 판단은 “확인 필요”로 적고 기술 문서에서 단정하지 않는다.
