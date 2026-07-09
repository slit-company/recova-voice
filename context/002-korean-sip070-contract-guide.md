# 002 — 한국 SIP/070 공급자 계약 가이드

- 작성일: 2026-07-09
- 상태: active
- 연결 문서: [`001-own-telephony-infra.md`](./001-own-telephony-infra.md)
- 기준 코드 상태: `428dac7 feat(telephony): add pre-carrier readiness smoke flow`

## 배경

Recova V1은 ClawOps 의존 없이 **Recova가 직접 운영하는 한국 070/SIP 전화 인프라**를 사용한다. 코드베이스에는 이미 공급자 없이 검증 가능한 contract-first Jambonz core, 번호 inventory, operator assignment, customer bind-only workflow, simulator/smoke, trusted live attestation 흐름이 들어갔다.

이 문서의 목적은 대표/운영자가 한국 SIP/070 공급자와 계약할 때 **무엇을 물어보고, 무엇을 계약서/기술 부속서에 넣고, 어떤 자료를 받아와야 하는지**를 한 번에 볼 수 있게 하는 것이다.

> 주의: 이 문서는 기술·운영 계약 체크리스트다. 전기통신사업법, 발신번호 변작 방지, 개인정보/녹취 고지, 통신판매/광고성 발신 등 법률 판단은 별도 변호사/규제 전문가 검토가 필요하다.

## 조사 근거 / 현재 구현 전제

- `context/001-own-telephony-infra.md`: V1은 jambonz 기반 contract-first core, ClawOps는 V1 core 런타임/폴백에서 제외.
- `docs/integrations/telephony/own-infra-readiness.mdx`: simulator evidence는 live trunk readiness가 아니며, trusted operator attestation만 live 검증으로 인정.
- `docs/integrations/telephony/own-infra-runbook.mdx`: 공급자 접근 후 real-number staging soak와 live attestation을 진행.
- 구현 커밋 `428dac7`: 공급자 없이 실행 가능한 `jambonz_contract_v1` smoke flow 추가.

## 결정

### 우리가 지금 계약해야 하는 것

**한국 070/SIP trunk 공급자 계약**이다. 단순히 “070 번호 몇 개 구매”가 아니라 아래를 모두 포함해야 한다.

1. Recova가 관리하는 070 번호 발급 또는 할당
2. 해당 번호의 inbound DID를 Recova Jambonz/SBC로 라우팅
3. Recova backend/Jambonz에서 outbound call을 만들 수 있는 SIP trunk
4. Recova가 배정한 번호를 발신번호로 사용할 수 있는 정책
5. 동시콜, CPS, 과금, 장애 대응, 로그/CDR 제공
6. staging/prod 분리 운영 또는 최소한 테스트 번호/운영 번호 분리

### 추천 계약 방향

**추천: enterprise/wholesale SIP trunk + 070 DID block + IP-auth 방식**

쉬운 말로 하면: 공급자에게 “우리가 운영하는 서버 IP에서 SIP 통화를 넣고 받을 수 있게 해주고, 070 번호 묶음을 우리에게 배정해달라”고 요청한다.

근거:

- Recova는 고객에게 SIP credential을 노출하지 않는다.
- 번호는 Recova inventory에서 operator가 조직에 배정한다.
- 고객은 배정된 번호를 workflow에 bind만 한다.
- IP-auth는 서버 운영 관점에서 credential 유출면이 작고, GCP Seoul static IP allowlist와 맞는다.
- live validation은 operator가 실제 통화 증거를 보고 `Attest live`로 찍는 구조와 맞다.

## 실제로 어디에 문의할까

정정된 전략은 **2트랙 병행**이다. 이전에 말한 “소규모 기업을 먼저 보자”는 말은 **빠른 실통화 검증용**으로 맞고, 통신 3사는 **production/main trunk 검증용**으로 병행한다.

| 트랙 | 우선순위 | 문의처 | 어떤 상품/키워드로 문의할지 | 판단 |
|---|---:|---|---|---|
| 빠른 검증 | 1 | 중소형 070/SIP/PBX 업체, 와이즈070/삼성 Wyz070, 이야기070, 지역 VoIP/PBX SI | `SIP 계정`, `070 DID`, `Asterisk/FreePBX/Jambonz 연동`, `IP-PBX 외부 연동`, `테스트 번호 1~5개` | 처음 live wire를 빨리 꽂아보는 목적. 조건이 맞으면 staging proof에 가장 빠르다. 단 CDR/SLA/장애 대응이 약하면 production 메인은 아니다. |
| 빠른 검증 | 2 | PBX/SI 업체 | `SIP trunk 대행`, `070 번호 연동`, `SBC`, `Asterisk 연동`, `통신사 DID/DOD gateway` | 통신사와 직접 말이 안 통할 때 중간 기술영업/구축 파트너로 유용하다. |
| production 후보 | 3 | SK브로드밴드 기업 | `인터넷전화(교환기설치형)`, `DID 100개 단위`, `30채널`, `IP-PBX/SIP 연동` | 공식 페이지에 30채널 단위와 DID 100개 단위가 명시되어 있어 장기 production 후보로 좋다. 초기 규모가 작으면 과할 수 있다. |
| production 후보 | 4 | KT Enterprise | `기업전화`, `기업구내전화`, `DID/DOD`, `SIP Trunk 직접 연동 가능 여부`, `PBX/SI 파트너` | DID/DOD와 번호 대역은 가능성이 있지만 일반 상담은 Centrex로 빠진다. 기술영업/PBX 파트너 경유가 필요하다. |
| production 후보 | 5 | LG U+ 기업 | `기업 인터넷전화`, `교환기설치/구축형`, `30회선 이상`, `CRM/콜센터 연동` | 기업 인터넷전화와 교환기 구축형을 공식 제공한다. SIP trunk/BYOC 가능 여부는 상담에서 확인해야 한다. |

### 후보 상세 리스트

| 우선순위 | 후보 | 연락/진입점 | 확인된 근거 | Recova 관점의 질문 |
|---:|---|---|---|---|
| 1 | JS Solution / 온누리070 / webs.co.kr | `070-7752-2000`, `010-9513-0019`, `voipkorea@yahoo.co.kr`, 카톡 `voipkorea` | 070 가입, IPPBX 구성, Asterisk, PSTN 트렁크, IP-PBX간 트렁크 공유, In-Band/RFC2833/SIP-INFO DTMF를 공개 페이지에서 직접 언급한다. | “070 DID 1~5개를 Jambonz/SBC로 inbound SIP routing하고, outbound caller ID로 같은 번호를 쓸 수 있나요?” |
| 2 | 와이즈070 / 삼성 Wyz070 IP-LINK | 고객센터 `1661-3311`, IP-LINK 상품 | IP-LINK가 기존 PBX/키폰 또는 IP-PBX와 와이즈070 시스템을 연동하는 상품이라고 설명한다. | “IP-LINK를 고객 보유 cloud IP-PBX/Jambonz와 연동할 수 있나요? 단말기 설치 없이 SIP trunk 정보 제공이 가능한가요?” |
| 3 | KT 기업가입센터 / KT Enterprise | `1522-5030`, KT 기업가입센터 1:1 문의 | KT 기업가입센터 Q&A에 2026년 5~6월 `070 SIP Trunk`, `SIP Trunk 도입`, `BYOC 연동`, `AI 콜봇용 070 SIP Trunk` 문의가 다수 올라와 있다. | 일반 Centrex가 아니라 `IP-PBX/SIP Trunk/BYOC 기술영업`으로 연결 가능한지 확인한다. |
| 4 | 대신네트웍스 DSN | `1588-8832`, `1588-8833`, `070-7013-0002` | 삼성 IP-PBX/OfficeServ/SCM 계열 구축사. DSN 페이지는 Samsung Communication Manager, Media Gateway, IP-PBX solution을 다룬다. | Recova가 삼성 PBX를 쓰려는 것은 아니지만, 통신사 SIP trunk를 Jambonz/SBC로 넘기는 구축/SI 파트너가 될 수 있는지 확인한다. |
| 5 | 블루베이네트웍스 | 사이트 문의 | IP IVR이 SIP 기반이고 IP-PBX/CTI와 연동 가능하며, SIP trunk로 컨택센터 교환기에 호를 넘길 수 있다고 설명한다. | 직접 번호 공급자보다는 IVR/컨택센터/SIP 연동 SI 후보. Jambonz/SIP trunk cutover 지원 가능성 확인용이다. |
| 6 | 엠투넷 | 사이트/블로그 문의 | VOIP플랫폼, 오토콜, IPCC, 070/02 번호 기반 상담·콜센터 플랫폼 글을 다수 게시한다. | AI 전화/PDS/콜센터 경험은 있어 보이나, 실제 070 DID/SIP trunk 제공자인지 SI인지 구분해서 물어본다. |
| 7 | iPECS / 아이펙스 파트너 | iPECS 공식/파트너 문의 | iPECS SSM/UCM/UCP/eMG 계열은 SIP trunk, IP-PBX, VoIP 방화벽/SBC 성격의 제품군을 갖고 있다. | Recova가 iPECS를 도입할 필요는 낮다. 다만 통신사 SIP trunk와 SBC/NAT 문제를 풀어줄 SI 파트너 후보로만 본다. |
| 제외/참고 | ClawOps | 참고만 | 한국 070 번호 API와 SIP 직접연결은 가장 명확하지만, Recova V1은 ClawOps 런타임/폴백을 제외하기로 결정했다. | 가격/UX/기술 기준 비교에는 쓸 수 있지만 V1 supplier로 채택하지 않는다. |
| production | SK브로드밴드 기업 | 기업영업/상품 문의 | `인터넷전화(교환기설치형)`은 30채널 단위와 DID 100개 단위 신청을 공개한다. | 초기 PoC에는 과할 수 있지만 production 번호 block과 채널 계약 후보로 유지한다. |
| production | LG U+ 기업 | 기업영업/상품 문의 | 기업 인터넷전화에서 센트릭스와 교환기설치형/구축형을 구분하고, 교환기설치형을 30회선 이상 대규모·다지점 대상으로 설명한다. | `자급 IP-PBX`, `외부 SIP trunk`, `BYOC`, `070 DID` 가능 여부를 확인한다. |

### 연락 우선순위

1. **JS Solution / 온누리070** — 제일 먼저 전화한다. 작고 직접적인 070/IPPBX/Asterisk 언급이 있어서 빠른 live wire 가능성이 가장 높다.
2. **와이즈070 IP-LINK** — PBX/IP-PBX 연동 상품명이 명확하다. 단, 단말기/게이트웨이 설치형으로만 가능한지 확인해야 한다.
3. **KT 기업가입센터 Q&A/전화** — 기존 KT 고객센터가 아니라 SIP Trunk 문의가 실제 올라오는 이 경로를 쓴다.
4. **DSN 또는 iPECS/Samsung PBX SI** — 통신사와 직접 말이 안 통할 때 SIP trunk/SBC 구축 파트너로 찌른다.
5. **SKB/LG U+ 기업영업** — production/main trunk 후보로 동시에 견적 넣는다.

문의할 때는 “070 인터넷전화 가입”이라고만 말하면 안 된다. 반드시 이렇게 말한다.

```text
기업용 070 DID 번호 블록과 outbound SIP trunk를 자체 IP-PBX/Jambonz에 연동하려고 합니다.
고객 단말용 인터넷전화가 아니라, 저희 서버/SBC와 SIP로 직접 연동하는 BYOC/SIP trunk 구성이 필요합니다.
```

공개 확인 근거:

- SK브로드밴드 기업 `인터넷전화(교환기설치형)`은 기본료를 채널 단위로 안내하고, 30채널 단위 신청 및 DID 번호 100개 단위 신청을 명시한다.
- KT Enterprise 기업전화는 Centrex/biz/기업구내전화 계열을 안내하며, DID/DOD나 IP-PBX 연동 가능성은 기업영업 확인 대상이다.
- LG U+ 기업 인터넷전화는 일반형/센트릭스/교환기설치형을 구분하고, 교환기설치형을 30회선 이상 대규모·다지점 기업/기관 대상으로 설명한다.
- 와이즈070 IP-CENTREX는 교환기 없이 기업 인터넷전화와 부가서비스를 제공하는 중소형 후보지만, Recova V1 production trunk로 쓰려면 SIP trunk, CDR, SLA 제공 여부를 별도로 확인해야 한다.
- JS Solution/온누리070 페이지는 070 가입, IPPBX 구성, Asterisk, PSTN 트렁크, IP-PBX간 트렁크 공유, DTMF 방식을 직접 언급한다.
- 와이즈070 IP-LINK는 기존 PBX/키폰 또는 IP-PBX와 와이즈070 시스템을 연동하는 상품이라고 설명한다.
- KT 기업가입센터 공개 Q&A에는 `070 SIP Trunk 및 DID 연동`, `SIP Trunk 도입`, `BYOC 연동`, `AI 콜봇용 070 SIP Trunk` 문의가 최근 다수 올라와 있다.
- DSN은 Samsung Communication Manager, Media Gateway, IP-PBX solution을 다루는 삼성 PBX 구축 후보로 확인된다.
- 블루베이네트웍스 IP IVR은 SIP 기반이며 IP-PBX/CTI와 연동 가능하고 SIP trunk로 컨택센터 교환기에 호를 넘길 수 있다고 설명한다.

### KT 기존 통화에서 확인된 점

사용자 기존 통화 기록:

- `/Users/slit/Downloads/kt 통화내역1.txt`
- `/Users/slit/Downloads/kt 통화내역2.txt`

핵심 해석:

1. **“070 번호 하나 개발용으로 받고 싶다”라고 말하면 KT 1차 상담은 기업용 인터넷전화/Centrex로 라우팅한다.**
   - 상담사는 “070은 인터넷전화이고, 전화기를 설치해야 번호를 받을 수 있다”고 안내했다.
   - 이 경로는 Recova가 원하는 server-to-server SIP trunk가 아니다.

2. **KT B2B 쪽 답변은 “고객이 원하는 서버 연결은 PBX/교환기 영역”이라는 취지였다.**
   - 상담사는 고객이 PBX를 직접 사서 구축해야 하거나, KT가 제공하는 `콜박스` 교환기 방식이 있다고 설명했다.
   - `콜박스`는 대략 **50회선 이상, 회선당 월 6천 원 이상** 수준이어야 KT가 투자/제공을 검토한다는 취지로 말했다.
   - 일반 Centrex 전화는 Recova가 원하는 “전화가 우리 서버로 들어오고, 우리 서버가 발신하는” 역할을 하지 못한다고 설명했다.

3. **따라서 KT에서 바로 살 상품은 ‘기업용 070 전화기 1대’가 아니다.**
   - KT에 다시 문의한다면 `기업구내전화 DID/DOD`, `IP-PBX 연동`, `SIP Trunk 직접 연동`, `콜봇/BYOC 연동`, `PBX 제조사/SI 연계` 키워드로 시작해야 한다.
   - 상담이 Centrex/전화기 설치로 흘러가면 “그 상품은 아닙니다. 고객 단말용 전화가 아니라 저희 cloud PBX/Jambonz/SBC로 DID와 outbound SIP trunk를 연동하려는 건입니다”라고 바로 정정한다.

KT 재문의 문구:

```text
이전에 기업용 070 인터넷전화/Centrex로 안내받았는데, 그 상품은 저희 용도와 맞지 않았습니다.

저희는 전화기 1대를 설치하려는 것이 아니라, 자체 cloud PBX/Jambonz/SBC를 운영하면서
KT DID/DOD 또는 SIP Trunk를 연동하려고 합니다.

확인하고 싶은 것은 다음입니다.

1. KT가 IP-PBX/SBC와 직접 SIP Trunk 방식으로 연동 가능한지
2. 가능하다면 070 DID 번호를 저희 SIP endpoint로 inbound routing 할 수 있는지
3. outbound trunk에서 KT가 할당한 070 번호를 caller ID로 사용할 수 있는지
4. 직접 SIP가 안 된다면 PRI/DID-DOD + gateway 방식 또는 KT 인증 PBX/SI 파트너를 통해 가능한지
5. 콜박스 방식만 가능하다면 최소 회선 수, 월 기본료, 설치비, 번호 수량, 외부 API/SIP 연동 가능 범위가 어떻게 되는지

이 건은 일반 인터넷전화 가입 상담이 아니라 IP-PBX/SIP Trunk/BYOC 기술영업 상담으로 연결 부탁드립니다.
```

판단:

- KT는 완전 탈락은 아니다. 다만 일반 고객센터 경로로는 계속 Centrex/전화기 설치로 빠질 가능성이 높다.
- KT를 쓰려면 **기술영업 또는 PBX/SI 파트너 경유**가 필요하다.
- 빠르게 Recova V1 live trunk를 붙이는 목적이면, KT만 붙잡기보다 SK브로드밴드 기업 교환기설치형과 LG U+ 교환기구축형을 동시에 견적 넣는 편이 낫다.

## 공급자 후보에게 보내는 1차 요청서

아래 문구를 그대로 복사해서 문의 메일/메신저 첫 메시지로 써도 된다.

```text
안녕하세요. Recova는 한국 B2B AI 전화 서비스를 준비 중입니다.

저희는 고객별로 070 번호를 배정하고, 해당 번호로 인바운드/아웃바운드 AI 전화를 처리하는 구조를 만들고 있습니다. 외부 CPaaS API가 아니라 자체 Jambonz/SIP 기반 인프라와 연동할 수 있는 070/SIP trunk 공급자를 찾고 있습니다.

확인하고 싶은 항목은 다음과 같습니다.

1. 070 번호 블록 발급/할당 가능 여부
2. inbound DID를 저희 SIP endpoint 또는 SBC/Jambonz로 라우팅 가능 여부
3. outbound SIP trunk 제공 가능 여부
4. IP-auth 방식 지원 여부, 또는 registration 방식만 가능한지
5. 저희에게 할당된 070 번호를 outbound caller ID로 사용할 수 있는지
6. 동시콜 제한, CPS 제한, 증설 방식
7. CDR 제공 방식과 장애 로그 제공 범위
8. 테스트 번호/staging 환경 제공 가능 여부
9. 발신번호 사전등록, 녹취/AI콜 고지, 광고성 발신 등 규제 관련 공급자 측 요구사항
10. SLA, 장애 대응 채널, 긴급 차단/복구 절차

기술 연동을 위해 SIP endpoint, 인증 방식, codec, DTMF, early media, SIP response code, CDR spec 문서도 받을 수 있는지 확인 부탁드립니다.
```

## 공급자에게 반드시 물어볼 질문

### 1. 번호 발급 / 번호 소유 / 번호 이동

| 질문 | 왜 중요한가 | 원하는 답 |
|---|---|---|
| 070 번호를 몇 개 단위로 받을 수 있나? | Recova inventory에 번호를 미리 넣어야 한다. | 10/50/100개 단위로 추가 가능 |
| 번호가 Recova 명의/계약으로 관리되는가? | 고객이 직접 통신사 credential을 만지지 않는 구조다. | Recova 계약 하에 번호 관리 가능 |
| 번호별로 사용 조직/고객을 내부적으로 매핑해도 되는가? | operator assignment 모델과 연결된다. | 가능 |
| 번호 해지/정지/재활성화 리드타임은? | quarantine/retire 운영정책에 필요하다. | 당일 또는 명확한 SLA |
| 번호 이동/회수 정책은? | 고객 이탈/번호 재배정 시 리스크가 있다. | 회수/보류 기간 명시 |

### 2. Inbound DID 라우팅

| 질문 | 왜 중요한가 | 원하는 답 |
|---|---|---|
| 특정 070 번호로 온 전화를 Recova SIP endpoint로 보낼 수 있나? | inbound workflow 실행의 핵심이다. | 가능 |
| 라우팅 대상은 IP/도메인 중 무엇을 지원하나? | GCP Seoul + Jambonz/SBC 구성에 필요하다. | FQDN 또는 static IP 모두 가능 |
| 이중화 endpoint를 지원하나? | multi-zone HA에 필요하다. | primary/secondary 또는 DNS failover 지원 |
| INVITE에 called number/DID가 어떤 header로 들어오나? | workflow binding을 찾으려면 필요하다. | To, Request-URI, Diversion 등 명확한 spec |
| 착신 실패 시 어떤 SIP code를 반환/기록하나? | 실패 분석/CDR에 필요하다. | 표준 SIP code와 CDR 제공 |

### 3. Outbound SIP trunk

| 질문 | 왜 중요한가 | 원하는 답 |
|---|---|---|
| IP-auth를 지원하나? | server-to-server 운영에 유리하다. | GCP static IP allowlist 가능 |
| registration 방식이라면 credential 회전/복수 노드 등록을 지원하나? | HA 구성에 필요하다. | 복수 등록 또는 명확한 제한 |
| CPS 제한은? | 캠페인 발신 속도 제한에 필요하다. | 초당 발신 제한 수치 제공 |
| 동시콜 제한은? | admission control에 필요하다. | 계약상 기본/증설 한도 제공 |
| 한국 휴대폰/유선/PSTN 발신 가능 범위는? | 고객 테스트/캠페인 범위에 필요하다. | 010/02/031 등 범위 명시 |

### 4. 발신번호 / caller ID

| 질문 | 왜 중요한가 | 원하는 답 |
|---|---|---|
| Recova에 할당된 070 번호를 outbound caller ID로 사용할 수 있나? | 고객이 배정받은 번호로 발신해야 한다. | 가능 |
| 발신번호 사전등록이 필요한가? | 한국은 발신번호 변작 방지 이슈가 있다. | 절차/서류/리드타임 명확화 |
| 번호별 발신 허용 목록을 API/CSV로 관리할 수 있나? | operator inventory와 맞춰야 한다. | 가능하면 API, 아니면 운영 요청 SLA |
| 고객 소유 번호를 caller ID로 쓰는 것을 지원하나? | V1 범위 밖이지만 향후 확장 판단에 필요하다. | 가능 여부만 확인, V1에는 미적용 |
| 차단/스팸/불법 발신 탐지 기준은? | 캠페인 운영 리스크다. | 정책 문서 제공 |

### 5. Media / codec / DTMF / early media

| 질문 | 왜 중요한가 | 원하는 답 |
|---|---|---|
| 지원 codec은? | Jambonz/Pipecat audio path와 맞춰야 한다. | G.711 PCMU/PCMA 우선, 필요 시 Opus 확인 |
| DTMF 방식은? | IVR/키패드 입력이 필요할 수 있다. | RFC2833/telephone-event 명시 |
| early media를 전달하나? | 통화 연결음/안내음/실패 분석에 영향이 있다. | 지원 여부와 처리 방식 명시 |
| 녹취 품질/샘플레이트 제한은? | STT/녹취 품질에 영향이 있다. | 제한 조건 명시 |
| NAT/SRTP/TLS 지원은? | 보안/운영정책 판단에 필요하다. | 지원 여부와 비용 명시 |

### 6. CDR / 로그 / 장애 대응

| 질문 | 왜 중요한가 | 원하는 답 |
|---|---|---|
| CDR은 어떤 방식으로 받을 수 있나? | Recova CDR/failure persistence와 맞춘다. | API, webhook, CSV 중 하나 이상 |
| CDR 필드는 무엇인가? | duration, status, cost, hangup cause가 필요하다. | 필드 spec 제공 |
| 실패 원인 코드를 제공하나? | 고객/운영자에게 원인을 설명해야 한다. | SIP code + provider reason 제공 |
| 실시간 장애 알림 채널은? | ops alert와 연결한다. | Slack/email/전화/상태페이지 |
| 장애 SLA와 보상 기준은? | B2B 서비스 신뢰성에 필요하다. | 계약서에 명시 |

### 7. 과금 / 정산

| 질문 | 왜 중요한가 | 원하는 답 |
|---|---|---|
| 번호 월 기본료는? | 고객당 번호 비용 산정에 필요하다. | 번호당 월 비용 |
| 국내 유선/휴대폰 발신 단가는? | 분당 원가 계산에 필요하다. | 목적지별 단가표 |
| 과금 단위는 1초/10초/1분 중 무엇인가? | cost-per-minute 계산에 필요하다. | 과금 단위 명시 |
| 실패/무응답/통화중 과금 여부는? | 캠페인 비용 예측에 필요하다. | 과금 기준 명확화 |
| 최소 사용료/약정/보증금이 있나? | 초기 리스크 관리에 필요하다. | 총 고정비 확인 |

## 계약서/부속서에 넣어야 하는 항목

### 필수 기술 부속서

공급자와 계약할 때 “말로 가능”만 받으면 안 된다. 최소한 아래 문서를 받아야 한다.

- SIP trunk endpoint/FQDN/IP
- 인증 방식: IP-auth 또는 registration credential
- inbound DID routing spec
- outbound INVITE format
- caller ID 허용 정책
- codec/DTMF/early media spec
- 동시콜/CPS 제한
- CDR format 및 제공 방식
- 장애 대응 연락망
- staging/test 번호 제공 조건
- 운영 변경 요청 SLA: 번호 추가, 번호 정지, caller ID 등록, trunk 증설

### 계약서에 명시할 운영 조건

- 공급자는 Recova에게 할당한 번호 목록을 명확히 제공한다.
- 공급자는 Recova가 허용된 번호를 outbound caller ID로 사용할 수 있게 한다.
- 공급자는 DID inbound 라우팅 장애 시 장애 원인과 시간을 제공한다.
- 공급자는 CDR 또는 equivalent call detail evidence를 제공한다.
- 공급자는 번호 추가/정지/회수 요청의 처리 시간을 명시한다.
- 공급자는 동시콜/CPS 증설 절차와 리드타임을 명시한다.
- 공급자는 운영 장애 연락 채널과 응답 시간을 명시한다.
- Recova는 고객에게 공급자 credential을 재판매/노출하지 않고, 내부 서비스 제공 목적으로 사용한다.

## 계약 전/계약 중/계약 후 체크리스트

### 계약 전 — 공급자 필터링

- [ ] 070 번호 block 제공 가능
- [ ] inbound DID → Recova SIP endpoint 라우팅 가능
- [ ] outbound SIP trunk 가능
- [ ] IP-auth 또는 HA 가능한 registration 지원
- [ ] 할당 번호 caller ID 지원
- [ ] 동시콜/CPS 제한 수치 제공
- [ ] CDR/실패 로그 제공
- [ ] staging/test 번호 제공
- [ ] 장애 연락/SLA 제공
- [ ] 법률/규제 관련 공급자 요구사항 문서 제공

### 계약 중 — 문서/조건 확보

- [ ] 번호 단가/발신 단가/과금 단위 수령
- [ ] 최소 약정/보증금/해지 조건 확인
- [ ] 번호 추가/정지/회수 SLA 확인
- [ ] caller ID 등록 절차 확인
- [ ] SIP technical spec 수령
- [ ] CDR spec 수령
- [ ] 장애 대응 프로세스 수령
- [ ] 테스트 번호와 운영 번호 분리 가능 여부 확인
- [ ] 법률 검토 요청 항목 정리

### 계약 직후 — Recova에 넣어야 하는 값

- [ ] 공급자 이름 / 계약 식별자
- [ ] trunk endpoint
- [ ] 인증 방식
- [ ] allowlist할 GCP Seoul static IP
- [ ] inbound DID routing target
- [ ] outbound caller ID 허용 번호 목록
- [ ] 동시콜 limit
- [ ] CPS limit
- [ ] codec/DTMF 정책
- [ ] CDR source 또는 다운로드/API 정보
- [ ] 장애 연락 채널
- [ ] 테스트 번호 목록
- [ ] production 번호 목록

## 공급자 선택 점수표

각 항목을 0~2점으로 평가한다.

- 0점: 불가/불명확
- 1점: 가능하지만 수동/제약 큼
- 2점: 명확히 지원하고 문서 있음

| 항목 | 점수 |
|---|---:|
| 070 번호 block 제공 | 0 / 1 / 2 |
| inbound DID SIP 라우팅 | 0 / 1 / 2 |
| outbound SIP trunk | 0 / 1 / 2 |
| IP-auth/HA 지원 | 0 / 1 / 2 |
| 할당 번호 caller ID 지원 | 0 / 1 / 2 |
| CDR/실패 로그 제공 | 0 / 1 / 2 |
| 동시콜/CPS 증설 명확성 | 0 / 1 / 2 |
| staging/test 번호 제공 | 0 / 1 / 2 |
| 장애 대응/SLA | 0 / 1 / 2 |
| 규제 관련 요구사항 문서화 | 0 / 1 / 2 |

판단 기준:

- **16점 이상**: 1순위 후보
- **12~15점**: 협상 가능 후보
- **11점 이하**: V1 production 공급자로는 위험
- **caller ID 또는 inbound DID가 0점이면 총점과 무관하게 탈락 후보**

## 레드플래그

아래 중 하나라도 나오면 V1 production 공급자로 쓰기 어렵다.

- “SIP spec 문서는 없고 해보면 된다”
- “발신번호는 아무거나 넣으면 된다”
- “CDR/장애 로그는 제공하지 않는다”
- “동시콜 제한은 운영 중 막히면 그때 보자”
- “070 번호는 제공하지만 inbound 라우팅은 불가”
- “caller ID 정책을 계약서에 못 쓴다”
- “장애 연락은 영업 담당자 개인 연락처뿐이다”
- “테스트 번호 없이 바로 운영 번호로 붙여야 한다”

## 계약 후 Recova 기술팀 실행 순서

공급자 계약이 끝나면 기술팀은 아래 순서로 간다.

1. 공급자 spec을 `jambonz_contract_v1` adapter mapping에 반영한다.
2. GCP Seoul staging의 static IP를 공급자 allowlist에 등록한다.
3. 테스트 번호를 Recova number inventory에 import한다.
4. operator가 테스트 조직에 번호를 assign한다.
5. 고객 workflow에 assigned number를 bind한다.
6. 실제 inbound call을 넣고 workflow가 실행되는지 확인한다.
7. 실제 outbound call을 걸고 caller ID/녹취/전사/CDR을 확인한다.
8. campaign test를 작은 규모로 실행한다.
9. operator가 실제 증거 ID로 `Attest live`를 찍는다.
10. 24시간 staging soak를 돌린다.
11. launch gate 통과 후 production 번호 block을 import한다.

## 법률/규제 검토에 넘길 질문

기술팀이 결론 내리면 안 되는 질문이다. 계약 전후로 별도 검토가 필요하다.

- Recova가 자체 계약한 070 번호를 고객 조직별로 배정해 AI 전화에 쓰는 모델의 법적 지위
- 고객별 발신번호 표시/사전등록 요구사항
- 통화 녹취 고지 문구와 저장/파기 정책
- AI 상담원 고지 의무 여부와 권장 문구
- 광고성/마케팅성 발신의 동의 요건
- 수신거부/차단번호 처리 요건
- 야간/휴일 발신 제한
- 민원/스팸 신고 발생 시 책임 분담
- 번호 회수/재배정 시 고객 데이터와 통화기록 보존 정책

## 최종적으로 공급자에게 받아야 하는 패키지

계약 완료 후 아래가 모두 있어야 Recova 기술팀이 바로 cutover 작업을 시작할 수 있다.

```text
1. 계약 번호 / 공급자 담당자 / 장애 연락망
2. 테스트 070 번호 목록
3. 운영 070 번호 목록
4. SIP trunk endpoint
5. 인증 방식과 credential 또는 IP allowlist 절차
6. inbound DID 라우팅 설정값
7. outbound caller ID 허용 번호 목록
8. codec / DTMF / early media spec
9. 동시콜 / CPS 제한
10. CDR spec / 제공 방식
11. 장애 코드 / SIP response code 설명
12. 번호 추가·정지·회수 요청 절차
13. 발신번호 등록/변경 절차
14. 요금표 / 과금 단위 / 정산 방식
15. 공급자 측 규제 준수 요구사항 문서
```

## 열린 질문

- 첫 공급자는 enterprise SIP trunk 한 곳으로 시작할지, 장애 대비로 2개 공급자를 동시에 계약할지.
- 초기 번호 block 크기를 10개, 50개, 100개 중 어디로 잡을지.
- 초기 동시콜을 10으로 시작할지, 30~50까지 미리 계약할지.
- production 이전에 별도 staging trunk를 계약할 수 있는지.
- 발신번호 사전등록을 operator 수동 프로세스로 시작할지, 향후 API 자동화까지 계약 조건에 넣을지.

## 추천 초기 선택

현재 Recova 단계에서는 다음이 가장 현실적이다.

- 공급자: SIP trunk/070 DID를 문서화해서 제공하는 enterprise 공급자 1곳
- 번호: 테스트 3~5개 + production 초기 20~50개
- 동시콜: 계약상 10으로 시작, 30/50 증설 단가와 리드타임 사전 합의
- 인증: IP-auth 우선, 불가하면 HA 가능한 registration
- 발신번호: Recova에 할당된 070 번호만 V1 caller ID로 사용
- 고객 소유 번호 발신: V1 제외, 후속 계약/법무 검토 과제
- staging: production 번호와 분리된 테스트 번호로 실제 trunk 검증

쉬운 말로 하면, 처음부터 통신사급 거대한 계약을 하려 하지 말고 **문서가 있고, 070 번호를 주고, SIP로 양방향 통화를 연결해주고, 장애/로그를 제공하는 공급자**를 잡는 것이 우선이다. 그 위에 Recova inventory와 Jambonz core는 이미 붙일 준비가 되어 있다.
