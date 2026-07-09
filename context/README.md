# context/ — Recova 의사결정·맥락 저장소

이 폴더는 Recova의 제품/인프라 방향에 대한 **의사결정 맥락**을 누적 저장하는 곳이다.
공개 문서(`docs/`, Mintlify)와 실행 계획(`plans/`)과 달리, 여기는 "왜 이 길을
택했는가"를 기록한다. 에이전트와 사람 모두 새 작업 전에 이 폴더를 먼저 읽는다.

## 규칙

- 파일명은 `NNN-주제.md` 순번제. 결정이 뒤집히면 파일을 고치지 말고 새 번호로
  추가하고 이전 문서 상단에 `superseded by NNN` 표기를 남긴다.
- 각 문서는 [배경 → 조사 근거 → 결정 → 열린 질문] 구조를 지킨다.
- 근거에는 소스(URL, 코드 경로, 커밋)를 명시한다. 추측과 사실을 구분한다.

## 목차

| 문서 | 주제 | 상태 |
|---|---|---|
| [001-own-telephony-infra.md](./001-own-telephony-infra.md) | 우리만의 ClawOps — 자체 한국 전화 인프라 구축 결정 | active |
| [002-korean-sip070-contract-guide.md](./002-korean-sip070-contract-guide.md) | 한국 SIP/070 공급자 계약·기술 부속서 가이드 | active |
| [003-sip070-phone-call-playbook.md](./003-sip070-phone-call-playbook.md) | SIP/070 공급자 전화 문의·상사 보고 플레이북 | active |
