# Recova 자체 한국 전화 인프라 — 작업 인수인계 메모

- 작성일: 2026-07-10
- 현재 기준 커밋: `a28fc26`
- 상태: 코드베이스 pre-carrier readiness 완료, 실제 SIP/070 공급자 계약·스펙 확보 대기
- 연결 문서:
  - [`../001-own-telephony-infra.md`](../001-own-telephony-infra.md)
  - [`../002-korean-sip070-contract-guide.md`](../002-korean-sip070-contract-guide.md)
  - [`../003-sip070-phone-call-playbook.md`](../003-sip070-phone-call-playbook.md)

## 이 폴더의 목적

다음 작업자가 “우리가 어디까지 했고, 다음에 뭘 해야 하는지”를 바로 이해하도록 만든 코딩 작업 인수인계 폴더다.

지금 병목은 코드가 아니라 **한국 SIP/070 공급자 스펙 확보**다. 공급자 답변/계약서/기술 문서가 들어오면 이 폴더 순서대로 읽고 개발을 재개한다.

## 읽는 순서

1. [`01-current-state.md`](./01-current-state.md)
   - 지금 끝난 것, 남은 것, 하면 안 되는 것.
2. [`02-code-map.md`](./02-code-map.md)
   - 관련 코드와 UI/문서/테스트 위치.
3. [`03-next-coding-after-supplier.md`](./03-next-coding-after-supplier.md)
   - 공급자 스펙을 받은 뒤 실제 코딩 순서.
4. [`04-verification-commands.md`](./04-verification-commands.md)
   - 검증 명령과 알려진 로컬 제약.
5. [`05-supplier-intake-template.md`](./05-supplier-intake-template.md)
   - 통화/메일로 받은 공급자 정보를 정리하는 템플릿.

## 한 줄 요약

Recova 자체 전화 인프라 V1은 **ClawOps 없이 Jambonz contract-first core + Recova-managed 070 number inventory**로 가며, 코드로 미리 만들 수 있는 핵심은 끝났다. 다음 코딩은 실제 공급자 SIP/070 스펙을 받은 뒤 adapter/cutover 설정을 맞추는 일이다.
