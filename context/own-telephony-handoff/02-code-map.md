# 02 — 코드 맵

이 문서는 Recova 자체 한국 전화 인프라 관련 주요 파일 위치를 정리한다.

## Backend: Jambonz provider / contract

| 파일 | 역할 |
|---|---|
| `api/services/telephony/providers/jambonz/contract.py` | `jambonz_contract_v1` Pydantic contract, event/status/CDR payload 정의. |
| `api/services/telephony/providers/jambonz/provider.py` | hidden Jambonz provider adapter. Assigned Recova 070 caller만 outbound 허용. |
| `api/services/telephony/providers/jambonz/routes.py` | Jambonz contract webhook/API route. |
| `api/services/telephony/providers/jambonz/serializers.py` | provider payload serialization. |
| `api/services/telephony/providers/jambonz/transport.py` | outbound transport abstraction. |
| `api/services/telephony/providers/jambonz/config.py` | Jambonz provider config schema. |
| `api/services/telephony/providers/jambonz/simulator_smoke.py` | supplier-independent smoke checks. |
| `api/scripts/jambonz_contract_smoke.py` | CLI smoke command entrypoint. |

## Backend: runtime policy / trust boundary

| 파일 | 역할 |
|---|---|
| `api/services/telephony/jambonz_policy.py` | assigned Recova 070 여부 검증. Inventory row + phone row를 모두 확인하는 핵심 trust boundary. |
| `api/services/telephony/runtime_policy.py` | campaign/outbound caller validation hooks. |
| `api/services/telephony/evidence_markers.py` | provider evidence marker extraction/sanitization. |
| `api/services/telephony/admission.py` | 동시콜/admission guard. |
| `api/services/telephony/ops_alerts.py` | typed ops alert sink/taxonomy. |
| `api/routes/telephony.py` | `/telephony/initiate-call`, `/telephony/inbound/run` runtime entrypoints. Jambonz assigned route policy 적용. |

## Backend: number inventory

| 파일 | 역할 |
|---|---|
| `api/db/telephony_number_inventory_client.py` | inventory DB operations. import/reserve/assign/quarantine/retire/backfill/live attestation. |
| `api/services/telephony_number_inventory.py` | inventory service layer, response shaping, safe metadata filtering. |
| `api/routes/telephony_number_inventory.py` | operator/customer inventory routes. |
| `api/schemas/telephony_number_inventory.py` | inventory/customer assigned number/live validation schemas. |
| `api/db/telephony_configuration_client.py` | telephony provider config DB helper. |
| `api/db/telephony_phone_number_client.py` | telephony phone number DB helper. |
| `api/db/telephony_call_event_client.py` | call event/CDR/failure persistence helper. |

Important routes:

```text
GET/POST /api/v1/telephony-number-inventory/...
POST /api/v1/telephony-number-inventory/{inventory_id}/live-validation
GET /api/v1/organizations/telephony-numbers/assigned
POST /api/v1/organizations/telephony-numbers/assigned/{inventory_id}/bind
DELETE /api/v1/organizations/telephony-numbers/assigned/{inventory_id}/bind
```

## Frontend

| 파일 | 역할 |
|---|---|
| `ui/src/app/superadmin/telephony-number-inventory/page.tsx` | superadmin inventory table/actions, audit, `Attest live`. |
| `ui/src/app/telephony-numbers/page.tsx` | customer assigned phone numbers page. |
| `ui/src/components/telephony/AssignedNumbersBinder.tsx` | assigned number workflow bind/unbind component. |
| `ui/src/app/workflow/[workflowId]/settings/page.tsx` | workflow settings에 assigned-number binder 노출. |
| `ui/src/app/campaigns/CampaignAdvancedSettings.tsx` | campaign concurrency/caller ID pool 안내. |
| `ui/src/app/campaigns/new/page.tsx` | managed caller ID campaign copy. |
| `ui/src/components/layout/AppSidebar.tsx` | `/telephony-numbers` sidebar exposure. |

주의:

- `ui/src/client/`는 generated client다. 직접 수정하지 않는다.
- 현재 UI는 `apiRequest`를 직접 쓰는 부분이 있다. future OpenAPI regeneration이 필요하면 `ui/src/client`는 generator로 갱신한다.

## Docs / context

| 파일 | 역할 |
|---|---|
| `context/001-own-telephony-infra.md` | 전체 의사결정 맥락. |
| `context/002-korean-sip070-contract-guide.md` | 공급자 후보/계약/질문 가이드. |
| `context/003-sip070-phone-call-playbook.md` | 실제 전화 문의 스크립트/상사 보고 가이드. |
| `docs/integrations/telephony/own-infra-readiness.mdx` | live readiness 기준. |
| `docs/integrations/telephony/own-infra-runbook.mdx` | operator/customer operational flow. |
| `docs/integrations/telephony/sip-070-cutover-checklist.mdx` | supplier cutover checklist. |
| `docs/docs.json` | Mintlify navigation. Telephony docs 추가 시 여기 확인. |

## Tests

| 파일 | 역할 |
|---|---|
| `api/tests/telephony/jambonz/test_simulator_smoke.py` | supplier-independent smoke checks. |
| `api/tests/telephony/jambonz/test_inventory_trust_boundary.py` | inventory assignment/live attestation trust boundary DB tests. |
| `api/tests/telephony/jambonz/test_policy.py` | assigned Recova 070 policy unit tests. |
| `api/tests/telephony/jambonz/test_provider.py` | Jambonz provider tests. |
| `api/tests/telephony/jambonz/test_routes.py` | Jambonz route tests. |
| `api/tests/test_telephony_number_inventory_routes.py` | inventory route tests. |
| `api/tests/test_telephony_lane_c.py` | lane C runtime/admission/CDR/alerts coverage. |

## Most important invariants

1. Organization-scoped reads/writes must filter or validate by `organization_id`.
2. Assigned Jambonz V1 core use requires the full managed-inventory tuple, not just matching phone number text.
3. Live readiness requires trusted operator/approved-tool evidence. Simulator and generic callback metadata never count.
4. Customer surfaces bind assigned numbers only. Provider credentials stay hidden.
5. ClawOps remains outside V1 core runtime/fallback.
