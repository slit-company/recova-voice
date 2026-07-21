# Onnuri outbound route remediation decision

- Decision status: implementation verified offline; live validation pending
- Product status: `Waiting`
- Last reviewed: 2026-07-21

## Decision

The Onnuri 070 outbound path uses the real Seoul facade → stock Jambonz Calls API → Drachtio/SBC route. The local ad-hoc UDP SIP caller is not an approved diagnostic client.

Registration authority remains a separate plane. Outbound route authority is selected from an authenticated provider-fact packet, sealed in a pre-build route-decision receipt, checked after build by a route-conformance receipt, and recursively verified by one backend/F12 implementation. The facade does not parse or duplicate provider facts or route receipts; it obtains a signed, recipient-bound, one-use F12 capability with a maximum 60-second lifetime immediately before dispatch.

Provider packet canonical hashing is non-self-referential: `canonical_payload_sha256` hashes the canonical payload with that field omitted. `fact_set_digest` hashes the explicit ordered fact-set projection defined by the shared verifier. Detached signatures cover the complete computed packet.

Outbound diagnostic state is a closed five-axis product graph. Media observations first enter explicit open products and then use named terminal transitions. `not_applicable` is restricted to verified non-answered carrier rejection. `none` requires a complete healthy signed post-answer zero-matching-packet observation. Ambiguous submission cannot create a retry or a second stock request.

## Live boundary

This decision and its implementation do not authorize provider traffic or Phase C activation. A renewed live diagnostic window requires a fresh immutable candidate, packet-present signed preflight, independent review, and explicit manual approval. The window permits at most three outbound attempts: one baseline and at most two evidence-based corrections, one approved comparison group per correction, concurrency one, deadline at most 60 seconds, and no automatic retry.

The trunk remains `Waiting` until outbound and inbound real-call evidence, bidirectional media attestation, cost/status evidence, and teardown all pass.

## Evidence

- Approved execution plan: `.gjc/_session-019f7bd6-4e8e-7000-85f7-83222d704b48/plans/ralplan/019f7bd6-4e8e-7000-85f7-83222d704b48/pending-approval.md`
- Shared verifier: `api/services/telephony/onnuri_route_receipts.py`
- Closed state fixture: `deploy/onnuri-jambonz-oss/fixtures/onnuri_outbound_diagnostic_v1_contract.json`
- F12 and facade boundaries: `api/services/onnuri_smoke_f12.py`, `api/services/telephony/providers/jambonz/facade/`
- Default-disabled deployment: `deploy/onnuri-jambonz-oss/compose.yaml`, `infra/onnuri-seoul-staging-phase-c-smoke/`
