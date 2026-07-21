# 004 — Onnuri staging no-traffic control checkpoint

- 작성일: 2026-07-13
- 상태: **Waiting** — this is a password-free design and operator-control record. It creates no cloud resource, network rule, scheduler, credential reference, reservation, binding, registration, RTP flow, or call.
- 근거: approved team intake, **Onnuri 070 SIP staging — consensus revision 3**, sections “Durable Data, Ownership, and Atomic Lifecycle”, “Network, Secret, Contract, Spend, and Disable Controls”, and “Sequencing and Dependencies”.

## 배경

The approved scope permits only a no-traffic foundation. Candidate import/classification is allowed without a preflight proof, but it must create no routability. Reservation, assignment, binding, registration, network enablement, and all call activity remain blocked until their separate gates are satisfied.

The `exception_waiting` predicate is a bounded discovery decision, not supplier authority, technical validation, attestation, soak, public readiness, or production readiness. Public and production remain **Waiting**.

## 조사 근거

The approved plan requires a reviewed intake/runbook; a known or approved IaC and sink owner/path; four disabled firewall controls and four one-shot Scheduler controls; constrained identity; default deny; redaction; threat model; and teardown evidence before any live-eligibility step. It also requires a database-current proof predicate so an expiry controller delay never restores routing.

This document records the required control shape only. Every field marked `required before gate B` is intentionally unfilled until an authorized operator supplies verifiable evidence. Missing or unverifiable evidence is a stop condition.

## 결정

### 1. Password-free intake and control schema

Create one redacted intake record per proposed candidate/proof revision. Store only the following fields in the durable preflight-proof flow or an approved secure operator system:

| Group | Required fields | Validation / stop condition |
|---|---|---|
| Candidate | candidate UUID, inventory ID, normalized DID, provider `jambonz`, environment `staging`, immutable classification `onnuri_staging_candidate_v1`, import actor/time/reason | Only dedicated superuser import creates it. Generic import and ordinary metadata cannot classify or modify it. |
| Scope | organization ID, scope key, proof revision, candidate UUID, linked inventory ID, compact canonical SHA-256 | Exact candidate/inventory/org/provider/environment/DID/UUID/hash linkage is required. Duplicate, stale, revised, or mismatched linkage is no-route. |
| Predicate | policy `exception_waiting` or `retain_standard`, allowed stage, proxy provenance, evidence reference, evaluator/signer/approval timestamps, expiry | `exception_waiting` accepts only `user_approved_canary_assumption`; `retain_standard` rejects that provenance. Missing approval, expiry, revocation, or invalidation is no-route. |
| Credit | finite normalized base-10 strings for starting, warning, stop, discovery-smoke, and soak amounts; currency; provider/portal evidence reference and observation time | Reject NaN, infinity, negative, or unbounded values. For the exception predicate: warning = starting × 0.20, stop = 0, discovery-smoke maximum = starting, soak maximum = 0. |
| Network checkpoint | edge identifier, exact source/destination/protocol/port rule IDs, sink identifier/path, Scheduler job IDs, control owner and approval evidence | Required before gate B. Do not infer facts from a candidate record or historical network state. |
| Ownership | selected organization, owned test destinations, named operator acknowledgement, service identity, teardown operator | Tenant mismatch, missing ownership, or missing named accountable role blocks the gate. |

The intake excludes credential material, secret payloads, secret-version identifiers, auth headers, raw SIP/RTP, and raw provider payloads. Evidence references must be redacted identifiers or approved secure-system links; they must not embed sensitive values.

### 2. GCP edge, sink, firewall, and Scheduler architecture checkpoint

This is an architecture inventory, not deployed IaC. The checkpoint is **not passed** until the owner records existing or approved IaC paths and verifies all listed controls are absent or disabled with no flow.

| Control plane | Required password-free shape | State required before any later gate |
|---|---|---|
| Edge | Isolated staging edge identifier; constrained Seoul workload identity; default-deny ingress/egress; no dynamic peer learning | IaC path, owner, approval reference, and disabled/default-deny evidence recorded. |
| SIP ingress firewall | One named disabled rule: exact fixed source `61.78.32.184/32` to the isolated edge only, UDP/5060 only, expected DID/URI/dialog/rate sink only | Rule ID and disable evidence recorded. No broader CIDR, host, protocol, port, or payload capture. |
| SIP egress firewall | One named disabled rule: isolated edge to `61.78.32.184/32` only, UDP/5060 only, registration-only | Rule ID and disable evidence recorded. No alternate proxy, destination, or retry route. |
| RTP ingress firewall | One named disabled rule: only exact authenticated SDP peer/port/dialog metadata | Rule ID and disable evidence recorded. No port range, dynamic allowlist, or raw media capture. |
| RTP egress firewall | One named disabled rule: only exact authenticated SDP peer/port/dialog metadata | Rule ID and disable evidence recorded. No port range, dynamic allowlist, or raw media capture. |
| Sink | Fixed-source ingress sink with an owner, approved path, correlation-only redacted event schema, and retention/kill/escalation controls | Sink path and owner recorded; sink accepts no raw SIP/RTP or auth material. |
| Scheduler | Four pre-created, named, one-shot least-privilege delete/disable jobs: SIP ingress, SIP egress, RTP ingress, RTP egress | Job ID, deadline, target, service identity, and disabled/no-flow evidence recorded for each control. |

The assumed proxy/source value above is limited to the approved exception-waiting discovery predicate. It is not supplier-authoritative evidence and cannot support retain-standard, attestation, soak, readiness, or a broader allowlist.

### 3. Audit, redaction, and threat model

Audit records contain only candidate/proof/inventory/organization identifiers, redacted reason, timestamps, and a hash prefix. They must not contain secrets, media, auth content, raw provider payloads, or resource payload exports.

| Threat | Required containment |
|---|---|
| Generic inventory bypass | Dedicated immutable classification; generic reserve/assign rejects classified rows before configuration, phone, workflow, or default side effects. |
| Stale, revised, revoked, or expired proof | Current-routability query checks database time and exact locked linkage. No positive authorization cache. Lifecycle cleanup lag remains no-route. |
| Cross-tenant routing | Every candidate/proof/inventory/phone/workflow lookup validates organization ID before a side effect. |
| Broad network aperture or learned peer | Default deny and exact fixed controls only; any mismatch stops and quarantines. |
| Sensitive evidence leakage | Redacted identifiers and correlation metadata only; no payload capture. |
| Scheduled-control failure | Scheduler health is observable, but its lag never restores routing because the proof predicate fails closed. |

### 4. Teardown and containment runbook

On any predicate, source, proxy, dialog, rate, credit, provider, expiry, revocation, or revision mismatch, stop before creating new work and record a redacted audit event. The ordered containment sequence is:

1. Stop dispatch and retries.
2. Disable or delete registration and SIP egress control.
3. Disable or delete SIP ingress and both RTP controls through the Scheduler or the documented manual fallback.
4. Quarantine and unbind affected inventory; clear default, active, validation, and route state while preserving immutable candidate history.
5. Verify no renewal, route, dialog, RTP, new event/CDR, or valid-validation result remains.
6. Preserve redacted audit evidence and escalate a plausible exposure through the approved security process.

No automated retry, route restoration, readiness status, attestation, or public/production transition is allowed from this runbook.

### 5. Operator checkpoint record

An authorized operator must record each item below before declaring the architecture checkpoint ready for the separate proof/reservation gate. Until then, the result is **Waiting**.

| Check | Evidence to record | Current result |
|---|---|---|
| Intake owner and storage path | Owner role, approved redacted storage path, review timestamp | Waiting |
| Immutable candidate path | Superuser import path and no-route verification evidence | Waiting |
| Edge/IaC owner and path | Owner role, IaC path, approval reference | Waiting |
| Fixed-source sink | Sink owner, path, redaction/retention/kill evidence | Waiting |
| Four firewall controls | Four rule IDs, exact shapes, disabled/default-deny/no-flow evidence | Waiting |
| Four Scheduler controls | Four job IDs, deadline/target/identity and disabled/no-flow evidence | Waiting |
| Constrained identity | Identity role and least-privilege review evidence | Waiting |
| Teardown drill | Redacted ordered-disable evidence | Waiting |
| Proof lifecycle tests | Revision/revocation/expiry/worker-lag/concurrency/tenant evidence | Waiting |

## 열린 질문

1. Which infrastructure owner and approved IaC path will provide the edge, sink, firewall, and Scheduler evidence?
2. Which secure redacted evidence system is approved for the operator checkpoint record?
3. Which authorized roles will approve proof, execute containment, and review the no-traffic test evidence?

These questions are operational ownership questions only. They do not authorize a network change, secret access, registration, media flow, call, attestation, or readiness transition.
