# 005 — Onnuri Seoul staging Phase A operator contract

- Status: **Waiting**
- Audience: internal operators, reviewers, and future Phase B designers.
- Scope: provider-free local specification, verification, and redacted local evidence only.

Phase A is structurally non-deployable. It creates no cloud resource, provider configuration, route, network rule, identity, scheduler job, sink, secret reference, reservation, binding, registration, media flow, or call. A passing local validator result proves only the closed local artifact contract. It never changes product status and cannot authorize Phase B or Phase C.

## Phase A boundary

The closed model has exactly four controls: `sip_ingress`, `sip_egress`, `rtp_ingress`, and `rtp_egress`. Each is disabled, is Phase A, has deployment forbidden, and remains evidence waiting. Each maps one-to-one to a non-executable `contain_<control_id>` action. An action is future disable-or-delete only, has no automatic retry or re-enable behavior, and contains no schedule, target, identity, token, project, operation, or handler.

These are L3/L4 shape controls only. They do not assert DID, URI, dialog, authentication, SDP, rate, retry, payload, or tenant enforcement; those concerns remain proof, SBC, and application concerns for later review. The two closed fixture-only address fields belong solely in the specification and must not be copied into intake, evidence, this record, or another control.

## Threat model and fail-closed response

| Threat | Phase A response |
| --- | --- |
| Ambient credentials or provider initialization mutate an external system. | No provider, cloud API, metadata access, registry, state backend, cloud command, or deployable root exists. The validator rejects prohibited environment names before the verifier runs. |
| A broad or dynamic peer opens an unintended network aperture. | The closed model rejects enabled or additional controls, any unapproved endpoint placement, dynamic peer, range, route, NAT, public endpoint, packet capture, and raw payload. RTP peer and ports remain unpopulated. |
| Stale, revised, revoked, expired, or unauthorized proof is mistaken for authority. | Missing, stale, revised, revoked, expired, unverifiable, cross-tenant, or mismatched proof remains no-route. Phase A evidence has no approval effect. |
| An inventory or tenant mismatch causes a side effect. | Future secure intake must bind the candidate, inventory, normalized DID, provider/environment/classification, organization, scope key, revision, and canonical hash before any separately approved action. |
| Redacted evidence leaks sensitive content. | Local evidence is limited to closed artifact metadata, opaque hashes and references, review roles, stage results, and source hashes. It excludes provider payloads, raw signaling/media, credentials, secret material, phone identifiers, endpoints, tenant data, and free text. |
| A future scheduled containment action fails or repeats. | Scheduler is not implemented in Phase A. Future design requires paused state, no retries, monotonic idempotent disable/delete, completion proof, permanent disable/delete, reconciliation quarantine, fallback, audit, deadline, escalation, and no recurrence. |

The local deny harness is not an operating-system network audit. A missing, bypassed, or escaped harness is a validator failure, not a waiver.

## G0 approval and secure proof/credit intake

G0 blocks all Phase B design/cloud action and all Phase C activity; it does not block this local Phase A artifact. Before either later phase, an approved secure and redacted record must name the IaC root/path owner, cloud and network owner, sink/data owner and type, security and Secret Manager owner, proof and tenant authority, containment operator, reviewer, approval time, immutable approval reference, and expiry or review cadence. Project identifiers, endpoints, secret paths or values, credentials, tenant identifiers, and raw provider data do not belong in Phase A.

Secure intake, not this repository evidence, must contain the full linkage: candidate UUID, inventory ID, normalized DID, provider, environment, classification, organization ID, scope key, revision, canonical SHA-256, evaluator, signer, approval, expiry, revocation state, and redacted evidence references. Each record must be current, unrevoked, unexpired, internally consistent, and authorized for its organization. Any failed predicate is no-route.

The proof/credit record must require, without recording values here:

- Decimal strings: `starting_balance`, `warning_balance`, `stop_balance`, `max_discovery_smoke_spend`, and `max_soak_spend`.
- Nonblank strings: `soak_policy`, `authorization_scope`, `proxy_provenance`, `authorization_reference`, `outbound_proxy`, `source_cidr`, `currency`, `provider_evidence_ref`, `starting_balance_evidence_ref`, `observed_at`, `scheduler_checkpoint_ref`, `firewall_checkpoint_ref`, `sink_checkpoint_ref`, `identity_checkpoint_ref`, and `owned_destinations_ref`.
- Nonnegative integers: `max_inbound_attempts`, `max_outbound_attempts`, `max_duration_seconds`, `max_concurrency`, `cps`, and `retries`.

Only secure intake can hold the finite canonical starting balance and the trimmed nonblank currency. It must validate the complete proof predicate and linkage before later work; it must not treat a local Phase A result as supplier authority, credit authority, destination ownership, or traffic authorization.

## Future sink, Secret Manager, and Scheduler decisions

The sink remains `service="undecided"` and `materialized=false`. G0 must decide its source, destination, IAM, encryption, retention, readers, kill switch, alerting, schema rejection, and evidence handling. A future sink can retain only logical control/action IDs, opaque correlation hashes and hash prefix, revision, phase, reason, timestamp, artifact/spec hash, role label, and opaque evidence reference. It must reject raw signaling/media/auth/provider data, credentials, secret names or versions, phone/address/endpoint data, exports, and free text.

Secret Manager remains external. Phase A contains no secret, version, reference, IAM, data, output, or principal. A future approved rotation design must identify the G0 owner and path, consumer reload behavior, reviewer, operators, rollback, and redacted evidence; separately manage access and old versions; halt and escalate on failure; preserve disabled controls; and never authorize traffic or readiness.

A future Scheduler design is a logical one-shot contract only. It must have an approved target/interface, act-as/token/audience/scope semantics, exact permission/resource condition, paused state, no retries, monotonic idempotent disable/delete, completion proof, permanent disable/delete, reconciliation quarantine, fallback/audit/deadline/escalation, and ordered containment: dispatch closure, SIP egress/registration, then SIP ingress/RTP. Default deny is a required Phase B design decision, not a deployed Phase A assertion.

## Local validation evidence

The paired local validators accept only help or a relative evidence directory. They fail closed on invalid interface/path input, prohibited environment names, closed-model violations, denied capabilities, or unavailable local infrastructure. A success emits only a relative evidence path. The evidence is a deterministic, redacted local JSON object with its own digest and contains the closed source hashes and mandated pass stages; it contains no host, user, environment, absolute path, endpoint, provider, secret, credit, tenant, or raw data.
The only accepted invocations are `--help` and `--evidence-dir <relative-directory>`. An evidence directory has nonempty normal slash-separated segments under the resolved Phase A root. Absolute, drive, UNC, dot, traversal, empty, backslash, symlink, and pre- or post-create containment failures are interface failures and write no evidence.

The exit contract is `0` for pass, `64` for interface or evidence-path failure, `65` for schema or invariant failure, `66` for a case-insensitive prohibited environment name, `69` for denied or missing capability enforcement, and `70` for runner, runtime, evidence, or parity infrastructure failure. Before invoking the verifier, both wrappers reject environment names starting with `GOOGLE_`, `GCLOUD_`, `CLOUDSDK_`, `GCP_`, `TF_`, `TF_VAR_`, `AWS_`, or `AZURE_`, and names containing `CREDENTIAL`, `TOKEN`, `SECRET`, `PROXY`, or `NO_PROXY`; they do not read or print their values. Both wrappers require Bash, PowerShell, and one matching Python implementation/minor; missing or spoofed runtimes fail with `70`. The shared runtime identity is `<sys.implementation.name>-<major>.<minor>`.

On success, the ordered stages are `interface`, `environment_guard`, `evidence_path`, `static_surface`, `schema`, `control_model`, `network_deny`, `unit_contract`, and `evidence_write`. The wrappers own the first two stages; the verifier owns the remaining stages and rejects direct invocation without a wrapper/runtime context. `network_deny` and `unit_contract` attest the reviewed static deny-harness and test-contract surfaces; they do not replace runtime unit tests or cross-shell parity, which remain separate mandatory completion evidence. A network probe is acceptable only when the deny harness intercepts it. A missing or bypassed harness, or an escaped connection attempt, is a `69` failure.

Evidence has exactly these members: `artifact_id`, `evidence_schema_version`, `evidence_sha256`, `phase`, `review_identities`, `source_files`, `spec_sha256`, `stage_results`, `validator_contract_version`, and `verifier_runtime_version`. Its review entries are ordered planner, architect, critic; source entries are bytewise path-sorted and cover only the schema, specification, verifier, paired wrappers, paired tests, README, and this contract. The digest omits `evidence_sha256`, then hashes UTF-8 JSON with `ensure_ascii=true`, separators `(',', ':')`, lexicographic keys, and no newline. The final canonical object adds one newline and is named `sha256-<digest>.json`. An atomic rehash mismatch is a `70` failure.
The source hashes describe the exact current nine-file snapshot; they are not an immutable approval baseline. Any source change yields a new digest and requires fresh review. Planner/architect/critic identities bind the approved Phase A contract only and never authorize deployment or traffic.

Evidence is useful for local review only. Preserve its digest and any future redacted supersession reference. Do not use it to infer external state, a network posture, an active sink, an IAM binding, a Scheduler job, a Secret Manager integration, supplier authority, or readiness.

## Rollback, containment, and exclusions

Phase A creates nothing external, so rollback is a separately reviewed code removal or supersession that retains prior hashes and never deletes immutable provenance or lifecycle state. When a G0-backed future control exists, retain a redacted supersession reference rather than treating deletion as evidence erasure.

Future containment remains contract-only: close dispatch and retries; disable or delete SIP egress/registration; disable or delete SIP ingress and RTP controls; prove operation and non-recurrence; quarantine on reconciliation mismatch; retain redacted evidence; and escalate through the approved security process. It must never re-enable routing, retry containment automatically, or promote readiness.

Phase B (cloud IaC, resources, identities, routing, sink, Scheduler, Secret Manager, and actual default-deny posture) requires G0 and independent architecture review. Phase C (any traffic or readiness activity) separately requires G0, a current immutable candidate/proof/inventory/organization linkage, owned destination, current unrevoked proof predicate, roles, and supplier authority. Neither phase is implemented, implied, or approved by this document.
