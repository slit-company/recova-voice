# Onnuri Seoul staging Phase A

This directory is a **provider-free, structurally non-deployable specification**. It does not create or configure GCP resources and it does not authorize SIP registration, RTP, calls, secrets, reservation, assignment, attestation, or readiness. The product capability remains `Waiting`.

## What this phase contains

- Exactly four disabled L3/L4 control intents: `sip_ingress`, `sip_egress`, `rtp_ingress`, and `rtp_egress`.
- Exactly four matching, non-executable future containment actions.
- A closed JSON schema and canonical instance.
- A standard-library verifier and hermetic contract tests.
- Matching Bash and PowerShell entrypoints that produce content-addressed, redacted local evidence.
- An internal operator/G0 contract in `context/005-onnuri-seoul-staging-phase-a-operator-contract.md`.

There is no Terraform, provider, backend, remote state, cloud SDK/API, project, network, edge, sink, secret reference, credential, deployment switch, or activation path in Phase A. Phase B cloud materialization and Phase C traffic require separate owner evidence, architecture review, and explicit approval.

## Exact non-authoritative fixture whitelist

Only these address-shaped values are permitted, only at their named disabled records:

- `controls.sip_ingress.fixture.source_cidr = "61.78.32.184/32"`
- `controls.sip_egress.provenance.outbound_proxy = "61.78.32.184:5060/UDP"`

Both records are marked `fixture_only`, `not_supplier_authoritative`, and `not_deployable`. They cannot prove supplier authority or unlock routing. RTP peer and port values remain `null` and `unpopulated`. DID, URI, dialog, authenticated SDP, rate, retry, tenant ownership, and payload policy belong to later SBC/application/proof gates, not this L3/L4 specification.

## Local verification

The paired commands accept only `--help` or `--evidence-dir <relative-directory>`:

```sh
./scripts/validate_onnuri_seoul_no_traffic.sh --evidence-dir evidence/local
pwsh -NoProfile -File ./scripts/validate_onnuri_seoul_no_traffic.ps1 --evidence-dir evidence/local
```

Run them from a minimal environment. They intentionally reject environment variable names associated with cloud credentials, tokens, secrets, or proxies without reading or printing their values. Evidence directories must remain beneath this Phase A root and may not use absolute, dotted, traversing, backslash, or symlink components.
Both wrappers require Bash, PowerShell, and the same resolved Python implementation/minor before evidence can be emitted. Calling `verify_spec.py` directly has no valid evidence contract and fails closed. The `network_deny` and `unit_contract` evidence stages attest the reviewed static deny-harness and test-contract surfaces; runtime unit and cross-shell parity results remain mandatory completion evidence outside the emitted source-hash artifact.

Successful verification emits one `sha256-<digest>.json` path. The artifact contains source hashes, immutable review identities, runtime identity, and ordered pass stages only. It contains no credit value, tenant identifier, DID, secret, host/user path, provider payload, SIP/RTP payload, or cloud export.
The artifact hashes the exact current nine-file source snapshot; it is not an immutable preapproval baseline. Any source change produces a different digest and requires fresh review. Review-identity hashes bind the approved plan and consensus, not an authorization to deploy the hashed source.

Exit classes are:

- `0`: all local checks and evidence revalidation passed.
- `64`: interface or evidence-path failure.
- `65`: malformed schema/specification or invariant failure.
- `66`: prohibited environment name.
- `69`: prohibited capability, unguarded network/process surface, or deny-harness escape.
- `70`: required local runtime, runner, parity, or evidence infrastructure failure.

An intercepted test-only socket or URL probe is a successful deny assertion; an unapproved client/import, missing guard, bypass, or escaping connection is `69`. Missing Bash, PowerShell, or the shared Python runtime is `70`, never a skipped pass.

## Security and lifecycle boundary

Infrastructure posture never replaces the database-current proof predicate or organization ownership checks. Missing, stale, revised, revoked, expired, unauthorized, or cross-tenant evidence remains no-route. Phase A evidence cannot reserve a number, bind a workflow, create a cloud control, access Secret Manager, or change `Waiting`.

Code-only rollback is a reviewed removal or supersession of this provider-free specification while preserving content hashes and immutable proof provenance. Cloud teardown, Scheduler semantics, credential rotation, and traffic containment remain future separately approved procedures.
