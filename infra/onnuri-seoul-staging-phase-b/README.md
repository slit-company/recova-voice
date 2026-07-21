# Onnuri Seoul Phase B foundation

**Status: `open-confirmations-pending` — offline source and hermetic validation only.**

This directory describes a future, intentionally empty GCP Seoul foundation. It
is not cloud authority, deployment approval, a readiness claim, or evidence of
supplier, tenant, proof, security, cost, or production approval. `slit` is the
offline IaC source owner/approver only; it has no cloud runner, deployer, or
cloud-owner authority.

## Fixed future graph

The approved future graph is exactly four resources and must remain no-traffic:

1. One custom VPC, `recova-onnuri-phase-b-vpc`, with no auto subnetworks,
   regional routing, default routes deleted on creation, and ULA internal IPv6
   disabled.
2. One IPv4-only Seoul subnet,
   `recova-onnuri-phase-b-subnet-seoul`, in `asia-northeast3`. Its RFC1918
   `/24` CIDR is fixed to the approved canonical `10.73.96.0/24`; collision,
   organization-policy, and quota preflight remain separate hard Waiting gates.
3. One targetless all-protocol ingress deny rule at priority `65534`, sourced
   from `0.0.0.0/0`.
4. One targetless all-protocol egress deny rule at priority `65534`, destined
   for `0.0.0.0/0`.

The source accepts only a non-placeholder, approved-shaped
`slit-497603` service-account email as its deployer input. It grants that
principal no resource or role; delegated authorization remains a Waiting gate.

The only permitted outputs are explicitly non-sensitive:
`project_id`, `region`, network/subnet self links and subnet CIDR, ingress and
egress deny-rule names and self links, and
`source_contract_version` (`phase-b-source-contract-v1`). They are the
non-secret source values required for a leader-signed dependency manifest.

No additional provider, module, data source, provisioner, resource, endpoint,
attachment, route, router/NAT, workload, secret, sink, Scheduler,
metric/alert, address, forwarding rule, supplier-shaped SIP/RTP allow rule,
or traffic-enabling input is permitted. The graph remains exactly the four
resources above; outputs do not add cloud resources or enable traffic.

## Offline-only validation

Source and fixtures are reviewed locally. Terraform may run only through the
repository's scrubbed, network-denied macOS sandbox runner using a pre-existing
local provider mirror and fixed Terraform version. A missing/invalid mirror,
CLI configuration, sandbox, checksum, or version is a fail-closed local
blocker; it must never trigger a download, registry/DNS lookup, remote backend
operation, or credential workaround.

Remote Terraform (`init` against a backend, plan, show, apply, destroy, state),
GCS, `gcloud`, console/API/IAM/billing actions, cloud credentials, and all
network or telephony traffic are outside this phase.

## Hard gates — all Waiting/pending

No remote proposal is allowed until independent owners confirm all of the
following:

- Cloud runner/deployer identity and delegated authorization.
- Seoul region, approved CIDR, quota, organization policy, and collision
  baseline.
- Dedicated state bucket, prefix, location, UBA/PAP, versioning, encryption,
  lifecycle, lock, and recovery controls.
- State/evidence security, ancestor IAM/Deny/PAB, and Secret deferral.
- Auditor/read role, audit retention/readers, redaction, and escalation.
- Finite KRW estimate, manual stop threshold, and budget-notification latency.
- Supplier/proof/tenant/currentness and Phase C authority.

State/backend identity, generation, serial, canonical-state hash,
non-sensitive-output hash, manifest hash, signature, signer identity, and
verification receipt are leader-generated external receipt fields. They are
not Terraform outputs, credentials, or authority from this source. Phase C
receives a leader-validated immutable manifest as an input and never reads,
imports, destroys, or otherwise uses Phase B remote state.

The own Korean 070, SIP/RTP, Secret, sink, Scheduler, proof/tenant, Phase C,
public, and production controls remain **Waiting**. A KRW 10 budget is a
notification only, never a cap.
