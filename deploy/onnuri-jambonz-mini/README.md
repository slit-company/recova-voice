# Onnuri Jambonz candidate boundary

This directory is an internal acquisition handoff contract, not a selected candidate, downloader, deployment bundle, or live-traffic approval. It contains no candidate manifest instance and no credential or endpoint.

## Gate ownership

G-1 requires separate, explicit network-artifact-acquisition authorization. In an approved acquisition environment, G-1 may select exactly one supported stock Jambonz mini release, acquire and scan it, close acquisition access, and issue the immutable receipt described by the schema. Supplier-authoritative RTP CIDR and port evidence is a separate, short-lived G4 live gate and never enters this stable candidate bundle. Acquisition does not occur in G0 and this repository code never downloads, selects, substitutes, updates, or repairs an artifact.

G0 is network denied. It receives the exact content-addressed artifact, manifest, evidence index, and evidence bundle from G-1 and validates only that acquired candidate. The caller must provide an explicit validation instant:

```text
python deploy/onnuri-jambonz-mini/verify_candidate_manifest.py MANIFEST.json \
  --evidence-index EVIDENCE-INDEX.json \
  --bundle-root EVIDENCE-BUNDLE \
  --as-of 2026-07-14T00:00:00Z
```

`--as-of` is mandatory so the same bytes and validation time produce the same expiry result; the verifier does not consult a clock, network, registry, subprocess, cloud API, SIP service, or media service. It opens the manifest, index, and indexed evidence files read-only, rejects path traversal/symlinks/extra assertions, and verifies every referenced evidence byte digest. A failure quarantines the candidate and returns the choice to consensus. It does not authorize an executor-selected fallback.

A valid candidate and successful offline validation still grant no build, fallback, deployment, cloud, secret, provider-configuration, REGISTER, SIP, SDP, RTP, WebSocket, audio, call, test, readiness, public, production, or live-traffic authority. Those remain separate gates.

## Exact manifest keys

Every object rejects additional keys. The required top-level keys are:

- `schema_version`
- `candidate`
- `runtime_contract`
- `storage_contract`
- `network_contract`
- `management_exposure`
- `artifact_acquisition_receipt`
- `renewed_review`
- `disqualifier_results`

Required nested keys are:

- `candidate.release`
- `candidate.source.{url,reference,digest}`
- `candidate.image.{reference,digest}`; `reference` must itself end in the same `@sha256:<64 lowercase hex>` digest
- `candidate.license.{spdx_id,entitlement_reference,status}`
- `candidate.provenance.{publisher,statement_reference,statement_digest,signature_status,sbom_reference,sbom_digest}`
- `candidate.supported_architectures`
- `candidate.component_topology.{components,connections}` with component `{name,role,artifact_digest}` and connection `{from,to,purpose}`
- `runtime_contract.hooks.inbound_initial_application.{timing,ordered_verbs,failure_behavior,synchronous_authority_response}`
- `runtime_contract.hooks.outbound_call.{timing,emits_listen_after_authority,synchronous_authority_response}`
- `runtime_contract.listen.ws_auth.{scheme,username_source,password_source}` plus `sample_rate_hz`, `encoding`, `channels`, and `direction`. `ws_auth` is the manifest spelling of the official Jambonz `listen.wsAuth` property.
- `runtime_contract.registration_secret_persistence.{classification,external_runtime_only,encrypted_ephemeral_mysql,destroy_with_process_and_disk}`
- each of `storage_contract.{mysql,influxdb,redis,logs,cdr,recordings}` with `{enabled,persistence,contains_registration_secret,encrypted_at_rest,raw_data_enabled,backup_enabled,replication_enabled,export_enabled,deletion_behavior}`
- `network_contract.local_rtp_pool.{protocol,port_start,port_end,bounded,host_sdp_exact_narrowing}`
- `management_exposure.{mode,public_admin,portal_enabled}`
- `artifact_acquisition_receipt.{receipt_reference,receipt_digest,acquired_by,acquired_at,expires_at,store_generation,authorized_readers_reference,signature_status,acquisition_access_closed}`
- `renewed_review.{architect,critic}`, each with `{identity,independent,decision,review_reference,review_digest,reviewed_at}`
- `disqualifier_results.{license_provenance,registration_secret_persistence,raw_logging,cdr_storage,recording,backup_replication_export,public_management,rtp_bounds,hook_semantics,ws_auth,media_codec,timer_behavior}`, each with `{result,evidence_reference,evidence_digest}`

Digests are lowercase `sha256:` values. Evidence locations are opaque `evidence:` references, not URLs, credentials, phone numbers, provider data, or secret-manager paths. Architecture and Critic decisions must be renewed after acquisition, approved, independent, content addressed, and made by different identities. The acquisition receipt must be unexpired at `--as-of`. Every disqualifier must have `result: "pass"` and content-addressed evidence; `pending`, unknown, or unresolved states fail. The evidence index binds the raw manifest digest, candidate image digest, receipt store generation, assertion kind/status, and exact bytes of every referenced evidence file.

The accepted registration-secret outcomes are only S1 (external runtime use with no persistence) or separately approved S2 (encrypted ephemeral MySQL, with no backup, replication, export, or query/raw logging, followed by process and disk destruction). Raw logs, CDR content, recordings, backups, public administration, unbounded RTP, unsupported hooks, missing official Basic `listen.wsAuth`, anything other than bidirectional mono 8 kHz L16, and unresolved license or timer behavior fail. Secret values and secret-, phone-, SIP-, SDP-, RTP-, or audio-looking payloads are prohibited even when placed in an otherwise textual field.

## Network closure and review

The acquisition receipt records the immutable store generation, authorized-reader evidence, signature result, acquisition time/expiry, and that acquisition access is closed. G0 must retain that closure: no registry lookup, package fetch, license call, candidate update, or alternate image is permitted. Supplier media evidence remains a separately signed, expiring G4 dependency; raw CIDRs, SIP/SDP/RTP captures, phone data, and audio do not belong in this manifest.

Any artifact, manifest, topology, persistence behavior, hook behavior, codec behavior, or digest change creates a different candidate. It must return to G-1/consensus and obtain renewed independent Architect and Critic review before a later G0 attempt.

## Facade image contract

`deploy/onnuri-jambonz-facade/Dockerfile` has exactly two required build-time inputs:

- `BASE_IMAGE_REPOSITORY`: the approved base-image repository name from the candidate/build manifest
- `BASE_IMAGE_DIGEST`: its `sha256:<64 lowercase hex>` digest

Neither has a default. The `FROM` reference is `${BASE_IMAGE_REPOSITORY}@${BASE_IMAGE_DIGEST}`, so an absent or invalid input fails before a floating image can be used. The approved base must already contain Python, the Recova application dependencies, and the injected ASGI runtime; this Dockerfile performs no package or network acquisition.

Runtime has exactly two entrypoint-control inputs:

- `FACADE_APP_FACTORY`, required to equal `api.services.telephony.providers.jambonz.facade.app:create_facade_app`
- `FACADE_ASGI_COMMAND_JSON`, a JSON argv array for the injected ASGI server/runtime containing exactly one `{app_factory}` placeholder

The entrypoint substitutes only that fixed provider-local factory and directly `exec`s argv without a shell. It defines no port, admin listener, endpoint, credential, certificate, key, username, or secret default. Concrete facade dependencies and all sensitive values are deployment-injected under their separately approved runtime contract; they must never be embedded in the image or command text. The image runs as numeric non-root UID/GID `65532`, suppresses bytecode writes, and requires no writable image path, making it compatible with a read-only root filesystem.
