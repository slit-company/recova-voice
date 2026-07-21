from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).parents[2]
MODULE_PATH = ROOT / "scripts" / "verify_phase_c_live_preflight.py"
SPEC = importlib.util.spec_from_file_location("phase_c_live_preflight", MODULE_PATH)
assert SPEC and SPEC.loader
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)
CREATOR_PATH = ROOT / "scripts" / "create_phase_c_live_preflight.py"
CREATOR_SPEC = importlib.util.spec_from_file_location("phase_c_live_preflight_creator", CREATOR_PATH)
assert CREATOR_SPEC and CREATOR_SPEC.loader
creator = importlib.util.module_from_spec(CREATOR_SPEC)
CREATOR_SPEC.loader.exec_module(creator)

NOW = datetime(2026, 7, 16, 12, 0, 0, tzinfo=timezone.utc)
H = "1" * 64
H2 = "2" * 64
H3 = "3" * 64
H4 = "4" * 64
CANDIDATE_MANIFEST_SHA256 = H2



def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def timestamp(delta: int) -> str:
    return (NOW + timedelta(seconds=delta)).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def authority(tmp_path, monkeypatch):
    private = {role: Ed25519PrivateKey.generate() for role in verifier.TRUSTED_KEYS}
    entries = []
    pinned = {}
    for role, key in private.items():
        raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        key_id = f"test-{role}-v1"
        fingerprint = sha(raw)
        pinned[role] = (key_id, fingerprint)
        entries.append({"algorithm": "Ed25519", "key_id": key_id, "public_key_base64url": base64.urlsafe_b64encode(raw).rstrip(b"=").decode(), "public_key_sha256": fingerprint, "role": role})
    keyset = {"keys": entries, "schema_version": "recova-phase-c-live-preflight-keyset.v1"}
    keyset_path = tmp_path / "keys.json"
    keyset_raw = canonical(keyset).encode()
    keyset_path.write_bytes(keyset_raw)
    monkeypatch.setattr(verifier, "KEYSET_PATH", keyset_path)
    monkeypatch.setattr(verifier, "TRUSTED_KEYSET_SHA256", sha(keyset_raw))
    monkeypatch.setattr(verifier, "TRUSTED_KEYS", pinned)
    return private


@pytest.fixture
def context():
    return {
        "schema_version": "recova-phase-c-live-context.v1", "project_id": "slit-497603", "region": "asia-northeast3",
        "run_id": "phase-c-test", "activation_nonce": "0123456789abcdef", "successor_review_payload_digest": f"sha256:{H}", "live_window_start_utc": timestamp(-20), "live_window_end_utc": timestamp(1200),
        "phase_b": {"manifest_sha256": H, "network_self_link": "https://www.googleapis.com/compute/v1/projects/slit-497603/global/networks/phase-b", "subnet_self_link": "https://www.googleapis.com/compute/v1/projects/slit-497603/regions/asia-northeast3/subnetworks/phase-b", "subnet_ipv4_cidr": "10.73.96.0/24", "private_ip_google_access": True, "ingress_deny_rule_name": "deny-in", "egress_deny_rule_name": "deny-out", "phase_b_source_sha256": H2, "backend_identity": "gcs://phase-c-state/state", "backend_generation": "1", "backend_serial": "0", "canonical_state_sha256": H3, "non_sensitive_outputs_sha256": H4, "prearm_canonical_inventory_sha256": H, "prearm_verification_receipt_sha256": H2},
        "supplier": {"signaling_ipv4_cidr": "203.0.113.8/32", "signaling_udp_port": "5060", "remote_ipv4_cidrs": ["203.0.113.8/32"], "remote_rtp_udp_port_min": "10000", "remote_rtp_udp_port_max": "10010", "remote_rtcp_udp_port_min": "10011", "remote_rtcp_udp_port_max": "10020", "max_concurrent_calls": "1", "calls_per_second": "1", "evidence_sha256": H, "endpoint_binding_canonical_sha256": H2, "endpoint_binding_verification_sha256": H3, "customer_external_ipv4": "203.0.113.10", "bound_signaling_ipv4_cidr": "203.0.113.8/32", "bound_signaling_remote_udp_port": "5060", "candidate_sip_listen_udp_port": "5090", "bound_media_ipv4_cidrs": ["203.0.113.8/32"], "bound_remote_rtp_udp_port_min": "10000", "bound_remote_rtp_udp_port_max": "10010", "bound_remote_rtcp_udp_port_min": "10011", "bound_remote_rtcp_udp_port_max": "10020"},
        "host_policy": {"policy_sha256": H, "tuple_binding_sha256": H2, "verification_receipt_sha256": H3, "candidate_sip_listen_udp_port": "5090", "candidate_local_rtp_udp_port_min": "40000", "candidate_local_rtp_udp_port_max": "40009", "candidate_local_rtcp_udp_port_min": "41000", "candidate_local_rtcp_udp_port_max": "41009", "issued_at_utc": timestamp(-30), "expires_at_utc": timestamp(1300)},
        "recova_destination": {"canonical_receipt_sha256": H, "verification_receipt_sha256": H2, "control_ipv4_cidrs": ["10.20.30.41/32", "10.20.30.42/32"], "media_ipv4_cidrs": ["10.20.30.43/32"], "f1_source_ipv4_cidrs": ["10.20.30.40/32"], "control_endpoint_sha256": H2, "media_endpoint_sha256": H3, "certificate_binding_sha256": H4, "f1_mtls_endpoint_path": "https://f1.recova.internal/dispatch", "f2_https_endpoint_path": "https://f2.recova.internal/callback", "f3_wss_endpoint_path": "wss://f3.recova.internal/media", "f4_https_endpoint_path": "https://f4.recova.internal/secrets", "f5_https_endpoint_path": "https://f5.recova.internal/logs", "f12_mtls_endpoint_path": "https://f12.recova.internal/authority"},
        "secrets": {
            "legacy": {purpose: f"projects/slit-497603/secrets/{secret_id}/versions/1" for purpose, secret_id in verifier.LEGACY_SECRET_IDS.items()},
        },
        "candidate_boot": {"image_self_link": "https://www.googleapis.com/compute/v1/projects/slit-497603/global/images/recova-jambonz-g009", "image_id": "1", "image_generation": "1", "source_sha256": H, "export_sha256": H, "derivative_sha256": H2, "runtime_image_digest": f"sha256:{H3}", "facade_image_digest": f"sha256:{H4}", "candidate_manifest_sha256": CANDIDATE_MANIFEST_SHA256, "candidate_receipt_sha256": H3, "candidate_receipt_signature_base64": "YWJj", "candidate_receipt_signer_key_id": "g009-test-signer", "candidate_receipt_verification_key_sha256": H4, "candidate_receipt_issued_at_utc": timestamp(-30), "candidate_receipt_expires_at_utc": timestamp(1300), "compose_sha256": H, "startup_sha256": H2},
        "bootstrap": {"g008_bootstrap_manifest_handle": "projects/slit-497603/secrets/g008-sealed-bootstrap-manifest/versions/22", "g008_bootstrap_manifest_binding_sha256": H, "review_payload_digest": f"sha256:{H}", "successor_review_payload_digest": f"sha256:{H}"},
        "execution": {
            "versions": {
                key: f"projects/slit-497603/secrets/{creator.verifier.G008_EXECUTION_SECRET_IDS[purpose] if hasattr(creator, 'verifier') else verifier.G008_EXECUTION_SECRET_IDS[purpose]}/versions/{index}"
                for index, (key, purpose) in enumerate((creator.verifier.BOOTSTRAP_EXECUTION_PURPOSES if hasattr(creator, 'verifier') else verifier.BOOTSTRAP_EXECUTION_PURPOSES).items(), 1)
            },
            "content_sha256": {key: sha(f"execution-{key}".encode()) for key in (creator.verifier.BOOTSTRAP_EXECUTION_KEYS if hasattr(creator, 'verifier') else verifier.BOOTSTRAP_EXECUTION_KEYS)},
            "review_payload_digest": f"sha256:{H}",
            "candidate_manifest_sha256": CANDIDATE_MANIFEST_SHA256,
            "runtime_image_digest": f"sha256:{H3}",
            "candidate_receipt_sha256": H3,
        },
        "provider": {"provider_id_digest": H, "account_id_digest": H2, "currency": "KRW", "starting_balance": "50000", "evidence_sha256": H3},
        "derivative": {"schema_version": "recova-g008-derivative-v3", "backend_image_digest": f"sha256:{H}", "backend_receipt_sha256": H, "postgres_image_digest": f"sha256:{H2}", "postgres_receipt_sha256": H2, "redis_image_digest": f"sha256:{H3}", "redis_receipt_sha256": H3, "ingress_image_digest": f"sha256:{H4}", "ingress_receipt_sha256": H4, "derivative_manifest_sha256": H, "candidate_manifest_sha256": CANDIDATE_MANIFEST_SHA256},
        "f12": {"origin_https_endpoint_path": "https://f12.internal/origin", "readiness_path": "/ready", "media_wss_endpoint_path": "wss://f12.internal/media", "endpoint_san": "f12.internal", "tls_certificate_sha256": H, "mtls_client_certificate_sha256": H2, "mtls_ca_certificate_sha256": H3, "dispatch_algorithm": "ES256", "dispatch_key_id": "dispatch-key", "dispatch_public_key_sha256": H4, "media_algorithm": "ES256", "media_key_id": "media-key", "media_public_key_sha256": H},
        "authority": {"tenant_digest": H, "account_digest": H2, "envelope_digest": H3, "candidate_digest": sha(canonical({"review_payload_digest": f"sha256:{H}", "candidate_manifest_sha256": CANDIDATE_MANIFEST_SHA256, "runtime_image_digest": f"sha256:{H3}", "candidate_receipt_sha256": H3}).encode())},
        "cost": {"currency": "KRW", "cost_ceiling_krw": "50000", "estimated_total_krw": "12000", "observed_total_krw": "1000", "recorded_at_utc": timestamp(-30), "expires_at_utc": timestamp(1200), "evidence_sha256": H, "signer_key_id": "cost-test-signer"},
        "iam_provisioning": {
            "schema_version": "recova-g008-external-iam-provisioning-receipt-v1",
            "bootstrap_manifest_binding_sha256": H,
            "runtime_service_account_email": "phase-c-runtime@slit-497603.iam.gserviceaccount.com",
            "transaction_service_account_email": "phase-c-transaction@slit-497603.iam.gserviceaccount.com",
            "live_window_start_utc": timestamp(-20),
            "live_window_end_utc": timestamp(1200),
            "destruction_deadline_utc": timestamp(3600),
            "candidate_manifest_sha256": H2,
            "run_id": "phase-c-test",
            "activation_nonce_sha256": sha(b"0123456789abcdef"),
            "activation_receipt_sha256": H3,
            "provisioning_outcome": "EXACT_BOUNDED_POLICY_APPLIED_NO_BROADER_BINDINGS",
            "exact_policy_result_sha256": H4,
            "issuer_key_id": verifier.TRUSTED_KEYS["iam-provisioning"][0],
            "issuer_key_fingerprint_sha256": verifier.TRUSTED_KEYS["iam-provisioning"][1],
            "issued_at_utc": timestamp(-30),
            "expires_at_utc": timestamp(1200),
        },
    }


def signed(payload, role, keys):
    signature = keys[role].sign(canonical(payload).encode())
    key_id = verifier.TRUSTED_KEYS[role][0]
    return {"payload": payload, "signature": {"algorithm": "Ed25519", "key_id": key_id, "value": base64.urlsafe_b64encode(signature).rstrip(b"=").decode()}}


def make_bundle(context, keys, *, observed=-5, issued=-4, receipt_expiry=1200, aggregate_expiry=1200):
    common = {"project_id": context["project_id"], "region": context["region"], "run_id_digest": sha(context["run_id"].encode()), "activation_nonce_digest": sha(context["activation_nonce"].encode()), "phase_b_manifest_sha256": context["phase_b"]["manifest_sha256"], "candidate_manifest_sha256": context["derivative"]["candidate_manifest_sha256"], "network_self_link_sha256": sha(context["phase_b"]["network_self_link"].encode()), "live_window_start_utc": context["live_window_start_utc"], "live_window_end_utc": context["live_window_end_utc"]}
    receipts = {}
    digests = {}
    for name in verifier.source_roles(context):
        payload = {"contract_version": "recova-phase-c-live-prerequisite.v1", "kind": name, "claims_sha256": sha(canonical(context[name]).encode()), **common, "observed_at_utc": timestamp(observed), "expires_at_utc": timestamp(receipt_expiry), "signer_key_id": verifier.TRUSTED_KEYS[verifier.ROLE_FOR_RECEIPT[name]][0]}
        receipts[name] = signed(payload, verifier.ROLE_FOR_RECEIPT[name], keys)
        digests[name] = sha(canonical(payload).encode())
    aggregate = {"contract_version": "recova-phase-c-live-preflight.v1", "kind": "phase_c_live_preflight", **common, "authorized_context_sha256": sha(canonical(context).encode()), "receipt_payload_sha256": {key: digests[key] for key in sorted(digests)}, "issued_at_utc": timestamp(issued), "expires_at_utc": timestamp(aggregate_expiry), "signer_key_id": verifier.TRUSTED_KEYS["phase-c-preflight"][0]}
    return {"schema_version": "recova-phase-c-live-preflight-bundle.v1", "receipts": receipts, "aggregate": signed(aggregate, "phase-c-preflight", keys)}


def write_bundle(tmp_path, bundle, raw=None):
    path = tmp_path / "bundle.json"
    path.write_bytes(canonical(bundle).encode() if raw is None else raw)
    return path


def terraform_block(source: str, resource_type: str, name: str) -> str:
    marker = f'resource "{resource_type}" "{name}" {{'
    start = source.index(marker)
    cursor = start + len(marker)
    depth = 1
    while depth:
        if source[cursor] == "{":
            depth += 1
        elif source[cursor] == "}":
            depth -= 1
        cursor += 1
    return source[start:cursor]


def verify(tmp_path, bundle, context, **kwargs):
    path = write_bundle(tmp_path, bundle)
    return verifier.verify_bundle(path, canonical(context), verification_stage=kwargs.pop("stage", "plan"), now=NOW, **kwargs)


def test_valid_bundle_verifies_all_eight_source_roles(tmp_path, authority, context):
    bundle = make_bundle(context, authority)
    result = verify(tmp_path, bundle, context)
    assert result["verified"] == "true"
    assert result["trusted_keyset_sha256"] == verifier.TRUSTED_KEYSET_SHA256
    assert set(result) == {"verified", "schema_version", "bundle_sha256", "aggregate_payload_sha256", "iam_provisioning_payload_sha256", "authorized_context_sha256", "run_id_digest", "activation_nonce_digest", "valid_from_utc", "expires_at_utc", "effective_cutoff_utc", "trusted_keyset_sha256"}
    iam_payload = bundle["receipts"]["iam_provisioning"]["payload"]
    assert result["iam_provisioning_payload_sha256"] == sha(canonical(iam_payload).encode())


def test_null_iam_provisioning_pre_live_omits_role_and_returns_empty_digest(
    tmp_path, authority, context
):
    pre_live = copy.deepcopy(context)
    pre_live["iam_provisioning"] = None
    bundle = make_bundle(pre_live, authority)
    assert "iam_provisioning" not in bundle["receipts"]
    result = verify(tmp_path, bundle, pre_live)
    assert result["verified"] == "true"
    assert result["iam_provisioning_payload_sha256"] == ""


def test_live_iam_claims_require_receipt_role(tmp_path, authority, context):
    bundle = make_bundle(context, authority)
    del bundle["receipts"]["iam_provisioning"]
    with pytest.raises(verifier.VerificationError, match="receipts_schema"):
        verify(tmp_path, bundle, context)


def test_execution_version_digest_and_candidate_substitution_fail_closed(tmp_path, authority, context):
    for mutation, error in (
        ("version", "context_execution_version"),
        ("digest", "context_execution_digest"),
        ("candidate", "context_execution_candidate"),
        ("authority", "context_authority_candidate"),
    ):
        changed = copy.deepcopy(context)
        if mutation == "version":
            changed["execution"]["versions"]["request"] = changed["execution"]["versions"]["target"]
        elif mutation == "digest":
            changed["execution"]["content_sha256"]["request"] = "not-a-digest"
        elif mutation == "candidate":
            changed["execution"]["candidate_receipt_sha256"] = H4
        else:
            changed["authority"]["candidate_digest"] = H4
        with pytest.raises(verifier.VerificationError, match=f"^{error}$"):
            verify(tmp_path, make_bundle(changed, authority), changed)

def test_signed_aggregate_binds_all_seven_execution_references_and_digests(
    tmp_path, authority, context
):
    bundle = make_bundle(context, authority)
    execution = context["execution"]

    assert set(execution["versions"]) == set(verifier.BOOTSTRAP_EXECUTION_KEYS)
    assert set(execution["content_sha256"]) == set(verifier.BOOTSTRAP_EXECUTION_KEYS)
    assert len(execution["versions"]) == len(execution["content_sha256"]) == 7

    changed = copy.deepcopy(context)
    changed["execution"]["versions"]["request"] = (
        "projects/slit-497603/secrets/g008-execution-request/versions/99"
    )
    with pytest.raises(verifier.VerificationError, match="^aggregate_digest_binding$"):
        verify(tmp_path, bundle, changed)

    changed = copy.deepcopy(context)
    changed["execution"]["content_sha256"]["request"] = H4
    with pytest.raises(verifier.VerificationError, match="^aggregate_digest_binding$"):
        verify(tmp_path, bundle, changed)

def test_null_iam_provisioning_pre_live_rejects_extra_role(
    tmp_path, authority, context
):
    live_bundle = make_bundle(context, authority)
    pre_live = copy.deepcopy(context)
    pre_live["iam_provisioning"] = None
    pre_live_bundle = make_bundle(pre_live, authority)
    pre_live_bundle["receipts"]["iam_provisioning"] = live_bundle["receipts"]["iam_provisioning"]
    with pytest.raises(verifier.VerificationError, match="receipts_schema"):
        verify(tmp_path, pre_live_bundle, pre_live)


def route_evidence_source(tmp_path) -> Path:
    source = {
        "schema_version": "recova-onnuri-route-evidence-bundle-v1",
        "numeric_version_resource_name": "projects/slit-497603/secrets/g008-route-evidence-bundle/versions/1",
        "organization_id": 7,
        "request_digest": "b" * 64,
        "candidate_digest": "c" * 64,
        "route_profile_digest": "d" * 64,
        "opaque_handle": "opaque-route-evidence-handle",
        "approved_root_locator_digest": "e" * 64,
        "inventory_locator_digest": "f" * 64,
        "inventory_version": "inventory-v1",
        "adapter_path": "adapter", "adapter_sha256": "a" * 64,
        "adapter_execution_mode": "fixed-executable-v1",
        "adapter_stdin_schema": "recova-onnuri-restricted-inventory-adapter-invocation-v1",
        "adapter_stdin_exactly_one_lf": True,
        "adapter_stdout_schema": "recova-onnuri-restricted-inventory-adapter-v1",
        "adapter_stdout_max_bytes": 1024, "adapter_stderr_max_bytes": 1024, "adapter_timeout_ms": 1000,
        **{f"{name}_sha256": "a" * 64 for name in verifier.ROUTE_EVIDENCE_FILE_NAMES},
    }
    path = tmp_path / "route-evidence-source.json"
    path.write_bytes(canonical(source).encode())
    return path

def test_producer_creates_exact_canonical_bootstrap_manifest(tmp_path):
    versions = {
        purpose: f"projects/slit-497603/secrets/{secret_id}/versions/{index}"
        for index, (purpose, secret_id) in enumerate(verifier.G008_SECRET_IDS.items(), 1)
    }
    versions_path = tmp_path / "versions.json"
    versions_path.write_bytes(canonical(versions).encode())
    manifest_path = tmp_path / "manifest.json"
    binding = creator.create_bootstrap_manifest(
        versions_path,
        "g008-transaction-authority@slit-497603.iam.gserviceaccount.com",
        manifest_path,
        route_evidence_source(tmp_path),
        sha(route_evidence_source(tmp_path).read_bytes() + b"\n"),
    )

    raw = manifest_path.read_bytes()
    assert raw == verifier._canonical_bootstrap_manifest(json.loads(raw))
    manifest = verifier.validate_bootstrap_manifest(manifest_path, binding, versions)


    assert set(manifest) == set(verifier.BOOTSTRAP_MANIFEST_KEYS)
    assert manifest["route_evidence_bundle"] == {
        "numeric_version_resource_name": "projects/slit-497603/secrets/g008-route-evidence-bundle/versions/1",
        "content_sha256": sha(route_evidence_source(tmp_path).read_bytes() + b"\n"),
        "schema_version": "recova-onnuri-route-evidence-bundle-v1",
        "organization_id": 7,
        "request_digest": "b" * 64,
        "candidate_digest": "c" * 64,
        "route_profile_digest": "d" * 64,
        "opaque_handle_digest": sha(b"opaque-route-evidence-handle"),
    }
    assert "content_sha256" not in route_evidence_source(tmp_path).read_text()
    assert len(manifest["secret_version_mounts"]) == 29
    assert len(manifest["execution_versions"]) == 7
    assert len({
        mount["version_resource_name"]
        for mount in manifest["secret_version_mounts"].values()
    } | set(manifest["execution_versions"].values())) == 36
    assert binding == sha(canonical({
        key: value for key, value in manifest.items() if key != "binding_sha256"
    }).encode())


@pytest.mark.parametrize("mutation", ["purpose", "alias", "latest", "binding", "missing_lf", "extra_lf", "leading_whitespace", "schema_substitution"])


def test_bootstrap_manifest_inventory_mutations_fail_closed(tmp_path, mutation):
    versions = {
        purpose: f"projects/slit-497603/secrets/{secret_id}/versions/{index}"
        for index, (purpose, secret_id) in enumerate(verifier.G008_SECRET_IDS.items(), 1)
    }
    versions_path = tmp_path / "versions.json"
    versions_path.write_bytes(canonical(versions).encode())
    manifest_path = tmp_path / "manifest.json"
    binding = creator.create_bootstrap_manifest(
        versions_path,
        "g008-transaction-authority@slit-497603.iam.gserviceaccount.com",
        manifest_path,
        route_evidence_source(tmp_path),
        sha(route_evidence_source(tmp_path).read_bytes() + b"\n"),
    )
    manifest = json.loads(manifest_path.read_bytes())
    if mutation == "purpose":
        del manifest["execution_versions"]["target"]
    elif mutation == "alias":
        manifest["execution_versions"]["target"] = manifest["execution_versions"]["request"]
    elif mutation == "latest":
        manifest["execution_versions"]["target"] = manifest["execution_versions"]["target"].rsplit("/", 1)[0] + "/latest"
    elif mutation == "binding":
        manifest["binding_sha256"] = H2
    elif mutation == "missing_lf":
        manifest_path.write_bytes(canonical(manifest).encode())
        with pytest.raises(verifier.VerificationError, match="bootstrap_manifest_noncanonical"):
            verifier.validate_bootstrap_manifest(manifest_path, binding, versions)
        return
    elif mutation == "extra_lf":
        manifest_path.write_bytes(canonical(manifest).encode() + b"\n\n")
        with pytest.raises(verifier.VerificationError, match="bootstrap_manifest_noncanonical"):
            verifier.validate_bootstrap_manifest(manifest_path, binding, versions)
        return
    elif mutation == "leading_whitespace":
        manifest_path.write_bytes(b" " + canonical(manifest).encode() + b"\n")
        with pytest.raises(verifier.VerificationError, match="bootstrap_manifest_noncanonical"):
            verifier.validate_bootstrap_manifest(manifest_path, binding, versions)
        return
    elif mutation == "schema_substitution":
        manifest["schema_version"] = "recova-g008-sealed-bootstrap-manifest-v2"
    else:
        manifest_path.write_bytes(canonical(manifest).encode() + b"\n")
        with pytest.raises(verifier.VerificationError, match="bootstrap_manifest_noncanonical"):
            verifier.validate_bootstrap_manifest(manifest_path, binding, versions)
        return


    if mutation != "binding":
        manifest["binding_sha256"] = sha(canonical({
            key: value for key, value in manifest.items() if key != "binding_sha256"
        }).encode())
    manifest_path.write_bytes(canonical(manifest).encode() + b"\n")


    with pytest.raises(verifier.VerificationError, match="bootstrap_manifest_"):
        verifier.validate_bootstrap_manifest(manifest_path, manifest["binding_sha256"], versions)


@pytest.mark.parametrize("mutation", ["missing", "extra", "mismatched_mount", "mismatched_execution"])
def test_bootstrap_manifest_complete_compose_inventory_fails_closed(tmp_path, mutation):
    versions = {
        purpose: f"projects/slit-497603/secrets/{secret_id}/versions/{index}"
        for index, (purpose, secret_id) in enumerate(verifier.G008_SECRET_IDS.items(), 1)
    }
    versions_path = tmp_path / "versions.json"
    versions_path.write_bytes(canonical(versions).encode())
    manifest_path = tmp_path / "manifest.json"
    binding = creator.create_bootstrap_manifest(
        versions_path,
        "g008-transaction-authority@slit-497603.iam.gserviceaccount.com",
        manifest_path,
        route_evidence_source(tmp_path),
        sha(route_evidence_source(tmp_path).read_bytes() + b"\n"),
    )
    manifest = json.loads(manifest_path.read_bytes())
    if mutation == "missing":
        del manifest["secret_version_mounts"]["stock_api_token"]
    elif mutation == "extra":
        manifest["secret_version_mounts"]["ambient_secret"] = {
            "version_resource_name": "projects/slit-497603/secrets/ambient-secret/versions/1",
            "target": "/run/secrets/ambient-secret",
            "consumer": "backend",
            "read_only": True,
        }
    elif mutation == "mismatched_mount":
        manifest["secret_version_mounts"]["stock_api_token"]["target"] = "/run/secrets/ambient-stock-token"
    else:
        manifest["execution_versions"]["operator_credential"] = manifest["execution_versions"]["execution_nonce"]
    manifest["binding_sha256"] = sha(canonical({
        key: value for key, value in manifest.items() if key != "binding_sha256"
    }).encode())
    manifest_path.write_bytes(canonical(manifest).encode())

    with pytest.raises(verifier.VerificationError, match="bootstrap_manifest_"):
        verifier.validate_bootstrap_manifest(manifest_path, manifest["binding_sha256"], versions)


def test_bootstrap_manifest_bytes_are_identical_in_creator_terraform_and_startup(tmp_path) -> None:
    workload = (ROOT / "infra/onnuri-seoul-staging-phase-c-smoke/workload.tf").read_text()
    startup = (ROOT / "infra/onnuri-seoul-staging-phase-c-smoke/startup-g008.sh").read_text()
    schema = '{"schema_version", "binding_sha256", "transaction_authority_service_account", "secret_version_mounts", "execution_versions", "route_evidence_bundle"}'
    parser = startup.split("# BEGIN G008_BOOTSTRAP_MANIFEST_PARSER\n", 1)[1].split(
        "# END G008_BOOTSTRAP_MANIFEST_PARSER", 1
    )[0]
    versions = {
        purpose: f"projects/slit-497603/secrets/{secret_id}/versions/{index}"
        for index, (purpose, secret_id) in enumerate(verifier.G008_SECRET_IDS.items(), 1)
    }
    versions_path = tmp_path / "versions.json"
    versions_path.write_bytes(canonical(versions).encode())

    manifest_path = tmp_path / "manifest.json"
    binding = creator.create_bootstrap_manifest(
        versions_path,
        "g008-transaction-authority@slit-497603.iam.gserviceaccount.com",
        manifest_path,
        route_evidence_source(tmp_path),
        sha(route_evidence_source(tmp_path).read_bytes() + b"\n"),
    )
    raw = manifest_path.read_bytes()
    namespace = {"json": json, "re": __import__("re"), "REFERENCE": __import__("re").compile(r"projects/slit-497603/secrets/[A-Za-z][A-Za-z0-9_-]{0,254}/versions/[1-9][0-9]*\Z")}
    exec(parser, namespace)

    assert raw == canonical(json.loads(raw)).encode() + b"\n"
    assert namespace["parse_bootstrap_manifest"](raw, binding)["binding_sha256"] == binding
    for variant in (raw[:-1], raw + b"\n", b" " + raw, raw.replace(b'"binding_sha256"', b'"binding_sha256_"', 1), raw.replace(b'v1"', b'v2"', 1)):
        with pytest.raises(SystemExit):
            namespace["parse_bootstrap_manifest"](variant, binding)

    assert 'schema_version                        = "recova-g008-sealed-bootstrap-manifest-v1"' in workload
    assert "transaction_authority_service_account = google_service_account.transaction_authority.email" in workload
    assert "secret_version_mounts                 = local.g008_secret_mounts" in workload
    assert "execution_versions                    = { for key, reference in local.g008_execution_secret_versions : key => reference if key != \"manifest\" }" in workload
    assert schema in startup
    assert '"compose_env"' not in startup
    assert '"execution_sha256"' not in startup


def test_terraform_and_startup_require_all_twenty_nine_runtime_secret_files() -> None:
    secrets = (ROOT / "infra/onnuri-seoul-staging-phase-c-smoke/secrets.tf").read_text()
    startup = (ROOT / "infra/onnuri-seoul-staging-phase-c-smoke/startup-g008.sh").read_text()
    purposes = {
        "jambones_mysql_password",
        "jwt_secret",
        "encryption_secret",
        "drachtio_feature_secret",
        "drachtio_sip_secret",
        "freeswitch_esl_password",
    }

    assert "length(local.g008_secret_mounts) == 29" in secrets
    assert "length(local.g008_all_secret_keys) == 36" in secrets
    for purpose in purposes:
        assert f"{purpose}" in secrets
        assert f'"{purpose}"' in startup


def test_bootstrap_manifest_rejects_ambient_and_secret_bearing_compose_inputs(tmp_path) -> None:
    versions = {
        purpose: f"projects/slit-497603/secrets/{secret_id}/versions/{index}"
        for index, (purpose, secret_id) in enumerate(verifier.G008_SECRET_IDS.items(), 1)
    }
    versions_path = tmp_path / "versions.json"
    versions_path.write_bytes(canonical(versions).encode())

    manifest_path = tmp_path / "manifest.json"
    binding = creator.create_bootstrap_manifest(
        versions_path,
        "g008-transaction-authority@slit-497603.iam.gserviceaccount.com",
        manifest_path,
        route_evidence_source(tmp_path),
        sha(route_evidence_source(tmp_path).read_bytes() + b"\n"),
    )
    manifest = json.loads(manifest_path.read_bytes())
    manifest["compose_env"] = {"G009_JWT_SECRET": "ambient-secret"}
    manifest["binding_sha256"] = sha(canonical({
        key: value for key, value in manifest.items() if key != "binding_sha256"
    }).encode())
    manifest_path.write_bytes(canonical(manifest).encode() + b"\n")


    with pytest.raises(verifier.VerificationError, match="bootstrap_manifest_schema"):
        verifier.validate_bootstrap_manifest(manifest_path, manifest["binding_sha256"], versions)

    manifest_path.write_bytes(canonical(manifest).encode() + b"\n\n")
    with pytest.raises(verifier.VerificationError, match="bootstrap_manifest_noncanonical"):
        verifier.validate_bootstrap_manifest(manifest_path, manifest["binding_sha256"], versions)


def test_candidate_boot_missing_or_substituted_identity_fails_closed(tmp_path, authority, context):
    changed = copy.deepcopy(context)
    changed["candidate_boot"]["runtime_image_digest"] = changed["candidate_boot"]["facade_image_digest"]
    with pytest.raises(verifier.VerificationError, match="context_candidate_boot_identity"):
        verify(tmp_path, make_bundle(context, authority), changed)


def test_candidate_boot_candidate_manifest_must_match_derivative(tmp_path, authority, context):
    changed = copy.deepcopy(context)
    changed["candidate_boot"]["candidate_manifest_sha256"] = H3
    with pytest.raises(verifier.VerificationError, match="context_candidate_boot_binding"):
        verify(tmp_path, make_bundle(context, authority), changed)

def test_production_keyset_and_all_pins_are_exact():
    path = ROOT / "infra/onnuri-seoul-staging-phase-c-smoke/trusted_keys/phase_c_live_preflight_v1.json"
    raw = path.read_bytes()
    assert sha(raw) == "00645f3af8230c742951c12f17a713afde209de12182cd6e3722ac59445507aa"
    keyset = json.loads(raw)
    assert len(keyset["keys"]) == 8
    file_pins = {(item["role"], item["key_id"], item["public_key_sha256"]) for item in keyset["keys"]}
    expected_file_pins = {
        (role, key_id, fingerprint)
        for role, (key_id, fingerprint) in verifier.TRUSTED_KEYS.items()
        if role != "iam-provisioning"
    }
    assert file_pins == expected_file_pins
    iam_public = base64.urlsafe_b64decode(verifier.IAM_PROVISIONING_PUBLIC_KEY_BASE64URL + "=")
    assert sha(iam_public) == verifier.TRUSTED_KEYS["iam-provisioning"][1]
    assert iam_public not in {
        base64.urlsafe_b64decode(item["public_key_base64url"] + "=")
        for item in keyset["keys"]
    }


@pytest.mark.parametrize("role", [*verifier.SOURCE_ROLES, "aggregate"])
def test_each_forged_signature_fails(tmp_path, authority, context, role):
    bundle = make_bundle(context, authority)
    target = bundle["aggregate"] if role == "aggregate" else bundle["receipts"][role]
    value = target["signature"]["value"]
    target["signature"]["value"] = ("B" if value.startswith("A") else "A") + value[1:]
    with pytest.raises(verifier.VerificationError, match="signature_invalid"):
        verify(tmp_path, bundle, context)


def test_iam_provisioning_receipt_signed_by_wrong_role_key_fails(tmp_path, authority, context):
    bundle = make_bundle(context, authority)
    payload = bundle["receipts"]["iam_provisioning"]["payload"]
    bundle["receipts"]["iam_provisioning"] = signed(payload, "authority", authority)
    with pytest.raises(verifier.VerificationError, match="role_key_binding"):
        verify(tmp_path, bundle, context)


@pytest.mark.parametrize("mutation", ["missing", "extra"])
def test_iam_provisioning_claim_schema_is_exact(tmp_path, authority, context, mutation):
    changed = copy.deepcopy(context)
    if mutation == "missing":
        del changed["iam_provisioning"]["exact_policy_result_sha256"]
    else:
        changed["iam_provisioning"]["secret_version_inventory"] = {"forbidden": "redacted"}
    with pytest.raises(verifier.VerificationError, match="context_iam_provisioning_schema"):
        verify(tmp_path, make_bundle(context, authority), changed)


def test_iam_provisioning_canonical_claim_mutation_breaks_real_signature_binding(tmp_path, authority, context):
    bundle = make_bundle(context, authority)
    changed = copy.deepcopy(context)
    changed["iam_provisioning"]["exact_policy_result_sha256"] = "5" * 64
    with pytest.raises(verifier.VerificationError, match="receipt_claims_binding|aggregate_digest_binding"):
        verify(tmp_path, bundle, changed)


def test_arbitrary_distinct_receipt_hashes_cannot_replace_verified_digests(tmp_path, authority, context):
    bundle = make_bundle(context, authority)
    result = verify(tmp_path, bundle, context)
    claims_digest = sha(canonical(context["iam_provisioning"]).encode())
    arbitrary_canonical = "5" * 64
    arbitrary_verification = "6" * 64
    assert arbitrary_canonical != claims_digest
    assert arbitrary_verification != result["iam_provisioning_payload_sha256"]


def test_iam_provisioning_payload_digest_mismatch_is_detectable_from_real_verifier(tmp_path, authority, context):
    result = verify(tmp_path, make_bundle(context, authority), context)
    terraform_receipt_verification_digest = "7" * 64
    assert terraform_receipt_verification_digest != result["iam_provisioning_payload_sha256"]

@pytest.mark.parametrize("mutation", ["missing_receipt", "extra_receipt", "missing_field", "extra_field"])
def test_missing_or_unknown_schema_fields_fail(tmp_path, authority, context, mutation):
    bundle = make_bundle(context, authority)
    if mutation == "missing_receipt": del bundle["receipts"]["cost"]
    elif mutation == "extra_receipt": bundle["receipts"]["other"] = bundle["receipts"]["cost"]
    elif mutation == "missing_field": del bundle["receipts"]["cost"]["payload"]["claims_sha256"]
    else: bundle["aggregate"]["signature"]["extra"] = "forbidden"
    with pytest.raises(verifier.VerificationError): verify(tmp_path, bundle, context)


def test_duplicate_and_noncanonical_json_fail(tmp_path, authority, context):
    bundle = make_bundle(context, authority)
    raw = canonical(bundle).encode()
    duplicate = raw.replace(b'{"aggregate":', b'{"schema_version":"duplicate","aggregate":', 1)
    path = write_bundle(tmp_path, bundle, duplicate)
    with pytest.raises(verifier.VerificationError, match="duplicate_json_key"):
        verifier.verify_bundle(path, canonical(context), now=NOW)
    path.write_bytes(raw + b"\n")
    with pytest.raises(verifier.VerificationError, match="bundle_noncanonical"):
        verifier.verify_bundle(path, canonical(context), now=NOW)


@pytest.mark.parametrize("observed,issued,error", [(-61, -4, "receipt_freshness"), (1, -4, "receipt_freshness"), (-5, -61, "aggregate_freshness"), (-5, 1, "aggregate_freshness")])
def test_stale_and_future_observations_fail(tmp_path, authority, context, observed, issued, error):
    with pytest.raises(verifier.VerificationError, match=error):
        verify(tmp_path, make_bundle(context, authority, observed=observed, issued=issued), context)


def test_overlong_aggregate_and_source_expiries_fail(tmp_path, authority, context):
    with pytest.raises(verifier.VerificationError, match="aggregate_freshness"):
        verify(tmp_path, make_bundle(context, authority, aggregate_expiry=1201), context)
    with pytest.raises(verifier.VerificationError, match="receipt_freshness"):
        verify(tmp_path, make_bundle(context, authority, receipt_expiry=1201), context)


def test_apply_rejects_bundle_swap(tmp_path, authority, context):
    bundle = make_bundle(context, authority)
    path = write_bundle(tmp_path, bundle)
    planned = verifier.verify_bundle(path, canonical(context), now=NOW)
    value = bundle["receipts"]["cost"]["signature"]["value"]
    bundle["receipts"]["cost"]["signature"]["value"] = ("B" if value.startswith("A") else "A") + value[1:]
    path.write_bytes(canonical(bundle).encode())
    with pytest.raises(verifier.VerificationError, match="bundle_digest_mismatch"):
        verifier.verify_bundle(path, canonical(context), planned["bundle_sha256"], "apply", now=NOW)


@pytest.mark.parametrize(
    ("window_start", "window_end", "apply_delta"),
    [
        (10, 40, 0),
        (-20, 20, 21),
        (-20, 30, 30),
    ],
)
def test_apply_wall_clock_must_be_inside_signed_window(
    tmp_path,
    authority,
    context,
    window_start,
    window_end,
    apply_delta,
):
    context["live_window_start_utc"] = timestamp(window_start)
    context["live_window_end_utc"] = timestamp(window_end)
    context["cost"]["expires_at_utc"] = timestamp(window_end)
    context["iam_provisioning"]["live_window_start_utc"] = timestamp(window_start)
    context["iam_provisioning"]["live_window_end_utc"] = timestamp(window_end)
    bundle = make_bundle(
        context,
        authority,
        receipt_expiry=window_end,
        aggregate_expiry=window_end,
    )
    path = write_bundle(tmp_path, bundle)
    planned = verifier.verify_bundle(path, canonical(context), now=NOW)

    with pytest.raises(verifier.VerificationError, match="live_window_inactive"):
        verifier.verify_bundle(
            path,
            canonical(context),
            planned["bundle_sha256"],
            "apply",
            now=NOW + timedelta(seconds=apply_delta),
        )


@pytest.mark.parametrize(
    ("remaining_seconds", "accepted"),
    [
        (899, False),
        (900, True),
        (901, True),
    ],
)
def test_apply_requires_full_minimum_remaining_runway(
    tmp_path,
    authority,
    context,
    remaining_seconds,
    accepted,
):
    context["cost"]["expires_at_utc"] = timestamp(remaining_seconds)
    bundle = make_bundle(context, authority)
    path = write_bundle(tmp_path, bundle)
    planned = verifier.verify_bundle(path, canonical(context), now=NOW)

    if not accepted:
        with pytest.raises(
            verifier.VerificationError,
            match="live_window_runway_insufficient",
        ):
            verifier.verify_bundle(
                path,
                canonical(context),
                planned["bundle_sha256"],
                "apply",
                now=NOW,
            )
        return

    result = verifier.verify_bundle(
        path,
        canonical(context),
        planned["bundle_sha256"],
        "apply",
        now=NOW,
    )
    assert result["verified"] == "true"
    assert result["effective_cutoff_utc"] == timestamp(remaining_seconds)


def test_live_mutations_wait_for_active_immutable_cutoff_controls():
    terraform_root = ROOT / "infra" / "onnuri-seoul-staging-phase-c-smoke"
    firewalls = (terraform_root / "firewalls.tf").read_text()
    iam = (terraform_root / "iam.tf").read_text()
    workload = (terraform_root / "workload.tf").read_text()
    containment = (terraform_root / "containment.tf").read_text()
    locals_source = (terraform_root / "locals.tf").read_text()
    crypto_gate = (terraform_root / "crypto_gate.tf").read_text()
    required_dependencies = (
        "terraform_data.phase_c_live_apply_gate",
        "google_cloud_scheduler_job.watchdog_disable_traffic",
        "google_cloud_scheduler_job.watchdog_stop_candidate",
    )

    for name in (
        "recova_f1_https_ingress",
        "sip_ingress",
        "sip_egress",
        "rtp_ingress",
        "rtp_egress",
        "facade_f2_f12_egress",
        "facade_wss_egress",
    ):
        block = terraform_block(firewalls, "google_compute_firewall", name)
        assert all(dependency in block for dependency in required_dependencies)

    block = terraform_block(
        iam,
        "google_secret_manager_secret_iam_member",
        "runtime",
    )
    assert all(dependency in block for dependency in required_dependencies)
    assert 'resource "google_secret_manager_secret_iam_member" "g008_' not in iam

    candidate = terraform_block(workload, "google_compute_instance", "candidate")
    assert all(dependency in candidate for dependency in required_dependencies)

    disable = terraform_block(
        containment,
        "google_cloud_scheduler_job",
        "watchdog_disable_traffic",
    )
    stop = terraform_block(
        containment,
        "google_cloud_scheduler_job",
        "watchdog_stop_candidate",
    )
    assert "paused           = false" in disable
    assert "paused           = false" in stop
    assert "for_each = local.network_path_armed" in disable
    assert "count = local.network_path_armed ? 1 : 0" in stop
    assert "google_project_iam_member.containment" in disable
    assert "google_project_iam_member.containment" in stop
    assert "local.immutable_names.instance" in stop
    assert "google_compute_firewall." not in disable
    assert "google_compute_instance." not in stop
    assert 'cost_evidence_watchdog_valid_until_utc = var.cost_evidence != null ? var.cost_evidence.expires_at_utc' in locals_source
    assert 'timeadd(var.cost_evidence.recorded_at_utc, "5m")' not in locals_source
    assert "local.cost_evidence_watchdog_valid_until_utc" in locals_source
    assert "result.effective_cutoff_utc, local.watchdog_cutoff_utc" in crypto_gate
    assert "cutoff_required = local.control_phase_ready || local.bounded_live_ready" in locals_source
    assert "local.disabled_zero_traffic_ready" in locals_source
    assert "!local.cutoff_required || timecmp" in crypto_gate

def test_apply_accepts_fresh_bundle_inside_one_hour_signed_window(tmp_path, authority, context):
    context["live_window_start_utc"] = timestamp(-20)
    context["live_window_end_utc"] = timestamp(3580)
    context["host_policy"]["expires_at_utc"] = timestamp(3600)
    context["cost"]["expires_at_utc"] = timestamp(3580)
    context["candidate_boot"]["candidate_receipt_expires_at_utc"] = timestamp(3600)
    context["iam_provisioning"]["live_window_start_utc"] = timestamp(-20)
    context["iam_provisioning"]["live_window_end_utc"] = timestamp(3580)
    context["iam_provisioning"]["expires_at_utc"] = timestamp(3600)
    bundle = make_bundle(
        context,
        authority,
        receipt_expiry=3580,
        aggregate_expiry=3580,
    )
    path = write_bundle(tmp_path, bundle)
    planned = verifier.verify_bundle(path, canonical(context), now=NOW)
    result = verifier.verify_bundle(
        path,
        canonical(context),
        planned["bundle_sha256"],
        "apply",
        now=NOW,
    )

    assert result["verified"] == "true"
    assert result["expires_at_utc"] == timestamp(3580)


def test_context_window_over_two_hours_fails_closed(tmp_path, authority, context):
    context["live_window_end_utc"] = timestamp(7201)
    context["host_policy"]["expires_at_utc"] = timestamp(7300)
    with pytest.raises(verifier.VerificationError, match="context_window"):
        verify(
            tmp_path,
            make_bundle(
                context,
                authority,
                receipt_expiry=7201,
                aggregate_expiry=7201,
            ),
            context,
        )


@pytest.mark.parametrize("path,value", [
    (("run_id",), "different-run"), (("activation_nonce",), "fedcba9876543210"),
    (("live_window_end_utc",), timestamp(1201)), (("phase_b", "manifest_sha256"), H4),
    (("phase_b", "network_self_link"), "https://www.googleapis.com/compute/v1/projects/slit-497603/global/networks/swapped"),
    (("derivative", "candidate_manifest_sha256"), H4), (("supplier", "signaling_udp_port"), "5061"),
    (("derivative", "backend_image_digest"), f"sha256:{H4}"), (("f12", "readiness_path"), "/swapped"),
    (("authority", "tenant_digest"), H4), (("provider", "account_id_digest"), H4),
    (("cost", "recorded_at_utc"), timestamp(-31)), (("cost", "expires_at_utc"), timestamp(1199)),
    (("cost", "signer_key_id"), "different-cost-signer"), (("cost", "evidence_sha256"), H4),
])
def test_exact_context_and_component_swaps_fail(tmp_path, authority, context, path, value):
    bundle = make_bundle(context, authority)
    changed = copy.deepcopy(context)
    target = changed
    for component in path[:-1]: target = target[component]
    target[path[-1]] = value
    with pytest.raises(verifier.VerificationError): verify(tmp_path, bundle, changed)


@pytest.mark.parametrize(
    ("recorded_delta", "expiry_delta"),
    [
        (-30, -1),
        (-30, 1201),
        (1, 1200),
    ],
)
def test_signed_cost_validity_must_be_ordered_inside_live_window(
    tmp_path,
    authority,
    context,
    recorded_delta,
    expiry_delta,
):
    context["cost"]["recorded_at_utc"] = timestamp(recorded_delta)
    context["cost"]["expires_at_utc"] = timestamp(expiry_delta)
    with pytest.raises(verifier.VerificationError, match="context_cost_time"):
        verify(tmp_path, make_bundle(context, authority), context)


@pytest.mark.parametrize("section", ["host_policy", "recova_destination", "secrets", "bootstrap"])
@pytest.mark.parametrize("mutation", ["omitted", "extra"])
def test_expanded_context_subsections_are_exact(tmp_path, authority, context, section, mutation):
    changed = copy.deepcopy(context)
    if mutation == "omitted":
        del changed[section]
    else:
        changed[section]["unexpected"] = "forbidden"
    with pytest.raises(verifier.VerificationError, match="context_"):
        verify(tmp_path, make_bundle(context, authority), changed)


@pytest.mark.parametrize(("section", "field"), [
    ("phase_b", "prearm_canonical_inventory_sha256"),
    ("supplier", "endpoint_binding_verification_sha256"),
    ("host_policy", "verification_receipt_sha256"),
    ("recova_destination", "media_endpoint_sha256"),
])
@pytest.mark.parametrize("mutation", ["omitted", "extra"])
def test_each_expanded_subsection_rejects_omitted_and_extra_fields(tmp_path, authority, context, section, field, mutation):
    changed = copy.deepcopy(context)
    if mutation == "omitted":
        del changed[section][field]
    else:
        changed[section]["unexpected"] = "forbidden"
    with pytest.raises(verifier.VerificationError, match=f"context_{section}_schema"):
        verify(tmp_path, make_bundle(context, authority), changed)


@pytest.mark.parametrize(("mutation"), ["omitted", "extra"])
def test_legacy_secret_map_rejects_omitted_and_extra_purposes(tmp_path, authority, context, mutation):
    changed = copy.deepcopy(context)
    if mutation == "omitted":
        del changed["secrets"]["legacy"][next(iter(changed["secrets"]["legacy"]))]
    else:
        changed["secrets"]["legacy"]["unexpected"] = "projects/slit-497603/secrets/unexpected/versions/1"
    with pytest.raises(verifier.VerificationError, match="context_secrets_schema"):
        verify(tmp_path, make_bundle(context, authority), changed)


@pytest.mark.parametrize(("path", "value", "error"), [
    (("supplier", "remote_ipv4_cidrs"), ["203.0.113.0/16"], "context_supplier_network"),
    (("supplier", "customer_external_ipv4"), "203.0.113.010", "context_supplier_network"),
    (("supplier", "bound_signaling_ipv4_cidr"), "203.0.113.0/24", "context_supplier_network"),
    (("supplier", "candidate_sip_listen_udp_port"), "05090", "context_supplier_port"),
    (("supplier", "bound_remote_rtp_udp_port_min"), "10011", "context_supplier_port"),
    (("supplier", "bound_signaling_remote_udp_port"), "5061", "context_supplier_tuple"),
    (("host_policy", "candidate_local_rtp_udp_port_max"), "40100", "context_host_policy_port"),
    (("host_policy", "candidate_local_rtcp_udp_port_min"), "41010", "context_host_policy_port"),
    (("recova_destination", "control_ipv4_cidrs"), ["10.20.30.0/24"], "context_recova_destination_network"),
    (("recova_destination", "media_ipv4_cidrs"), ["10.20.30.43/32", "10.20.30.43/32"], "context_recova_destination_network"),
    (("supplier", "remote_rtp_udp_port_max"), "10100", "context_supplier_port"),
    (("host_policy", "expires_at_utc"), timestamp(100), "context_host_policy_time"),
    (("recova_destination", "f1_mtls_endpoint_path"), "https://example.com/dispatch", "context_recova_destination_endpoint"),
])
def test_expanded_network_and_port_contract_fails_closed(tmp_path, authority, context, path, value, error):
    changed = copy.deepcopy(context)
    changed[path[0]][path[1]] = value
    with pytest.raises(verifier.VerificationError, match=error):
        verify(tmp_path, make_bundle(changed, authority), changed)


def test_recova_endpoint_substitution_breaks_signed_context(tmp_path, authority, context):
    bundle = make_bundle(context, authority)
    changed = copy.deepcopy(context)
    changed["recova_destination"]["f1_mtls_endpoint_path"] = "https://other.internal/dispatch"
    with pytest.raises(verifier.VerificationError, match="aggregate_digest_binding"):
        verify(tmp_path, bundle, changed)


@pytest.mark.parametrize(("purpose", "value"), [
    ("f12_endpoint_credential", "projects/slit-497603/secrets/f12-mtls-certificate/versions/1"),
    ("sip_password", "projects/other/secrets/onnuri-sip-password-staging/versions/1"),
    ("sip_password", "projects/slit-497603/secrets/onnuri-sip-password-staging/versions/latest"),
    ("sip_password", "projects/slit-497603/secrets/onnuri-sip-password-staging/versions/01"),
])
def test_secret_references_reject_swaps_aliases_and_wrong_project(tmp_path, authority, context, purpose, value):
    changed = copy.deepcopy(context)
    changed["secrets"]["legacy"][purpose] = value
    with pytest.raises(verifier.VerificationError, match="context_secrets_reference"):
        verify(tmp_path, make_bundle(changed, authority), changed)


@pytest.mark.parametrize(("section", "field"), [
    ("phase_b", "prearm_canonical_inventory_sha256"),
    ("supplier", "endpoint_binding_canonical_sha256"),
    ("host_policy", "tuple_binding_sha256"),
    ("recova_destination", "certificate_binding_sha256"),
])
def test_new_subsection_digest_mismatch_breaks_aggregate_binding(tmp_path, authority, context, section, field):
    bundle = make_bundle(context, authority)
    changed = copy.deepcopy(context)
    changed[section][field] = H4 if context[section][field] != H4 else H3
    with pytest.raises(verifier.VerificationError):
        verify(tmp_path, bundle, changed)


@pytest.mark.parametrize(("section", "field"), [
    ("phase_b", "prearm_verification_receipt_sha256"),
    ("supplier", "customer_external_ipv4"),
    ("host_policy", "policy_sha256"),
    ("recova_destination", "control_endpoint_sha256"),
    ("secrets", "legacy"),
])
def test_any_expanded_context_mutation_invalidates_aggregate_signature(tmp_path, authority, context, section, field):
    bundle = make_bundle(context, authority)
    bundle_context = copy.deepcopy(context)
    if section == "secrets":
        bundle_context[section][field]["callback_hmac_key"] = "projects/slit-497603/secrets/callback-hmac-key/versions/2"
    elif field.endswith("sha256"):
        bundle_context[section][field] = H4 if context[section][field] != H4 else H3
    else:
        bundle_context[section][field] = "203.0.113.11"
    mutated = make_bundle(bundle_context, authority)
    mutated["aggregate"] = bundle["aggregate"]
    with pytest.raises(verifier.VerificationError, match="signature_invalid|aggregate_digest_binding"):
        verify(tmp_path, mutated, bundle_context)


@pytest.mark.parametrize("field,value", [("currency", "USD"), ("cost_ceiling_krw", "50001"), ("estimated_total_krw", "-1"), ("observed_total_krw", "50001"), ("observed_total_krw", "01")])
def test_invalid_signed_cost_contract_fails(tmp_path, authority, context, field, value):
    changed = copy.deepcopy(context); changed["cost"][field] = value
    with pytest.raises(verifier.VerificationError, match="context_cost"):
        verify(tmp_path, make_bundle(changed, authority), changed)


def test_role_key_swap_and_duplicate_authority_key_fail(tmp_path, authority, context, monkeypatch):
    bundle = make_bundle(context, authority)
    bundle["receipts"]["cost"] = signed(bundle["receipts"]["cost"]["payload"], "provider", authority)
    with pytest.raises(verifier.VerificationError, match="role_key_binding"):
        verify(tmp_path, bundle, context)
    keyset = json.loads(verifier.KEYSET_PATH.read_text())
    keyset["keys"][-1]["public_key_base64url"] = keyset["keys"][0]["public_key_base64url"]
    raw = canonical(keyset).encode(); verifier.KEYSET_PATH.write_bytes(raw)
    monkeypatch.setattr(verifier, "TRUSTED_KEYSET_SHA256", sha(raw))
    with pytest.raises(verifier.VerificationError): verify(tmp_path, make_bundle(context, authority), context)


def test_noncanonical_signature_and_context_encoding_fail(tmp_path, authority, context):
    bundle = make_bundle(context, authority)
    bundle["receipts"]["phase_b"]["signature"]["value"] += "="
    with pytest.raises(verifier.VerificationError, match="signature_encoding"):
        verify(tmp_path, bundle, context)
    clean = make_bundle(context, authority); path = write_bundle(tmp_path, clean)
    with pytest.raises(verifier.VerificationError, match="context_noncanonical"):
        verifier.verify_bundle(path, json.dumps(context), now=NOW)


def test_failures_and_success_output_are_redacted(tmp_path, authority, context):
    bundle = make_bundle(context, authority)
    result = verify(tmp_path, bundle, context)
    serialized = canonical(result)
    assert "provider_id_digest" not in serialized and "starting_balance" not in serialized
    assert "secret_version_mounts" not in serialized and "execution_versions" not in serialized
    bundle["receipts"]["provider"]["signature"]["value"] = "A" * 86
    with pytest.raises(verifier.VerificationError) as failure:
        verify(tmp_path, bundle, context)
    assert str(failure.value) == "signature_invalid"


def test_external_iam_receipt_terraform_contract_is_external_redacted_and_fail_closed():
    variables = (ROOT / "infra/onnuri-seoul-staging-phase-c-smoke/variables.tf").read_text()
    locals_source = (ROOT / "infra/onnuri-seoul-staging-phase-c-smoke/locals.tf").read_text()
    workload = (ROOT / "infra/onnuri-seoul-staging-phase-c-smoke/workload.tf").read_text()
    crypto_gate = (ROOT / "infra/onnuri-seoul-staging-phase-c-smoke/crypto_gate.tf").read_text()

    required_claims = {
        "schema_version",
        "bootstrap_manifest_binding_sha256",
        "runtime_service_account_email",
        "transaction_service_account_email",
        "live_window_start_utc",
        "live_window_end_utc",
        "destruction_deadline_utc",
        "candidate_manifest_sha256",
        "run_id",
        "activation_nonce_sha256",
        "activation_receipt_sha256",
        "exact_policy_result_sha256",
        "provisioning_outcome",
        "issuer_key_id",
        "issuer_key_fingerprint_sha256",
        "g008_external_iam_trusted_issuer_key_id",
        "g008_external_iam_trusted_issuer_key_fingerprint_sha256",
        "issued_at_utc",
        "expires_at_utc",
        "canonical_receipt_sha256",
        "cryptographic_verification_receipt_sha256",
    }
    assert all(claim in variables for claim in required_claims)
    assert "secret_version_resource_names" not in variables[
        variables.index('variable "g008_external_iam_provisioning_receipt"'):
        variables.index('variable "g008_execution_trigger"')
    ]
    assert "g008_exact_binding_receipt_sha256 = local.g008_bootstrap_manifest_binding_sha256" not in workload
    assert "local.g008_external_iam_receipt_ready" in workload
    assert "local.g008_external_iam_receipt_ready" in locals_source
    assert 'g008-iam-receipt-canonical-sha256' in workload
    assert 'g008-iam-receipt-verification-sha256' in workload
    assert "exact_policy_result_sha256" not in workload
    assert "issuer_key_fingerprint_sha256" not in workload
    signed_claims_block = crypto_gate[
        crypto_gate.index("g008_external_iam_signed_claims ="):
        crypto_gate.index("phase_c_live_expected_context =")
    ]
    assert "canonical_receipt_sha256" not in signed_claims_block
    assert "cryptographic_verification_receipt_sha256" not in signed_claims_block
    assert "iam_provisioning = local.g008_external_iam_signed_claims" in crypto_gate
    assert "!local.g008_external_iam_live_requested ? null" in crypto_gate
    assert 'try(data.external.phase_c_live_plan[0].result.iam_provisioning_payload_sha256, "") != ""' in crypto_gate
    assert "sha256(jsonencode(local.g008_external_iam_signed_claims))" in locals_source
    assert "result.iam_provisioning_payload_sha256" in locals_source
    assert "local.phase_c_live_plan_verified" in locals_source[
        locals_source.index("g008_external_iam_receipt_ready ="):
        locals_source.index("supplier_signaling_bound =")
    ]


@pytest.mark.parametrize(
    ("mutation", "field", "value"),
    [
        ("self_derived", "canonical_receipt_sha256", H),
        ("broad_policy", "provisioning_outcome", "POLICY_APPLIED"),
        ("stale", "expires_at_utc", timestamp(-1)),
        ("wrong_runtime_principal", "runtime_service_account_email", "other@slit-497603.iam.gserviceaccount.com"),
        ("wrong_transaction_principal", "transaction_service_account_email", "other@slit-497603.iam.gserviceaccount.com"),
        ("wrong_window", "live_window_end_utc", timestamp(1199)),
        ("wrong_manifest", "bootstrap_manifest_binding_sha256", H4),
        ("wrong_candidate_context", "candidate_manifest_sha256", H4),
        ("wrong_run_context", "run_id", "other-run"),
        ("wrong_activation_context", "activation_receipt_sha256", H4),
        ("wrong_key", "issuer_key_fingerprint_sha256", H),
        ("wrong_key_id", "issuer_key_id", "other-provisioner-v1"),
        ("invalid_digest", "canonical_receipt_sha256", "not-a-sha256"),
    ],
)
def test_external_iam_receipt_negative_cases_cannot_be_ready(mutation, field, value):
    expected = {
        "bootstrap_manifest_binding_sha256": H,
        "runtime_service_account_email": "runtime@slit-497603.iam.gserviceaccount.com",
        "transaction_service_account_email": "transaction@slit-497603.iam.gserviceaccount.com",
        "live_window_start_utc": timestamp(-20),
        "live_window_end_utc": timestamp(1200),
        "destruction_deadline_utc": timestamp(3600),
        "candidate_manifest_sha256": H2,
        "run_id": "phase-c-test",
        "activation_nonce_sha256": H3,
        "activation_receipt_sha256": H2,
        "exact_policy_result_sha256": H3,
        "provisioning_outcome": "EXACT_BOUNDED_POLICY_APPLIED_NO_BROADER_BINDINGS",
        "issuer_key_id": verifier.TRUSTED_KEYS["iam-provisioning"][0],
        "issuer_key_fingerprint_sha256": verifier.TRUSTED_KEYS["iam-provisioning"][1],
        "issued_at_utc": timestamp(-30),
        "expires_at_utc": timestamp(1300),
        "canonical_receipt_sha256": "5" * 64,
        "cryptographic_verification_receipt_sha256": "6" * 64,
    }
    receipt = copy.deepcopy(expected)
    receipt[field] = value
    digest_fields = {
        "bootstrap_manifest_binding_sha256",
        "activation_nonce_sha256",
        "activation_receipt_sha256",
        "exact_policy_result_sha256",
        "issuer_key_fingerprint_sha256",
        "canonical_receipt_sha256",
        "cryptographic_verification_receipt_sha256",
    }
    syntactically_valid = all(
        len(receipt[name]) == 64 and set(receipt[name]) <= set("0123456789abcdef")
        for name in digest_fields
    )
    independent = len({
        receipt["bootstrap_manifest_binding_sha256"],
        receipt["exact_policy_result_sha256"],
        receipt["issuer_key_fingerprint_sha256"],
        receipt["canonical_receipt_sha256"],
        receipt["cryptographic_verification_receipt_sha256"],
    }) == 5
    context_equal = all(
        receipt[name] == expected[name]
        for name in {
            "bootstrap_manifest_binding_sha256",
            "runtime_service_account_email",
            "transaction_service_account_email",
            "live_window_start_utc",
            "live_window_end_utc",
            "destruction_deadline_utc",
            "candidate_manifest_sha256",
            "run_id",
            "activation_nonce_sha256",
            "activation_receipt_sha256",
            "provisioning_outcome",
            "issuer_key_id",
            "issuer_key_fingerprint_sha256",
        }
    )
    fresh = receipt["issued_at_utc"] <= timestamp(0) < receipt["expires_at_utc"]
    assert not (syntactically_valid and independent and context_equal and fresh), mutation