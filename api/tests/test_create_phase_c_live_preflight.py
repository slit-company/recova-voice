from __future__ import annotations

import base64
import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import create_phase_c_live_preflight as creator


NOW = datetime(2026, 7, 16, 12, 0, 0, tzinfo=timezone.utc)
H = "1" * 64
H2 = "2" * 64
H3 = "3" * 64
H4 = "4" * 64

CANDIDATE_MANIFEST_SHA256 = H2


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def timestamp(delta: int) -> str:
    return (NOW + timedelta(seconds=delta)).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def context():
    return {
        "schema_version": "recova-phase-c-live-context.v1", "project_id": "slit-497603", "region": "asia-northeast3",
        "run_id": "phase-c-test", "activation_nonce": "0123456789abcdef", "successor_review_payload_digest": f"sha256:{H}", "live_window_start_utc": timestamp(-20), "live_window_end_utc": timestamp(240),
        "phase_b": {"manifest_sha256": H, "network_self_link": "https://www.googleapis.com/compute/v1/projects/slit-497603/global/networks/phase-b", "subnet_self_link": "https://www.googleapis.com/compute/v1/projects/slit-497603/regions/asia-northeast3/subnetworks/phase-b", "subnet_ipv4_cidr": "10.73.96.0/24", "private_ip_google_access": True, "ingress_deny_rule_name": "deny-in", "egress_deny_rule_name": "deny-out", "phase_b_source_sha256": H2, "backend_identity": "gcs://phase-c-state/state", "backend_generation": "1", "backend_serial": "0", "canonical_state_sha256": H3, "non_sensitive_outputs_sha256": H4, "prearm_canonical_inventory_sha256": H, "prearm_verification_receipt_sha256": H2},
        "supplier": {"signaling_ipv4_cidr": "203.0.113.8/32", "signaling_udp_port": "5060", "remote_ipv4_cidrs": ["203.0.113.8/32"], "remote_rtp_udp_port_min": "10000", "remote_rtp_udp_port_max": "10010", "remote_rtcp_udp_port_min": "10011", "remote_rtcp_udp_port_max": "10020", "max_concurrent_calls": "1", "calls_per_second": "1", "evidence_sha256": H, "endpoint_binding_canonical_sha256": H2, "endpoint_binding_verification_sha256": H3, "customer_external_ipv4": "198.51.100.20", "bound_signaling_ipv4_cidr": "203.0.113.8/32", "bound_signaling_remote_udp_port": "5060", "candidate_sip_listen_udp_port": "25060", "bound_media_ipv4_cidrs": ["203.0.113.8/32"], "bound_remote_rtp_udp_port_min": "10000", "bound_remote_rtp_udp_port_max": "10010", "bound_remote_rtcp_udp_port_min": "10011", "bound_remote_rtcp_udp_port_max": "10020"},
        "host_policy": {"policy_sha256": H, "tuple_binding_sha256": H2, "verification_receipt_sha256": H3, "candidate_sip_listen_udp_port": "25060", "candidate_local_rtp_udp_port_min": "20000", "candidate_local_rtp_udp_port_max": "20010", "candidate_local_rtcp_udp_port_min": "20011", "candidate_local_rtcp_udp_port_max": "20020", "issued_at_utc": timestamp(-30), "expires_at_utc": timestamp(300)},
        "recova_destination": {"canonical_receipt_sha256": H, "verification_receipt_sha256": H2, "control_ipv4_cidrs": ["198.51.100.10/32"], "media_ipv4_cidrs": ["198.51.100.11/32"], "f1_source_ipv4_cidrs": ["198.51.100.12/32"], "control_endpoint_sha256": H3, "media_endpoint_sha256": H4, "certificate_binding_sha256": H, "f1_mtls_endpoint_path": "https://f1.recova.internal/dispatch", "f2_https_endpoint_path": "https://f2.recova.internal/callback", "f3_wss_endpoint_path": "wss://f3.recova.internal/media", "f4_https_endpoint_path": "https://f4.recova.internal/secrets", "f5_https_endpoint_path": "https://f5.recova.internal/logs", "f12_mtls_endpoint_path": "https://f12.recova.internal/authority"},
        "secrets": {
            "legacy": {purpose: f"projects/slit-497603/secrets/{secret_id}/versions/1" for purpose, secret_id in creator.verifier.LEGACY_SECRET_IDS.items()},
        },
        "candidate_boot": {"image_self_link": "https://www.googleapis.com/compute/v1/projects/slit-497603/global/images/recova-jambonz-g009", "image_id": "1", "image_generation": "1", "source_sha256": H, "export_sha256": H, "derivative_sha256": H2, "runtime_image_digest": f"sha256:{H3}", "facade_image_digest": f"sha256:{H4}", "candidate_manifest_sha256": CANDIDATE_MANIFEST_SHA256, "candidate_receipt_sha256": H3, "candidate_receipt_signature_base64": "YWJj", "candidate_receipt_signer_key_id": "g009-test-signer", "candidate_receipt_verification_key_sha256": H4, "candidate_receipt_issued_at_utc": timestamp(-30), "candidate_receipt_expires_at_utc": timestamp(300), "compose_sha256": H, "startup_sha256": H2},
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
        "authority": {"tenant_digest": H, "account_digest": H2, "envelope_digest": H3, "candidate_digest": sha(canonical({"review_payload_digest": f"sha256:{H}", "candidate_manifest_sha256": CANDIDATE_MANIFEST_SHA256, "runtime_image_digest": f"sha256:{H3}", "candidate_receipt_sha256": H3}))},
        "cost": {"currency": "KRW", "cost_ceiling_krw": "50000", "estimated_total_krw": "12000", "observed_total_krw": "1000", "recorded_at_utc": timestamp(-30), "expires_at_utc": timestamp(240), "evidence_sha256": H, "signer_key_id": "cost-test-signer"},
        "iam_provisioning": None,
    }


@pytest.fixture
def authority(tmp_path, monkeypatch):
    private = {role: Ed25519PrivateKey.generate() for role in creator.verifier.TRUSTED_KEYS}
    entries = []
    pinned = {}
    paths = {}
    for role, key in private.items():
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        key_id = f"test-{role}-v1"
        fingerprint = sha(public)
        pinned[role] = (key_id, fingerprint)
        entries.append({"algorithm": "Ed25519", "key_id": key_id, "public_key_base64url": base64.urlsafe_b64encode(public).rstrip(b"=").decode(), "public_key_sha256": fingerprint, "role": role})
        path = tmp_path / f"{role}.pem"
        path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        paths[role] = path
    keyset = {"keys": entries, "schema_version": "recova-phase-c-live-preflight-keyset.v1"}
    keyset_path = tmp_path / "trusted.json"
    keyset_raw = canonical(keyset)
    keyset_path.write_bytes(keyset_raw)
    monkeypatch.setattr(creator.verifier, "KEYSET_PATH", keyset_path)
    monkeypatch.setattr(creator.verifier, "TRUSTED_KEYSET_SHA256", sha(keyset_raw))
    monkeypatch.setattr(creator.verifier, "TRUSTED_KEYS", pinned)
    monkeypatch.setattr(creator, "_now", lambda: NOW)
    return private, paths


@pytest.fixture
def inputs(tmp_path, context, authority):
    _, keys = authority
    context_path = tmp_path / "context.json"
    context_path.write_bytes(canonical(context))
    receipts = {}
    required_roles = creator.verifier.source_roles(context)
    for role in required_roles:
        path = tmp_path / f"receipt-{role}.json"
        creator.sign_source(role, context_path, keys[creator.verifier.ROLE_FOR_RECEIPT[role]], timestamp(-5), timestamp(240), path)
        receipts[role] = path
    arguments = [f"{role}={receipts[role]}" for role in required_roles]
    return context_path, receipts, arguments, keys


def test_valid_independent_signing_assembly_and_production_verification(tmp_path, context, inputs):
    context_path, receipts, arguments, keys = inputs
    assert all(set(json.loads(path.read_bytes())) == {"payload", "signature"} for path in receipts.values())
    bundle_path = tmp_path / "bundle.json"
    creator.assemble(context_path, arguments, keys["phase-c-preflight"], timestamp(-4), timestamp(240), bundle_path)
    assert bundle_path.read_bytes() == canonical(json.loads(bundle_path.read_bytes()))
    result = creator.verifier.verify_bundle(bundle_path, canonical(context).decode(), now=NOW)
    assert result["verified"] == "true"
    assert set(json.loads(bundle_path.read_bytes())["receipts"]) == set(creator.verifier.source_roles(context))
    execution = context["execution"]
    assert set(execution["versions"]) == set(creator.verifier.BOOTSTRAP_EXECUTION_KEYS)
    assert set(execution["content_sha256"]) == set(creator.verifier.BOOTSTRAP_EXECUTION_KEYS)
    assert len(execution["versions"]) == len(execution["content_sha256"]) == 7
    assert json.loads(bundle_path.read_bytes())["aggregate"]["payload"][
        "authorized_context_sha256"
    ] == creator.verifier._sha(creator.verifier._canonical(context))


@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        ("secret_version_inventory", "context_secrets_schema"),
        ("manifest_handle_self_reference", "context_bootstrap_schema"),
    ],
)
def test_context_cannot_embed_bootstrap_inventory_or_self_reference(
    tmp_path, context, authority, mutation, error
):
    _, keys = authority
    changed = copy.deepcopy(context)
    if mutation == "secret_version_inventory":
        changed["secrets"]["g008"] = {
            purpose: f"projects/slit-497603/secrets/{secret_id}/versions/1"
            for purpose, secret_id in creator.verifier.G008_SECRET_IDS.items()
        }
    else:
        changed["bootstrap"]["execution_request"] = changed["bootstrap"][
            "g008_bootstrap_manifest_handle"
        ]
    context_path = tmp_path / f"{mutation}.json"
    context_path.write_bytes(canonical(changed))
    output = tmp_path / f"{mutation}-receipt.json"

    with pytest.raises(creator.CreationError, match=f"^{error}$"):
        creator.sign_source(
            "cost",
            context_path,
            keys["cost"],
            timestamp(-5),
            timestamp(240),
            output,
        )
    assert not output.exists()


def test_creator_produces_one_hour_bundle(tmp_path, context, authority):
    _, keys = authority
    context["live_window_start_utc"] = timestamp(-20)
    context["live_window_end_utc"] = timestamp(3580)
    context["host_policy"]["expires_at_utc"] = timestamp(3600)
    context["cost"]["expires_at_utc"] = timestamp(3580)
    context["candidate_boot"]["candidate_receipt_expires_at_utc"] = timestamp(3600)
    context_path = tmp_path / "one-hour-context.json"
    context_path.write_bytes(canonical(context))
    arguments = []
    for role in creator.verifier.source_roles(context):
        receipt_path = tmp_path / f"one-hour-{role}.json"
        creator.sign_source(
            role,
            context_path,
            keys[creator.verifier.ROLE_FOR_RECEIPT[role]],
            timestamp(-5),
            timestamp(3580),
            receipt_path,
        )
        arguments.append(f"{role}={receipt_path}")

    bundle_path = tmp_path / "one-hour-bundle.json"
    creator.assemble(
        context_path,
        arguments,
        keys["phase-c-preflight"],
        timestamp(-4),
        timestamp(3580),
        bundle_path,
    )

    result = creator.verifier.verify_bundle(
        bundle_path,
        canonical(context).decode(),
        verification_stage="plan",
        now=NOW,
    )
    assert result["verified"] == "true"
    assert result["expires_at_utc"] == timestamp(3580)


def test_wrong_role_private_key_is_rejected_without_output(tmp_path, context, authority):
    _, keys = authority
    context_path = tmp_path / "context.json"; context_path.write_bytes(canonical(context))
    output = tmp_path / "receipt.json"
    with pytest.raises(creator.CreationError, match="^private_key_mismatch$"):
        creator.sign_source("cost", context_path, keys["provider"], timestamp(-5), timestamp(240), output)
    assert not output.exists()


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "extra"])
def test_assemble_requires_exactly_the_context_roles(tmp_path, inputs, mutation):
    context_path, _, arguments, keys = inputs
    changed = arguments[:-1] if mutation == "missing" else arguments + ([arguments[0]] if mutation == "duplicate" else ["other=/unused"])
    with pytest.raises(creator.CreationError, match="^receipt_roles$"):
        creator.assemble(context_path, changed, keys["phase-c-preflight"], timestamp(-4), timestamp(240), tmp_path / "bundle.json")


def test_tampered_receipt_is_rejected(tmp_path, inputs):
    context_path, receipts, arguments, keys = inputs
    receipt = json.loads(receipts["provider"].read_bytes())
    receipt["payload"]["claims_sha256"] = H4
    receipts["provider"].write_bytes(canonical(receipt))
    with pytest.raises(creator.CreationError, match="^signature_invalid$"):
        creator.assemble(context_path, arguments, keys["phase-c-preflight"], timestamp(-4), timestamp(240), tmp_path / "bundle.json")


def test_noncanonical_context_and_receipt_are_rejected(tmp_path, context, authority, inputs):
    _, key_paths = authority
    context_path = tmp_path / "pretty-context.json"; context_path.write_text(json.dumps(context))
    with pytest.raises(creator.CreationError, match="^context_noncanonical$"):
        creator.sign_source("cost", context_path, key_paths["cost"], timestamp(-5), timestamp(240), tmp_path / "unused.json")
    canonical_context, receipts, arguments, keys = inputs
    receipts["cost"].write_bytes(receipts["cost"].read_bytes() + b"\n")
    with pytest.raises(creator.CreationError, match="^receipt_noncanonical$"):
        creator.assemble(canonical_context, arguments, keys["phase-c-preflight"], timestamp(-4), timestamp(240), tmp_path / "bundle.json")


@pytest.mark.parametrize("observed,expires", [(-61, 240), (1, 240), (-5, -1)])
def test_sign_source_rejects_stale_future_and_expired_times(tmp_path, context, authority, observed, expires):
    _, keys = authority
    context_path = tmp_path / "context.json"; context_path.write_bytes(canonical(context))
    with pytest.raises(creator.CreationError, match="^receipt_freshness$"):
        creator.sign_source("cost", context_path, keys["cost"], timestamp(observed), timestamp(expires), tmp_path / "receipt.json")


@pytest.mark.parametrize("issued,expires", [(-61, 240), (1, 240), (-4, 241)])
def test_assemble_rejects_stale_future_and_overlong_aggregate(tmp_path, inputs, issued, expires):
    context_path, _, arguments, keys = inputs
    with pytest.raises(creator.CreationError, match="^aggregate_freshness$"):
        creator.assemble(context_path, arguments, keys["phase-c-preflight"], timestamp(issued), timestamp(expires), tmp_path / "bundle.json")


def test_outputs_are_never_overwritten(tmp_path, context, authority, inputs):
    _, key_paths = authority
    context_path, _, arguments, keys = inputs
    output = tmp_path / "existing.json"; output.write_text("operator-data")
    with pytest.raises(creator.CreationError, match="^output_unavailable$"):
        creator.sign_source("cost", context_path, key_paths["cost"], timestamp(-5), timestamp(240), output)
    assert output.read_text() == "operator-data"
    with pytest.raises(creator.CreationError, match="^output_unavailable$"):
        creator.assemble(context_path, arguments, keys["phase-c-preflight"], timestamp(-4), timestamp(240), output)
    assert output.read_text() == "operator-data"


def test_aggregate_key_mismatch_is_rejected(tmp_path, inputs):
    context_path, _, arguments, keys = inputs
    with pytest.raises(creator.CreationError, match="^private_key_mismatch$"):
        creator.assemble(context_path, arguments, keys["provider"], timestamp(-4), timestamp(240), tmp_path / "bundle.json")


def test_cli_errors_are_redacted(tmp_path, context, authority, capsys):
    _, keys = authority
    secret = "do-not-disclose-context"
    context_path = tmp_path / secret; context_path.write_bytes(canonical(context))
    output = tmp_path / "receipt.json"
    status = creator.main(["sign-source", "--role", "cost", "--context", str(context_path), "--private-key", str(keys["provider"]), "--observed-at-utc", timestamp(-5), "--expires-at-utc", timestamp(240), "--output", str(output)])
    captured = capsys.readouterr()
    assert status == 1 and captured.out == ""
    assert captured.err == "phase_c_live_preflight_create:private_key_mismatch\n"
    assert secret not in captured.err and str(keys["provider"]) not in captured.err


def test_cli_surface_has_no_trust_root_or_clock_overrides():
    help_text = creator._parser().format_help()
    assert "public-key" not in help_text
    assert "key-id" not in help_text
    assert "schema" not in help_text
    assert "--now" not in help_text


def route_evidence_source() -> dict[str, object]:
    files = {name: b"evidence-" + name.encode() for name in creator.verifier.ROUTE_EVIDENCE_FILE_NAMES}
    return {
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
        "adapter_path": "adapter",
        "adapter_sha256": sha(b"adapter"),
        "adapter_execution_mode": "fixed-executable-v1",
        "adapter_stdin_schema": "recova-onnuri-restricted-inventory-adapter-invocation-v1",
        "adapter_stdin_exactly_one_lf": True,
        "adapter_stdout_schema": "recova-onnuri-restricted-inventory-adapter-v1",
        "adapter_stdout_max_bytes": 1024,
        "adapter_stderr_max_bytes": 1024,
        "adapter_timeout_ms": 1000,
        **{f"{name}_sha256": sha(value) for name, value in files.items()},
    }


def write_route_evidence_source(tmp_path: Path) -> Path:
    source = tmp_path / "route-evidence-source.json"
    source.write_bytes(canonical(route_evidence_source()))
    return source

def test_sealed_route_evidence_bundle_retains_signed_evidence_digests(tmp_path: Path) -> None:
    source = route_evidence_source()
    source_path = tmp_path / "source.json"
    source_path.write_bytes(canonical(source))
    files = []
    for name in creator.verifier.ROUTE_EVIDENCE_FILE_NAMES:
        path = tmp_path / name
        path.write_bytes(b"evidence-" + name.encode())
        files.append(f"{name}={path}")
    adapter = tmp_path / "adapter"
    adapter.write_bytes(b"adapter")
    sealed = tmp_path / "bundle.json"

    bundle_sha256, _ = creator.seal_route_evidence_bundle(source_path, files, adapter, sealed)

    bundle = json.loads(sealed.read_bytes())
    assert set(bundle) == set(creator.verifier.ROUTE_EVIDENCE_BUNDLE_KEYS)
    assert all(bundle[f"{name}_sha256"] == source[f"{name}_sha256"] for name in creator.verifier.ROUTE_EVIDENCE_FILE_NAMES)
    assert bundle_sha256 == sha(sealed.read_bytes())
    assert "content_sha256" not in bundle

def test_create_bootstrap_manifest_uses_compact_sorted_utf8_bytes_terminated_by_exactly_one_lf(tmp_path):
    versions = {
        purpose: f"projects/slit-497603/secrets/{secret_id}/versions/{index}"
        for index, (purpose, secret_id) in enumerate(creator.verifier.G008_SECRET_IDS.items(), 1)
    }
    versions_path = tmp_path / "versions.json"
    versions_path.write_bytes(canonical(versions))
    manifest_path = tmp_path / "manifest.json"

    binding = creator.create_bootstrap_manifest(
        versions_path,
        "g008-transaction-authority@slit-497603.iam.gserviceaccount.com",
        manifest_path,
        write_route_evidence_source(tmp_path),
        sha(canonical(route_evidence_source()) + b"\n"),
    )

    raw = manifest_path.read_bytes()
    assert raw == creator.verifier._canonical_bootstrap_manifest(json.loads(raw))
    assert raw.endswith(b"\n") and not raw.endswith(b"\n\n")
    creator.verifier.validate_bootstrap_manifest(manifest_path, binding, versions)


def test_bootstrap_manifest_rejects_non_numeric_route_evidence_reference(tmp_path):
    source = route_evidence_source()
    source["numeric_version_resource_name"] = "projects/slit-497603/secrets/g008-route-evidence-bundle/versions/latest"
    source_path = tmp_path / "route-evidence-source.json"
    source_path.write_bytes(canonical(source))
    versions = {
        purpose: f"projects/slit-497603/secrets/{secret_id}/versions/{index}"
        for index, (purpose, secret_id) in enumerate(creator.verifier.G008_SECRET_IDS.items(), 1)
    }
    versions_path = tmp_path / "versions.json"
    versions_path.write_bytes(canonical(versions))
    with pytest.raises(creator.CreationError, match="^bootstrap_manifest_route_evidence$"):
        creator.create_bootstrap_manifest(
            versions_path,
            "g008-transaction-authority@slit-497603.iam.gserviceaccount.com",
            tmp_path / "manifest.json",
            source_path,
            sha(canonical(source) + b"\n"),
        )
