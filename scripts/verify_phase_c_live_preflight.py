#!/usr/bin/env python3
"""Fail-closed Ed25519 verifier for the Phase C Terraform live preflight."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
KEYSET_PATH = Path(__file__).resolve().parents[1] / "infra" / "onnuri-seoul-staging-phase-c-smoke" / "trusted_keys" / "phase_c_live_preflight_v1.json"
TRUSTED_KEYSET_SHA256 = "00645f3af8230c742951c12f17a713afde209de12182cd6e3722ac59445507aa"
TRUSTED_KEYS = {
    "phase-b": ("recova-g008-phase-b-v1", "83f0d748928d70bca5b2c3f9cf80c059d74b359a215ec0ba1f99c334e45968b0"),
    "supplier": ("recova-g008-supplier-v1", "06a4275c751d9e6145cde4c2380c2fd0bbb0b66bcc8542c82b4c611d5d365fdb"),
    "provider": ("recova-g008-provider-v1", "eb17788d64ad5dd51183b843910ad70da143dfc32b857aa29ad449b4b58505bf"),
    "derivative": ("recova-g008-derivative-v1", "fc49b9709d1b2e99dabc57b9f2857d30639fd13589c49c464b68ec1cf22e2dfa"),
    "f12": ("recova-g008-f12-v1", "e38b55ccd4827f4971750e9bcd66b54e745dda3f10d6977db5a50940df331e17"),
    "authority": ("recova-g008-authority-v1", "977e114e74aae8a837e41665a800e5b545ccd201883223569b95a566c1e9667d"),
    "cost": ("recova-g008-cost-v1", "3aa58f8873d25c0ea32e77194d395709fd392b43a56efcb92826543f23dc06ec"),
    "iam-provisioning": ("recova-g008-iam-provisioning-v1", "619ea6c111ac0172161251dba08843b4a182e412a1f66a43a3418abe793aa5ac"),
    "phase-c-preflight": ("recova-g008-phase-c-preflight-v1", "68af3d0f08a9553df3a97e6887e59d415896314f907e4fac0e6a80cc165e046e"),
}
IAM_PROVISIONING_PUBLIC_KEY_BASE64URL = "J9CQast79fwKNsb059oUOjvmHYgsWXvWF1Lx5kZZ9QA"
SOURCE_ROLES = ("phase_b", "supplier", "provider", "derivative", "f12", "authority", "cost", "iam_provisioning")
ROLE_FOR_RECEIPT = {
    "phase_b": "phase-b",
    "iam_provisioning": "iam-provisioning",
    **{
        role: role
        for role in SOURCE_ROLES
        if role not in ("phase_b", "iam_provisioning")
    },
}

def source_roles(context: dict[str, Any]) -> tuple[str, ...]:
    return tuple(
        role for role in SOURCE_ROLES
        if role != "iam_provisioning" or context.get("iam_provisioning") is not None
    )
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
UINT = re.compile(r"(?:0|[1-9][0-9]*)\Z")
POSINT = re.compile(r"[1-9][0-9]*\Z")
DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?\Z")
B64URL = re.compile(r"[A-Za-z0-9_-]+\Z")
MINIMUM_APPLY_RUNWAY = timedelta(minutes=15)

CONTEXT_KEYS = ("schema_version", "project_id", "region", "run_id", "activation_nonce", "successor_review_payload_digest", "live_window_start_utc", "live_window_end_utc", "phase_b", "execution_contract", "supplier", "host_policy", "recova_destination", "candidate_boot", "secrets", "bootstrap", "execution", "provider", "derivative", "f12", "authority", "cost", "iam_provisioning")
SUBSECTION_KEYS = {
    "phase_b": ("manifest_sha256", "network_self_link", "subnet_self_link", "subnet_ipv4_cidr", "private_ip_google_access", "ingress_deny_rule_name", "egress_deny_rule_name", "phase_b_source_sha256", "backend_identity", "backend_generation", "backend_serial", "canonical_state_sha256", "non_sensitive_outputs_sha256", "prearm_canonical_inventory_sha256", "prearm_verification_receipt_sha256"),
    "execution_contract": ("sip_connection_mode", "source_external_ipv4", "peer_signaling_ipv4_cidr", "peer_signaling_udp_port", "owned_target_sha256", "stage_sequence", "register_attempt_budget", "unregister_attempt_budget", "total_call_attempt_budget", "retry_count", "concurrency_count", "call_deadline_seconds", "peer_detach_required", "containment_cleanup_required"),
    "supplier": ("signaling_ipv4_cidr", "signaling_udp_port", "remote_ipv4_cidrs", "remote_rtp_udp_port_min", "remote_rtp_udp_port_max", "remote_rtcp_udp_port_min", "remote_rtcp_udp_port_max", "max_concurrent_calls", "calls_per_second", "evidence_sha256", "endpoint_binding_canonical_sha256", "endpoint_binding_verification_sha256", "customer_external_ipv4", "bound_signaling_ipv4_cidr", "bound_signaling_remote_udp_port", "candidate_sip_listen_udp_port", "bound_media_ipv4_cidrs", "bound_remote_rtp_udp_port_min", "bound_remote_rtp_udp_port_max", "bound_remote_rtcp_udp_port_min", "bound_remote_rtcp_udp_port_max"),
    "host_policy": ("policy_sha256", "tuple_binding_sha256", "verification_receipt_sha256", "candidate_sip_listen_udp_port", "candidate_local_rtp_udp_port_min", "candidate_local_rtp_udp_port_max", "candidate_local_rtcp_udp_port_min", "candidate_local_rtcp_udp_port_max", "issued_at_utc", "expires_at_utc"),
    "recova_destination": ("canonical_receipt_sha256", "verification_receipt_sha256", "control_ipv4_cidrs", "media_ipv4_cidrs", "f1_source_ipv4_cidrs", "control_endpoint_sha256", "media_endpoint_sha256", "certificate_binding_sha256", "f1_mtls_endpoint_path", "f2_https_endpoint_path", "f3_wss_endpoint_path", "f4_https_endpoint_path", "f5_https_endpoint_path", "f12_mtls_endpoint_path"),
    "candidate_boot": ("image_self_link", "image_id", "image_generation", "source_sha256", "export_sha256", "derivative_sha256", "runtime_image_digest", "facade_image_digest", "candidate_manifest_sha256", "candidate_receipt_sha256", "candidate_receipt_signature_base64", "candidate_receipt_signer_key_id", "candidate_receipt_verification_key_sha256", "candidate_receipt_issued_at_utc", "candidate_receipt_expires_at_utc", "compose_sha256", "startup_sha256"),
    "secrets": ("legacy",),
    "bootstrap": ("g008_bootstrap_manifest_handle", "g008_bootstrap_manifest_binding_sha256", "review_payload_digest", "successor_review_payload_digest"),
    "execution": ("versions", "content_sha256", "review_payload_digest", "candidate_manifest_sha256", "runtime_image_digest", "candidate_receipt_sha256"),
    "provider": ("provider_id_digest", "account_id_digest", "currency", "starting_balance", "evidence_sha256"),
    "derivative": ("schema_version", "backend_image_digest", "backend_receipt_sha256", "postgres_image_digest", "postgres_receipt_sha256", "redis_image_digest", "redis_receipt_sha256", "ingress_image_digest", "ingress_receipt_sha256", "derivative_manifest_sha256", "candidate_manifest_sha256"),
    "f12": ("origin_https_endpoint_path", "readiness_path", "media_wss_endpoint_path", "endpoint_san", "tls_certificate_sha256", "mtls_client_certificate_sha256", "mtls_ca_certificate_sha256", "dispatch_algorithm", "dispatch_key_id", "dispatch_public_key_sha256", "media_algorithm", "media_key_id", "media_public_key_sha256"),
    "authority": ("tenant_digest", "account_digest", "envelope_digest", "candidate_digest"),
    "cost": ("currency", "cost_ceiling_krw", "estimated_total_krw", "observed_total_krw", "recorded_at_utc", "expires_at_utc", "evidence_sha256", "signer_key_id"),
    "iam_provisioning": ("schema_version", "bootstrap_manifest_binding_sha256", "runtime_service_account_email", "transaction_service_account_email", "live_window_start_utc", "live_window_end_utc", "destruction_deadline_utc", "candidate_manifest_sha256", "run_id", "activation_nonce_sha256", "activation_receipt_sha256", "provisioning_outcome", "exact_policy_result_sha256", "issuer_key_id", "issuer_key_fingerprint_sha256", "issued_at_utc", "expires_at_utc"),
}
LEGACY_SECRET_IDS = {
    "sip_password": "onnuri-sip-password-staging",
    "f12_endpoint_credential": "f12-endpoint-credential",
    "f12_mtls_certificate": "f12-mtls-certificate",
    "facade_adapter_credential": "facade-adapter-credential",
    "callback_hmac_key": "callback-hmac-key",
    "tls_private_key": "tls-private-key",
    "stock_local_api_credential": "stock-local-api-credential",
}
G008_RUNTIME_SECRET_IDS = {
    "postgres_password": "g008-postgres-password",
    "redis_password": "g008-redis-password",
    "f12_tls_private_key": "g008-f12-tls-private-key",
    "f12_tls_certificate": "g008-f12-tls-certificate",
    "f12_mtls_private_key": "g008-f12-mtls-private-key",
    "f12_mtls_certificate": "g008-f12-mtls-certificate",
    "f12_mtls_ca_certificate": "g008-f12-mtls-ca-certificate",
    "dispatch_es256_private_key": "g008-dispatch-private-key",
    "dispatch_es256_public_key": "g008-dispatch-public-key",
    "media_es256_private_key": "g008-media-private-key",
    "media_es256_public_key": "g008-media-public-key",
    "execution_evidence_es256_private_key": "g008-execution-evidence-private-key",
    "execution_evidence_es256_public_key": "g008-execution-evidence-public-key",
    "registration_attestation_es256_private_key": "g008-registration-attestation-private-key",
    "registration_attestation_es256_public_key": "g008-registration-attestation-public-key",
    "authority_recovery_key": "g008-authority-recovery-key",
    "mariadb_root_password": "g009-mariadb-root-password",
    "webhook_secret": "g009-webhook-secret",
    "account_api_token": "g009-account-api-token",
    "registration_egress_proof": "g009-registration-egress-proof",
    "f12_endpoint_credential": "g008-f12-endpoint-credential",
    "registration_f12_endpoint_credential": "g008-registration-f12-endpoint-credential",
    "stock_api_token": "g008-stock-api-token",
    "jambones_mysql_password": "g008-jambones-mysql-password",
    "jwt_secret": "g008-jwt-secret",
    "encryption_secret": "g008-encryption-secret",
    "drachtio_feature_secret": "g008-drachtio-feature-secret",
    "drachtio_sip_secret": "g008-drachtio-sip-secret",
    "freeswitch_esl_password": "g008-freeswitch-esl-password",
}
G008_EXECUTION_SECRET_IDS = {
    "execution_request": "g008-execution-request",
    "execution_sip_username": "g008-sip-username",
    "execution_sip_password": "g008-sip-password",
    "execution_sip_realm": "g008-sip-realm",
    "execution_target": "g008-execution-target",
    "execution_nonce": "g008-execution-nonce",
    "operator_credential": "g008-operator-credential",
}
G008_SECRET_IDS = {**G008_RUNTIME_SECRET_IDS, **G008_EXECUTION_SECRET_IDS}
G008_MOUNT_SPECS = {
    "postgres_password": ("/run/secrets/g008-recova-postgres-password", "backend"),
    "redis_password": ("/run/secrets/g008-recova-redis-password", "backend"),
    "f12_tls_private_key": ("/run/secrets/g008-f12-tls-private-key", "f12_ingress"),
    "f12_tls_certificate": ("/run/secrets/g008-f12-tls-certificate", "f12_ingress"),
    "f12_mtls_private_key": ("/run/secrets/g008-f12-mtls-private-key", "transaction_authority"),
    "f12_mtls_certificate": ("/run/secrets/g008-f12-mtls-certificate", "transaction_authority"),
    "f12_mtls_ca_certificate": ("/run/secrets/g008-f12-mtls-ca-certificate", "transaction_authority"),
    "dispatch_es256_private_key": ("/run/secrets/g008-dispatch-es256-private-key", "backend"),
    "dispatch_es256_public_key": ("/run/secrets/g008-dispatch-es256-public-key", "backend"),
    "media_es256_private_key": ("/run/secrets/g008-media-es256-private-key", "backend"),
    "media_es256_public_key": ("/run/secrets/g008-media-es256-public-key", "backend"),
    "execution_evidence_es256_private_key": ("/run/secrets/g008-execution-evidence-es256-private-key", "backend"),
    "execution_evidence_es256_public_key": ("/run/secrets/g008-execution-evidence-es256-public-key", "backend"),
    "registration_attestation_es256_private_key": ("/run/secrets/g008-registration-attestation-es256-private-key", "transaction_authority"),
    "registration_attestation_es256_public_key": ("/run/secrets/g008-registration-attestation-es256-public-key", "backend"),
    "authority_recovery_key": ("/run/secrets/g008-authority-recovery-key", "backend"),
    "mariadb_root_password": ("/run/secrets/g009-mariadb-root-password", "backend"),
    "webhook_secret": ("/run/secrets/g009-webhook-secret", "backend"),
    "account_api_token": ("/run/secrets/g009-account-api-token", "backend"),
    "registration_egress_proof": ("/run/secrets/g009-registration-egress-proof", "backend"),
    "f12_endpoint_credential": ("/run/secrets/g008-f12-endpoint-credential", "backend"),
    "registration_f12_endpoint_credential": ("/run/secrets/g008-registration-f12-endpoint-credential", "transaction_authority"),
    "stock_api_token": ("/run/secrets/g008-stock-api-token", "backend"),
    "jambones_mysql_password": ("/run/secrets/g009-jambones-mysql-password", "backend"),
    "jwt_secret": ("/run/secrets/g009-jwt-secret", "backend"),
    "encryption_secret": ("/run/secrets/g009-encryption-secret", "backend"),
    "drachtio_feature_secret": ("/run/secrets/g009-drachtio-feature-secret", "backend"),
    "drachtio_sip_secret": ("/run/secrets/g009-drachtio-sip-secret", "backend"),
    "freeswitch_esl_password": ("/run/secrets/g009-freeswitch-esl-password", "backend"),
}
BOOTSTRAP_MANIFEST_KEYS = ("schema_version", "binding_sha256", "transaction_authority_service_account", "secret_version_mounts", "execution_versions", "route_evidence_bundle")
BOOTSTRAP_EXECUTION_KEYS = ("request", "sip_username", "sip_password", "sip_realm", "target", "execution_nonce", "operator_credential")
BOOTSTRAP_EXECUTION_PURPOSES = {
    "request": "execution_request",
    "sip_username": "execution_sip_username",
    "sip_password": "execution_sip_password",
    "sip_realm": "execution_sip_realm",
    "target": "execution_target",
    "execution_nonce": "execution_nonce",
    "operator_credential": "operator_credential",
}

SERVICE_ACCOUNT = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]@slit-497603\.iam\.gserviceaccount\.com\Z")
SECRET_VERSION = re.compile(r"projects/slit-497603/secrets/([A-Za-z][A-Za-z0-9_-]{0,254})/versions/([1-9][0-9]*)\Z")
RECEIPT_PAYLOAD_KEYS = ("contract_version", "kind", "claims_sha256", "project_id", "region", "run_id_digest", "activation_nonce_digest", "phase_b_manifest_sha256", "candidate_manifest_sha256", "network_self_link_sha256", "live_window_start_utc", "live_window_end_utc", "observed_at_utc", "expires_at_utc", "signer_key_id")
AGGREGATE_PAYLOAD_KEYS = ("contract_version", "kind", "project_id", "region", "run_id_digest", "activation_nonce_digest", "phase_b_manifest_sha256", "candidate_manifest_sha256", "network_self_link_sha256", "live_window_start_utc", "live_window_end_utc", "authorized_context_sha256", "receipt_payload_sha256", "issued_at_utc", "expires_at_utc", "signer_key_id")
SIGNATURE_KEYS = ("algorithm", "key_id", "value")

ROUTE_EVIDENCE_FILE_NAMES = (
    "provider_fact_packet",
    "provider_fact_packet_signatures",
    "route_decision",
    "route_decision_signatures",
    "route_conformance",
    "route_conformance_signatures",
    "trusted_keyset",
    "revocations",
)
ROUTE_EVIDENCE_PROTOCOL_KEYS = (
    "adapter_path", "adapter_sha256", "adapter_execution_mode", "adapter_stdin_schema",
    "adapter_stdin_exactly_one_lf", "adapter_stdout_schema", "adapter_stdout_max_bytes",
    "adapter_stderr_max_bytes", "adapter_timeout_ms",
)
ROUTE_EVIDENCE_STAGED_PROTOCOL_KEYS = tuple(
    key for key in ROUTE_EVIDENCE_PROTOCOL_KEYS if key != "adapter_path"
)
ROUTE_EVIDENCE_SOURCE_KEYS = (
    "schema_version", "numeric_version_resource_name", "organization_id",
    "request_digest", "candidate_digest", "route_profile_digest", "opaque_handle",
    "approved_root_locator_digest", "inventory_locator_digest", "inventory_version",
    *ROUTE_EVIDENCE_PROTOCOL_KEYS, *(f"{name}_sha256" for name in ROUTE_EVIDENCE_FILE_NAMES),
)
ROUTE_EVIDENCE_BUNDLE_KEYS = (
    "schema_version", "numeric_version_resource_name", "organization_id",
    "request_digest", "candidate_digest", "route_profile_digest", "opaque_handle",
    "approved_root_locator_digest", "inventory_locator_digest", "inventory_version",
    *ROUTE_EVIDENCE_STAGED_PROTOCOL_KEYS, *(f"{name}_sha256" for name in ROUTE_EVIDENCE_FILE_NAMES),
    "adapter", *ROUTE_EVIDENCE_FILE_NAMES,
)
ROUTE_EVIDENCE_STAGED_MANIFEST_KEYS = (
    "schema_version", "numeric_version_resource_name", "organization_id",
    "request_digest", "candidate_digest", "route_profile_digest", "opaque_handle",
    "approved_root_locator_digest", "inventory_locator_digest", "inventory_version",
    *ROUTE_EVIDENCE_STAGED_PROTOCOL_KEYS, *(f"{name}_sha256" for name in ROUTE_EVIDENCE_FILE_NAMES),
)
ROUTE_EVIDENCE_MANIFEST_KEYS = ROUTE_EVIDENCE_STAGED_MANIFEST_KEYS
BOOTSTRAP_ROUTE_EVIDENCE_BUNDLE_KEYS = (
    "numeric_version_resource_name", "content_sha256", "schema_version", "organization_id",
    "request_digest", "candidate_digest", "route_profile_digest", "opaque_handle_digest",
)

class VerificationError(ValueError):
    """A deliberately non-sensitive verification failure."""


def _fail(code: str) -> None:
    raise VerificationError(code)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

# Bootstrap manifests are compact, sorted UTF-8 JSON terminated by exactly one LF.
def _canonical_bootstrap_manifest(value: Any) -> bytes:
    return _canonical(value) + b"\n"



def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _exact(obj: Any, keys: tuple[str, ...], code: str) -> dict[str, Any]:
    if not isinstance(obj, dict) or set(obj) != set(keys):
        _fail(code)
    return obj


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate_json_key")
        result[key] = value
    return result


def _decode_json(raw: bytes | str, code: str) -> Any:
    try:
        text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
        return json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=lambda _: _fail(code))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail(code)


def _timestamp(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not TIME.fullmatch(value):
        _fail(code)
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        _fail(code)


def _hex(value: Any, code: str) -> None:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        _fail(code)


def _canonical_cidr(value: Any, code: str, prefix: int | None = None) -> None:
    try:
        network = ipaddress.ip_network(value, strict=True)
    except (TypeError, ValueError):
        _fail(code)
    if network.version != 4 or str(network) != value or (prefix is not None and network.prefixlen != prefix):
        _fail(code)


def _canonical_ipv4(value: Any, code: str) -> None:
    try:
        address = ipaddress.ip_address(value)
    except (TypeError, ValueError):
        _fail(code)
    if address.version != 4 or str(address) != value:
        _fail(code)


def _cidr_list(value: Any, code: str, *, prefix: int | None = None, max_items: int | None = None) -> None:
    if (
        not isinstance(value, list)
        or not all(isinstance(cidr, str) for cidr in value)
        or value != sorted(set(value))
        or not value
        or (max_items is not None and len(value) > max_items)
    ):
        _fail(code)
    for cidr in value:
        _canonical_cidr(cidr, code, prefix)
        if prefix is None and ipaddress.ip_network(cidr).prefixlen < 24:
            _fail(code)


def _port(value: Any, code: str, *, unprivileged: bool = False) -> int:
    if not isinstance(value, str) or not POSINT.fullmatch(value):
        _fail(code)
    number = int(value)
    if not (1024 if unprivileged else 1) <= number <= 65535:
        _fail(code)
    return number

def _private_endpoint(value: Any, scheme: str, code: str) -> None:
    pattern = rf"{scheme}://[A-Za-z0-9][A-Za-z0-9.-]*\.internal(?::[0-9]{{1,5}})?/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+\Z"
    if (
        not isinstance(value, str)
        or re.fullmatch(pattern, value) is None
        or ".." in value
        or "@" in value
    ):
        _fail(code)


def _secret_map(value: Any, expected: dict[str, str]) -> None:
    value = _exact(value, tuple(expected), "context_secrets_schema")
    for purpose, secret_id in expected.items():
        reference = value[purpose]
        match = SECRET_VERSION.fullmatch(reference) if isinstance(reference, str) else None
        if match is None or match.group(1) != secret_id:
            _fail("context_secrets_reference")
    if len(set(value.values())) != len(value):
        _fail("context_secrets_reference")


def _validate_context(context: Any) -> dict[str, Any]:
    context = _exact(context, CONTEXT_KEYS, "context_schema")
    if context["schema_version"] != "recova-phase-c-live-context.v1" or context["project_id"] != "slit-497603" or context["region"] != "asia-northeast3":
        _fail("context_identity")
    if not isinstance(context["run_id"], str) or not re.fullmatch(r"[a-z][a-z0-9-]{5,39}", context["run_id"]) or context["run_id"].endswith("-"):
        _fail("context_run_id")
    if not isinstance(context["successor_review_payload_digest"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", context["successor_review_payload_digest"]):
        _fail("context_review_digest")
    if not isinstance(context["activation_nonce"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", context["activation_nonce"]):
        _fail("context_nonce")
    start = _timestamp(context["live_window_start_utc"], "context_window")
    end = _timestamp(context["live_window_end_utc"], "context_window")
    if end <= start or end - start > timedelta(hours=2):
        _fail("context_window")
    for name, keys in SUBSECTION_KEYS.items():
        if name == "iam_provisioning" and context[name] is None:
            continue
        _exact(context[name], keys, f"context_{name}_schema")

    phase_b = context["phase_b"]
    for key in ("manifest_sha256", "phase_b_source_sha256", "canonical_state_sha256", "non_sensitive_outputs_sha256", "prearm_canonical_inventory_sha256", "prearm_verification_receipt_sha256"):
        _hex(phase_b[key], "context_phase_b_digest")
    if phase_b["private_ip_google_access"] is not True or not POSINT.fullmatch(str(phase_b["backend_generation"])) or not UINT.fullmatch(str(phase_b["backend_serial"])):
        _fail("context_phase_b_value")
    if not isinstance(phase_b["backend_generation"], str) or not isinstance(phase_b["backend_serial"], str):
        _fail("context_phase_b_number")
    _canonical_cidr(phase_b["subnet_ipv4_cidr"], "context_phase_b_network")
    if not re.fullmatch(r"https://www\.googleapis\.com/compute/v1/projects/slit-497603/global/networks/[a-z][a-z0-9-]{0,62}", phase_b["network_self_link"] or ""):
        _fail("context_phase_b_network")
    if not re.fullmatch(r"https://www\.googleapis\.com/compute/v1/projects/slit-497603/regions/asia-northeast3/subnetworks/[a-z][a-z0-9-]{0,62}", phase_b["subnet_self_link"] or ""):
        _fail("context_phase_b_network")

    execution_contract = context["execution_contract"]
    mode = execution_contract["sip_connection_mode"]
    if mode not in ("registration", "ip_to_ip"):
        _fail("context_execution_contract_mode")
    for key in (
        "register_attempt_budget", "unregister_attempt_budget", "total_call_attempt_budget",
        "retry_count", "concurrency_count", "call_deadline_seconds",
    ):
        if not isinstance(execution_contract[key], str) or not UINT.fullmatch(execution_contract[key]):
            _fail("context_execution_contract_budget")
    if (
        execution_contract["total_call_attempt_budget"] != "3"
        or execution_contract["retry_count"] != "0"
        or execution_contract["concurrency_count"] != "1"
        or execution_contract["call_deadline_seconds"] != "60"
        or execution_contract["containment_cleanup_required"] is not True
    ):
        _fail("context_execution_contract_budget")
    if mode == "registration":
        if (
            execution_contract["stage_sequence"] != ["register", "outbound_call", "inbound_call", "unregister"]
            or execution_contract["register_attempt_budget"] != "1"
            or execution_contract["unregister_attempt_budget"] != "1"
            or execution_contract["peer_detach_required"] is not False
        ):
            _fail("context_execution_contract_registration")
    else:
        _canonical_ipv4(execution_contract["source_external_ipv4"], "context_execution_contract_source")
        _canonical_cidr(execution_contract["peer_signaling_ipv4_cidr"], "context_execution_contract_peer", 32)
        _hex(execution_contract["owned_target_sha256"], "context_execution_contract_target")
        if (
            execution_contract["stage_sequence"] != ["peer_attach", "outbound_call", "inbound_call", "peer_detach"]
            or execution_contract["register_attempt_budget"] != "0"
            or execution_contract["unregister_attempt_budget"] != "0"
            or execution_contract["peer_signaling_udp_port"] != "5060"
            or execution_contract["peer_detach_required"] is not True
            or execution_contract["source_external_ipv4"] == execution_contract["peer_signaling_ipv4_cidr"].removesuffix("/32")
        ):
            _fail("context_execution_contract_ip_to_ip")

    supplier = context["supplier"]
    _canonical_cidr(supplier["signaling_ipv4_cidr"], "context_supplier_network", 32)
    _canonical_cidr(supplier["bound_signaling_ipv4_cidr"], "context_supplier_network", 32)
    _canonical_ipv4(supplier["customer_external_ipv4"], "context_supplier_network")
    _cidr_list(supplier["remote_ipv4_cidrs"], "context_supplier_network", max_items=8)
    _cidr_list(supplier["bound_media_ipv4_cidrs"], "context_supplier_network", max_items=8)
    port_keys = (
        "signaling_udp_port", "remote_rtp_udp_port_min", "remote_rtp_udp_port_max",
        "remote_rtcp_udp_port_min", "remote_rtcp_udp_port_max",
        "bound_signaling_remote_udp_port", "candidate_sip_listen_udp_port",
        "bound_remote_rtp_udp_port_min", "bound_remote_rtp_udp_port_max",
        "bound_remote_rtcp_udp_port_min", "bound_remote_rtcp_udp_port_max",
    )
    ports = {key: _port(supplier[key], "context_supplier_port", unprivileged=key == "candidate_sip_listen_udp_port") for key in port_keys}
    for prefix in ("remote_rtp", "remote_rtcp", "bound_remote_rtp", "bound_remote_rtcp"):
        low, high = ports[f"{prefix}_udp_port_min"], ports[f"{prefix}_udp_port_max"]
        if low > high or high - low + 1 > 100:
            _fail("context_supplier_port")
    if (
        supplier["signaling_ipv4_cidr"] != supplier["bound_signaling_ipv4_cidr"]
        or supplier["signaling_udp_port"] != supplier["bound_signaling_remote_udp_port"]
        or supplier["remote_ipv4_cidrs"] != supplier["bound_media_ipv4_cidrs"]
        or any(supplier[key] != supplier[f"bound_{key}"] for key in (
            "remote_rtp_udp_port_min", "remote_rtp_udp_port_max",
            "remote_rtcp_udp_port_min", "remote_rtcp_udp_port_max",
        ))
    ):
        _fail("context_supplier_tuple")
    if supplier["max_concurrent_calls"] != "1" or supplier["calls_per_second"] != "1":
        _fail("context_supplier_limit")
    for key in ("evidence_sha256", "endpoint_binding_canonical_sha256", "endpoint_binding_verification_sha256"):
        _hex(supplier[key], "context_supplier_digest")
    if mode == "ip_to_ip" and (
        execution_contract["peer_signaling_ipv4_cidr"] != supplier["signaling_ipv4_cidr"]
        or execution_contract["source_external_ipv4"] != supplier["customer_external_ipv4"]
    ):
        _fail("context_execution_contract_binding")

    host_policy = context["host_policy"]
    for key in ("policy_sha256", "tuple_binding_sha256", "verification_receipt_sha256"):
        _hex(host_policy[key], "context_host_policy_digest")
    host_ports = {
        key: _port(value, "context_host_policy_port", unprivileged=True)
        for key, value in host_policy.items() if key.endswith("_port") or "_port_" in key
    }
    if host_policy["candidate_sip_listen_udp_port"] != supplier["candidate_sip_listen_udp_port"]:
        _fail("context_host_policy_tuple")
    for prefix in ("candidate_local_rtp_udp_port", "candidate_local_rtcp_udp_port"):
        low, high = host_ports[f"{prefix}_min"], host_ports[f"{prefix}_max"]
        if low > high or high - low + 1 > 100:
            _fail("context_host_policy_port")
    host_issued = _timestamp(host_policy["issued_at_utc"], "context_host_policy_time")
    host_expires = _timestamp(host_policy["expires_at_utc"], "context_host_policy_time")
    if host_issued > start or host_expires < end or host_issued >= host_expires:
        _fail("context_host_policy_time")

    recova = context["recova_destination"]
    for key in ("canonical_receipt_sha256", "verification_receipt_sha256", "control_endpoint_sha256", "media_endpoint_sha256", "certificate_binding_sha256"):
        _hex(recova[key], "context_recova_destination_digest")
    for key in ("control_ipv4_cidrs", "media_ipv4_cidrs", "f1_source_ipv4_cidrs"):
        _cidr_list(recova[key], "context_recova_destination_network", prefix=32)
    for key, scheme in (
        ("f1_mtls_endpoint_path", "https"),
        ("f2_https_endpoint_path", "https"),
        ("f3_wss_endpoint_path", "wss"),
        ("f4_https_endpoint_path", "https"),
        ("f5_https_endpoint_path", "https"),
        ("f12_mtls_endpoint_path", "https"),
    ):
        _private_endpoint(recova[key], scheme, "context_recova_destination_endpoint")

    candidate_boot = context["candidate_boot"]
    for key in ("export_sha256", "derivative_sha256", "candidate_manifest_sha256", "candidate_receipt_sha256", "candidate_receipt_verification_key_sha256", "compose_sha256", "startup_sha256"):
        _hex(candidate_boot[key], "context_candidate_boot_digest")
    if (
        not isinstance(candidate_boot["image_self_link"], str)
        or re.fullmatch(r"https://www\.googleapis\.com/compute/v1/projects/slit-497603/global/images/[a-z][a-z0-9-]{0,62}", candidate_boot["image_self_link"]) is None
        or not isinstance(candidate_boot["image_id"], str) or not POSINT.fullmatch(candidate_boot["image_id"])
        or not isinstance(candidate_boot["image_generation"], str) or not POSINT.fullmatch(candidate_boot["image_generation"])
        or not isinstance(candidate_boot["runtime_image_digest"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", candidate_boot["runtime_image_digest"])
        or not isinstance(candidate_boot["facade_image_digest"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", candidate_boot["facade_image_digest"])
        or candidate_boot["runtime_image_digest"] == candidate_boot["facade_image_digest"]
        or not isinstance(candidate_boot["candidate_receipt_signature_base64"], str) or B64URL.fullmatch(candidate_boot["candidate_receipt_signature_base64"]) is None
        or not isinstance(candidate_boot["candidate_receipt_signer_key_id"], str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:-]{2,255}", candidate_boot["candidate_receipt_signer_key_id"]) is None
    ):
        _fail("context_candidate_boot_identity")
    candidate_issued = _timestamp(candidate_boot["candidate_receipt_issued_at_utc"], "context_candidate_boot_time")
    candidate_expires = _timestamp(candidate_boot["candidate_receipt_expires_at_utc"], "context_candidate_boot_time")
    if candidate_issued >= candidate_expires or candidate_issued > start or candidate_expires < end or candidate_boot["candidate_manifest_sha256"] != context["derivative"]["candidate_manifest_sha256"]:
        _fail("context_candidate_boot_binding")

    secrets = context["secrets"]
    _secret_map(secrets["legacy"], LEGACY_SECRET_IDS)
    bootstrap = context["bootstrap"]
    reference = bootstrap["g008_bootstrap_manifest_handle"]
    match = SECRET_VERSION.fullmatch(reference) if isinstance(reference, str) else None
    if match is None:
        _fail("context_bootstrap_handle")
    _hex(bootstrap["g008_bootstrap_manifest_binding_sha256"], "context_bootstrap_binding")
    if bootstrap["review_payload_digest"] != context["successor_review_payload_digest"] or bootstrap["successor_review_payload_digest"] != context["successor_review_payload_digest"]:
        _fail("context_bootstrap_binding")

    execution = context["execution"]
    execution_versions = _exact(execution["versions"], BOOTSTRAP_EXECUTION_KEYS, "context_execution_versions")
    execution_digests = _exact(execution["content_sha256"], BOOTSTRAP_EXECUTION_KEYS, "context_execution_digests")
    for key, purpose in BOOTSTRAP_EXECUTION_PURPOSES.items():
        reference = execution_versions[key]
        match = SECRET_VERSION.fullmatch(reference) if isinstance(reference, str) else None
        if match is None or match.group(1) != G008_EXECUTION_SECRET_IDS[purpose]:
            _fail("context_execution_version")
        _hex(execution_digests[key], "context_execution_digest")
    if len(set(execution_versions.values())) != len(BOOTSTRAP_EXECUTION_KEYS):
        _fail("context_execution_version")
    if (
        execution["review_payload_digest"] != context["successor_review_payload_digest"]
        or execution["candidate_manifest_sha256"] != candidate_boot["candidate_manifest_sha256"]
        or execution["runtime_image_digest"] != candidate_boot["runtime_image_digest"]
        or execution["candidate_receipt_sha256"] != candidate_boot["candidate_receipt_sha256"]
    ):
        _fail("context_execution_candidate")

    if secrets["legacy"]["sip_password"] != "projects/slit-497603/secrets/onnuri-sip-password-staging/versions/1":
        _fail("context_secrets_reference")

    provider = context["provider"]
    for key in ("provider_id_digest", "account_id_digest", "evidence_sha256"):
        _hex(provider[key], "context_provider_digest")
    if provider["currency"] != "KRW" or not isinstance(provider["starting_balance"], str) or not DECIMAL.fullmatch(provider["starting_balance"]):
        _fail("context_provider_value")

    derivative = context["derivative"]
    if derivative["schema_version"] != "recova-g008-derivative-v3":
        _fail("context_derivative_version")
    for key, value in derivative.items():
        if key.endswith("_image_digest"):
            if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value): _fail("context_derivative_digest")
        elif key.endswith("_sha256"):
            _hex(value, "context_derivative_digest")

    f12 = context["f12"]
    for key in ("tls_certificate_sha256", "mtls_client_certificate_sha256", "mtls_ca_certificate_sha256", "dispatch_public_key_sha256", "media_public_key_sha256"):
        _hex(f12[key], "context_f12_digest")
    if f12["dispatch_algorithm"] != "ES256" or f12["media_algorithm"] != "ES256" or f12["dispatch_key_id"] == f12["media_key_id"]:
        _fail("context_f12_key")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*\.internal", f12["endpoint_san"] or "") or not str(f12["origin_https_endpoint_path"]).startswith(f"https://{f12['endpoint_san']}/") or not str(f12["media_wss_endpoint_path"]).startswith(f"wss://{f12['endpoint_san']}/") or not str(f12["readiness_path"]).startswith("/"):
        _fail("context_f12_endpoint")

    for value in context["authority"].values(): _hex(value, "context_authority_digest")
    if context["authority"]["candidate_digest"] != _sha(_canonical({
        "review_payload_digest": context["successor_review_payload_digest"],
        "candidate_manifest_sha256": candidate_boot["candidate_manifest_sha256"],
        "runtime_image_digest": candidate_boot["runtime_image_digest"],
        "candidate_receipt_sha256": candidate_boot["candidate_receipt_sha256"],
    })):
        _fail("context_authority_candidate")
    cost = context["cost"]
    if cost["currency"] != "KRW" or cost["cost_ceiling_krw"] != "50000":
        _fail("context_cost_contract")
    for key in ("estimated_total_krw", "observed_total_krw"):
        if not isinstance(cost[key], str) or not UINT.fullmatch(cost[key]) or int(cost[key]) > 50000:
            _fail("context_cost_total")
    recorded = _timestamp(cost["recorded_at_utc"], "context_cost_time")
    cost_expires = _timestamp(cost["expires_at_utc"], "context_cost_time")
    if recorded > start or cost_expires <= recorded or cost_expires <= start or cost_expires > end:
        _fail("context_cost_time")
    _hex(cost["evidence_sha256"], "context_cost_digest")
    if not isinstance(cost["signer_key_id"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:-]{2,255}", cost["signer_key_id"]):
        _fail("context_cost_signer")

    iam = context["iam_provisioning"]
    if iam is not None:
        if iam["schema_version"] != "recova-g008-external-iam-provisioning-receipt-v1":
            _fail("context_iam_provisioning_version")
        for key in (
            "bootstrap_manifest_binding_sha256",
            "candidate_manifest_sha256",
            "activation_nonce_sha256",
            "activation_receipt_sha256",
            "exact_policy_result_sha256",
            "issuer_key_fingerprint_sha256",
        ):
            _hex(iam[key], "context_iam_provisioning_digest")
        if (
            not SERVICE_ACCOUNT.fullmatch(iam["runtime_service_account_email"] or "")
            or not SERVICE_ACCOUNT.fullmatch(iam["transaction_service_account_email"] or "")
            or iam["runtime_service_account_email"] == iam["transaction_service_account_email"]
        ):
            _fail("context_iam_provisioning_principal")
        iam_issued = _timestamp(iam["issued_at_utc"], "context_iam_provisioning_time")
        iam_expires = _timestamp(iam["expires_at_utc"], "context_iam_provisioning_time")
        destruction = _timestamp(iam["destruction_deadline_utc"], "context_iam_provisioning_time")
        if (
            iam["bootstrap_manifest_binding_sha256"] != bootstrap["g008_bootstrap_manifest_binding_sha256"]
            or iam["candidate_manifest_sha256"] != derivative["candidate_manifest_sha256"]
            or iam["run_id"] != context["run_id"]
            or iam["activation_nonce_sha256"] != _sha(context["activation_nonce"].encode())
            or iam["live_window_start_utc"] != context["live_window_start_utc"]
            or iam["live_window_end_utc"] != context["live_window_end_utc"]
            or iam["provisioning_outcome"] != "EXACT_BOUNDED_POLICY_APPLIED_NO_BROADER_BINDINGS"
            or iam["issuer_key_id"] != TRUSTED_KEYS["iam-provisioning"][0]
            or iam["issuer_key_fingerprint_sha256"] != TRUSTED_KEYS["iam-provisioning"][1]
            or iam_issued > start
            or iam_expires < end
            or iam_issued >= iam_expires
            or destruction < end
        ):
            _fail("context_iam_provisioning_binding")
    return context


def validate_bootstrap_manifest(
    manifest_path: str | Path,
    expected_binding_sha256: str = "",
    expected_secret_versions: dict[str, str] | None = None,
) -> dict[str, Any]:
    try:
        raw = Path(manifest_path).read_bytes()
    except (OSError, TypeError):
        _fail("bootstrap_manifest_unavailable")
    manifest = _decode_json(raw, "bootstrap_manifest_json")
    if _canonical_bootstrap_manifest(manifest) != raw:
        _fail("bootstrap_manifest_noncanonical")
    manifest = _exact(manifest, BOOTSTRAP_MANIFEST_KEYS, "bootstrap_manifest_schema")
    if manifest["schema_version"] != "recova-g008-sealed-bootstrap-manifest-v1":
        _fail("bootstrap_manifest_version")
    binding = manifest["binding_sha256"]
    _hex(binding, "bootstrap_manifest_binding")
    binding_input = {key: value for key, value in manifest.items() if key != "binding_sha256"}
    if _sha(_canonical(binding_input)) != binding or (
        expected_binding_sha256 and binding != expected_binding_sha256
    ):
        _fail("bootstrap_manifest_binding")
    if not isinstance(manifest["transaction_authority_service_account"], str) or not SERVICE_ACCOUNT.fullmatch(manifest["transaction_authority_service_account"]):
        _fail("bootstrap_manifest_authority")

    route = _exact(manifest["route_evidence_bundle"], BOOTSTRAP_ROUTE_EVIDENCE_BUNDLE_KEYS, "bootstrap_manifest_route_evidence")
    if (
        SECRET_VERSION.fullmatch(route["numeric_version_resource_name"] or "") is None
        or not isinstance(route["content_sha256"], str) or HEX64.fullmatch(route["content_sha256"]) is None
        or route["schema_version"] != "recova-onnuri-route-evidence-bundle-v1"
        or not isinstance(route["organization_id"], int) or route["organization_id"] <= 0
        or not all(isinstance(route[name], str) and HEX64.fullmatch(route[name]) for name in ("request_digest", "candidate_digest", "route_profile_digest", "opaque_handle_digest"))
    ):
        _fail("bootstrap_manifest_route_evidence")
    mounts = _exact(manifest["secret_version_mounts"], tuple(G008_MOUNT_SPECS), "bootstrap_manifest_mounts_schema")
    execution = _exact(manifest["execution_versions"], BOOTSTRAP_EXECUTION_KEYS, "bootstrap_manifest_execution_schema")
    references: dict[str, str] = {}
    for purpose, (target, consumer) in G008_MOUNT_SPECS.items():
        mount = _exact(mounts[purpose], ("version_resource_name", "target", "consumer", "read_only"), "bootstrap_manifest_mount_schema")
        if mount["target"] != target or mount["consumer"] != consumer or mount["read_only"] is not True:
            _fail("bootstrap_manifest_mount")
        references[purpose] = mount["version_resource_name"]
    for key, purpose in BOOTSTRAP_EXECUTION_PURPOSES.items():
        references[purpose] = execution[key]
    try:
        _secret_map(references, G008_SECRET_IDS)
    except VerificationError:
        _fail("bootstrap_manifest_inventory")
    if expected_secret_versions is not None and references != expected_secret_versions:
        _fail("bootstrap_manifest_inventory_binding")
    return manifest

def _decode_unpadded(value: Any, length: int, code: str) -> bytes:
    if not isinstance(value, str) or not B64URL.fullmatch(value) or "=" in value:
        _fail(code)
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception:
        _fail(code)
    if len(raw) != length or base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
        _fail(code)
    return raw


def _load_keys() -> dict[str, bytes]:
    try:
        raw = KEYSET_PATH.read_bytes()
    except OSError:
        _fail("trusted_keyset_unavailable")
    if _sha(raw) != TRUSTED_KEYSET_SHA256:
        _fail("trusted_keyset_digest")
    keyset = _decode_json(raw, "trusted_keyset_json")
    if _canonical(keyset) != raw:
        _fail("trusted_keyset_noncanonical")
    _exact(keyset, ("keys", "schema_version"), "trusted_keyset_schema")
    if keyset["schema_version"] != "recova-phase-c-live-preflight-keyset.v1" or not isinstance(keyset["keys"], list) or len(keyset["keys"]) not in (len(TRUSTED_KEYS) - 1, len(TRUSTED_KEYS)):
        _fail("trusted_keyset_schema")
    result: dict[str, bytes] = {}
    seen_ids: set[str] = set()
    seen_raw: set[bytes] = set()
    for entry in keyset["keys"]:
        _exact(entry, ("algorithm", "key_id", "public_key_base64url", "public_key_sha256", "role"), "trusted_key_schema")
        role = entry["role"]
        if role not in TRUSTED_KEYS or entry["algorithm"] != "Ed25519" or (entry["key_id"], entry["public_key_sha256"]) != TRUSTED_KEYS.get(role):
            _fail("trusted_key_binding")
        public = _decode_unpadded(entry["public_key_base64url"], 32, "trusted_key_encoding")
        if _sha(public) != entry["public_key_sha256"] or entry["key_id"] in seen_ids or public in seen_raw or role in result:
            _fail("trusted_key_distinctness")
        seen_ids.add(entry["key_id"]); seen_raw.add(public); result[role] = public
    if "iam-provisioning" not in result:
        public = _decode_unpadded(IAM_PROVISIONING_PUBLIC_KEY_BASE64URL, 32, "trusted_key_encoding")
        key_id, fingerprint = TRUSTED_KEYS["iam-provisioning"]
        if _sha(public) != fingerprint or key_id in seen_ids or public in seen_raw:
            _fail("trusted_key_binding")
        result["iam-provisioning"] = public
    if set(result) != set(TRUSTED_KEYS): _fail("trusted_key_roles")
    return result


def _verify_signature(container: Any, role: str, key: bytes, payload_keys: tuple[str, ...]) -> tuple[dict[str, Any], str]:
    container = _exact(container, ("payload", "signature"), "receipt_schema")
    payload = _exact(container["payload"], payload_keys, "payload_schema")
    signature = _exact(container["signature"], SIGNATURE_KEYS, "signature_schema")
    key_id = TRUSTED_KEYS[role][0]
    if payload["signer_key_id"] != key_id or signature["algorithm"] != "Ed25519" or signature["key_id"] != key_id:
        _fail("role_key_binding")
    payload_bytes = _canonical(payload)
    sig = _decode_unpadded(signature["value"], 64, "signature_encoding")
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(sig, payload_bytes)
    except (InvalidSignature, ValueError):
        _fail("signature_invalid")
    return payload, _sha(payload_bytes)


def verify_bundle(bundle_path: str | Path, expected_context_json: str, expected_bundle_sha256: str = "", verification_stage: str = "plan", *, now: datetime | None = None) -> dict[str, str]:
    if verification_stage not in ("plan", "apply") or (verification_stage == "plan" and expected_bundle_sha256) or (verification_stage == "apply" and not HEX64.fullmatch(expected_bundle_sha256)):
        _fail("adapter_stage")
    context = _decode_json(expected_context_json, "context_json")
    if _canonical(context).decode() != expected_context_json:
        _fail("context_noncanonical")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    context = _validate_context(context)
    if verification_stage == "plan" and _timestamp(context["cost"]["expires_at_utc"], "context_cost_time") <= current:
        _fail("context_cost_time")
    if verification_stage == "apply":
        window_start = _timestamp(context["live_window_start_utc"], "context_window")
        window_end = _timestamp(context["live_window_end_utc"], "context_window")
        effective_cutoff = min(
            window_end,
            _timestamp(context["cost"]["expires_at_utc"], "context_cost_time"),
        )
        if not window_start <= current < effective_cutoff:
            _fail("live_window_inactive")
        if effective_cutoff - current < MINIMUM_APPLY_RUNWAY:
            _fail("live_window_runway_insufficient")
    try:
        raw_bundle = Path(bundle_path).read_bytes()
    except (OSError, TypeError):
        _fail("bundle_unavailable")
    bundle_sha = _sha(raw_bundle)
    if expected_bundle_sha256 and bundle_sha != expected_bundle_sha256:
        _fail("bundle_digest_mismatch")
    bundle = _decode_json(raw_bundle, "bundle_json")
    if _canonical(bundle) != raw_bundle:
        _fail("bundle_noncanonical")
    bundle = _exact(bundle, ("schema_version", "receipts", "aggregate"), "bundle_schema")
    if bundle["schema_version"] != "recova-phase-c-live-preflight-bundle.v1": _fail("bundle_version")
    receipt_roles = source_roles(context)
    receipts = _exact(bundle["receipts"], receipt_roles, "receipts_schema")
    keys = _load_keys()
    common = {
        "project_id": context["project_id"], "region": context["region"],
        "run_id_digest": _sha(context["run_id"].encode()),
        "activation_nonce_digest": _sha(context["activation_nonce"].encode()),
        "phase_b_manifest_sha256": context["phase_b"]["manifest_sha256"],
        "candidate_manifest_sha256": context["derivative"]["candidate_manifest_sha256"],
        "network_self_link_sha256": _sha(context["phase_b"]["network_self_link"].encode()),
        "live_window_start_utc": context["live_window_start_utc"], "live_window_end_utc": context["live_window_end_utc"],
    }
    payload_digests: dict[str, str] = {}
    expiries: list[datetime] = []
    observations: list[datetime] = []
    for name in receipt_roles:
        role = ROLE_FOR_RECEIPT[name]
        payload, payload_digests[name] = _verify_signature(receipts[name], role, keys[role], RECEIPT_PAYLOAD_KEYS)
        if payload["contract_version"] != "recova-phase-c-live-prerequisite.v1" or payload["kind"] != name or payload["claims_sha256"] != _sha(_canonical(context[name])):
            _fail("receipt_claims_binding")
        if any(payload[key] != value for key, value in common.items()): _fail("receipt_common_binding")
        observed = _timestamp(payload["observed_at_utc"], "receipt_time")
        expires = _timestamp(payload["expires_at_utc"], "receipt_time")
        if (
            observed > current
            or current - observed > timedelta(seconds=60)
            or expires != _timestamp(context["live_window_end_utc"], "context_window")
            or expires <= current
            or observed >= expires
        ):
            _fail("receipt_freshness")
        observations.append(observed); expiries.append(expires)

    aggregate, aggregate_sha = _verify_signature(bundle["aggregate"], "phase-c-preflight", keys["phase-c-preflight"], AGGREGATE_PAYLOAD_KEYS)
    if aggregate["contract_version"] != "recova-phase-c-live-preflight.v1" or aggregate["kind"] != "phase_c_live_preflight": _fail("aggregate_contract")
    if any(aggregate[key] != value for key, value in common.items()): _fail("aggregate_common_binding")
    if aggregate["authorized_context_sha256"] != _sha(_canonical(context)) or aggregate["receipt_payload_sha256"] != {key: payload_digests[key] for key in sorted(payload_digests)}:
        _fail("aggregate_digest_binding")
    issued = _timestamp(aggregate["issued_at_utc"], "aggregate_time")
    expires = _timestamp(aggregate["expires_at_utc"], "aggregate_time")
    window_end = _timestamp(context["live_window_end_utc"], "context_window")
    if (
        issued > current
        or current - issued > timedelta(seconds=60)
        or expires != window_end
        or expires <= current
        or expires <= issued
        or expires > min(expiries)
    ):
        _fail("aggregate_freshness")
    effective_cutoff = min(
        expires,
        _timestamp(context["cost"]["expires_at_utc"], "context_cost_time"),
    )
    return {"verified": "true", "schema_version": "recova-phase-c-live-preflight-verification.v1", "bundle_sha256": bundle_sha, "aggregate_payload_sha256": aggregate_sha, "iam_provisioning_payload_sha256": payload_digests.get("iam_provisioning", ""), "authorized_context_sha256": aggregate["authorized_context_sha256"], "run_id_digest": common["run_id_digest"], "activation_nonce_digest": common["activation_nonce_digest"], "valid_from_utc": max(observations + [issued]).strftime("%Y-%m-%dT%H:%M:%SZ"), "expires_at_utc": expires.strftime("%Y-%m-%dT%H:%M:%SZ"), "effective_cutoff_utc": effective_cutoff.strftime("%Y-%m-%dT%H:%M:%SZ"), "trusted_keyset_sha256": TRUSTED_KEYSET_SHA256}


def main() -> int:
    try:
        query = _decode_json(sys.stdin.buffer.read(), "adapter_json")
        query = _exact(query, ("bundle_path", "expected_context_json", "expected_bundle_sha256", "verification_stage"), "adapter_schema")
        if not all(isinstance(value, str) for value in query.values()): _fail("adapter_types")
        result = verify_bundle(**query)
        sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except VerificationError as exc:
        sys.stderr.write(f"phase_c_live_preflight:{exc}\n")
        return 1
    except Exception:
        sys.stderr.write("phase_c_live_preflight:internal_error\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
