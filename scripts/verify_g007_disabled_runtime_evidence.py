#!/usr/bin/env python3
"""Fail-closed offline verifier for signed G007 disabled-runtime evidence."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

CONTRACT_VERSION = "g007-disabled-runtime-evidence-v2"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
KEY_ID = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
DIGEST_FILES = {
    "instance_sha256": "instance-redacted.json",
    "image_sha256": "image-redacted.json",
    "facade_sha256": "facade-binding.json",
    "tenant_sha256": "tenant-scope.json",
    "effective_firewall_sha256": "effective-firewalls.json",
    "flow_log_sha256": "flow-summary.json",
    "application_gate_process_state_sha256": "application-state.json",
    "provider_no_registration_no_call_receipt_sha256": "provider-zero-traffic.json",
    "containment_stop_drill_sha256": "containment-stop.json",
    "destroy_plan_sha256": "destroy-plan-summary.json",
    "durable_destroy_arm_receipt_sha256": "durable-destroy.json",
    "destroy_execution_sha256": "destroy-execution.json",
    "destroy_build_request_sha256": "destroy-build-request.json",
    "destroy_dry_run_request_sha256": "destroy-dry-run-request.json",
    "destroy_build_result_sha256": "destroy-build-result.json",
    "secret_reference_policy_sha256": "secret-references.json",
    "phase_b_before_sha256": "phase-b-before.json",
    "phase_b_after_sha256": "phase-b-after.json",
}
DIGEST_FIELDS = frozenset(DIGEST_FILES)
COUNTER_FIELDS = frozenset({"sip", "rtp", "register", "call"})
PAYLOAD_FIELDS = frozenset({
    "contract_version", "signer_key_id", "issued_at", "expires_at",
    "observation_window", "counters", "product_status", "redaction_assertion",
    "destroyer_armed", *DIGEST_FIELDS,
})
RECEIPT_FIELDS = frozenset({"payload", "signature_b64"})
TRUSTED_KEY_FIELDS = frozenset({"key_id", "public_key_b64"})
WINDOW_FIELDS = frozenset({"started_at", "ended_at"})
G009_RECEIPT_FIELDS = frozenset({
    "candidate_receipt_sha256", "candidate_receipt_signature_base64", "payload",
})
G009_PAYLOAD_FIELDS = frozenset({
    "schema_version", "project_id", "image_self_link", "image_id", "image_generation",
    "candidate_manifest_sha256", "source_sha256", "export_sha256", "derivative_sha256",
    "runtime_image_digest", "facade_image_digest", "private_probe",
    "candidate_receipt_signer_key_id", "candidate_receipt_verification_key_sha256",
    "candidate_receipt_issued_at_utc", "candidate_receipt_expires_at_utc",
})
EXPECTED_DESTROY_RESOURCES = frozenset({
    ("google_compute_address.candidate", "google_compute_address"),
    ("google_compute_firewall.deny_all_egress", "google_compute_firewall"),
    ("google_compute_firewall.deny_all_ingress", "google_compute_firewall"),
    ("google_compute_firewall.recova_f1_https_ingress", "google_compute_firewall"),
    ("google_compute_firewall.sip_egress", "google_compute_firewall"),
    ("google_compute_firewall.sip_ingress", "google_compute_firewall"),
    ("google_compute_instance.candidate", "google_compute_instance"),
    ("google_logging_log_view.evidence", "google_logging_log_view"),
    ("google_logging_log_view_iam_member.evidence", "google_logging_log_view_iam_member"),
    ("google_logging_metric.containment_stop", "google_logging_metric"),
    ("google_logging_metric.firewall_mutation", "google_logging_metric"),
    ("google_logging_project_bucket_config.evidence", "google_logging_project_bucket_config"),
    ("google_logging_project_sink.evidence", "google_logging_project_sink"),
    ("google_monitoring_alert_policy.containment_stop", "google_monitoring_alert_policy"),
    ("google_monitoring_alert_policy.unexpected_firewall_mutation", "google_monitoring_alert_policy"),
    ("google_project_iam_custom_role.containment", "google_project_iam_custom_role"),
    ("google_project_iam_custom_role.evidence", "google_project_iam_custom_role"),
    ("google_project_iam_custom_role.logging", "google_project_iam_custom_role"),
    ("google_project_iam_custom_role.runtime", "google_project_iam_custom_role"),
    ("google_project_iam_member.containment", "google_project_iam_member"),
    ("google_project_iam_member.logging", "google_project_iam_member"),
    ('google_secret_manager_secret_iam_member.runtime["callback_hmac_key"]', "google_secret_manager_secret_iam_member"),
    ('google_secret_manager_secret_iam_member.runtime["f12_endpoint_credential"]', "google_secret_manager_secret_iam_member"),
    ('google_secret_manager_secret_iam_member.runtime["f12_mtls_certificate"]', "google_secret_manager_secret_iam_member"),
    ('google_secret_manager_secret_iam_member.runtime["facade_adapter_credential"]', "google_secret_manager_secret_iam_member"),
    ('google_secret_manager_secret_iam_member.runtime["sip_password"]', "google_secret_manager_secret_iam_member"),
    ('google_secret_manager_secret_iam_member.runtime["stock_local_api_credential"]', "google_secret_manager_secret_iam_member"),
    ('google_secret_manager_secret_iam_member.runtime["tls_private_key"]', "google_secret_manager_secret_iam_member"),
    ("google_service_account.containment", "google_service_account"),
    ("google_service_account.evidence", "google_service_account"),
    ("google_service_account.logging", "google_service_account"),
    ("google_service_account.runtime", "google_service_account"),
})


class EvidenceError(ValueError):
    pass


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("duplicate JSON key")
        result[key] = value
    return result


def parse_json(raw: bytes, label: str) -> Any:
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates,
                          parse_constant=lambda _: (_ for _ in ()).throw(EvidenceError("invalid JSON constant")))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"invalid {label} JSON") from error


def _safe_file(directory: Path, filename: str, label: str) -> Path:
    path = directory / filename
    try:
        metadata = path.lstat()
    except OSError as error:
        raise EvidenceError(f"cannot read {label}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise EvidenceError(f"{label} is not a regular non-symlink file")
    try:
        if path.resolve().parent != directory:
            raise EvidenceError(f"{label} escapes evidence directory")
    except OSError as error:
        raise EvidenceError(f"cannot resolve {label}") from error
    return path


def _evidence_directory(path: str) -> Path:
    directory = Path(path)
    try:
        metadata = directory.lstat()
        resolved = directory.resolve(strict=True)
    except OSError as error:
        raise EvidenceError("cannot read evidence directory") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise EvidenceError("evidence directory is not a non-symlink directory")
    return resolved


def read_canonical(path: str | Path, label: str) -> Any:
    try:
        raw = Path(path).read_bytes()
    except OSError as error:
        raise EvidenceError(f"cannot read {label}") from error
    value = parse_json(raw, label)
    if canonical_json(value) != raw:
        raise EvidenceError(f"{label} is not canonical JSON")
    return value


def exact_object(value: Any, fields: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise EvidenceError(f"{label} has missing or unknown fields")
    return value


def string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise EvidenceError(f"invalid {label}")
    return value


def digest(value: Any, label: str, *, prefixed: bool = False) -> str:
    text = string(value, label)
    pattern = r"sha256:[0-9a-f]{64}" if prefixed else r"[0-9a-f]{64}"
    if re.fullmatch(pattern, text) is None:
        raise EvidenceError(f"invalid {label}")
    return text


def timestamp(value: Any, label: str) -> datetime:
    text = string(value, label)
    if not TIMESTAMP.fullmatch(text):
        raise EvidenceError(f"invalid {label}")
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise EvidenceError(f"invalid {label}") from error


def decode_b64(value: Any, label: str, length: int) -> bytes:
    try:
        decoded = base64.b64decode(string(value, label).encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as error:
        raise EvidenceError(f"invalid {label}") from error
    if len(decoded) != length:
        raise EvidenceError(f"invalid {label}")
    return decoded


def validate_claims(value: Any) -> dict[str, Any]:
    claims = exact_object(value, PAYLOAD_FIELDS, "payload")
    if claims["contract_version"] != CONTRACT_VERSION:
        raise EvidenceError("unsupported contract version")
    for name in DIGEST_FIELDS:
        digest(claims[name], name)
    window = exact_object(claims["observation_window"], WINDOW_FIELDS, "observation_window")
    started = timestamp(window["started_at"], "observation_window.started_at")
    ended = timestamp(window["ended_at"], "observation_window.ended_at")
    if not started < ended <= started + timedelta(seconds=60):
        raise EvidenceError("observation window must be positive and at most 60 seconds")
    counters = exact_object(claims["counters"], COUNTER_FIELDS, "counters")
    if any(isinstance(value, bool) or not isinstance(value, int) or value != 0 for value in counters.values()):
        raise EvidenceError("all SIP/RTP/REGISTER/call counters must be zero")
    if claims["product_status"] != "Waiting":
        raise EvidenceError("product status is not Waiting")
    if claims["redaction_assertion"] != "redacted-digests-only":
        raise EvidenceError("redaction assertion is invalid")
    if claims["destroyer_armed"] is not True:
        raise EvidenceError("destroyer is not armed")
    if not KEY_ID.fullmatch(string(claims["signer_key_id"], "signer_key_id")):
        raise EvidenceError("invalid signer_key_id")
    issued = timestamp(claims["issued_at"], "issued_at")
    expires = timestamp(claims["expires_at"], "expires_at")
    if not ended <= issued <= ended + timedelta(minutes=5) or not issued < expires <= issued + timedelta(hours=1):
        raise EvidenceError("receipt timestamps are invalid")
    return claims


def read_trusted_key(path: str) -> tuple[str, Ed25519PublicKey]:
    key = exact_object(read_canonical(path, "trusted key"), TRUSTED_KEY_FIELDS, "trusted key")
    key_id = string(key["key_id"], "key_id")
    if not KEY_ID.fullmatch(key_id):
        raise EvidenceError("invalid key_id")
    return key_id, Ed25519PublicKey.from_public_bytes(decode_b64(key["public_key_b64"], "public_key_b64", 32))


def _artifact(directory: Path, filename: str, label: str) -> tuple[Any, bytes]:
    path = _safe_file(directory, filename, label)
    raw = path.read_bytes()
    value = parse_json(raw, label)
    if raw not in (canonical_json(value), canonical_json(value) + b"\n"):
        raise EvidenceError(f"{label} is not canonical JSON")
    return value, raw


def _field(value: Any, name: str, label: str) -> Any:
    if not isinstance(value, dict) or name not in value:
        raise EvidenceError(f"{label} is missing {name}")
    return value[name]


def _verify_g009(directory: Path, image: Any, facade: Any) -> dict[str, Any]:
    manifest, manifest_raw = _artifact(directory, "candidate-manifest.json", "candidate manifest")
    manifest_sha = hashlib.sha256(manifest_raw).hexdigest()
    if digest(_field(image, "candidate_manifest_sha256", "image evidence"), "candidate_manifest_sha256") != manifest_sha:
        raise EvidenceError("candidate manifest digest mismatch")
    if digest(_field(facade, "candidate_manifest_sha256", "facade evidence"), "candidate_manifest_sha256") != manifest_sha:
        raise EvidenceError("facade candidate manifest digest mismatch")

    support_images = _field(manifest, "support_images", "candidate manifest")
    if not isinstance(support_images, list):
        raise EvidenceError("invalid candidate manifest support_images")
    facade_images = [item for item in support_images if isinstance(item, dict) and item.get("name") == "facade"]
    if len(facade_images) != 1:
        raise EvidenceError("candidate manifest must contain exactly one facade support image")
    facade_image = string(_field(facade_images[0], "image", "facade support image"), "facade support image")
    if "@" not in facade_image:
        raise EvidenceError("invalid facade support image")
    manifest_facade_digest = digest(facade_image.rsplit("@", 1)[1], "facade support image digest", prefixed=True)
    facade_image_digest = digest(_field(facade, "image_digest", "facade evidence"), "facade image_digest", prefixed=True)
    if manifest_facade_digest != facade_image_digest:
        raise EvidenceError("facade support image digest mismatch")

    receipt, receipt_raw = _artifact(directory, "g009-compute-image-receipt.json", "G009 compute receipt")
    receipt = exact_object(receipt, G009_RECEIPT_FIELDS, "G009 compute receipt")
    payload = exact_object(receipt["payload"], G009_PAYLOAD_FIELDS, "G009 compute receipt payload")
    receipt_sha = hashlib.sha256(receipt_raw).hexdigest()
    if digest(_field(image, "compute_receipt_sha256", "image evidence"), "compute_receipt_sha256") != receipt_sha:
        raise EvidenceError("image compute receipt digest mismatch")
    if digest(_field(facade, "compute_receipt_sha256", "facade evidence"), "compute_receipt_sha256") != receipt_sha:
        raise EvidenceError("facade compute receipt digest mismatch")

    public_path = _safe_file(directory, "g009-compute-receipt-public-key.pem", "G009 compute receipt public key")
    public_raw = public_path.read_bytes()
    try:
        public_key = serialization.load_pem_public_key(public_raw)
    except (ValueError, TypeError) as error:
        raise EvidenceError("invalid G009 compute receipt public key") from error
    if not isinstance(public_key, Ed25519PublicKey):
        raise EvidenceError("G009 compute receipt public key is not Ed25519")
    signed_payload = canonical_json(payload) + b"\n"
    if digest(receipt["candidate_receipt_sha256"], "candidate_receipt_sha256") != hashlib.sha256(signed_payload).hexdigest():
        raise EvidenceError("G009 compute receipt payload digest mismatch")
    if digest(payload["candidate_receipt_verification_key_sha256"], "candidate_receipt_verification_key_sha256") != hashlib.sha256(public_raw).hexdigest():
        raise EvidenceError("G009 compute receipt key digest mismatch")
    try:
        public_key.verify(
            decode_b64(receipt["candidate_receipt_signature_base64"], "candidate_receipt_signature_base64", 64),
            signed_payload,
        )
    except InvalidSignature as error:
        raise EvidenceError("invalid G009 compute receipt signature") from error

    image_id = payload["image_id"]
    image_generation = payload["image_generation"]
    if isinstance(image_id, bool) or not isinstance(image_id, int) or image_id <= 0:
        raise EvidenceError("invalid G009 image_id")
    if isinstance(image_generation, bool) or not isinstance(image_generation, int) or image_generation <= 0:
        raise EvidenceError("invalid G009 image_generation")
    bindings = {
        "image_self_link": string(_field(image, "selfLink", "image evidence"), "image selfLink"),
        "candidate_manifest_sha256": manifest_sha,
        "runtime_image_digest": digest(_field(image, "runtime_image_digest", "image evidence"), "runtime_image_digest", prefixed=True),
        "facade_image_digest": facade_image_digest,
    }
    if any(payload[name] != expected for name, expected in bindings.items()):
        raise EvidenceError("G009 compute receipt payload does not match evidence artifacts")
    if str(image_id) != string(_field(image, "id", "image evidence"), "image id"):
        raise EvidenceError("G009 compute receipt image id mismatch")
    if image_generation != _field(image, "image_generation", "image evidence"):
        raise EvidenceError("G009 compute receipt image generation mismatch")
    return receipt


def verify(receipt_path: str, trusted_key_path: str, evidence_dir: str, now: str) -> str:
    receipt = exact_object(read_canonical(receipt_path, "receipt"), RECEIPT_FIELDS, "receipt")
    payload = validate_claims(receipt["payload"])
    key_id, public_key = read_trusted_key(trusted_key_path)
    if payload["signer_key_id"] != key_id:
        raise EvidenceError("untrusted signer_key_id")
    try:
        public_key.verify(decode_b64(receipt["signature_b64"], "signature_b64", 64), canonical_json(payload))
    except InvalidSignature as error:
        raise EvidenceError("invalid receipt signature") from error

    directory = _evidence_directory(evidence_dir)
    artifacts: dict[str, Any] = {}
    raws: dict[str, bytes] = {}
    for field, filename in DIGEST_FILES.items():
        value, raw = _artifact(directory, filename, filename)
        if hashlib.sha256(raw).hexdigest() != payload[field]:
            raise EvidenceError(f"digest mismatch for {filename}")
        artifacts[field] = value
        raws[field] = raw
    compute_receipt = _verify_g009(
        directory, artifacts["image_sha256"], artifacts["facade_sha256"]
    )
    current = timestamp(now, "now")
    _validate_g009_time(compute_receipt["payload"], payload, current)
    _validate_semantics(artifacts, raws, payload, compute_receipt)


    issued = timestamp(payload["issued_at"], "issued_at")
    expires = timestamp(payload["expires_at"], "expires_at")
    if current < issued or current >= expires:
        raise EvidenceError("receipt is stale or not yet valid")
    return hashlib.sha256(canonical_json({"contract_version": CONTRACT_VERSION, "receipt_sha256": hashlib.sha256(canonical_json(receipt)).hexdigest()})).hexdigest()


def _integer(value: Any, label: str, expected: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or (expected is not None and value != expected):
        raise EvidenceError(f"invalid {label}")
    return value


def _zero(value: Any, label: str) -> None:
    _integer(value, label, 0)



def _validate_instance(instance: Any, image: Any, compute_receipt: Any) -> None:
    image = exact_object(image, frozenset({
        "archiveSizeBytes", "candidate_manifest_sha256", "compute_receipt_sha256",
        "diskSizeGb", "family", "guestOsFeatures", "id", "image_generation", "name",
        "runtime_image_digest", "selfLink", "status", "storageLocations",
    }), "image evidence")
    if image["status"] != "READY" or image["family"] != "recova-jambonz-g009-disabled":
        raise EvidenceError("invalid G009 image state")
    string(image["archiveSizeBytes"], "image archiveSizeBytes")
    string(image["diskSizeGb"], "image diskSizeGb")
    string(image["name"], "image name")
    if not isinstance(image["guestOsFeatures"], list) or not image["guestOsFeatures"]:
        raise EvidenceError("invalid image guest OS features")
    if image["storageLocations"] != ["asia"]:
        raise EvidenceError("invalid image storage location")
    probe = exact_object(compute_receipt["payload"]["private_probe"], frozenset({
        "bytes_sent", "instance_id", "registration_profile_absent",
        "rtp_flow_records", "services", "sip_flow_records",
    }), "G009 private probe")
    for name in ("bytes_sent", "rtp_flow_records", "sip_flow_records"):
        _zero(probe[name], f"G009 private probe {name}")
    _integer(probe["services"], "G009 private probe services", 13)
    if probe["registration_profile_absent"] is not True:
        raise EvidenceError("G009 private probe registration profile is present")
    if isinstance(probe["instance_id"], bool) or not isinstance(probe["instance_id"], int) or probe["instance_id"] <= 0:
        raise EvidenceError("invalid G009 private probe instance_id")
    fields = frozenset({
        "boot_source_image_self_link", "external_access_config_count", "id", "labels",
        "metadata", "name", "network_ip_sha256", "network_self_link",
        "service_account_sha256", "shieldedInstanceConfig", "status", "subnetwork_self_link",
    })
    instance = exact_object(instance, fields, "instance evidence")
    if instance["status"] != "RUNNING":
        raise EvidenceError("instance is not RUNNING")
    _zero(instance["external_access_config_count"], "external_access_config_count")
    labels = exact_object(instance["labels"], frozenset({
        "application", "calls", "compute", "dispatch", "environment",
        "goog-terraform-provisioned", "managed_by", "phase", "region", "rtp",
        "run_id", "sip", "workload",
    }), "instance labels")
    expected_labels = {
        "application": "recova", "calls": "disabled", "compute": "running",
        "dispatch": "disabled", "environment": "staging",
        "goog-terraform-provisioned": "true", "managed_by": "terraform",
        "phase": "c-smoke", "region": "asia-northeast3", "rtp": "disabled",
        "sip": "disabled", "workload": "candidate",
    }
    if any(labels[name] != expected for name, expected in expected_labels.items()):
        raise EvidenceError("invalid staging/disabled instance labels")
    string(labels["run_id"], "instance labels.run_id")
    metadata = exact_object(instance["metadata"], frozenset({
        "g009-image-generation", "g009-image-id", "g009-image-receipt-sha256",
        "inbound-call-enabled", "media-enabled", "outbound-call-enabled",
        "serial-port-enable", "sip-register-enabled", "workload-dispatch-enabled",
    }), "instance metadata")
    for gate in ("inbound-call-enabled", "media-enabled", "outbound-call-enabled",
                 "sip-register-enabled", "workload-dispatch-enabled", "serial-port-enable"):
        if metadata[gate] != "FALSE":
            raise EvidenceError("instance metadata gate is not FALSE")
    shielded = exact_object(instance["shieldedInstanceConfig"], frozenset({
        "enableIntegrityMonitoring", "enableSecureBoot", "enableVtpm",
    }), "shieldedInstanceConfig")
    if any(value is not True for value in shielded.values()):
        raise EvidenceError("shielded instance protections are not all enabled")
    if instance["boot_source_image_self_link"] != image["selfLink"]:
        raise EvidenceError("instance boot source image mismatch")
    payload = compute_receipt["payload"]
    if metadata["g009-image-id"] != image["id"] or metadata["g009-image-generation"] != str(image["image_generation"]):
        raise EvidenceError("instance image metadata mismatch")
    if metadata["g009-image-receipt-sha256"] != compute_receipt["candidate_receipt_sha256"]:
        raise EvidenceError("instance compute receipt payload digest mismatch")
    for name in ("network_ip_sha256", "service_account_sha256"):
        digest(instance[name], f"instance {name}")
    string(instance["name"], "instance name")
    string(instance["network_self_link"], "instance network_self_link")
    string(instance["subnetwork_self_link"], "instance subnetwork_self_link")
    if payload["project_id"] not in instance["network_self_link"] or payload["project_id"] not in instance["subnetwork_self_link"]:
        raise EvidenceError("instance network identity does not match project")


def _validate_application(application: Any, tenant: Any, claims: dict[str, Any]) -> None:
    application = exact_object(application, frozenset({
        "boot_marker", "gates", "observation_window", "product_status", "project_id",
        "registration_profile_absent", "run_id", "services",
    }), "application evidence")
    _integer(application["services"], "application services", 13)
    if application["registration_profile_absent"] is not True:
        raise EvidenceError("registration profile is present")
    gates = exact_object(application["gates"], frozenset({
        "inbound-call-enabled", "media-enabled", "outbound-call-enabled",
        "sip-register-enabled", "workload-dispatch-enabled",
    }), "application gates")
    if any(value != "FALSE" for value in gates.values()):
        raise EvidenceError("application gate is not FALSE")
    if application["product_status"] != "Waiting":
        raise EvidenceError("application product status is not Waiting")
    if application["project_id"] != tenant["project_id"] or application["run_id"] != tenant["run_id"]:
        raise EvidenceError("application tenant binding mismatch")
    if application["observation_window"] != claims["observation_window"]:
        raise EvidenceError("application observation window mismatch")
    string(application["boot_marker"], "application boot_marker")


def _validate_traffic(flow: Any, provider: Any, claims: dict[str, Any]) -> None:
    flow = exact_object(flow, frozenset({
        "bytes_sent", "destination_ip_sha256_counts", "destination_ports",
        "packets_attempted", "protocols", "records", "rtp_records", "sip_records", "window",
    }), "flow evidence")
    for name in ("bytes_sent", "rtp_records", "sip_records"):
        _zero(flow[name], f"flow {name}")
    for name in ("packets_attempted", "records"):
        if _integer(flow[name], f"flow {name}") < 0:
            raise EvidenceError(f"invalid flow {name}")
    hashes = flow["destination_ip_sha256_counts"]
    if not isinstance(hashes, dict) or any(not SHA256.fullmatch(key) or _integer(value, "destination hash count") < 0
                                           for key, value in hashes.items()):
        raise EvidenceError("invalid redacted flow destinations")
    for name, expected_keys in (("destination_ports", {"443"}), ("protocols", {"6"})):
        counts = flow[name]
        if not isinstance(counts, dict) or not set(counts) <= expected_keys:
            raise EvidenceError("flow contains non-HTTPS destination data")
        if any(_integer(value, f"flow {name} count") < 0 for value in counts.values()):
            raise EvidenceError(f"invalid flow {name} count")
    if flow["window"] != claims["observation_window"]:
        raise EvidenceError("flow observation window mismatch")
    provider = exact_object(provider, frozenset({
        "bytes_sent", "call_flow_records", "observation_window", "register_events",
        "registration_profile_absent", "rtp_flow_records", "sip_flow_records",
    }), "provider evidence")
    for name in ("bytes_sent", "call_flow_records", "register_events", "rtp_flow_records", "sip_flow_records"):
        _zero(provider[name], f"provider {name}")
    if provider["registration_profile_absent"] is not True:
        raise EvidenceError("provider registration profile is present")
    if provider["observation_window"] != claims["observation_window"]:
        raise EvidenceError("provider observation window mismatch")


def _validate_firewalls(value: Any, instance: Any) -> None:
    value = exact_object(value, frozenset({"rules"}), "firewall evidence")
    rules = value["rules"]
    if not isinstance(rules, list) or len(rules) != 5:
        raise EvidenceError("firewall evidence must contain exactly five rules")
    enabled = [rule for rule in rules if isinstance(rule, dict) and rule.get("disabled") is False]
    disabled = [rule for rule in rules if isinstance(rule, dict) and rule.get("disabled") is True]
    if len(enabled) != 2 or len(disabled) != 3:
        raise EvidenceError("invalid enabled/disabled firewall rule counts")
    service_accounts: set[str] = set()
    for rule in rules:
        accounts = _field(rule, "targetServiceAccounts", "firewall rule")
        if not isinstance(accounts, list) or len(accounts) != 1:
            raise EvidenceError("invalid firewall target service account")
        service_accounts.add(string(accounts[0], "firewall target service account"))
    if len(service_accounts) != 1 or hashlib.sha256(next(iter(service_accounts)).encode()).hexdigest() != instance["service_account_sha256"]:
        raise EvidenceError("firewall target service account mismatch")
    prefix = instance["name"].removesuffix("-vm")
    by_name = {string(rule.get("name"), "firewall name"): rule for rule in rules}
    expected_names = {
        f"{prefix}-deny-in", f"{prefix}-deny-out", f"{prefix}-recova-in",
        f"{prefix}-sip-in", f"{prefix}-sip-out",
    }
    if set(by_name) != expected_names:
        raise EvidenceError("firewall rule names do not match exact Phase C graph")

    enabled_fields = frozenset({
        "allowed", "denied", "destinationRanges", "direction", "disabled", "id",
        "logConfig", "name", "priority", "sourceRanges", "targetServiceAccounts",
    })
    deny_common = {
        "allowed": None,
        "denied": [{"IPProtocol": "all"}],
        "disabled": False,
        "logConfig": {"enable": True, "metadata": "INCLUDE_ALL_METADATA"},
        "priority": 65534,
    }
    deny_in = exact_object(by_name[f"{prefix}-deny-in"], enabled_fields, "ingress deny rule")
    deny_out = exact_object(by_name[f"{prefix}-deny-out"], enabled_fields, "egress deny rule")
    for key, expected in deny_common.items():
        if deny_in[key] != expected or deny_out[key] != expected:
            raise EvidenceError("enabled firewall rule is not logged deny-all")
    if (
        deny_in["direction"] != "INGRESS"
        or deny_in["sourceRanges"] != ["0.0.0.0/0"]
        or deny_in["destinationRanges"] is not None
        or deny_out["direction"] != "EGRESS"
        or deny_out["sourceRanges"] is not None
        or deny_out["destinationRanges"] != ["0.0.0.0/0"]
    ):
        raise EvidenceError("enabled deny-all firewall ranges are not blanket")

    disabled_specs = {
        f"{prefix}-recova-in": (
            "INGRESS", 1100, [{"IPProtocol": "tcp", "ports": ["443"]}],
            "sourceRanges_sha256",
        ),
        f"{prefix}-sip-in": (
            "INGRESS", 1110, [{"IPProtocol": "udp", "ports": ["5060"]}],
            "sourceRanges_sha256",
        ),
        f"{prefix}-sip-out": (
            "EGRESS", 1110, [{"IPProtocol": "udp", "ports": ["5060"]}],
            "destinationRanges_sha256",
        ),
    }
    range_digests: dict[str, str] = {}
    for name, (direction, priority, allowed, range_field) in disabled_specs.items():
        rule = exact_object(by_name[name], frozenset({
            "allowed", "denied", "direction", "disabled", "id", "logConfig", "name",
            "priority", range_field, "targetServiceAccounts",
        }), "disabled firewall rule")
        if (
            rule["direction"] != direction
            or rule["priority"] != priority
            or rule["allowed"] != allowed
            or rule["denied"] is not None
            or rule["disabled"] is not True
            or rule["logConfig"] != {"enable": False}
        ):
            raise EvidenceError("disabled allow rule does not match exact tuple")
        range_digests[name] = digest(rule[range_field], f"firewall {range_field}")
    if range_digests[f"{prefix}-sip-in"] != range_digests[f"{prefix}-sip-out"]:
        raise EvidenceError("SIP ingress/egress endpoint range digests differ")


def _validate_destroy(plan: Any, durable: Any, claims: dict[str, Any]) -> None:
    plan = exact_object(plan, frozenset({
        "action_counts", "phase_b_resource_count", "resource_count", "resources",
        "schema_version", "source_plan_sha256",
    }), "destroy plan")
    if plan["schema_version"] != "recova-phase-c-destroy-plan-summary/v1":
        raise EvidenceError("invalid destroy plan schema")
    counts = exact_object(plan["action_counts"], frozenset({"create", "delete", "no-op", "update"}), "destroy action counts")
    for name in ("create", "update", "no-op"):
        _zero(counts[name], f"destroy {name} count")
    _integer(counts["delete"], "destroy delete count", 32)
    _integer(plan["resource_count"], "destroy resource count", 32)
    _zero(plan["phase_b_resource_count"], "phase B resource count")
    resources = plan["resources"]
    if not isinstance(resources, list) or len(resources) != 32:
        raise EvidenceError("destroy plan must contain exactly 32 resources")
    actual_resources: set[tuple[str, str]] = set()
    for resource in resources:
        resource = exact_object(resource, frozenset({"actions", "address", "type"}), "destroy resource")
        if resource["actions"] != ["delete"]:
            raise EvidenceError("destroy resource action is not exactly delete")
        address = string(resource["address"], "destroy resource address")
        resource_type = string(resource["type"], "destroy resource type")
        actual_resources.add((address, resource_type))
    if actual_resources != EXPECTED_DESTROY_RESOURCES:
        raise EvidenceError("destroy plan does not match exact Phase C resource set")
    digest(plan["source_plan_sha256"], "source_plan_sha256")

    durable = exact_object(durable, frozenset({
        "cleanup_bundle_sha256", "destroy_before_deadline", "dry_run_build_id",
        "dry_run_status", "job_name", "phase_c_deadline", "schedule", "scheduleTime",
        "state", "timeZone",
    }), "durable destroy")
    if durable["state"] != "ENABLED" or durable["timeZone"] != "UTC" or durable["dry_run_status"] != "SUCCESS":
        raise EvidenceError("durable destroy scheduler is not enabled and verified")
    if durable["destroy_before_deadline"] is not True:
        raise EvidenceError("destroy is not scheduled before deadline")
    schedule = timestamp(durable["scheduleTime"], "durable scheduleTime")
    deadline = timestamp(durable["phase_c_deadline"], "phase_c_deadline")
    observation_end = timestamp(claims["observation_window"]["ended_at"], "observation end")
    if not observation_end < schedule < deadline:
        raise EvidenceError("durable destroy schedule is outside the allowed window")
    receipt_issued = timestamp(claims["issued_at"], "G007 issued_at")
    if deadline > receipt_issued + timedelta(hours=24):
        raise EvidenceError("phase C deadline exceeds 24 hours from staging receipt issuance")
    digest(durable["cleanup_bundle_sha256"], "cleanup_bundle_sha256")
    string(durable["dry_run_build_id"], "dry_run_build_id")
    string(durable["job_name"], "destroy job_name")
    expected_cron = f"{schedule.minute} {schedule.hour} {schedule.day} {schedule.month} *"
    if durable["schedule"] != expected_cron:
        raise EvidenceError("durable destroy cron does not match scheduleTime")

def _expected_build_request(service_account: str, bundle_uri: str,
                            bundle_sha: str, final_args: list[str]) -> dict[str, Any]:
    archive = "/workspace/phase-c-cleanup-bundle.tar.gz"
    download = (
        f"gcloud storage cp {bundle_uri} {archive} && "
        f"echo '{bundle_sha}  {archive}' | sha256sum -c - && "
        f"tar -xzf {archive} -C /workspace"
    )
    return {
        "options": {"logging": "CLOUD_LOGGING_ONLY"},
        "serviceAccount": service_account,
        "steps": [
            {
                "args": ["-ceu", download],
                "entrypoint": "bash",
                "name": "gcr.io/google.com/cloudsdktool/cloud-sdk:slim",
            },
            {
                "args": [
                    "init", "-reconfigure", "-input=false",
                    "-backend-config=phase-c-backend.hcl",
                ],
                "dir": "phase-c",
                "entrypoint": "terraform",
                "name": "hashicorp/terraform:1.15.8",
            },
            {
                "args": final_args,
                "dir": "phase-c",
                "entrypoint": "terraform",
                "name": "hashicorp/terraform:1.15.8",
            },
        ],
        "timeout": "3600s",
    }


def _validate_destroy_execution(value: Any, durable: Any, tenant: Any,
                                claims: dict[str, Any], build_request: Any,
                                dry_run_request: Any, build_result: Any) -> None:
    value = exact_object(value, frozenset({
        "backend", "build_request_sha256", "build_service_account",
        "cleanup_bundle_sha256", "cleanup_bundle_uri", "destroy_args",
        "dry_run_request_sha256", "dry_run_result_sha256", "iam", "init_args",
        "phase_c_deadline", "project_id", "run_id", "scheduler",
        "schema_version",
    }), "destroy execution")
    if value["schema_version"] != "recova-phase-c-destroy-execution/v1":
        raise EvidenceError("invalid destroy execution schema")
    project = string(tenant["project_id"], "tenant project_id")
    run_id = string(tenant["run_id"], "tenant run_id")
    if value["project_id"] != project or value["run_id"] != run_id:
        raise EvidenceError("destroy execution tenant mismatch")
    if value["phase_c_deadline"] != durable["phase_c_deadline"]:
        raise EvidenceError("destroy execution deadline mismatch")

    cleanup = f"onnuri-phase-c-cleanup@{project}.iam.gserviceaccount.com"
    bucket = f"{project}-onnuri-phase-c-tfstate"
    request_sha = digest(value["build_request_sha256"], "build_request_sha256")
    dry_request_sha = digest(value["dry_run_request_sha256"], "dry_run_request_sha256")
    dry_result_sha = digest(value["dry_run_result_sha256"], "dry_run_result_sha256")
    bundle_sha = digest(value["cleanup_bundle_sha256"], "cleanup_bundle_sha256")
    if request_sha != claims["destroy_build_request_sha256"]:
        raise EvidenceError("scheduled build request digest mismatch")
    if dry_request_sha != claims["destroy_dry_run_request_sha256"]:
        raise EvidenceError("dry-run build request digest mismatch")
    if dry_result_sha != claims["destroy_build_result_sha256"]:
        raise EvidenceError("dry-run build result digest mismatch")
    if value["build_service_account"] != f"projects/{project}/serviceAccounts/{cleanup}":
        raise EvidenceError("destroy build service account mismatch")
    if bundle_sha != durable["cleanup_bundle_sha256"]:
        raise EvidenceError("destroy cleanup bundle mismatch")
    if value["cleanup_bundle_uri"] != f"gs://{bucket}/cleanup/{run_id}/phase-c-cleanup-bundle.tar.gz":
        raise EvidenceError("destroy cleanup bundle URI mismatch")
    backend = exact_object(value["backend"], frozenset({"bucket", "prefix"}), "destroy backend")
    if backend != {
        "bucket": bucket,
        "prefix": f"onnuri-seoul-staging-phase-c-smoke/{run_id}",
    }:
        raise EvidenceError("destroy backend mismatch")
    if value["init_args"] != [
        "init", "-reconfigure", "-input=false", "-backend-config=phase-c-backend.hcl",
    ]:
        raise EvidenceError("destroy init command mismatch")
    if value["destroy_args"] != [
        "destroy", "-auto-approve", "-input=false", "-lock-timeout=300s",
        "-var-file=phase-c.tfvars.json",
    ]:
        raise EvidenceError("destroy command is not executable auto-approved teardown")

    service_account = value["build_service_account"]
    expected_scheduled = _expected_build_request(
        service_account, value["cleanup_bundle_uri"], bundle_sha, value["destroy_args"]
    )
    if build_request != expected_scheduled:
        raise EvidenceError("scheduled build request semantics mismatch")
    plan_args = [
        "plan", "-destroy", "-input=false", "-lock=false",
        "-var-file=phase-c.tfvars.json",
    ]
    expected_dry_run = _expected_build_request(
        service_account, value["cleanup_bundle_uri"], bundle_sha, plan_args
    )
    if dry_run_request != expected_dry_run:
        raise EvidenceError("dry-run build request semantics mismatch")

    scheduler = exact_object(value["scheduler"], frozenset({
        "attempt_deadline", "body_sha256", "http_method", "name",
        "oauth_service_account", "schedule", "schedule_time", "state",
        "time_zone", "uri",
    }), "destroy scheduler")
    expected_job = f"projects/{project}/locations/asia-northeast3/jobs/onnuri-{run_id}-destroy"
    if scheduler != {
        "attempt_deadline": "180s",
        "body_sha256": request_sha,
        "http_method": "POST",
        "name": expected_job,
        "oauth_service_account": cleanup,
        "schedule": durable["schedule"],
        "schedule_time": durable["scheduleTime"],
        "state": "ENABLED",
        "time_zone": "UTC",
        "uri": f"https://cloudbuild.googleapis.com/v1/projects/{project}/locations/global/builds",
    }:
        raise EvidenceError("destroy scheduler/build request binding mismatch")
    if durable["job_name"] != expected_job:
        raise EvidenceError("durable destroy job mismatch")

    iam = exact_object(value["iam"], frozenset({
        "condition_expression_sha256", "condition_title", "principal_sha256",
        "project_roles", "service_account_act_as_principal_sha256",
        "service_account_act_as_role", "storage_bucket", "storage_role",
    }), "destroy IAM")
    condition = f"request.time < timestamp('{durable['phase_c_deadline']}')"
    required_roles = [
        "roles/cloudbuild.builds.editor", "roles/compute.admin",
        "roles/iam.roleAdmin", "roles/iam.serviceAccountAdmin",
        "roles/logging.admin", "roles/logging.logWriter", "roles/monitoring.admin",
        "roles/resourcemanager.projectIamAdmin", "roles/secretmanager.admin",
    ]
    if iam["condition_title"] != "phase-c-destroy-before-expiry":
        raise EvidenceError("destroy IAM condition title mismatch")
    if iam["condition_expression_sha256"] != hashlib.sha256(condition.encode()).hexdigest():
        raise EvidenceError("destroy IAM deadline condition mismatch")
    if iam["principal_sha256"] != hashlib.sha256(cleanup.encode()).hexdigest():
        raise EvidenceError("destroy IAM principal mismatch")
    if iam["project_roles"] != required_roles:
        raise EvidenceError("destroy IAM roles are incomplete or unordered")
    if iam["storage_bucket"] != bucket or iam["storage_role"] != "roles/storage.objectAdmin":
        raise EvidenceError("destroy state storage IAM mismatch")
    if (
        iam["service_account_act_as_role"] != "roles/iam.serviceAccountUser"
        or iam["service_account_act_as_principal_sha256"] != iam["principal_sha256"]
    ):
        raise EvidenceError("destroy build service-account actAs binding mismatch")

    build_result = exact_object(build_result, frozenset({
        "build_id", "cleanup_bundle_sha256", "create_time", "finish_time",
        "init_args", "plan_args", "request_sha256", "scheduled_request_sha256",
        "schema_version", "service_account", "start_time", "status",
        "step_statuses",
    }), "destroy build result")
    if build_result != {
        "build_id": durable["dry_run_build_id"],
        "cleanup_bundle_sha256": bundle_sha,
        "create_time": build_result["create_time"],
        "finish_time": build_result["finish_time"],
        "init_args": value["init_args"],
        "plan_args": plan_args,
        "request_sha256": dry_request_sha,
        "scheduled_request_sha256": request_sha,
        "schema_version": "recova-phase-c-cleanup-build-result/v1",
        "service_account": service_account,
        "start_time": build_result["start_time"],
        "status": "SUCCESS",
        "step_statuses": ["SUCCESS", "SUCCESS", "SUCCESS"],
    }:
        raise EvidenceError("destroy dry-run result binding mismatch")
    created = timestamp(build_result["create_time"], "destroy build create_time")
    started = timestamp(build_result["start_time"], "destroy build start_time")
    finished = timestamp(build_result["finish_time"], "destroy build finish_time")
    if not created <= started < finished:
        raise EvidenceError("destroy dry-run timestamps are invalid")
    schedule = timestamp(scheduler["schedule_time"], "destroy scheduler time")
    issued = timestamp(claims["issued_at"], "G007 issued_at")
    deadline = timestamp(value["phase_c_deadline"], "destroy execution deadline")
    if not issued < schedule < deadline <= issued + timedelta(hours=24):
        raise EvidenceError("destroy execution is outside the G007 TTL")


def _validate_secrets(value: Any) -> None:
    value = exact_object(value, frozenset({
        "bindings", "numeric_versions_only", "reference_count", "secret_values_read",
    }), "secret references")
    if value["secret_values_read"] is not False or value["numeric_versions_only"] is not True:
        raise EvidenceError("invalid secret reference policy")
    _integer(value["reference_count"], "secret reference_count", 7)
    bindings = value["bindings"]
    expected = {
        "callback_hmac_key", "f12_endpoint_credential", "f12_mtls_certificate",
        "facade_adapter_credential", "sip_password", "stock_local_api_credential",
        "tls_private_key",
    }
    if not isinstance(bindings, list) or len(bindings) != 7:
        raise EvidenceError("secret references must contain exactly seven bindings")
    purposes: set[str] = set()
    fields = frozenset({
        "condition_expression_sha256", "condition_title", "member_sha256",
        "numeric_version_only", "purpose", "role_sha256", "secret_reference_sha256",
    })
    for binding in bindings:
        binding = exact_object(binding, fields, "secret binding")
        purposes.add(string(binding["purpose"], "secret purpose"))
        if binding["numeric_version_only"] is not True or binding["condition_title"] != "numeric-version-before-phase-c-expiry":
            raise EvidenceError("invalid numeric secret binding")
        for name in fields:
            if name.endswith("_sha256"):
                digest(binding[name], f"secret binding {name}")
    if purposes != expected:
        raise EvidenceError("secret purposes are incomplete or duplicated")


def _validate_phase_b(before: Any, after: Any, before_raw: bytes, after_raw: bytes, instance: Any) -> None:
    if before_raw != after_raw or before != after:
        raise EvidenceError("Phase B before/after evidence differs")
    phase = exact_object(before, frozenset({"network", "rules", "subnet"}), "Phase B evidence")
    network = phase["network"]
    subnet = phase["subnet"]
    if _field(network, "selfLink", "Phase B network") != instance["network_self_link"]:
        raise EvidenceError("Phase B network does not match instance")
    if _field(subnet, "selfLink", "Phase B subnet") != instance["subnetwork_self_link"]:
        raise EvidenceError("Phase B subnet does not match instance")
    if subnet.get("privateIpGoogleAccess") is not True or subnet.get("ipCidrRange") != "10.73.96.0/24":
        raise EvidenceError("invalid Phase B private subnet")
    sampling = subnet.get("logConfig", {}).get("flowSampling")
    if isinstance(sampling, bool) or sampling != 1.0:
        raise EvidenceError("Phase B full flow logging is not enabled")
    if subnet.get("logConfig") != {
        "aggregationInterval": "INTERVAL_5_SEC", "enable": True, "filterExpr": "true",
        "flowSampling": 1.0, "metadata": "INCLUDE_ALL_METADATA",
    }:
        raise EvidenceError("Phase B full flow logging is not enabled")
    rules = phase["rules"]
    if not isinstance(rules, list) or len(rules) != 2:
        raise EvidenceError("Phase B must contain exactly two firewall rules")
    for rule in rules:
        if rule.get("disabled") is not False or rule.get("denied") != [{"IPProtocol": "all"}] or rule.get("logConfig") != {
            "enable": True, "metadata": "INCLUDE_ALL_METADATA",
        }:
            raise EvidenceError("Phase B firewall is not active logged deny-all")
    if {rule.get("direction") for rule in rules} != {"INGRESS", "EGRESS"}:
        raise EvidenceError("Phase B deny-all directions are incomplete")


def _validate_semantics(artifacts: dict[str, Any], raws: dict[str, bytes], claims: dict[str, Any],
                        compute_receipt: dict[str, Any]) -> None:
    tenant = exact_object(artifacts["tenant_sha256"], frozenset({"binding", "project_id", "run_id"}), "tenant evidence")
    if tenant["binding"] != "none-before-g3":
        raise EvidenceError("invalid tenant binding")
    string(tenant["project_id"], "tenant project_id")
    string(tenant["run_id"], "tenant run_id")
    instance = artifacts["instance_sha256"]
    image = artifacts["image_sha256"]
    _validate_instance(instance, image, compute_receipt)
    exact_object(artifacts["facade_sha256"], frozenset({
        "candidate_manifest_sha256", "compute_receipt_sha256", "image_digest", "name",
    }), "facade evidence")
    if artifacts["facade_sha256"]["name"] != "facade":
        raise EvidenceError("invalid facade binding")
    if instance["labels"]["run_id"] != tenant["run_id"] or compute_receipt["payload"]["project_id"] != tenant["project_id"]:
        raise EvidenceError("instance tenant binding mismatch")
    application = artifacts["application_gate_process_state_sha256"]
    _validate_application(application, tenant, claims)
    _validate_traffic(artifacts["flow_log_sha256"],
                      artifacts["provider_no_registration_no_call_receipt_sha256"], claims)
    _validate_firewalls(artifacts["effective_firewall_sha256"], instance)
    containment = exact_object(artifacts["containment_stop_drill_sha256"], frozenset({
        "count", "instance_name", "method", "observed", "post_restart_marker", "principal_sha256",
    }), "containment evidence")
    if containment["observed"] is not True or containment["method"] != "v1.compute.instances.stop":
        raise EvidenceError("containment stop was not observed")
    if containment["instance_name"] != instance["name"] or containment["post_restart_marker"] != application["boot_marker"]:
        raise EvidenceError("containment evidence binding mismatch")
    if _integer(containment["count"], "containment count") <= 0:
        raise EvidenceError("containment count is not positive")
    expected_containment = (
        instance["name"].removesuffix("-vm")
        + "-contain@"
        + tenant["project_id"]
        + ".iam.gserviceaccount.com"
    )
    if containment["principal_sha256"] != hashlib.sha256(expected_containment.encode()).hexdigest():
        raise EvidenceError("containment principal is not the dedicated service account")
    _validate_destroy(artifacts["destroy_plan_sha256"],
                      artifacts["durable_destroy_arm_receipt_sha256"], claims)
    _validate_destroy_execution(
        artifacts["destroy_execution_sha256"],
        artifacts["durable_destroy_arm_receipt_sha256"],
        tenant,
        claims,
        artifacts["destroy_build_request_sha256"],
        artifacts["destroy_dry_run_request_sha256"],
        artifacts["destroy_build_result_sha256"],
    )
    _validate_secrets(artifacts["secret_reference_policy_sha256"])
    _validate_phase_b(artifacts["phase_b_before_sha256"], artifacts["phase_b_after_sha256"],
                      raws["phase_b_before_sha256"], raws["phase_b_after_sha256"], instance)


def _validate_g009_time(payload: dict[str, Any], claims: dict[str, Any],
                        current: datetime) -> None:
    issued = timestamp(payload["candidate_receipt_issued_at_utc"], "G009 receipt issued_at")
    expires = timestamp(payload["candidate_receipt_expires_at_utc"], "G009 receipt expires_at")
    observation_start = timestamp(claims["observation_window"]["started_at"], "observation start")
    observation_end = timestamp(claims["observation_window"]["ended_at"], "observation end")
    g007_issued = timestamp(claims["issued_at"], "G007 issued_at")
    g007_expires = timestamp(claims["expires_at"], "G007 expires_at")
    if not issued < expires <= issued + timedelta(hours=24):
        raise EvidenceError("G009 receipt timestamps are invalid")
    if not (
        issued <= observation_start <= observation_end <= g007_issued
        <= current < g007_expires <= expires
    ):
        raise EvidenceError("G007 evidence falls outside G009 receipt validity")
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--trusted-key", required=True)
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--now", required=True)
    args = parser.parse_args(argv)
    try:
        print(verify(args.receipt, args.trusted_key, args.evidence_dir, args.now))
    except (EvidenceError, OSError) as error:
        print(f"G007 evidence verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
