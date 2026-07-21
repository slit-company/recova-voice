#!/usr/bin/env python3
"""Deterministically validate one already-acquired Jambonz candidate manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
EVIDENCE = re.compile(r"evidence:[A-Za-z0-9._/-]{1,240}\Z")
GCP_PROJECT = re.compile(r"[a-z][a-z0-9-]{4,61}[a-z0-9]\Z")
GCP_IMAGE_NAME = re.compile(r"[a-z]([-a-z0-9]{0,61}[a-z0-9])?\Z")
STOCK_IMAGE_ID = "8849856699999487269"
STOCK_EXPORT_SHA256 = "sha256:106c4544fdd0450d7f9c4383f0d8028c490ee949173bc0ce1c507c3339400c73"
NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
PHONE = re.compile(r"(?<![0-9A-Fa-f])(?:\+?[0-9][ ()-]*){10,15}(?![0-9A-Fa-f])")
INDEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
INDEX_SCHEMA_VERSION = "onnuri-jambonz-evidence-index/v1"
EVIDENCE_KINDS = {
    "license_entitlement",
    "provenance_statement",
    "sbom",
    "vulnerability_report",
    "hardening_receipt",
    "one_shot_receipt",
    "acquisition_receipt",
    "authorized_readers",
    "renewed_review",
    "disqualifier",
    "redaction_attestation",
}
SENSITIVE = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.I),
    re.compile(r"\b(?:bearer|basic)\s+[A-Za-z0-9+/_.=-]{8,}", re.I),
    re.compile(r"\b(?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*\S+", re.I),
    re.compile(r"\bsips?:[^\s]+", re.I),
    re.compile(r"(?:^|\n)(?:v=0|o=\S+\s+\d+\s+\d+\s+IN\s+IP|m=audio\s+\d+)", re.I),
    re.compile(r"data:audio/", re.I),
    re.compile(r"\b(?:RTP/(?:AVP|SAVP)|(?:RTP|RTCP)\s*(?:packet|payload))\b", re.I),
)
UNRESOLVED = re.compile(r"(?:^|[^a-z])(?:pending|unknown|unresolved|tbd|todo|n/?a)(?:$|[^a-z])", re.I)
MAX_TEXT_EVIDENCE_BYTES = 1_048_576

Errors = list[str]


def duplicate_safe_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def obj(value: Any, path: str, required: set[str], errors: Errors) -> dict[str, Any]:
    if not isinstance(value, dict):
        errors.append(f"{path}: expected object")
        return {}
    missing = required - value.keys()
    unknown = value.keys() - required
    errors.extend(f"{path}: missing field {key}" for key in sorted(missing))
    errors.extend(f"{path}: unknown field {key}" for key in sorted(unknown))
    return value


def string(value: Any, path: str, errors: Errors, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value:
        errors.append(f"{path}: expected non-empty string")
        return ""
    if pattern is not None and pattern.fullmatch(value) is None:
        errors.append(f"{path}: invalid format")
    return value


def exact(value: Any, expected: Any, path: str, errors: Errors) -> None:
    if value != expected or type(value) is not type(expected):
        errors.append(f"{path}: expected {expected!r}")


def boolean(value: Any, path: str, errors: Errors) -> bool:
    if type(value) is not bool:
        errors.append(f"{path}: expected boolean")
        return False
    return value


def integer(value: Any, path: str, errors: Errors) -> int:
    if type(value) is not int:
        errors.append(f"{path}: expected integer")
        return 0
    return value


def timestamp(value: Any, path: str, errors: Errors) -> datetime | None:
    text = string(value, path, errors)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"{path}: invalid RFC 3339 timestamp")
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        errors.append(f"{path}: timestamp must include an offset")
        return None
    return parsed


def enum(value: Any, allowed: set[str], path: str, errors: Errors) -> str:
    text = string(value, path, errors)
    if text not in allowed:
        errors.append(f"{path}: unsupported value {text!r}")
    return text


def validate_reference(value: Any, path: str, errors: Errors) -> None:
    string(value, path, errors, EVIDENCE)


def validate_digest(value: Any, path: str, errors: Errors) -> None:
    string(value, path, errors, SHA256)


def validate_candidate(value: Any, errors: Errors) -> None:
    path = "candidate"
    data = obj(value, path, {"release", "source_image", "derivative", "license", "provenance", "vulnerability_report", "supported_architectures", "component_topology"}, errors)
    exact(data.get("release"), "10.2.2", f"{path}.release", errors)

    source_image = obj(data.get("source_image"), f"{path}.source_image", {"provider", "project", "name", "immutable_image_id", "export_sha256"}, errors)
    exact(source_image.get("provider"), "gcp", f"{path}.source_image.provider", errors)
    string(source_image.get("project"), f"{path}.source_image.project", errors, GCP_PROJECT)
    string(source_image.get("name"), f"{path}.source_image.name", errors, GCP_IMAGE_NAME)
    exact(source_image.get("immutable_image_id"), STOCK_IMAGE_ID, f"{path}.source_image.immutable_image_id", errors)
    exact(source_image.get("export_sha256"), STOCK_EXPORT_SHA256, f"{path}.source_image.export_sha256", errors)

    derivative = obj(data.get("derivative"), f"{path}.derivative", {"final_disk_sha256", "rootfs_tree_sha256", "hardening_receipt_reference", "hardening_receipt_digest", "one_shot_receipt_reference", "one_shot_receipt_digest"}, errors)
    validate_digest(derivative.get("final_disk_sha256"), f"{path}.derivative.final_disk_sha256", errors)
    validate_digest(derivative.get("rootfs_tree_sha256"), f"{path}.derivative.rootfs_tree_sha256", errors)
    validate_reference(derivative.get("hardening_receipt_reference"), f"{path}.derivative.hardening_receipt_reference", errors)
    validate_digest(derivative.get("hardening_receipt_digest"), f"{path}.derivative.hardening_receipt_digest", errors)
    validate_reference(derivative.get("one_shot_receipt_reference"), f"{path}.derivative.one_shot_receipt_reference", errors)
    validate_digest(derivative.get("one_shot_receipt_digest"), f"{path}.derivative.one_shot_receipt_digest", errors)

    license_data = obj(data.get("license"), f"{path}.license", {"spdx_id", "entitlement_reference", "entitlement_digest", "status"}, errors)
    string(license_data.get("spdx_id"), f"{path}.license.spdx_id", errors)
    validate_reference(license_data.get("entitlement_reference"), f"{path}.license.entitlement_reference", errors)
    validate_digest(license_data.get("entitlement_digest"), f"{path}.license.entitlement_digest", errors)
    exact(license_data.get("status"), "approved", f"{path}.license.status", errors)

    provenance = obj(data.get("provenance"), f"{path}.provenance", {"publisher", "statement_reference", "statement_digest", "signature_status", "sbom_reference", "sbom_digest"}, errors)
    string(provenance.get("publisher"), f"{path}.provenance.publisher", errors)
    validate_reference(provenance.get("statement_reference"), f"{path}.provenance.statement_reference", errors)
    validate_digest(provenance.get("statement_digest"), f"{path}.provenance.statement_digest", errors)
    exact(provenance.get("signature_status"), "verified", f"{path}.provenance.signature_status", errors)
    validate_reference(provenance.get("sbom_reference"), f"{path}.provenance.sbom_reference", errors)
    validate_digest(provenance.get("sbom_digest"), f"{path}.provenance.sbom_digest", errors)

    vulnerability = obj(data.get("vulnerability_report"), f"{path}.vulnerability_report", {"reference", "digest", "tool", "database"}, errors)
    validate_reference(vulnerability.get("reference"), f"{path}.vulnerability_report.reference", errors)
    validate_digest(vulnerability.get("digest"), f"{path}.vulnerability_report.digest", errors)
    string(vulnerability.get("tool"), f"{path}.vulnerability_report.tool", errors)
    database = obj(vulnerability.get("database"), f"{path}.vulnerability_report.database", {"name", "version", "updated_at"}, errors)
    string(database.get("name"), f"{path}.vulnerability_report.database.name", errors)
    string(database.get("version"), f"{path}.vulnerability_report.database.version", errors)
    timestamp(database.get("updated_at"), f"{path}.vulnerability_report.database.updated_at", errors)

    architectures = data.get("supported_architectures")
    if not isinstance(architectures, list) or not architectures:
        errors.append(f"{path}.supported_architectures: expected a non-empty array")
    else:
        if len(architectures) != len(set(item for item in architectures if isinstance(item, str))):
            errors.append(f"{path}.supported_architectures: duplicate architecture")
        for index, architecture in enumerate(architectures):
            enum(architecture, {"amd64", "arm64"}, f"{path}.supported_architectures[{index}]", errors)

    topology = obj(data.get("component_topology"), f"{path}.component_topology", {"components", "connections"}, errors)
    components = topology.get("components")
    names: set[str] = set()
    if not isinstance(components, list) or not components:
        errors.append(f"{path}.component_topology.components: expected a non-empty array")
    else:
        for index, component_value in enumerate(components):
            component_path = f"{path}.component_topology.components[{index}]"
            component = obj(component_value, component_path, {"name", "role", "artifact_digest"}, errors)
            name = string(component.get("name"), f"{component_path}.name", errors, NAME)
            if name in names:
                errors.append(f"{component_path}.name: duplicate component")
            names.add(name)
            enum(component.get("role"), {"sip_signaling", "media", "application", "database", "cache", "metrics"}, f"{component_path}.role", errors)
            validate_digest(component.get("artifact_digest"), f"{component_path}.artifact_digest", errors)
    connections = topology.get("connections")
    if not isinstance(connections, list):
        errors.append(f"{path}.component_topology.connections: expected array")
    else:
        seen: set[tuple[str, str, str]] = set()
        for index, connection_value in enumerate(connections):
            connection_path = f"{path}.component_topology.connections[{index}]"
            connection = obj(connection_value, connection_path, {"from", "to", "purpose"}, errors)
            origin = string(connection.get("from"), f"{connection_path}.from", errors, NAME)
            target = string(connection.get("to"), f"{connection_path}.to", errors, NAME)
            purpose = enum(connection.get("purpose"), {"control", "signaling", "media", "state", "metrics"}, f"{connection_path}.purpose", errors)
            if origin not in names or target not in names:
                errors.append(f"{connection_path}: connection references an undeclared component")
            edge = (origin, target, purpose)
            if edge in seen:
                errors.append(f"{connection_path}: duplicate connection")
            seen.add(edge)


def validate_runtime(value: Any, errors: Errors) -> str:
    path = "runtime_contract"
    data = obj(value, path, {"hooks", "listen", "registration_secret_persistence"}, errors)
    hooks = obj(data.get("hooks"), f"{path}.hooks", {"inbound_initial_application", "outbound_call"}, errors)
    inbound = obj(hooks.get("inbound_initial_application"), f"{path}.hooks.inbound_initial_application", {"timing", "ordered_verbs", "failure_behavior", "synchronous_authority_response"}, errors)
    exact(inbound.get("timing"), "pre_answer", f"{path}.hooks.inbound_initial_application.timing", errors)
    exact(inbound.get("ordered_verbs"), ["answer", "listen"], f"{path}.hooks.inbound_initial_application.ordered_verbs", errors)
    enum(inbound.get("failure_behavior"), {"no_answer_or_listen", "candidate_proven_reject_or_hangup"}, f"{path}.hooks.inbound_initial_application.failure_behavior", errors)
    exact(inbound.get("synchronous_authority_response"), True, f"{path}.hooks.inbound_initial_application.synchronous_authority_response", errors)
    outbound = obj(hooks.get("outbound_call"), f"{path}.hooks.outbound_call", {"timing", "emits_listen_after_authority", "synchronous_authority_response"}, errors)
    exact(outbound.get("timing"), "post_answer", f"{path}.hooks.outbound_call.timing", errors)
    exact(outbound.get("emits_listen_after_authority"), True, f"{path}.hooks.outbound_call.emits_listen_after_authority", errors)
    exact(outbound.get("synchronous_authority_response"), True, f"{path}.hooks.outbound_call.synchronous_authority_response", errors)

    listen = obj(data.get("listen"), f"{path}.listen", {"ws_auth", "sample_rate_hz", "encoding", "channels", "direction"}, errors)
    auth = obj(listen.get("ws_auth"), f"{path}.listen.ws_auth", {"scheme", "username_source", "password_source"}, errors)
    exact(auth.get("scheme"), "basic", f"{path}.listen.ws_auth.scheme", errors)
    exact(auth.get("username_source"), "fixed_non_secret", f"{path}.listen.ws_auth.username_source", errors)
    exact(auth.get("password_source"), "opaque_media_authority", f"{path}.listen.ws_auth.password_source", errors)
    exact(listen.get("sample_rate_hz"), 8000, f"{path}.listen.sample_rate_hz", errors)
    exact(listen.get("encoding"), "L16", f"{path}.listen.encoding", errors)
    exact(listen.get("channels"), 1, f"{path}.listen.channels", errors)
    exact(listen.get("direction"), "bidirectional", f"{path}.listen.direction", errors)

    persistence = obj(data.get("registration_secret_persistence"), f"{path}.registration_secret_persistence", {"classification", "external_runtime_only", "encrypted_ephemeral_mysql", "destroy_with_process_and_disk"}, errors)
    classification = enum(persistence.get("classification"), {"S1", "S2"}, f"{path}.registration_secret_persistence.classification", errors)
    external = boolean(persistence.get("external_runtime_only"), f"{path}.registration_secret_persistence.external_runtime_only", errors)
    mysql = boolean(persistence.get("encrypted_ephemeral_mysql"), f"{path}.registration_secret_persistence.encrypted_ephemeral_mysql", errors)
    exact(persistence.get("destroy_with_process_and_disk"), True, f"{path}.registration_secret_persistence.destroy_with_process_and_disk", errors)
    if classification == "S1" and (not external or mysql):
        errors.append(f"{path}.registration_secret_persistence: S1 requires external-only use and no MySQL persistence")
    if classification == "S2" and (external or not mysql):
        errors.append(f"{path}.registration_secret_persistence: S2 requires encrypted ephemeral MySQL only")
    return classification


def validate_storage(value: Any, classification: str, errors: Errors) -> None:
    path = "storage_contract"
    names = {"mysql", "influxdb", "redis", "logs", "cdr", "recordings"}
    data = obj(value, path, names, errors)
    secret_stores: list[str] = []
    for name in sorted(names):
        store_path = f"{path}.{name}"
        store = obj(data.get(name), store_path, {"enabled", "persistence", "contains_registration_secret", "encrypted_at_rest", "raw_data_enabled", "backup_enabled", "replication_enabled", "export_enabled", "deletion_behavior"}, errors)
        enabled = boolean(store.get("enabled"), f"{store_path}.enabled", errors)
        persistence = enum(store.get("persistence"), {"disabled", "ephemeral"}, f"{store_path}.persistence", errors)
        contains_secret = boolean(store.get("contains_registration_secret"), f"{store_path}.contains_registration_secret", errors)
        encrypted = boolean(store.get("encrypted_at_rest"), f"{store_path}.encrypted_at_rest", errors)
        exact(store.get("raw_data_enabled"), False, f"{store_path}.raw_data_enabled", errors)
        exact(store.get("backup_enabled"), False, f"{store_path}.backup_enabled", errors)
        exact(store.get("replication_enabled"), False, f"{store_path}.replication_enabled", errors)
        exact(store.get("export_enabled"), False, f"{store_path}.export_enabled", errors)
        deletion = enum(store.get("deletion_behavior"), {"not_applicable", "process_and_disk_destroy"}, f"{store_path}.deletion_behavior", errors)
        if enabled and (persistence != "ephemeral" or deletion != "process_and_disk_destroy"):
            errors.append(f"{store_path}: enabled storage must be ephemeral and destroyed with process and disk")
        if not enabled and (persistence != "disabled" or deletion != "not_applicable"):
            errors.append(f"{store_path}: disabled storage must use disabled/not_applicable behavior")
        if contains_secret:
            secret_stores.append(name)
            if not enabled or not encrypted:
                errors.append(f"{store_path}: registration-secret storage must be enabled and encrypted")
        if name != "mysql" and contains_secret:
            errors.append(f"{store_path}: registration secret is permitted only in S2 MySQL")
        if name == "recordings" and enabled:
            errors.append(f"{store_path}: recordings must be disabled")
    if classification == "S1" and secret_stores:
        errors.append(f"{path}: S1 forbids registration-secret persistence")
    if classification == "S2" and secret_stores != ["mysql"]:
        errors.append(f"{path}: S2 requires registration secret only in encrypted ephemeral MySQL")


def validate_network(value: Any, errors: Errors) -> None:
    data = obj(value, "network_contract", {"local_rtp_pool"}, errors)
    pool = obj(data.get("local_rtp_pool"), "network_contract.local_rtp_pool", {"protocol", "port_start", "port_end", "bounded", "host_sdp_exact_narrowing"}, errors)
    exact(pool.get("protocol"), "udp", "network_contract.local_rtp_pool.protocol", errors)
    start = integer(pool.get("port_start"), "network_contract.local_rtp_pool.port_start", errors)
    end = integer(pool.get("port_end"), "network_contract.local_rtp_pool.port_end", errors)
    if not 1024 <= start <= end <= 65535:
        errors.append("network_contract.local_rtp_pool: invalid port range")
    elif end - start + 1 > 100:
        errors.append("network_contract.local_rtp_pool: pool exceeds the 100-port local bound")
    exact(pool.get("bounded"), True, "network_contract.local_rtp_pool.bounded", errors)
    exact(pool.get("host_sdp_exact_narrowing"), True, "network_contract.local_rtp_pool.host_sdp_exact_narrowing", errors)


def validate_store_receipts(data: dict[str, Any], as_of: datetime, errors: Errors) -> datetime | None:

    receipt = obj(data.get("artifact_acquisition_receipt"), "artifact_acquisition_receipt", {"receipt_reference", "receipt_digest", "acquired_by", "acquired_at", "expires_at", "store_generation", "authorized_readers_reference", "signature_status", "acquisition_access_closed"}, errors)
    validate_reference(receipt.get("receipt_reference"), "artifact_acquisition_receipt.receipt_reference", errors)
    validate_digest(receipt.get("receipt_digest"), "artifact_acquisition_receipt.receipt_digest", errors)
    string(receipt.get("acquired_by"), "artifact_acquisition_receipt.acquired_by", errors)
    acquired = timestamp(receipt.get("acquired_at"), "artifact_acquisition_receipt.acquired_at", errors)
    expiry = timestamp(receipt.get("expires_at"), "artifact_acquisition_receipt.expires_at", errors)
    string(receipt.get("store_generation"), "artifact_acquisition_receipt.store_generation", errors)
    validate_reference(receipt.get("authorized_readers_reference"), "artifact_acquisition_receipt.authorized_readers_reference", errors)
    exact(receipt.get("signature_status"), "verified", "artifact_acquisition_receipt.signature_status", errors)
    exact(receipt.get("acquisition_access_closed"), True, "artifact_acquisition_receipt.acquisition_access_closed", errors)
    if acquired and acquired > as_of:
        errors.append("artifact_acquisition_receipt.acquired_at: is after validation time")
    if expiry and expiry <= as_of:
        errors.append("artifact_acquisition_receipt.expires_at: receipt is expired")
    if acquired and expiry and expiry <= acquired:
        errors.append("artifact_acquisition_receipt: expiry must follow acquisition")
    return acquired


def validate_reviews(value: Any, acquired: datetime | None, as_of: datetime, errors: Errors) -> None:
    reviews = obj(value, "renewed_review", {"architect", "critic", "qa"}, errors)
    identities: list[str] = []
    for role in ("architect", "critic", "qa"):
        path = f"renewed_review.{role}"
        review = obj(reviews.get(role), path, {"identity", "independent", "decision", "review_reference", "review_digest", "reviewed_at"}, errors)
        identities.append(string(review.get("identity"), f"{path}.identity", errors))
        exact(review.get("independent"), True, f"{path}.independent", errors)
        exact(review.get("decision"), "approved", f"{path}.decision", errors)
        validate_reference(review.get("review_reference"), f"{path}.review_reference", errors)
        validate_digest(review.get("review_digest"), f"{path}.review_digest", errors)
        reviewed = timestamp(review.get("reviewed_at"), f"{path}.reviewed_at", errors)
        if reviewed and reviewed > as_of:
            errors.append(f"{path}.reviewed_at: is after validation time")
        if reviewed and acquired and reviewed < acquired:
            errors.append(f"{path}.reviewed_at: renewed review predates acquisition")
    if len(identities) == 3 and len(set(identities)) != 3:
        errors.append("renewed_review: Architect, Critic, and QA identities must differ")


def scan_sensitive(value: Any, path: str, errors: Errors) -> None:
    if isinstance(value, dict):
        for key in sorted(value):
            scan_sensitive(value[key], f"{path}.{key}" if path else key, errors)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            scan_sensitive(item, f"{path}[{index}]", errors)
    elif isinstance(value, str):
        if UNRESOLVED.search(value):
            errors.append(f"{path}: unresolved value is forbidden")
        if PHONE.search(value):
            errors.append(f"{path}: phone-looking data is forbidden")
        if any(pattern.search(value) for pattern in SENSITIVE):
            errors.append(f"{path}: secret or raw signaling/media data is forbidden")


def validate_manifest(data: Any, as_of: datetime) -> Errors:
    errors: Errors = []
    required = {"schema_version", "candidate", "runtime_contract", "storage_contract", "network_contract", "management_exposure", "artifact_acquisition_receipt", "renewed_review", "disqualifier_results"}
    root = obj(data, "$", required, errors)
    exact(root.get("schema_version"), "onnuri-jambonz-candidate/v1", "schema_version", errors)
    validate_candidate(root.get("candidate"), errors)
    classification = validate_runtime(root.get("runtime_contract"), errors)
    validate_storage(root.get("storage_contract"), classification, errors)
    validate_network(root.get("network_contract"), errors)

    management = obj(root.get("management_exposure"), "management_exposure", {"mode", "public_admin", "portal_enabled"}, errors)
    enum(management.get("mode"), {"disabled", "private_local_only"}, "management_exposure.mode", errors)
    exact(management.get("public_admin"), False, "management_exposure.public_admin", errors)
    exact(management.get("portal_enabled"), False, "management_exposure.portal_enabled", errors)

    acquired = validate_store_receipts(root, as_of, errors)
    validate_reviews(root.get("renewed_review"), acquired, as_of, errors)

    disqualifier_names = {"license_provenance", "registration_secret_persistence", "raw_logging", "cdr_storage", "recording", "backup_replication_export", "public_management", "rtp_bounds", "hook_semantics", "ws_auth", "media_codec", "timer_behavior"}
    disqualifiers = obj(root.get("disqualifier_results"), "disqualifier_results", disqualifier_names, errors)
    for name in sorted(disqualifier_names):
        path = f"disqualifier_results.{name}"
        result = obj(disqualifiers.get(name), path, {"result", "evidence_reference", "evidence_digest"}, errors)
        exact(result.get("result"), "pass", f"{path}.result", errors)
        validate_reference(result.get("evidence_reference"), f"{path}.evidence_reference", errors)
        validate_digest(result.get("evidence_digest"), f"{path}.evidence_digest", errors)

    scan_sensitive(root, "", errors)
    return sorted(set(errors))


def evidence_assertions(data: Any, errors: Errors) -> dict[str, tuple[str | None, str]]:
    if not isinstance(data, dict):
        return {}
    assertions: list[tuple[str, str | None, str, str]] = []

    def add(reference: Any, digest: Any, kind: str, path: str) -> None:
        if isinstance(reference, str) and EVIDENCE.fullmatch(reference):
            assertions.append((reference, digest if isinstance(digest, str) else None, kind, path))

    candidate = data.get("candidate")
    if isinstance(candidate, dict):
        license_data = candidate.get("license")
        if isinstance(license_data, dict):
            add(license_data.get("entitlement_reference"), license_data.get("entitlement_digest"), "license_entitlement", "candidate.license.entitlement_reference")
        provenance = candidate.get("provenance")
        if isinstance(provenance, dict):
            add(provenance.get("statement_reference"), provenance.get("statement_digest"), "provenance_statement", "candidate.provenance.statement_reference")
            add(provenance.get("sbom_reference"), provenance.get("sbom_digest"), "sbom", "candidate.provenance.sbom_reference")
        derivative = candidate.get("derivative")
        if isinstance(derivative, dict):
            add(derivative.get("hardening_receipt_reference"), derivative.get("hardening_receipt_digest"), "hardening_receipt", "candidate.derivative.hardening_receipt_reference")
            add(derivative.get("one_shot_receipt_reference"), derivative.get("one_shot_receipt_digest"), "one_shot_receipt", "candidate.derivative.one_shot_receipt_reference")
        vulnerability = candidate.get("vulnerability_report")
        if isinstance(vulnerability, dict):
            add(vulnerability.get("reference"), vulnerability.get("digest"), "vulnerability_report", "candidate.vulnerability_report.reference")
    receipt = data.get("artifact_acquisition_receipt")
    if isinstance(receipt, dict):
        add(receipt.get("receipt_reference"), receipt.get("receipt_digest"), "acquisition_receipt", "artifact_acquisition_receipt.receipt_reference")
        add(receipt.get("authorized_readers_reference"), None, "authorized_readers", "artifact_acquisition_receipt.authorized_readers_reference")
    reviews = data.get("renewed_review")
    if isinstance(reviews, dict):
        for role in ("architect", "critic", "qa"):
            review = reviews.get(role)
            if isinstance(review, dict):
                add(review.get("review_reference"), review.get("review_digest"), "renewed_review", f"renewed_review.{role}.review_reference")
    disqualifiers = data.get("disqualifier_results")
    if isinstance(disqualifiers, dict):
        for name, result in disqualifiers.items():
            if isinstance(result, dict):
                add(result.get("evidence_reference"), result.get("evidence_digest"), "disqualifier", f"disqualifier_results.{name}.evidence_reference")

    result: dict[str, tuple[str | None, str]] = {}
    for reference, digest, kind, path in assertions:
        if reference in result:
            errors.append(f"{path}: duplicate evidence reference {reference!r}")
        else:
            result[reference] = (digest, kind)
    return result


def safe_evidence_file(bundle_root: Path, relative_path: Any, path: str, errors: Errors) -> Path | None:
    if not isinstance(relative_path, str) or not relative_path:
        errors.append(f"{path}.path: expected non-empty string")
        return None
    relative = PurePosixPath(relative_path)
    if "\\" in relative_path or relative.is_absolute() or "." in relative.parts or ".." in relative.parts:
        errors.append(f"{path}.path: must be a normalized bundle-relative path")
        return None
    candidate = bundle_root.joinpath(*relative.parts)
    try:
        if stat.S_ISLNK(bundle_root.lstat().st_mode) or not stat.S_ISDIR(bundle_root.stat().st_mode):
            errors.append("bundle_root: must be a non-symlink directory")
            return None
        current = bundle_root
        for part in relative.parts:
            current = current / part
            if stat.S_ISLNK(current.lstat().st_mode):
                errors.append(f"{path}.path: symlinks are forbidden")
                return None
        if not stat.S_ISREG(candidate.stat().st_mode):
            errors.append(f"{path}.path: must name a regular file")
            return None
        candidate.resolve().relative_to(bundle_root.resolve())
    except (OSError, ValueError):
        errors.append(f"{path}.path: must name a regular file inside bundle_root")
        return None
    return candidate


def scan_evidence_text(content: bytes, path: str, errors: Errors) -> None:
    if len(content) > MAX_TEXT_EVIDENCE_BYTES:
        errors.append(f"{path}: textual evidence exceeds the {MAX_TEXT_EVIDENCE_BYTES}-byte bound")
        return
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        errors.append(f"{path}: textual evidence must be UTF-8")
        return
    if PHONE.search(text):
        errors.append(f"{path}: phone-looking data is forbidden")
    if any(pattern.search(text) for pattern in SENSITIVE):
        errors.append(f"{path}: secret or raw signaling/media data is forbidden")


def validate_evidence_index(index: Any, data: Any, manifest_bytes: bytes, bundle_root: Path, errors: Errors) -> None:
    fields = {"schema_version", "manifest_sha256", "source_image_id", "source_export_sha256", "final_disk_sha256", "rootfs_tree_sha256", "receipt_store_generation", "evidence", "redaction_attestations"}
    root = obj(index, "evidence_index", fields, errors)
    exact(root.get("schema_version"), INDEX_SCHEMA_VERSION, "evidence_index.schema_version", errors)
    manifest_sha256 = string(root.get("manifest_sha256"), "evidence_index.manifest_sha256", errors, INDEX_SHA256)
    if manifest_sha256 and manifest_sha256 != hashlib.sha256(manifest_bytes).hexdigest():
        errors.append("evidence_index.manifest_sha256: does not match manifest bytes")

    candidate = data.get("candidate") if isinstance(data, dict) else None
    source_image = candidate.get("source_image") if isinstance(candidate, dict) else None
    derivative = candidate.get("derivative") if isinstance(candidate, dict) else None
    expected_image_id = source_image.get("immutable_image_id") if isinstance(source_image, dict) else None
    expected_export = source_image.get("export_sha256") if isinstance(source_image, dict) else None
    expected_disk = derivative.get("final_disk_sha256") if isinstance(derivative, dict) else None
    expected_tree = derivative.get("rootfs_tree_sha256") if isinstance(derivative, dict) else None
    bindings = {
        "source_image_id": expected_image_id,
        "source_export_sha256": expected_export,
        "final_disk_sha256": expected_disk,
        "rootfs_tree_sha256": expected_tree,
    }
    for field, expected_value in bindings.items():
        if root.get(field) != expected_value:
            errors.append(f"evidence_index.{field}: does not match candidate derivative chain")
    receipt = data.get("artifact_acquisition_receipt") if isinstance(data, dict) else None
    expected_generation = receipt.get("store_generation") if isinstance(receipt, dict) else None
    if root.get("receipt_store_generation") != expected_generation:
        errors.append("evidence_index.receipt_store_generation: does not match acquisition receipt")

    expected = evidence_assertions(data, errors)
    attestations = root.get("redaction_attestations")
    approved_opaque_digests: set[str] = set()
    if not isinstance(attestations, dict):
        errors.append("evidence_index.redaction_attestations: expected object")
        attestations = {}
    for target_digest, attestation_value in attestations.items():
        attestation_path = f"evidence_index.redaction_attestations.{target_digest}"
        if not isinstance(target_digest, str) or INDEX_SHA256.fullmatch(target_digest) is None:
            errors.append(f"{attestation_path}: target digest must be SHA-256")
        attestation = obj(attestation_value, attestation_path, {"reference", "digest", "independent", "decision"}, errors)
        reference = attestation.get("reference")
        digest = attestation.get("digest")
        validate_reference(reference, f"{attestation_path}.reference", errors)
        validate_digest(digest, f"{attestation_path}.digest", errors)
        exact(attestation.get("independent"), True, f"{attestation_path}.independent", errors)
        exact(attestation.get("decision"), "approved", f"{attestation_path}.decision", errors)
        if isinstance(reference, str) and EVIDENCE.fullmatch(reference):
            if reference in expected:
                errors.append(f"{attestation_path}.reference: duplicates manifest evidence reference")
            else:
                expected[reference] = (digest if isinstance(digest, str) else None, "redaction_attestation")
        if isinstance(target_digest, str) and INDEX_SHA256.fullmatch(target_digest) and attestation.get("independent") is True and attestation.get("decision") == "approved":
            approved_opaque_digests.add(target_digest)

    entries = root.get("evidence")
    if not isinstance(entries, dict):
        errors.append("evidence_index.evidence: expected object")
        return
    actual = set(entries)
    errors.extend(f"evidence_index.evidence: missing reference {reference}" for reference in sorted(set(expected) - actual))
    errors.extend(f"evidence_index.evidence: extra reference {reference}" for reference in sorted(actual - set(expected)))
    seen_paths: set[str] = set()
    for reference in sorted(set(expected) & actual):
        entry_path = f"evidence_index.evidence.{reference}"
        entry = obj(entries[reference], entry_path, {"path", "sha256", "kind", "verification_status", "content_type"}, errors)
        expected_digest, expected_kind = expected[reference]
        digest = string(entry.get("sha256"), f"{entry_path}.sha256", errors, INDEX_SHA256)
        kind = enum(entry.get("kind"), EVIDENCE_KINDS, f"{entry_path}.kind", errors)
        content_type = enum(entry.get("content_type"), {"text", "opaque"}, f"{entry_path}.content_type", errors)
        exact(entry.get("verification_status"), "verified", f"{entry_path}.verification_status", errors)
        if kind != expected_kind:
            errors.append(f"{entry_path}.kind: does not match manifest assertion")
        if expected_digest and digest != expected_digest.removeprefix("sha256:"):
            errors.append(f"{entry_path}.sha256: does not match manifest assertion digest")
        evidence_file = safe_evidence_file(bundle_root, entry.get("path"), entry_path, errors)
        if isinstance(entry.get("path"), str):
            if entry["path"] in seen_paths:
                errors.append(f"{entry_path}.path: duplicate evidence path")
            seen_paths.add(entry["path"])
        if evidence_file is not None and digest:
            try:
                content = evidence_file.read_bytes()
            except OSError as exc:
                errors.append(f"{entry_path}.path: cannot read evidence file: {exc}")
                continue
            if hashlib.sha256(content).hexdigest() != digest:
                errors.append(f"{entry_path}.sha256: does not match evidence bytes")
            if content_type == "text":
                scan_evidence_text(content, entry_path, errors)
            elif content_type == "opaque" and digest not in approved_opaque_digests:
                errors.append(f"{entry_path}: opaque evidence requires an independently approved digest-bound redaction attestation")

def load_json(path: Path, label: str) -> tuple[Any, bytes] | tuple[None, None]:
    try:
        raw = path.read_bytes()
        return json.loads(raw.decode("utf-8"), object_pairs_hook=duplicate_safe_object), raw
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        print(f"{label}: cannot read valid unique-key JSON: {exc}", file=sys.stderr)
        return None, None

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="path to an already-acquired candidate manifest")
    parser.add_argument("--evidence-index", required=True, type=Path, help="JSON index binding manifest evidence references to evidence bytes")
    parser.add_argument("--bundle-root", required=True, type=Path, help="non-symlink root containing all indexed evidence files")
    parser.add_argument("--as-of", required=True, help="explicit RFC 3339 validation time (required for deterministic expiry checks)")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    errors: Errors = []
    as_of = timestamp(args.as_of, "--as-of", errors)
    if as_of is None:
        for error in sorted(errors):
            print(error, file=sys.stderr)
        return 2
    data, manifest_bytes = load_json(args.manifest, "manifest")
    if data is None or manifest_bytes is None:
        return 2
    index, _ = load_json(args.evidence_index, "evidence_index")
    if index is None:
        return 2
    errors = validate_manifest(data, as_of)
    validate_evidence_index(index, data, manifest_bytes, args.bundle_root, errors)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("candidate manifest valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
