#!/usr/bin/env python3
"""Fail-closed verifier for an immutable source-built Jambonz OSS candidate."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import stat
import sys
from datetime import datetime, timedelta
from pathlib import Path, PurePosixPath
import urllib.parse
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCHEMA_VERSION = "onnuri-jambonz-oss-candidate/v1"
GENERATION = "jambonz-oss-0.9.x"
CORE = {"jambonz-feature-server", "jambonz-api-server", "sbc-inbound", "sbc-outbound", "sbc-call-router", "sbc-sip-sidecar", "sbc-rtpengine-sidecar"}
RUNTIME_IMAGES = CORE | {"drachtio-server", "freeswitch", "rtpengine"}
REQUIRED_SOURCES = RUNTIME_IMAGES | {"jambonz-freeswitch-modules", "spandsp", "sofia-sip"}
SUPPORT_IMAGES = {
    "mariadb",
    "redis",
    "facade",
    "recova-backend",
    "postgres",
    "recova-redis",
    "f12-ingress",
}
SUPPORT_OCI_LICENSES = {
    "mariadb": "GPL-2.0-only",
    "redis": "BSD-3-Clause",
    "facade": "LicenseRef-Recova-Proprietary",
    "recova-backend": "LicenseRef-Recova-Proprietary",
    "postgres": "PostgreSQL",
    "recova-redis": "BSD-3-Clause",
    "f12-ingress": "BSD-2-Clause",
}
FIRST_PARTY_SUPPORT_SOURCE = "https://github.com/slit-company/recova-voice"
SOURCE_REVISION_LABEL = "org.opencontainers.image.revision"
SOURCE_TREE_LABEL = "org.recova.source-tree.sha256"
APPROVAL_REFERENCES = {
    f"evidence:evidence/approval-{role}.json"
    for role in ("architect", "critic", "qa")
}
BUILD_RECIPES = {
    **{name: "Dockerfile.node-app" for name in RUNTIME_IMAGES - {"drachtio-server", "freeswitch", "rtpengine"}},
    "drachtio-server": "Dockerfile.drachtio",
    "freeswitch": "Dockerfile.freeswitch",
    "rtpengine": "Dockerfile.rtpengine",
}
REQUIRED_LICENSES = {
    **{name: "MIT" for name in CORE | {"drachtio-server"}},
    "freeswitch": "MPL-1.1",
    "rtpengine": "GPL-3.0",
    "jambonz-freeswitch-modules": "MIT OR AGPL-3.0",
    "spandsp": "LGPL-2.1-only AND GPL-2.0-only",
    "sofia-sip": "LGPL-2.1-only",
}
RUNTIME_OCI_LICENSES = {
    **{name: "MIT" for name in CORE | {"drachtio-server"}},
    "freeswitch": "MPL-1.1 AND MIT AND LGPL-2.1-only",
    "rtpengine": "GPL-3.0",
}
FREESWITCH_CONTRIBUTIONS = {
    "jambonz-freeswitch-modules": ("30f21899869fe445776078ddbc3e70dcb0ae6309", "mod_audio_fork", "MIT"),
    "spandsp": ("e29ef78944d905b935d1306fa622e2eb2dc8ad75", "spandsp runtime library", "LGPL-2.1-only AND GPL-2.0-only"),
    "sofia-sip": ("6198851a610b7889c17e2d98fb84617bc1dd7aec", "Sofia-SIP runtime library", "LGPL-2.1-only"),
}
COPYRIGHT_PREFIX = re.compile(r"(?i)^copyright\s+(?:\(c\)\s*)?(?:\d{4}(?:-\d{4})?\s*)?")
SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
IMAGE = re.compile(r".+@sha256:[0-9a-f]{64}\Z")
REFERENCE = re.compile(r"evidence:[A-Za-z0-9][A-Za-z0-9._/-]{0,239}\Z")
INDEX_SHA = re.compile(r"[0-9a-f]{64}\Z")
GITHUB = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?\Z")
UNRESOLVED = re.compile(r"(?:^|[^a-z])(?:pending|unknown|unresolved|tbd|todo|n/?a)(?:$|[^a-z])", re.I)
PHONE = re.compile(r"(?<![A-Za-z0-9-])(?:\+[1-9][0-9 -]{8,14}[0-9]|0[0-9]{1,3}-[0-9]{3,4}-[0-9]{4}|0[0-9]{9,10})(?![A-Za-z0-9-])")
ENV_PLACEHOLDER = re.compile(r"""["']?\$\{[A-Za-z_][A-Za-z0-9_]*\}["']?[,;]?\Z""")
CREDENTIAL_ASSIGNMENT = re.compile(
    r"\b(?:password|passwd|secret|token|api[_-]?key|license[_ -]?key)"
    r"""["']?\s*[:=]\s*(\S+)""",
    re.I,
)
SOURCE_CREDENTIAL_ASSIGNMENT = re.compile(
    r"""(?im)^\s*["']?(?:password|passwd|secret|token|api[_-]?key|license[_ -]?key)"""
    r"""["']?\s*[:=]\s*["']?([A-Za-z0-9+/_.=-]{8,})["']?\s*[,;]?\s*$"""
)
SOURCE_AUTH_LITERAL = re.compile(
    r"""\bauthorization\s*[:=]\s*["']?(?:bearer|basic)\s+[A-Za-z0-9+/_.=-]{8,}""",
    re.I,
)
SOURCE_SYMBOL = re.compile(r"[A-Z][A-Z0-9_]{2,}[,;]?\Z")
SENSITIVE = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.I),
    re.compile(r"\b(?:bearer|basic)\s+[A-Za-z0-9+/_.=-]{8,}", re.I),
    re.compile(r"\bsips?:[^\s]+", re.I),
    re.compile(r"(?:^|\n)(?:v=0|o=\S+\s+\d+\s+\d+\s+IN\s+IP|m=audio\s+\d+)", re.I),
    re.compile(r"\b(?:RTP/(?:AVP|SAVP)|(?:RTP|RTCP)\s*(?:packet|payload)|data:audio/)\b", re.I),
)
PERSONAL_EMAIL = re.compile(r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b")
PERSONAL_NAME = re.compile(r"^[A-Z][a-z]+(?:[ -][A-Z][a-z]+)+$")
NON_PERSONAL_IDENTITIES = {
    "Recova", "Recova Voice", "Jambonz", "FreeSWITCH", "Sofia-SIP", "SpanDSP",
    "PostgreSQL", "MariaDB", "Redis", "nginx", "Anchore", "Syft", "Grype",
}
CONFORMANCE_SIGNER_IDENTITY = "recova-g008-phase-c-preflight-v1"
CONFORMANCE_SIGNER_KEY_ID = "recova-g008-phase-c-preflight-v1"
CONFORMANCE_SIGNER_ROLE = "phase-c-preflight"
CONFORMANCE_CHECKS = {
    "offline_default_deny": "pytest:offline-compose",
    "registration_request_cardinality": "pytest:registration-cardinality",
    "registration_no_retry_concurrency": "pytest:registration-no-retry-concurrency",
    "media_contract": "pytest:media-basic-l16-8000-mono-bidirectional",
    "call_deadline": "pytest:call-deadline-60s",
}

CONFORMANCE_TRUSTED_KEYSET_SHA256 = "00645f3af8230c742951c12f17a713afde209de12182cd6e3722ac59445507aa"
BOOTSTRAP_SECRET_MOUNT_COUNT = 29
BOOTSTRAP_EXECUTION_REFERENCE_COUNT = 7
FROZEN_RUNTIME_EVIDENCE = {
    "candidate_input_g008_live_smoke_runner": (
        "evidence:evidence/g008-live-smoke-runner.py",
        "13b9b5b801a4ffb00bb410623b673bb8b493096d0403500a4627f9c7f28d21a3",
    ),
    "candidate_input_runtime_compose": (
        "evidence:evidence/runtime-compose.yaml",
        "340086636e82286f094db7b8c755a6c8191378d5c37db23c58b774fffeb1b95b",
    ),
    "candidate_input_sealed_secret_wrapper": (
        "evidence:evidence/sealed-secret-wrapper.sh",
        "2a09aba9970da289794b09400bfd72bf17a2f98ff6a9e311015ab828d7376b07",
    ),
    "candidate_input_bootstrap_binding": (
        "evidence:evidence/phase-c-startup-g008.sh",
        "181d7df7975679bd8fc5d80f8e6fc7df55ccaa5aefd41fefa2d7ad362ad5fdff",
    ),
    "candidate_input_phase_c_live_preflight_trusted_keyset": (
        "evidence:evidence/runtime-phase-c-live-preflight-trusted-keyset.json",
        "00645f3af8230c742951c12f17a713afde209de12182cd6e3722ac59445507aa",
    ),
}
PHASE_C_EVIDENCE = {
    "startup-g008.sh": "181d7df7975679bd8fc5d80f8e6fc7df55ccaa5aefd41fefa2d7ad362ad5fdff",
    "backend.tf": "4a3e917be1d0ffe925505b1bdaa4d205effb9bd142cf0ccb655b0204fa06a7a2",
    "containment.tf": "174f821de4bf18df83a0252fc1ff5f51962a0860c0de0843ee658b075686d967",
    "crypto_gate.tf": "1450c556687d2ffe189c45b5796209cbffff39314926d3f48eb770a331c214a7",
    "firewalls.tf": "c1b3c6af27def65bd5c115dd90660402741b11bb8d7a37e75ecd52364a0a7e6a",
    "iam.tf": "894791c62712571c43605aaded6e737f50d3eb4b5d5c8a9084331bdec0871834",
    "locals.tf": "c04d2861f8d33a9ce6bea3ff8361d11cf33e150e4bb571183307a3c6f39fc3b6",
    "network.tf": "e920ab3827bd5548a7251294f21d7d66211e552462e59af343bf33810a328f99",
    "observability.tf": "8b7c8de24b86f42253fe10329141034ddb2618fca4db93915147f89e77292e01",
    "outputs.tf": "fdab75096a58ce62487390fb0170a69e1494c7aa002c920bc202e25737caef39",
    "providers.tf": "d44f95858aebade0afaa2b7908677e11e0aff018c4a42698e4f45eeb493fff71",
    "secrets.tf": "c18c551e42960ff57a3a18e1837e61fdde4ff2ad7cdcbeb5a163d978e59c8743",
    "variables.tf": "ab5c3e79fabbb3eefdd9a9dc62b0a0c45aa23a1cddfa02a0b5eaf3c09d4fae3a",
    "versions.tf": "16031e61a9de9aab9358f537d68d5f41c6065bb626a65d84f0b8f5d195be4fe0",
    "workload.tf": "e33c6530fbf7e690f8d1b0d1583cac7b07e5f1c136e579757faef73af90d40fd",
}
def validate_bootstrap_manifest_evidence(
    data: dict[str, Any], index: dict[str, Any], root: Path, errors: Errors
) -> None:
    result = data.get("disqualifier_results", {}).get("candidate_input_bootstrap_binding")
    if not isinstance(result, dict):
        errors.append("bootstrap binding: missing mandatory evidence assertion")
        return
    entry = index.get(result.get("reference"))
    if not isinstance(entry, dict) or entry.get("content_type") != "text":
        errors.append("bootstrap binding: must be indexed text evidence")
        return
    evidence = safe_file(root, entry.get("path"), "bootstrap.binding", errors)
    if evidence is None:
        return
    raw = read_hashed(evidence, MAX_TEXT_EVIDENCE_BYTES, "bootstrap.binding", errors, True)
    if raw is None:
        return
    try:
        source = raw.decode("utf-8")
    except UnicodeDecodeError:
        errors.append("bootstrap binding: evidence must be UTF-8")
        return
    required_fragments = (
        'set(manifest) != {"schema_version", "binding_sha256", "transaction_authority_service_account", "secret_version_mounts", "execution_versions", "route_evidence_bundle"}',
        "set(mounts) != set(EXPECTED_MOUNTS)",
        "set(execution) != EXECUTION_KEYS",
        "binding_input.pop(\"binding_sha256\")",
        "actual_binding != expected_binding",
        "manifest[\"binding_sha256\"] != expected_binding",
    )
    if any(fragment not in source for fragment in required_fragments):
        errors.append("bootstrap binding: exact five-field boot binding enforcement is absent")
    mounts_match = re.search(r"EXPECTED_MOUNTS\s*=\s*\{(?P<body>.*?)^\}", source, re.MULTILINE | re.DOTALL)
    execution_match = re.search(r"EXECUTION_KEYS\s*=\s*\{(?P<body>.*?)\}", source, re.DOTALL)
    if mounts_match is None or mounts_match.group("body").count(": (") != BOOTSTRAP_SECRET_MOUNT_COUNT:
        errors.append("bootstrap binding: expected 29 runtime secret mounts")
    if execution_match is None or execution_match.group("body").count('"') // 2 != BOOTSTRAP_EXECUTION_REFERENCE_COUNT:
        errors.append("bootstrap binding: expected seven execution references")
def validate_signed_candidate_boot_context(
    data: dict[str, Any], index: dict[str, Any], root: Path, errors: Errors
) -> None:
    record_name = "candidate_input_phase_c_configuration_crypto_gate.tf"
    result = data.get("disqualifier_results", {}).get(record_name)
    if not isinstance(result, dict):
        errors.append("candidate boot: missing signed context evidence assertion")
        return
    entry = index.get(result.get("reference"))
    if not isinstance(entry, dict) or entry.get("content_type") != "text":
        errors.append("candidate boot: signed context must be indexed text evidence")
        return
    evidence = safe_file(root, entry.get("path"), "candidate.boot", errors)
    if evidence is None:
        return
    raw = read_hashed(evidence, MAX_TEXT_EVIDENCE_BYTES, "candidate.boot", errors, True)
    if raw is None:
        return
    try:
        source = raw.decode("utf-8")
    except UnicodeDecodeError:
        errors.append("candidate boot: evidence must be UTF-8")
        return
    required_fragments = (
        "candidate_boot = {",
        "candidate_receipt_sha256",
        "candidate_receipt_signature_base64",
        "candidate_receipt_signer_key_id",
        "candidate_receipt_verification_key_sha256",
        "candidate_manifest_sha256",
        "compose_sha256",
        "startup_sha256",
    )
    if any(fragment not in source for fragment in required_fragments):
        errors.append("candidate boot: signed candidate context is incomplete")





def contains_personal_metadata(value: Any, key: str = "") -> bool:
    if isinstance(value, dict):
        return any(
            contains_personal_metadata(child, str(child_key))
            for child_key, child in value.items()
        )
    if isinstance(value, list):
        return any(contains_personal_metadata(child, key) for child in value)
    if not isinstance(value, str):
        return False
    if PERSONAL_EMAIL.search(value):
        return True
    identity = (
        COPYRIGHT_PREFIX.sub("", value)
        if key.lower() == "copyright"
        else value
    )
    return (
        key.lower() in {
            "author",
            "maintainer",
            "creator",
            "contact",
            "name",
            "copyright",
        }
        and PERSONAL_NAME.fullmatch(identity) is not None
        and identity not in NON_PERSONAL_IDENTITIES
    )


def is_phase_c_record(name: str) -> bool:
    return name.startswith("candidate_input_phase_c_configuration_")



def expected_conformance_records() -> set[str]:
    return {
        "candidate_input_conformance",
        "candidate_input_conformance_output_offline_default_deny",
        "candidate_input_conformance_output_registration_request_cardinality",
        "candidate_input_conformance_output_registration_no_retry_concurrency",
        "candidate_input_conformance_output_media_contract",
        "candidate_input_conformance_output_call_deadline",
    }


def expected_phase_c_records() -> set[str]:
    return {
        "candidate_input_phase_c_configuration_" + name.replace("/", "-")
        for name in (
            "startup-g008.sh", "backend.tf", "containment.tf", "crypto_gate.tf",
            "firewalls.tf", "iam.tf", "locals.tf", "network.tf", "observability.tf",
            "outputs.tf", "providers.tf", "secrets.tf", "variables.tf", "versions.tf",
            "workload.tf",
        )
    }
def contains_forbidden_text(
    value: str,
    *,
    unresolved: bool,
    source_evidence: bool = False,
) -> bool:
    if unresolved and UNRESOLVED.search(value):
        return True
    if PHONE.search(value) or SENSITIVE[0].search(value):
        return True
    if source_evidence:
        if SOURCE_AUTH_LITERAL.search(value):
            return True
        return any(
            not ENV_PLACEHOLDER.fullmatch(match.group(1))
            and not SOURCE_SYMBOL.fullmatch(match.group(1))
            for match in SOURCE_CREDENTIAL_ASSIGNMENT.finditer(value)
        )
    if any(pattern.search(value) for pattern in SENSITIVE[1:]):
        return True
    return any(
        not ENV_PLACEHOLDER.fullmatch(match.group(1))
        and match.group(1).strip(",;").lower() not in {"false", "null", "none"}
        for match in CREDENTIAL_ASSIGNMENT.finditer(value)
    )


MAX_TEXT_EVIDENCE_BYTES = 1_048_576
MAX_SCANNER_EVIDENCE_BYTES = 256 * 1_048_576
MAX_ARCHIVE_EVIDENCE_BYTES = 16 * 1024 * 1_048_576
SCANNER_CONTENT_TYPES = {"application/vnd.cyclonedx+json", "application/vnd.anchore.syft+json", "application/vnd.anchore.grype+json"}
Errors = list[str]


def duplicate_safe_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def object_(value: Any, path: str, fields: set[str], errors: Errors, optional: set[str] | None = None) -> dict[str, Any]:
    optional = optional or set()
    if not isinstance(value, dict):
        errors.append(f"{path}: expected object")
        return {}
    errors.extend(f"{path}: missing field {field}" for field in sorted(fields - optional - value.keys()))
    errors.extend(f"{path}: unknown field {field}" for field in sorted(value.keys() - fields))
    return value


def exact(value: Any, expected: Any, path: str, errors: Errors) -> None:
    if value != expected or type(value) is not type(expected):
        errors.append(f"{path}: expected {expected!r}")


def text(value: Any, path: str, errors: Errors, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value:
        errors.append(f"{path}: expected non-empty string")
        return ""
    if pattern and pattern.fullmatch(value) is None:
        errors.append(f"{path}: invalid format")
    return value


def digest(value: Any, path: str, errors: Errors) -> str:
    return text(value, path, errors, SHA)


def reference(value: Any, path: str, errors: Errors) -> str:
    return text(value, path, errors, REFERENCE)


def timestamp(value: Any, path: str, errors: Errors) -> datetime | None:
    raw = text(value, path, errors)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"{path}: invalid RFC 3339 timestamp")
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        errors.append(f"{path}: timestamp must include an offset")
        return None
    return parsed


def require_false(data: dict[str, Any], field: str, path: str, errors: Errors) -> None:
    exact(data.get(field), False, f"{path}.{field}", errors)


def review_payload_digest(data: dict[str, Any]) -> str:
    payload = {
        key: value
        for key, value in data.items()
        if key not in {"approvals", "review_payload_digest"}
    }
    evidence_index = payload.get("evidence_index")
    if isinstance(evidence_index, dict):
        payload["evidence_index"] = {
            reference: value
            for reference, value in evidence_index.items()
            if reference not in APPROVAL_REFERENCES
        }
    return "sha256:" + hashlib.sha256(canonical_json(payload)).hexdigest()

def validate_manifest(data: Any, as_of: datetime) -> Errors:
    errors: Errors = []
    root_fields = {"schema_version", "candidate_generation", "source_lock_sha256", "sources", "images", "support_images", "review_payload_digest", "license_policy", "runtime_contract", "management_exposure", "storage_contract", "acquisition_receipt", "approvals", "disqualifier_results", "evidence_index"}
    root = object_(data, "$", root_fields, errors)
    exact(root.get("schema_version"), SCHEMA_VERSION, "schema_version", errors)
    exact(root.get("candidate_generation"), GENERATION, "candidate_generation", errors)
    digest(root.get("source_lock_sha256"), "source_lock_sha256", errors)
    sources = validate_sources(root.get("sources"), errors)
    validate_images(root.get("images"), sources, errors)
    validate_support_images(root.get("support_images"), errors)
    digest(root.get("review_payload_digest"), "review_payload_digest", errors)
    exact(root.get("review_payload_digest"), review_payload_digest(root), "review_payload_digest", errors)
    validate_policy(root.get("license_policy"), errors)
    validate_runtime(root.get("runtime_contract"), errors)
    validate_management_storage(root.get("management_exposure"), root.get("storage_contract"), errors)
    validate_receipt(root.get("acquisition_receipt"), as_of, errors)
    validate_approvals(root.get("approvals"), errors)
    validate_disqualifiers(root.get("disqualifier_results"), errors)
    validate_index_shape(root.get("evidence_index"), errors)
    validate_exact_runtime_evidence(root, errors)
    for field, value in root.items():
        if field != "approvals":
            scan_value(value, field, errors)
    return sorted(set(errors))


def validate_sources(value: Any, errors: Errors) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list):
        errors.append("sources: expected array")
        return {}
    sources: dict[str, dict[str, Any]] = {}
    fields = {
        "name", "repository", "commit", "upstream_tree_sha256",
        "source_tree_reference", "source_tree_sha256", "submodules_reference",
        "submodules_sha256", "submodules", "license_spdx", "license_reference",
        "license_sha256", "patch_reference", "patch_sha256", "patch_content_sha256", "conditional_mit",
    }
    for i, raw in enumerate(value):
        path = f"sources[{i}]"
        item = object_(raw, path, fields, errors, {"conditional_mit"})
        name = text(item.get("name"), f"{path}.name", errors)
        if name in sources:
            errors.append(f"{path}.name: duplicate source")
        sources[name] = item
        text(item.get("commit"), f"{path}.commit", errors, COMMIT)
        text(item.get("repository"), f"{path}.repository", errors, GITHUB)
        digest(item.get("upstream_tree_sha256"), f"{path}.upstream_tree_sha256", errors)
        for field in ("source_tree_reference", "submodules_reference", "license_reference", "patch_reference"):
            reference(item.get(field), f"{path}.{field}", errors)
        for field in ("source_tree_sha256", "submodules_sha256", "license_sha256", "patch_sha256", "patch_content_sha256"):
            digest(item.get(field), f"{path}.{field}", errors)
        validate_submodules(item.get("submodules"), f"{path}.submodules", errors)
        expected_license = REQUIRED_LICENSES.get(name)
        if expected_license is None:
            errors.append(f"{path}.name: unknown source")
        else:
            exact(item.get("license_spdx"), expected_license, f"{path}.license_spdx", errors)
            if name in FREESWITCH_CONTRIBUTIONS:
                exact(item.get("commit"), FREESWITCH_CONTRIBUTIONS[name][0], f"{path}.commit", errors)
        conditional = item.get("conditional_mit")
        if name == "jambonz-freeswitch-modules":
            validate_conditional_mit(conditional, f"{path}.conditional_mit", errors)
        elif conditional is not None:
            errors.append(f"{path}.conditional_mit: only the Cyrenity source may assert conditional MIT")
    if set(sources) != REQUIRED_SOURCES:
        errors.append("sources: must contain exactly the required Node, drachtio, FreeSWITCH, Cyrenity, spandsp, Sofia-SIP, and rtpengine sources")
    return sources


def validate_images(value: Any, sources: dict[str, dict[str, Any]], errors: Errors) -> None:
    if not isinstance(value, list):
        errors.append("images: expected array")
        return
    names: set[str] = set()
    fields = {
        "name", "source_name", "source_commit", "platform", "image", "base_images",
        "build_mode", "build_recipe_reference", "build_recipe_sha256",
        "build_provenance_reference", "build_provenance_sha256",
        "network_archive_reference", "network_archive_sha256",
        "network_archive_record_reference", "network_archive_record_sha256",
        "source_contributions", "notices_reference", "notices_sha256",
        "sbom_reference", "sbom_sha256", "vulnerability_reference",
        "vulnerability_sha256", "scanner", "vulnerability_acceptance_reference",
        "vulnerability_acceptance_sha256", "vulnerability_summary",
    }
    for i, raw in enumerate(value):
        path = f"images[{i}]"
        item = object_(raw, path, fields, errors)
        name = text(item.get("name"), f"{path}.name", errors)
        if name in names:
            errors.append(f"{path}.name: duplicate image")
        names.add(name)
        source = text(item.get("source_name"), f"{path}.source_name", errors)
        commit = text(item.get("source_commit"), f"{path}.source_commit", errors, COMMIT)
        if source != name or source not in sources or sources[source].get("commit") != commit:
            errors.append(f"{path}: image must bind to its declared source and exact commit")
        exact(item.get("platform"), "linux/amd64", f"{path}.platform", errors)
        text(item.get("image"), f"{path}.image", errors, IMAGE)
        validate_base_images(item.get("base_images"), f"{path}.base_images", errors)
        exact(item.get("build_mode"), "source_only", f"{path}.build_mode", errors)
        recipe = BUILD_RECIPES.get(name)
        expected_recipe_reference = f"evidence:evidence/recipes-{recipe}" if recipe else None
        exact(item.get("build_recipe_reference"), expected_recipe_reference, f"{path}.build_recipe_reference", errors)
        reference(item.get("build_recipe_reference"), f"{path}.build_recipe_reference", errors)
        digest(item.get("build_recipe_sha256"), f"{path}.build_recipe_sha256", errors)
        for field in (
            "build_provenance_reference", "network_archive_reference",
            "network_archive_record_reference", "notices_reference", "sbom_reference",
            "vulnerability_reference", "vulnerability_acceptance_reference",
        ):
            reference(item.get(field), f"{path}.{field}", errors)
        for field in (
            "build_provenance_sha256", "network_archive_sha256",
            "network_archive_record_sha256", "notices_sha256", "sbom_sha256",
            "vulnerability_sha256", "vulnerability_acceptance_sha256",
        ):
            digest(item.get(field), f"{path}.{field}", errors)
        validate_scanner(item.get("scanner"), f"{path}.scanner", errors)
        validate_contributions(item.get("source_contributions"), name, sources, f"{path}.source_contributions", errors)
        validate_vulnerability_summary(item.get("vulnerability_summary"), f"{path}.vulnerability_summary", errors)
    if names != RUNTIME_IMAGES:
        errors.append("images: must contain exactly the required immutable Node, drachtio, FreeSWITCH, and rtpengine runtime images")
def validate_support_images(value: Any, errors: Errors) -> None:
    if not isinstance(value, list):
        errors.append("support_images: expected array")
        return
    fields = {
        "name", "image", "platform", "source", "source_provenance",
        "source_provenance_reference", "source_provenance_sha256",
        "base_images", "license_spdx", "oci_license_reference",
        "oci_license_sha256", "notices_reference", "notices_sha256",
        "sbom_reference", "sbom_sha256", "vulnerability_reference",
        "vulnerability_sha256", "scanner", "vulnerability_acceptance_reference",
        "vulnerability_acceptance_sha256", "vulnerability_summary",
        "network_archive_reference", "network_archive_sha256",
        "network_archive_record_reference", "network_archive_record_sha256",
    }
    names: set[str] = set()
    for i, raw in enumerate(value):
        path = f"support_images[{i}]"
        item = object_(raw, path, fields, errors)
        name = text(item.get("name"), f"{path}.name", errors)
        if name in names:
            errors.append(f"{path}.name: duplicate support image")
        names.add(name)
        text(item.get("image"), f"{path}.image", errors, IMAGE)
        source = text(item.get("source"), f"{path}.source", errors)
        parsed_source = urllib.parse.urlsplit(source)
        if (
            parsed_source.scheme != "https"
            or not parsed_source.hostname
            or parsed_source.username is not None
            or parsed_source.password is not None
            or parsed_source.query
            or parsed_source.fragment
            or not parsed_source.path.strip("/")
        ):
            errors.append(f"{path}.source: invalid OCI source URL")
        if name in {"facade", "recova-backend"}:
            exact(source, FIRST_PARTY_SUPPORT_SOURCE, f"{path}.source", errors)
        provenance = object_(
            item.get("source_provenance"),
            f"{path}.source_provenance",
            {"label", "type", "value"},
            errors,
        )
        if name == "facade":
            exact(provenance.get("label"), SOURCE_REVISION_LABEL, f"{path}.source_provenance.label", errors)
            exact(provenance.get("type"), "source_tree_sha256", f"{path}.source_provenance.type", errors)
            digest(provenance.get("value"), f"{path}.source_provenance.value", errors)
        elif name == "recova-backend":
            exact(provenance.get("label"), SOURCE_REVISION_LABEL, f"{path}.source_provenance.label", errors)
            exact(provenance.get("type"), "source_tree_sha256", f"{path}.source_provenance.type", errors)
            digest(provenance.get("value"), f"{path}.source_provenance.value", errors)
        else:
            exact(provenance.get("label"), SOURCE_REVISION_LABEL, f"{path}.source_provenance.label", errors)
            if provenance.get("type") == "git_revision":
                text(provenance.get("value"), f"{path}.source_provenance.value", errors, COMMIT)
            elif provenance.get("type") == "source_image_digest":
                digest(provenance.get("value"), f"{path}.source_provenance.value", errors)
            else:
                errors.append(f"{path}.source_provenance.type: expected immutable Git revision or source image digest")
        exact(item.get("platform"), "linux/amd64", f"{path}.platform", errors)
        validate_base_images(item.get("base_images"), f"{path}.base_images", errors)
        exact(item.get("license_spdx"), SUPPORT_OCI_LICENSES.get(name), f"{path}.license_spdx", errors)
        for field in (
            "source_provenance_reference", "oci_license_reference",
            "notices_reference", "sbom_reference", "vulnerability_reference",
            "vulnerability_acceptance_reference", "network_archive_reference",
            "network_archive_record_reference",
        ):
            reference(item.get(field), f"{path}.{field}", errors)
        for field in (
            "source_provenance_sha256", "oci_license_sha256", "notices_sha256",
            "sbom_sha256", "vulnerability_sha256",
            "vulnerability_acceptance_sha256", "network_archive_sha256",
            "network_archive_record_sha256",
        ):
            digest(item.get(field), f"{path}.{field}", errors)
        validate_scanner(item.get("scanner"), f"{path}.scanner", errors)
        validate_vulnerability_summary(item.get("vulnerability_summary"), f"{path}.vulnerability_summary", errors)
    if names != SUPPORT_IMAGES:
        errors.append("support_images: must contain exactly the seven G008-expanded support images")
def validate_submodules(value: Any, path: str, errors: Errors) -> None:
    if not isinstance(value, list):
        errors.append(f"{path}: expected array")
        return
    paths: set[str] = set()
    for i, raw in enumerate(value):
        item_path = f"{path}[{i}]"
        item = object_(raw, item_path, {"path", "commit", "tree_sha256"}, errors)
        submodule_path = text(item.get("path"), f"{item_path}.path", errors)
        if not submodule_path or submodule_path.startswith("/") or "\\" in submodule_path or ".." in PurePosixPath(submodule_path).parts:
            errors.append(f"{item_path}.path: must be a normalized relative path")
        if submodule_path in paths:
            errors.append(f"{item_path}.path: duplicate submodule")
        paths.add(submodule_path)
        text(item.get("commit"), f"{item_path}.commit", errors, COMMIT)
        digest(item.get("tree_sha256"), f"{item_path}.tree_sha256", errors)


def validate_conditional_mit(value: Any, path: str, errors: Errors) -> None:
    item = object_(
        value,
        path,
        {
            "selected_license", "dedicated_freeswitch", "dynamic_load",
            "incoming_call_control", "reference", "sha256",
            "topology_reference", "topology_sha256",
        },
        errors,
    )
    exact(item.get("selected_license"), "MIT", f"{path}.selected_license", errors)
    exact(item.get("dedicated_freeswitch"), True, f"{path}.dedicated_freeswitch", errors)
    exact(item.get("dynamic_load"), "mod_audio_fork", f"{path}.dynamic_load", errors)
    exact(
        item.get("incoming_call_control"),
        "jambonz-feature-server/outbound-esl",
        f"{path}.incoming_call_control",
        errors,
    )
    for field in ("reference", "topology_reference"):
        reference(item.get(field), f"{path}.{field}", errors)
    for field in ("sha256", "topology_sha256"):
        digest(item.get(field), f"{path}.{field}", errors)


def validate_base_images(value: Any, path: str, errors: Errors) -> None:
    if not isinstance(value, list) or not value:
        errors.append(f"{path}: expected non-empty array")
        return
    if len(set(value)) != len(value):
        errors.append(f"{path}: duplicate base image")
    for i, image in enumerate(value):
        text(image, f"{path}[{i}]", errors, IMAGE)


def validate_contributions(value: Any, image_name: str, sources: dict[str, dict[str, Any]], path: str, errors: Errors) -> None:
    if not isinstance(value, list):
        errors.append(f"{path}: expected array")
        return
    if image_name != "freeswitch" and value:
        errors.append(f"{path}: only FreeSWITCH may include source contributions")
    if image_name == "freeswitch" and len(value) != len(FREESWITCH_CONTRIBUTIONS):
        errors.append(f"{path}: FreeSWITCH must bind exactly the Cyrenity, spandsp, and Sofia-SIP runtime contributions")
    seen: set[str] = set()
    for i, raw in enumerate(value):
        item_path = f"{path}[{i}]"
        item = object_(raw, item_path, {"source_name", "source_commit", "contribution", "license_mode", "reference", "sha256"}, errors)
        source_name = text(item.get("source_name"), f"{item_path}.source_name", errors)
        if source_name in seen:
            errors.append(f"{item_path}.source_name: duplicate contribution")
        seen.add(source_name)
        expected = FREESWITCH_CONTRIBUTIONS.get(source_name)
        if expected is None:
            errors.append(f"{item_path}.source_name: unknown FreeSWITCH contribution source")
        else:
            expected_commit, expected_contribution, expected_license = expected
            exact(item.get("source_commit"), expected_commit, f"{item_path}.source_commit", errors)
            source = sources.get(source_name, {})
            if source.get("commit") != expected_commit:
                errors.append(f"{item_path}: contribution source must bind its declared exact commit")
            exact(item.get("reference"), source.get("license_reference"), f"{item_path}.reference", errors)
            exact(item.get("sha256"), source.get("license_sha256"), f"{item_path}.sha256", errors)
            exact(item.get("contribution"), expected_contribution, f"{item_path}.contribution", errors)
            exact(item.get("license_mode"), expected_license, f"{item_path}.license_mode", errors)
        text(item.get("source_commit"), f"{item_path}.source_commit", errors, COMMIT)
        reference(item.get("reference"), f"{item_path}.reference", errors)
        digest(item.get("sha256"), f"{item_path}.sha256", errors)
    if image_name == "freeswitch" and seen != set(FREESWITCH_CONTRIBUTIONS):
        errors.append(f"{path}: must contain exactly the required FreeSWITCH contribution sources")


def validate_scanner(value: Any, path: str, errors: Errors) -> None:
    item = object_(value, path, {"syft_version", "grype_version", "grype_db_identity_reference", "grype_db_identity_sha256"}, errors)
    text(item.get("syft_version"), f"{path}.syft_version", errors)
    text(item.get("grype_version"), f"{path}.grype_version", errors)
    reference(item.get("grype_db_identity_reference"), f"{path}.grype_db_identity_reference", errors)
    digest(item.get("grype_db_identity_sha256"), f"{path}.grype_db_identity_sha256", errors)


def validate_vulnerability_summary(value: Any, path: str, errors: Errors) -> None:
    item = object_(value, path, {"critical", "high", "unaccepted_critical", "unaccepted_high"}, errors)
    for field in ("critical", "high", "unaccepted_critical", "unaccepted_high"):
        count = item.get(field)
        if type(count) is not int or count < 0:
            errors.append(f"{path}.{field}: must be a non-negative integer")
    if item.get("unaccepted_critical") != 0:
        errors.append(f"{path}.unaccepted_critical: must be zero")
    if item.get("unaccepted_high") != 0:
        errors.append(f"{path}.unaccepted_high: must be zero")



def validate_policy(value: Any, errors: Errors) -> None:
    fields = {
        "all_third_party_components_open_source",
        "first_party_support_boundary",
        "runtime_license_key_required",
        "activation_service_required",
        "trial_or_paid_entitlement_used",
        "commercial_image_used",
        "circumvention_used",
    }
    data = object_(value, "license_policy", fields, errors)
    exact(
        data.get("all_third_party_components_open_source"),
        True,
        "license_policy.all_third_party_components_open_source",
        errors,
    )
    exact(
        data.get("first_party_support_boundary"),
        "LicenseRef-Recova-Proprietary",
        "license_policy.first_party_support_boundary",
        errors,
    )
    for field in fields - {
        "all_third_party_components_open_source",
        "first_party_support_boundary",
    }:
        require_false(data, field, "license_policy", errors)


def validate_runtime(value: Any, errors: Errors) -> None:
    data = object_(
        value,
        "runtime_contract",
        {"inbound", "outbound", "listen", "receipt_signing", "registration", "calls", "timers", "teardown"},
        errors,
    )
    inbound = object_(
        data.get("inbound"),
        "runtime_contract.inbound",
        {"timing", "verbs"},
        errors,
    )
    exact(inbound.get("timing"), "pre_answer", "runtime_contract.inbound.timing", errors)
    exact(inbound.get("verbs"), ["answer", "listen"], "runtime_contract.inbound.verbs", errors)
    outbound = object_(
        data.get("outbound"),
        "runtime_contract.outbound",
        {"timing", "verbs"},
        errors,
    )
    exact(outbound.get("timing"), "post_answer", "runtime_contract.outbound.timing", errors)
    exact(outbound.get("verbs"), ["listen"], "runtime_contract.outbound.verbs", errors)
    listen = object_(
        data.get("listen"),
        "runtime_contract.listen",
        {"ws_auth", "encoding", "sample_rate_hz", "channels", "direction"},
        errors,
    )
    for field, expected in {
        "ws_auth": "Basic",
        "encoding": "L16",
        "sample_rate_hz": 8000,
        "channels": 1,
        "direction": "bidirectional",
    }.items():
        exact(listen.get(field), expected, f"runtime_contract.listen.{field}", errors)
    receipt_signing = object_(
        data.get("receipt_signing"),
        "runtime_contract.receipt_signing",
        {"dispatch", "media"},
        errors,
    )
    for role, key_id, trust_domain in (
        ("dispatch", "dispatch-es256", "recova.dispatch"),
        ("media", "media-es256", "recova.media"),
    ):
        signer = object_(
            receipt_signing.get(role),
            f"runtime_contract.receipt_signing.{role}",
            {"algorithm", "key_id", "trust_domain"},
            errors,
        )
        exact(signer.get("algorithm"), "ES256", f"runtime_contract.receipt_signing.{role}.algorithm", errors)
        exact(signer.get("key_id"), key_id, f"runtime_contract.receipt_signing.{role}.key_id", errors)
        exact(signer.get("trust_domain"), trust_domain, f"runtime_contract.receipt_signing.{role}.trust_domain", errors)
    registration = object_(
        data.get("registration"),
        "runtime_contract.registration",
        {
            "mode",
            "automatic_retry",
            "max_concurrency",
            "receipt_binding_fields",
            "operations",
        },
        errors,
    )
    exact(
        registration.get("mode"),
        "one_register_then_unregister",
        "runtime_contract.registration.mode",
        errors,
    )
    exact(registration.get("automatic_retry"), False, "runtime_contract.registration.automatic_retry", errors)
    exact(registration.get("max_concurrency"), 1, "runtime_contract.registration.max_concurrency", errors)
    exact(
        registration.get("receipt_binding_fields"),
        [
            "tenant_digest",
            "account_digest",
            "envelope_digest",
            "candidate_digest",
            "operation",
            "prior_receipt_digest",
        ],
        "runtime_contract.registration.receipt_binding_fields",
        errors,
    )
    operations = registration.get("operations")
    if not isinstance(operations, list) or len(operations) != 2:
        errors.append("runtime_contract.registration.operations: expected exact register/unregister pair")
    else:
        expected_operations = (
            ("register", "authority_receipt_digest"),
            ("unregister", "register_receipt_digest"),
        )
        for position, (operation_name, predecessor) in enumerate(expected_operations):
            operation_path = f"runtime_contract.registration.operations[{position}]"
            operation = object_(
                operations[position],
                operation_path,
                {
                    "operation", "challenge_aware", "max_wire_transmissions",
                    "automatic_retry", "max_concurrency",
                    "terminal_deadline_seconds", "causal_predecessor",
                },
                errors,
            )
            for field, expected in {
                "operation": operation_name,
                "challenge_aware": True,
                "max_wire_transmissions": 2,
                "automatic_retry": False,
                "max_concurrency": 1,
                "terminal_deadline_seconds": 32,
                "causal_predecessor": predecessor,
            }.items():
                exact(operation.get(field), expected, f"{operation_path}.{field}", errors)
    calls = object_(
        data.get("calls"),
        "runtime_contract.calls",
        {"automatic_retry", "max_concurrency", "maximum_attempts", "contingency_attempts", "contingency_authority_required", "contingency_direction_bound", "target_scope", "target_binding"},
        errors,
    )
    exact(calls.get("automatic_retry"), False, "runtime_contract.calls.automatic_retry", errors)
    exact(calls.get("max_concurrency"), 1, "runtime_contract.calls.max_concurrency", errors)
    exact(calls.get("maximum_attempts"), 3, "runtime_contract.calls.maximum_attempts", errors)
    exact(calls.get("contingency_attempts"), 1, "runtime_contract.calls.contingency_attempts", errors)
    exact(calls.get("contingency_authority_required"), True, "runtime_contract.calls.contingency_authority_required", errors)
    exact(calls.get("contingency_direction_bound"), True, "runtime_contract.calls.contingency_direction_bound", errors)
    exact(calls.get("target_scope"), "single_owned_destination", "runtime_contract.calls.target_scope", errors)
    exact(calls.get("target_binding"), "destination_hmac_digest_and_private_owned_target_file", "runtime_contract.calls.target_binding", errors)
    timers = object_(
        data.get("timers"),
        "runtime_contract.timers",
        {"register_terminal_deadline_seconds", "call_deadline_seconds"},
        errors,
    )
    exact(
        timers.get("register_terminal_deadline_seconds"),
        32,
        "runtime_contract.timers.register_terminal_deadline_seconds",
        errors,
    )
    exact(
        timers.get("call_deadline_seconds"),
        60,
        "runtime_contract.timers.call_deadline_seconds",
        errors,
    )
    teardown = object_(
        data.get("teardown"),
        "runtime_contract.teardown",
        {"unregister_required", "active_call_hangup_required", "execution_containment_required", "secret_erasure_required", "failure_cleanup_required"},
        errors,
    )
    for field in ("unregister_required", "active_call_hangup_required", "execution_containment_required", "secret_erasure_required", "failure_cleanup_required"):
        exact(teardown.get(field), True, f"runtime_contract.teardown.{field}", errors)


def validate_management_storage(management_value: Any, storage_value: Any, errors: Errors) -> None:
    management = object_(management_value, "management_exposure", {"default_deny", "local_only"}, errors)
    exact(management.get("default_deny"), True, "management_exposure.default_deny", errors)
    exact(management.get("local_only"), True, "management_exposure.local_only", errors)
    storage = object_(storage_value, "storage_contract", {"ephemeral", "raw_logs", "cdr", "recordings", "backups", "exports"}, errors)
    exact(storage.get("ephemeral"), True, "storage_contract.ephemeral", errors)
    for field in {"raw_logs", "cdr", "recordings", "backups", "exports"}: require_false(storage, field, "storage_contract", errors)


def validate_receipt(value: Any, as_of: datetime, errors: Errors) -> None:
    data = object_(value, "acquisition_receipt", {"reference", "sha256", "acquired_at", "expires_at"}, errors)
    reference(data.get("reference"), "acquisition_receipt.reference", errors); digest(data.get("sha256"), "acquisition_receipt.sha256", errors)
    acquired = timestamp(data.get("acquired_at"), "acquisition_receipt.acquired_at", errors)
    expires = timestamp(data.get("expires_at"), "acquisition_receipt.expires_at", errors)
    if acquired and acquired > as_of: errors.append("acquisition_receipt.acquired_at: is after validation time")
    if expires and expires <= as_of: errors.append("acquisition_receipt.expires_at: receipt is expired")
    if acquired and expires and expires <= acquired: errors.append("acquisition_receipt: expiry must follow acquisition")


def validate_approvals(value: Any, errors: Errors) -> None:
    approvals = object_(value, "approvals", {"architect", "critic", "qa"}, errors); identities: set[str] = set()
    for role in ("architect", "critic", "qa"):
        path = f"approvals.{role}"; item = object_(approvals.get(role), path, {"identity", "independent", "decision", "reference", "sha256"}, errors)
        identity = text(item.get("identity"), f"{path}.identity", errors)
        if identity in identities: errors.append("approvals: Architect, Critic, and QA identities must differ")
        identities.add(identity); exact(item.get("independent"), True, f"{path}.independent", errors); exact(item.get("decision"), "approved", f"{path}.decision", errors)
        reference(item.get("reference"), f"{path}.reference", errors); digest(item.get("sha256"), f"{path}.sha256", errors)


def validate_approval_evidence(
    data: dict[str, Any],
    index: dict[str, Any],
    bundle_root: Path,
    as_of: datetime,
    errors: Errors,
) -> None:
    approvals = data.get("approvals")
    if not isinstance(approvals, dict):
        return
    identities: set[str] = set()
    fields = {
        "schema_version",
        "role",
        "identity",
        "independent",
        "decision",
        "review_payload_digest",
        "source_lock_sha256",
        "approved_at",
        "findings",
    }
    for role in ("architect", "critic", "qa"):
        approval = approvals.get(role)
        if not isinstance(approval, dict):
            continue
        reference_value = approval.get("reference")
        entry = index.get(reference_value)
        path = f"approvals.{role}.reference"
        if not isinstance(entry, dict):
            errors.append(f"{path}: missing approval evidence")
            continue
        evidence = safe_file(
            bundle_root,
            entry.get("path"),
            f"evidence_index.{reference_value}",
            errors,
        )
        if evidence is None:
            continue
        try:
            document = json.loads(
                evidence.read_text(encoding="utf-8"),
                object_pairs_hook=duplicate_safe_object,
            )
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
            errors.append(f"{path}: invalid approval evidence JSON")
            continue
        document = object_(document, f"approvals.{role}.evidence", fields, errors)
        exact(
            document.get("schema_version"),
            "onnuri-jambonz-oss-approval/v1",
            f"approvals.{role}.evidence.schema_version",
            errors,
        )
        exact(document.get("role"), role, f"approvals.{role}.evidence.role", errors)
        exact(
            document.get("identity"),
            approval.get("identity"),
            f"approvals.{role}.evidence.identity",
            errors,
        )
        exact(
            document.get("independent"),
            True,
            f"approvals.{role}.evidence.independent",
            errors,
        )
        exact(
            document.get("decision"),
            "approved",
            f"approvals.{role}.evidence.decision",
            errors,
        )
        exact(
            document.get("review_payload_digest"),
            data.get("review_payload_digest"),
            f"approvals.{role}.evidence.review_payload_digest",
            errors,
        )
        exact(
            document.get("source_lock_sha256"),
            data.get("source_lock_sha256"),
            f"approvals.{role}.evidence.source_lock_sha256",
            errors,
        )
        identity = document.get("identity")
        if isinstance(identity, str):
            if identity in identities:
                errors.append("approval evidence identities must be distinct")
            identities.add(identity)
        approved_at = timestamp(
            document.get("approved_at"),
            f"approvals.{role}.evidence.approved_at",
            errors,
        )
        if approved_at is not None:
            if approved_at > as_of + timedelta(minutes=5):
                errors.append(f"approvals.{role}.evidence.approved_at: is in the future")
            if approved_at < as_of - timedelta(hours=24):
                errors.append(f"approvals.{role}.evidence.approved_at: is stale")
        findings = document.get("findings")
        if not isinstance(findings, list) or any(
            not isinstance(item, str) or not item for item in findings
        ):
            errors.append(f"approvals.{role}.evidence.findings: invalid")


def validate_disqualifiers(value: Any, errors: Errors) -> None:
    if not isinstance(value, dict) or not value:
        errors.append("disqualifier_results: expected non-empty object")
        return
    expected_records = (
        expected_conformance_records()
        | expected_phase_c_records()
        | set(FROZEN_RUNTIME_EVIDENCE)
    )
    if expected_records - set(value):
        errors.append("disqualifier_results: missing signed conformance, frozen runtime, or Phase C evidence")
    for name, (expected_reference, expected_sha256) in FROZEN_RUNTIME_EVIDENCE.items():
        item = value.get(name)
        if not isinstance(item, dict):
            continue
        exact(item.get("reference"), expected_reference, f"disqualifier_results.{name}.reference", errors)
        exact(item.get("sha256"), "sha256:" + expected_sha256, f"disqualifier_results.{name}.sha256", errors)
    for name, raw in value.items():
        item = object_(raw, f"disqualifier_results.{name}", {"result", "reference", "sha256"}, errors)
        exact(item.get("result"), "pass", f"disqualifier_results.{name}.result", errors)
        reference(item.get("reference"), f"disqualifier_results.{name}.reference", errors)
        digest(item.get("sha256"), f"disqualifier_results.{name}.sha256", errors)


def validate_exact_runtime_evidence(data: dict[str, Any], errors: Errors) -> None:
    results = data.get("disqualifier_results")
    index = data.get("evidence_index")
    if not isinstance(results, dict) or not isinstance(index, dict):
        return
    for name, (reference_value, expected_sha256) in FROZEN_RUNTIME_EVIDENCE.items():
        result = results.get(name)
        entry = index.get(reference_value)
        if not isinstance(result, dict) or not isinstance(entry, dict):
            continue
        exact(entry.get("sha256"), expected_sha256, f"evidence_index.{reference_value}.sha256", errors)
        exact(entry.get("content_type"), "text", f"evidence_index.{reference_value}.content_type", errors)
    for relative_path, expected_sha256 in PHASE_C_EVIDENCE.items():
        reference_value = "evidence:evidence/phase-c-" + relative_path
        record_name = "candidate_input_phase_c_configuration_" + relative_path
        result = results.get(record_name)
        entry = index.get(reference_value)
        if not isinstance(result, dict) or not isinstance(entry, dict):
            continue
        exact(result.get("reference"), reference_value, f"disqualifier_results.{record_name}.reference", errors)
        exact(result.get("sha256"), "sha256:" + expected_sha256, f"disqualifier_results.{record_name}.sha256", errors)
        exact(entry.get("sha256"), expected_sha256, f"evidence_index.{reference_value}.sha256", errors)
        exact(entry.get("content_type"), "text", f"evidence_index.{reference_value}.content_type", errors)

def validate_index_shape(value: Any, errors: Errors) -> None:
    if not isinstance(value, dict) or not value: errors.append("evidence_index: expected non-empty object"); return
    for ref, raw in value.items():
        reference(ref, f"evidence_index.{ref}", errors)
        item = object_(raw, f"evidence_index.{ref}", {"path", "sha256", "content_type"}, errors)
        text(item.get("path"), f"evidence_index.{ref}.path", errors)
        text(item.get("sha256"), f"evidence_index.{ref}.sha256", errors, INDEX_SHA)
        if item.get("content_type") not in {"text", "application/x-tar"} | SCANNER_CONTENT_TYPES:
            errors.append(f"evidence_index.{ref}.content_type: unsupported evidence type")


def scan_value(
    value: Any,
    path: str,
    errors: Errors,
    *,
    unresolved: bool = True,
    source_evidence: bool = False,
) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            scan_value(
                child,
                f"{path}.{key}" if path else key,
                errors,
                unresolved=unresolved,
                source_evidence=source_evidence,
            )
    elif isinstance(value, list):
        for i, child in enumerate(value):
            scan_value(
                child,
                f"{path}[{i}]",
                errors,
                unresolved=unresolved,
                source_evidence=source_evidence,
            )
    elif isinstance(value, str) and contains_forbidden_text(
        value,
        unresolved=unresolved,
        source_evidence=source_evidence,
    ):
        errors.append(
            f"{path}: unresolved, secret, phone, or raw signaling/media data is forbidden"
        )


def evidence_assertions(data: dict[str, Any]) -> dict[str, str]:
    asserted: dict[str, str] = {}
    def add(ref: Any, sha: Any) -> None:
        if not isinstance(ref, str) or not isinstance(sha, str):
            return
        previous = asserted.get(ref)
        asserted[ref] = sha if previous in {None, sha} else ""
    for source in data.get("sources", []):
        if isinstance(source, dict):
            add(source.get("source_tree_reference"), source.get("source_tree_sha256"))
            add(source.get("submodules_reference"), source.get("submodules_sha256"))
            add(source.get("license_reference"), source.get("license_sha256"))
            add(source.get("patch_reference"), source.get("patch_sha256"))
            conditional = source.get("conditional_mit")
            if isinstance(conditional, dict):
                add(conditional.get("reference"), conditional.get("sha256"))
                add(conditional.get("topology_reference"), conditional.get("topology_sha256"))
    for image in data.get("images", []):
        if isinstance(image, dict):
            add(image.get("build_recipe_reference"), image.get("build_recipe_sha256"))
            add(image.get("build_provenance_reference"), image.get("build_provenance_sha256"))
            add(image.get("network_archive_reference"), image.get("network_archive_sha256"))
            add(image.get("network_archive_record_reference"), image.get("network_archive_record_sha256"))
            add(image.get("notices_reference"), image.get("notices_sha256"))
            add(image.get("sbom_reference"), image.get("sbom_sha256"))
            add(image.get("vulnerability_reference"), image.get("vulnerability_sha256"))
            scanner = image.get("scanner")
            if isinstance(scanner, dict):
                add(scanner.get("grype_db_identity_reference"), scanner.get("grype_db_identity_sha256"))
            add(image.get("vulnerability_acceptance_reference"), image.get("vulnerability_acceptance_sha256"))
            for contribution in image.get("source_contributions", []):
                if isinstance(contribution, dict):
                    add(contribution.get("reference"), contribution.get("sha256"))
    for image in data.get("support_images", []):
        if isinstance(image, dict):
            add(image.get("source_provenance_reference"), image.get("source_provenance_sha256"))
            add(image.get("notices_reference"), image.get("notices_sha256"))
            add(image.get("sbom_reference"), image.get("sbom_sha256"))
            add(image.get("vulnerability_reference"), image.get("vulnerability_sha256"))
            scanner = image.get("scanner")
            if isinstance(scanner, dict):
                add(scanner.get("grype_db_identity_reference"), scanner.get("grype_db_identity_sha256"))
            add(image.get("vulnerability_acceptance_reference"), image.get("vulnerability_acceptance_sha256"))
            add(image.get("oci_license_reference"), image.get("oci_license_sha256"))
            add(image.get("network_archive_reference"), image.get("network_archive_sha256"))
            add(image.get("network_archive_record_reference"), image.get("network_archive_record_sha256"))
    receipt = data.get("acquisition_receipt", {})
    if isinstance(receipt, dict): add(receipt.get("reference"), receipt.get("sha256"))
    for approval in data.get("approvals", {}).values() if isinstance(data.get("approvals"), dict) else []:
        if isinstance(approval, dict): add(approval.get("reference"), approval.get("sha256"))
    for result in data.get("disqualifier_results", {}).values() if isinstance(data.get("disqualifier_results"), dict) else []:
        if isinstance(result, dict): add(result.get("reference"), result.get("sha256"))
    return asserted
def validate_source_lock_binding(
    data: dict[str, Any],
    index: dict[str, Any],
    bundle_root: Path,
    errors: Errors,
) -> None:
    receipt = data.get("acquisition_receipt")
    if not isinstance(receipt, dict):
        return
    reference_value = receipt.get("reference")
    entry = index.get(reference_value)
    if not isinstance(entry, dict):
        errors.append("acquisition_receipt.reference: missing source receipt evidence")
        return
    evidence = safe_file(
        bundle_root,
        entry.get("path"),
        f"evidence_index.{reference_value}",
        errors,
    )
    if evidence is None:
        return
    try:
        source_receipt = json.loads(
            evidence.read_text(encoding="utf-8"),
            object_pairs_hook=duplicate_safe_object,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        errors.append("acquisition_receipt.reference: invalid source receipt JSON")
        return
    if not isinstance(source_receipt, dict):
        errors.append("acquisition_receipt.reference: source receipt must be an object")
        return
    lock_hash = source_receipt.get("source_lock_sha256")
    if not isinstance(lock_hash, str) or not INDEX_SHA.fullmatch(lock_hash):
        errors.append("acquisition_receipt.reference: invalid source-lock digest")
        return
    exact(
        data.get("source_lock_sha256"),
        "sha256:" + lock_hash,
        "source_lock_sha256",
        errors,
    )


def validate_patch_evidence(data: dict[str, Any], index: dict[str, Any], bundle_root: Path, errors: Errors) -> None:
    for i, source in enumerate(data.get("sources", [])):
        if not isinstance(source, dict): continue
        reference_value = source.get("patch_reference")
        entry = index.get(reference_value)
        path = f"sources[{i}].patch_reference"
        if not isinstance(entry, dict):
            errors.append(f"{path}: missing patch evidence index entry")
            continue
        evidence = safe_file(bundle_root, entry.get("path"), f"evidence_index.{reference_value}", errors)
        if evidence is None: continue
        try:
            record = json.loads(evidence.read_text(encoding="utf-8"), object_pairs_hook=duplicate_safe_object)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
            errors.append(f"{path}: invalid patch evidence JSON")
            continue
        if not isinstance(record, dict) or set(record) != {"name", "commit", "patch_path", "patch_sha256"}:
            errors.append(f"{path}: invalid patch evidence shape")
            continue
        exact(record.get("name"), source.get("name"), f"{path}.name", errors)
        exact(record.get("commit"), source.get("commit"), f"{path}.commit", errors)
        patch_path = text(record.get("patch_path"), f"{path}.patch_path", errors)
        relative = PurePosixPath(patch_path)
        if "\\" in patch_path or relative.is_absolute() or not relative.parts or "." in relative.parts or ".." in relative.parts:
            errors.append(f"{path}.patch_path: must be a normalized relative path")
        patch_digest = digest(record.get("patch_sha256"), f"{path}.patch_sha256", errors)
        exact(patch_digest, source.get("patch_content_sha256"), f"{path}.patch_sha256", errors)


def validate_build_recipe_evidence(data: dict[str, Any], index: dict[str, Any], bundle_root: Path, errors: Errors) -> None:
    sources_by_name = {
        source.get("name"): source
        for source in data.get("sources", [])
        if isinstance(source, dict)
    }
    for i, image in enumerate(data.get("images", [])):
        if not isinstance(image, dict):
            continue
        path = f"images[{i}]"
        reference_value = image.get("build_provenance_reference")
        entry = index.get(reference_value)
        if not isinstance(entry, dict):
            errors.append(f"{path}.build_provenance_reference: missing provenance evidence index entry")
            continue
        evidence = safe_file(bundle_root, entry.get("path"), f"evidence_index.{reference_value}", errors)
        if evidence is None:
            continue
        try:
            provenance = json.loads(evidence.read_text(encoding="utf-8"), object_pairs_hook=duplicate_safe_object)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
            errors.append(f"{path}.build_provenance_reference: invalid provenance JSON")
            continue
        if canonical_json(provenance) != evidence.read_bytes():
            errors.append(f"{path}.build_provenance_reference: must use canonical JSON")
        fields = {
            "source", "commit", "source_tree_sha256", "image_config_digest",
            "distribution_manifest", "base_image", "build_recipe_reference",
            "build_recipe_sha256", "runtime_oci_license",
        }
        provenance = object_(provenance, f"{path}.build_provenance", fields, errors)
        exact(provenance.get("source"), image.get("source_name"), f"{path}.build_provenance.source", errors)
        exact(provenance.get("commit"), image.get("source_commit"), f"{path}.build_provenance.commit", errors)
        source = sources_by_name.get(image.get("source_name"))
        exact(
            provenance.get("source_tree_sha256"),
            source.get("upstream_tree_sha256") if isinstance(source, dict) else None,
            f"{path}.build_provenance.source_tree_sha256",
            errors,
        )
        exact(
            provenance.get("runtime_oci_license"),
            RUNTIME_OCI_LICENSES.get(image.get("name")),
            f"{path}.build_provenance.runtime_oci_license",
            errors,
        )
        digest(provenance.get("image_config_digest"), f"{path}.build_provenance.image_config_digest", errors)
        distribution = digest(provenance.get("distribution_manifest"), f"{path}.build_provenance.distribution_manifest", errors)
        if isinstance(image.get("image"), str) and "@" in image["image"]:
            exact(distribution, image["image"].rsplit("@", 1)[1], f"{path}.build_provenance.distribution_manifest", errors)
        text(provenance.get("base_image"), f"{path}.build_provenance.base_image", errors, IMAGE)
        exact(provenance.get("base_image"), (image.get("base_images") or [None])[0], f"{path}.build_provenance.base_image", errors)
        exact(provenance.get("build_recipe_reference"), image.get("build_recipe_reference"), f"{path}.build_provenance.build_recipe_reference", errors)
        exact(provenance.get("build_recipe_sha256"), image.get("build_recipe_sha256"), f"{path}.build_provenance.build_recipe_sha256", errors)
        reference(provenance.get("build_recipe_reference"), f"{path}.build_provenance.build_recipe_reference", errors)
        digest(provenance.get("build_recipe_sha256"), f"{path}.build_provenance.build_recipe_sha256", errors)

def safe_file(root: Path, relative_path: Any, label: str, errors: Errors) -> Path | None:
    if not isinstance(relative_path, str): errors.append(f"{label}.path: expected string"); return None
    relative = PurePosixPath(relative_path)
    if "\\" in relative_path or relative.is_absolute() or not relative.parts or "." in relative.parts or ".." in relative.parts:
        errors.append(f"{label}.path: must be a normalized traversal-safe relative path"); return None
    try:
        if stat.S_ISLNK(root.lstat().st_mode) or not stat.S_ISDIR(root.stat().st_mode): raise OSError("invalid bundle root")
        candidate = root.joinpath(*relative.parts)
        if any(stat.S_ISLNK((root.joinpath(*relative.parts[:i])).lstat().st_mode) for i in range(1, len(relative.parts) + 1)): raise OSError("symlink")
        if not stat.S_ISREG(candidate.stat().st_mode): raise OSError("not regular")
        candidate.resolve().relative_to(root.resolve())
        return candidate
    except (OSError, ValueError): errors.append(f"{label}.path: must be a regular non-symlink file inside bundle root"); return None


def read_hashed(path: Path, maximum: int, label: str, errors: Errors, collect: bool = False) -> bytes | None:
    total = 0
    hashed = hashlib.sha256()
    chunks: list[bytes] = []
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1_048_576):
                total += len(chunk)
                if total > maximum:
                    errors.append(f"{label}: evidence exceeds type-specific byte limit")
                    return None
                hashed.update(chunk)
                if collect:
                    chunks.append(chunk)
    except OSError:
        errors.append(f"{label}: cannot read evidence")
        return None
    return b"".join(chunks) if collect else hashed.digest()


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def json_evidence(path: Path, maximum: int, label: str, errors: Errors) -> Any | None:
    content = read_hashed(path, maximum, label, errors, True)
    if content is None:
        return None
    try:
        return json.loads(content.decode("utf-8"), object_pairs_hook=duplicate_safe_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        errors.append(f"{label}: invalid UTF-8 unique-key JSON")
        return None


def redact_image_reference(value: str) -> str:
    _, separator, remainder = value.partition("/")
    return "local-registry/" + (remainder if separator else value)

def finding_key(image: str, finding: dict[str, Any]) -> str | None:
    vulnerability, artifact = finding.get("vulnerability"), finding.get("artifact")
    values = (image, vulnerability.get("id") if isinstance(vulnerability, dict) else None, artifact.get("name") if isinstance(artifact, dict) else None, artifact.get("version") if isinstance(artifact, dict) else None, artifact.get("type") if isinstance(artifact, dict) else None)
    if not all(isinstance(value, str) and value for value in values):
        return None
    return urllib.parse.urlencode(list(zip(("image", "vulnerability", "artifact_name", "artifact_version", "artifact_type"), values)))

def finding_digest(finding: dict[str, Any]) -> str | None:
    vulnerability, artifact = finding.get("vulnerability"), finding.get("artifact")
    fix = vulnerability.get("fix") if isinstance(vulnerability, dict) else None
    projection = {
        "vulnerability": vulnerability.get("id") if isinstance(vulnerability, dict) else None,
        "severity": str(vulnerability.get("severity", "")).upper() if isinstance(vulnerability, dict) else None,
        "artifact_name": artifact.get("name") if isinstance(artifact, dict) else None,
        "artifact_version": artifact.get("version") if isinstance(artifact, dict) else None,
        "artifact_type": artifact.get("type") if isinstance(artifact, dict) else None,
        "fix_state": fix.get("state") if isinstance(fix, dict) else None,
        "fix_versions": sorted(fix.get("versions", [])) if isinstance(fix, dict) and isinstance(fix.get("versions", []), list) else [],
    }
    if not all(isinstance(projection[field], str) and projection[field] for field in ("vulnerability", "severity", "artifact_name", "artifact_version", "artifact_type")):
        return None
    if projection["fix_state"] is not None and not isinstance(projection["fix_state"], str):
        return None
    if projection["fix_versions"] is None or any(not isinstance(version, str) or not version for version in projection["fix_versions"]):
        return None
    return hashlib.sha256(canonical_json(projection)).hexdigest()





def validate_image_evidence(data: dict[str, Any], index: dict[str, Any], root: Path, as_of: datetime, errors: Errors, *, archives: bool = True) -> None:
    for i, image in enumerate(data.get("images", [])):
        if not isinstance(image, dict):
            continue
        path = f"images[{i}]"
        def entry(ref: Any, suffix: str, kinds: set[str]) -> tuple[dict[str, Any], Path] | None:
            raw = index.get(ref)
            if not isinstance(raw, dict) or raw.get("content_type") not in kinds:
                errors.append(f"{path}.{suffix}: missing or wrong evidence type")
                return None
            evidence = safe_file(root, raw.get("path"), f"evidence_index.{ref}", errors)
            return (raw, evidence) if evidence is not None else None
        if archives:
            archive = entry(image.get("network_archive_reference"), "network_archive_reference", {"application/x-tar"})
            archive_record = entry(image.get("network_archive_record_reference"), "network_archive_record_reference", {"text"})
            if archive and archive[0].get("sha256") != str(image.get("network_archive_sha256", "")).removeprefix("sha256:"):
                errors.append(f"{path}.network_archive_reference: archive digest does not bind archive evidence")
            if archive_record:
                record = json_evidence(archive_record[1], MAX_TEXT_EVIDENCE_BYTES, f"{path}.network_archive_record", errors)
                if not isinstance(record, dict) or set(record) != {"name", "archive_reference", "archive_sha256", "mode", "network_denied"}:
                    errors.append(f"{path}.network_archive_record: invalid canonical archive record")
                else:
                    if canonical_json(record) != archive_record[1].read_bytes(): errors.append(f"{path}.network_archive_record: must use canonical JSON")
                    exact(record.get("name"), image.get("name"), f"{path}.network_archive_record.name", errors)
                    exact(record.get("archive_reference"), image.get("network_archive_reference"), f"{path}.network_archive_record.archive_reference", errors)
                    exact(record.get("archive_sha256"), image.get("network_archive_sha256"), f"{path}.network_archive_record.archive_sha256", errors)
                    exact(record.get("mode"), "0444", f"{path}.network_archive_record.mode", errors)
                    exact(record.get("network_denied"), True, f"{path}.network_archive_record.network_denied", errors)
        scanner = image.get("scanner")
        if not isinstance(scanner, dict):
            continue
        sbom, grype, acceptance = entry(image.get("sbom_reference"), "sbom_reference", {"application/vnd.cyclonedx+json", "application/vnd.anchore.syft+json"}), entry(image.get("vulnerability_reference"), "vulnerability_reference", {"application/vnd.anchore.grype+json"}), entry(image.get("vulnerability_acceptance_reference"), "vulnerability_acceptance_reference", {"text"})
        db_identity = entry(scanner.get("grype_db_identity_reference"), "scanner.grype_db_identity_reference", {"text"})
        if sbom and not isinstance(json_evidence(sbom[1], MAX_SCANNER_EVIDENCE_BYTES, f"{path}.sbom_reference", errors), dict):
            errors.append(f"{path}.sbom_reference: invalid Syft JSON")
        if not grype or not acceptance or not db_identity:
            continue
        findings = json_evidence(grype[1], MAX_SCANNER_EVIDENCE_BYTES, f"{path}.vulnerability_reference", errors)
        decisions_record = json_evidence(acceptance[1], MAX_TEXT_EVIDENCE_BYTES, f"{path}.vulnerability_acceptance_reference", errors)
        database = json_evidence(db_identity[1], MAX_TEXT_EVIDENCE_BYTES, f"{path}.scanner.grype_db_identity_reference", errors)
        if not isinstance(decisions_record, dict) or set(decisions_record) != {"image", "scanner", "decisions"}:
            errors.append(f"{path}.vulnerability_acceptance_reference: invalid acceptance record")
            continue
        if canonical_json(decisions_record) != acceptance[1].read_bytes(): errors.append(f"{path}.vulnerability_acceptance_reference: must use canonical JSON")
        exact(decisions_record.get("image"), image.get("name"), f"{path}.vulnerability_acceptance.image", errors)
        accepted_scanner = decisions_record.get("scanner")
        if not isinstance(accepted_scanner, dict) or set(accepted_scanner) != {"grype_version", "grype_db_identity"}:
            errors.append(f"{path}.vulnerability_acceptance.scanner: invalid scanner identity")
            continue
        exact(accepted_scanner.get("grype_version"), scanner.get("grype_version"), f"{path}.vulnerability_acceptance.scanner.grype_version", errors)
        exact(accepted_scanner.get("grype_db_identity"), database, f"{path}.vulnerability_acceptance.scanner.grype_db_identity", errors)
        matches, decisions = findings.get("matches") if isinstance(findings, dict) else None, decisions_record.get("decisions")
        if not isinstance(matches, list) or not isinstance(decisions, dict):
            errors.append(f"{path}: invalid Grype findings or acceptance decisions")
            continue
        critical = high = unaccepted_critical = unaccepted_high = 0
        for finding in matches:
            severity = str(finding.get("vulnerability", {}).get("severity", "")).upper() if isinstance(finding, dict) else ""
            if severity not in {"CRITICAL", "HIGH"}:
                continue
            key = finding_key(str(image.get("name", "")), finding)
            if key is None:
                errors.append(f"{path}.vulnerability_reference: invalid Critical/High finding identity")
                continue
            if severity == "CRITICAL": critical += 1
            else: high += 1
            decision = decisions.get(key)
            expiry = timestamp(decision.get("expires_at"), f"{path}.vulnerability_acceptance.decisions.{key}.expires_at", errors) if isinstance(decision, dict) else None
            accepted = isinstance(decision, dict) and set(decision) == {"reason", "expires_at", "finding_sha256"} and isinstance(decision.get("reason"), str) and bool(decision["reason"]) and decision.get("finding_sha256") == finding_digest(finding) and expiry is not None and expiry > as_of
            if not accepted:
                if severity == "CRITICAL": unaccepted_critical += 1
                else: unaccepted_high += 1
        summary = image.get("vulnerability_summary")
        if isinstance(summary, dict):
            for field, actual in (("critical", critical), ("high", high), ("unaccepted_critical", unaccepted_critical), ("unaccepted_high", unaccepted_high)): exact(summary.get(field), actual, f"{path}.vulnerability_summary.{field}", errors)
        if unaccepted_critical or unaccepted_high: errors.append(f"{path}.vulnerability_summary: unaccepted Critical/High findings are forbidden")


def validate_support_evidence(data: dict[str, Any], index: dict[str, Any], root: Path, errors: Errors) -> None:
    for i, support in enumerate(data.get("support_images", [])):
        if not isinstance(support, dict):
            continue
        path = f"support_images[{i}]"

        def text_evidence(reference_value: Any, field: str) -> tuple[dict[str, Any], Path] | None:
            entry = index.get(reference_value)
            if not isinstance(entry, dict) or entry.get("content_type") != "text":
                errors.append(f"{path}.{field}: missing or wrong evidence type")
                return None
            evidence = safe_file(root, entry.get("path"), f"evidence_index.{reference_value}", errors)
            return (entry, evidence) if evidence is not None else None

        provenance_entry = text_evidence(
            support.get("source_provenance_reference"),
            "source_provenance_reference",
        )
        if provenance_entry:
            provenance_document = json_evidence(
                provenance_entry[1],
                MAX_TEXT_EVIDENCE_BYTES,
                f"{path}.source_provenance_reference",
                errors,
            )
            expected_provenance = {
                "image": support.get("image"),
                "name": support.get("name"),
                "source": support.get("source"),
                "source_provenance": support.get("source_provenance"),
            }
            if provenance_document != expected_provenance:
                errors.append(f"{path}.source_provenance_reference: provenance mismatch")
            elif canonical_json(provenance_document) != provenance_entry[1].read_bytes():
                errors.append(f"{path}.source_provenance_reference: must use canonical JSON")
        notice_entry = text_evidence(support.get("notices_reference"), "notices_reference")
        license_entry = text_evidence(support.get("oci_license_reference"), "oci_license_reference")
        if not notice_entry or not license_entry:
            continue
        notice = json_evidence(notice_entry[1], MAX_TEXT_EVIDENCE_BYTES, f"{path}.notices_reference", errors)
        oci_license = json_evidence(license_entry[1], MAX_TEXT_EVIDENCE_BYTES, f"{path}.oci_license_reference", errors)
        if not isinstance(notice, dict) or set(notice) != {"name", "image", "oci_labels"}:
            errors.append(f"{path}.notices_reference: invalid support notice")
            continue
        if canonical_json(notice) != notice_entry[1].read_bytes():
            errors.append(f"{path}.notices_reference: must use canonical JSON")
        exact(notice.get("name"), support.get("name"), f"{path}.notices.name", errors)
        exact(notice.get("image"), support.get("image"), f"{path}.notices.image", errors)
        labels = notice.get("oci_labels")
        if not isinstance(labels, dict) or any(not isinstance(key, str) or not isinstance(value, str) for key, value in labels.items()):
            errors.append(f"{path}.notices.oci_labels: invalid OCI labels")
            continue
        exact(labels.get("org.opencontainers.image.licenses"), support.get("license_spdx"), f"{path}.notices.license_spdx", errors)
        base = labels.get("org.recova.base.digest")
        if not isinstance(base, str) or not IMAGE.fullmatch(base):
            errors.append(f"{path}.notices.base_image: invalid immutable base image")
        else:
            exact(support.get("base_images"), [redact_image_reference(base)], f"{path}.base_images", errors)
        if not isinstance(oci_license, dict) or set(oci_license) != {
            "name", "image", "license_spdx", "oci_labels_sha256"
        }:
            errors.append(f"{path}.oci_license_reference: invalid OCI license record")
            continue
        if canonical_json(oci_license) != license_entry[1].read_bytes():
            errors.append(f"{path}.oci_license_reference: must use canonical JSON")
        exact(oci_license.get("name"), support.get("name"), f"{path}.oci_license.name", errors)
        exact(oci_license.get("image"), support.get("image"), f"{path}.oci_license.image", errors)
        exact(oci_license.get("license_spdx"), support.get("license_spdx"), f"{path}.oci_license.license_spdx", errors)
        exact(
            oci_license.get("oci_labels_sha256"),
            "sha256:" + hashlib.sha256(canonical_json(labels)).hexdigest(),
            f"{path}.oci_license.oci_labels_sha256",
            errors,
        )
def validate_acceptance_expiry_bound(
    data: dict[str, Any],
    index: dict[str, Any],
    bundle_root: Path,
    errors: Errors,
) -> None:
    receipt = data.get("acquisition_receipt")
    if not isinstance(receipt, dict):
        return
    acquisition_expiry = timestamp(
        receipt.get("expires_at"), "acquisition_receipt.expires_at", errors
    )
    if acquisition_expiry is None:
        return
    for collection in ("images", "support_images"):
        for position, image in enumerate(data.get(collection, [])):
            if not isinstance(image, dict):
                continue
            reference_value = image.get("vulnerability_acceptance_reference")
            entry = index.get(reference_value)
            if not isinstance(entry, dict):
                continue
            evidence = safe_file(
                bundle_root,
                entry.get("path"),
                f"evidence_index.{reference_value}",
                errors,
            )
            if evidence is None:
                continue
            try:
                acceptance = json.loads(
                    evidence.read_text(encoding="utf-8"),
                    object_pairs_hook=duplicate_safe_object,
                )
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
                continue
            decisions = acceptance.get("decisions") if isinstance(acceptance, dict) else None
            if not isinstance(decisions, dict):
                continue
            for key, decision in decisions.items():
                if not isinstance(decision, dict):
                    continue
                expiry = timestamp(
                    decision.get("expires_at"),
                    f"{collection}[{position}].acceptances.{key}.expires_at",
                    errors,
                )
                if expiry is not None and acquisition_expiry > expiry:
                    errors.append(
                        "acquisition_receipt.expires_at: exceeds vulnerability "
                        f"acceptance expiry for {collection}[{position}]"
                    )


def validate_evidence(data: Any, bundle_root: Path, errors: Errors, as_of: datetime | None = None) -> None:
    if not isinstance(data, dict): return
    index = data.get("evidence_index"); asserted = evidence_assertions(data)
    if not isinstance(index, dict): return
    if set(index) != set(asserted): errors.append("evidence_index: must contain exactly all asserted evidence references")
    paths: set[str] = set()
    for ref in set(index) & set(asserted):
        item = index[ref]
        if not isinstance(item, dict): continue
        label, evidence = f"evidence_index.{ref}", safe_file(bundle_root, item.get("path"), f"evidence_index.{ref}", errors)
        if item.get("path") in paths: errors.append(f"{label}.path: duplicate evidence path")
        if isinstance(item.get("path"), str): paths.add(item["path"])
        if item.get("sha256") != asserted[ref].removeprefix("sha256:"): errors.append(f"{label}.sha256: does not match manifest assertion")
        if evidence is None: continue
        kind = item.get("content_type"); maximum = MAX_ARCHIVE_EVIDENCE_BYTES if kind == "application/x-tar" else MAX_SCANNER_EVIDENCE_BYTES if kind in SCANNER_CONTENT_TYPES else MAX_TEXT_EVIDENCE_BYTES
        hashed = read_hashed(evidence, maximum, label, errors, kind == "text")
        if hashed is None: continue
        actual = hashlib.sha256(hashed).hexdigest() if kind == "text" else hashed.hex()
        if actual != item.get("sha256"): errors.append(f"{label}.sha256: does not match evidence bytes")
        if ref.endswith(("-notices.json", "-sbom.json")):
            document = json_evidence(evidence, maximum, label, errors)
            if document is not None and contains_personal_metadata(document):
                errors.append(f"{label}: personal metadata is not permitted in support notices or SBOM evidence")
        if kind == "text":
            try:
                decoded = hashed.decode("utf-8")
                scan_value(
                    decoded,
                    label,
                    errors,
                    unresolved=False,
                    source_evidence=ref.startswith(
                        (
                            "evidence:evidence/runtime-",
                            "evidence:evidence/source-patch-",
                        )
                    )
                    or ref == "evidence:evidence/sealed-secret-wrapper.sh",
                )
            except UnicodeDecodeError:
                errors.append(f"{label}: textual evidence must be UTF-8")
    validate_patch_evidence(data, index, bundle_root, errors)
    validate_source_lock_binding(data, index, bundle_root, errors)
    validate_build_recipe_evidence(data, index, bundle_root, errors)
    validate_support_evidence(data, index, bundle_root, errors)
    validate_acceptance_expiry_bound(data, index, bundle_root, errors)
    validate_conformance_evidence(data, index, bundle_root, errors)


    if as_of is not None:
        validate_image_evidence(data, index, bundle_root, as_of, errors)
        validate_approval_evidence(data, index, bundle_root, as_of, errors)
        validate_image_evidence({"images": data.get("support_images", [])}, index, bundle_root, as_of, errors)


def trusted_conformance_key() -> Ed25519PublicKey | None:
    keyset_path = Path(__file__).parents[2] / "infra/onnuri-seoul-staging-phase-c-smoke/trusted_keys/phase_c_live_preflight_v1.json"
    try:
        raw = keyset_path.read_bytes()
        keyset = json.loads(raw, object_pairs_hook=duplicate_safe_object)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        return None
    if not isinstance(keyset, dict) or hashlib.sha256(raw).hexdigest() != CONFORMANCE_TRUSTED_KEYSET_SHA256 or canonical_json(keyset) != raw:
        return None
    keys = keyset.get("keys")
    if keyset.get("schema_version") != "recova-phase-c-live-preflight-keyset.v1" or not isinstance(keys, list):
        return None
    matches = [item for item in keys if isinstance(item, dict) and item.get("algorithm") == "Ed25519" and item.get("key_id") == CONFORMANCE_SIGNER_KEY_ID and item.get("role") == CONFORMANCE_SIGNER_ROLE and isinstance(item.get("public_key_base64url"), str) and isinstance(item.get("public_key_sha256"), str)]
    if len(matches) != 1:
        return None
    try:
        encoded = matches[0]["public_key_base64url"]
        key_bytes = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        if len(key_bytes) != 32 or hashlib.sha256(key_bytes).hexdigest() != matches[0]["public_key_sha256"]:
            return None
        return Ed25519PublicKey.from_public_bytes(key_bytes)
    except (TypeError, ValueError):
        return None


def conformance_signature_payload(receipt: dict[str, Any]) -> bytes:
    return canonical_json({key: value for key, value in receipt.items() if key != "signature"})



def validate_conformance_receipt(data: dict[str, Any], index: dict[str, Any], root: Path, errors: Errors) -> None:
    result = data.get("disqualifier_results", {}).get("candidate_input_conformance")
    if not isinstance(result, dict):
        errors.append("conformance: missing signed receipt assertion")
        return
    entry = index.get(result.get("reference"))
    if not isinstance(entry, dict) or entry.get("content_type") != "text":
        errors.append("conformance: signed receipt must be indexed text evidence")
        return
    evidence = safe_file(root, entry.get("path"), "conformance.receipt", errors)
    if evidence is None:
        return
    raw = read_hashed(evidence, MAX_TEXT_EVIDENCE_BYTES, "conformance.receipt", errors, True)
    if raw is None:
        return
    try:
        receipt = json.loads(raw, object_pairs_hook=duplicate_safe_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        errors.append("conformance.receipt: invalid JSON")
        return
    if canonical_json(receipt) != raw:
        errors.append("conformance.receipt: must be canonical signed JSON")
    fields = {"schema_version", "generated_at", "source_lock_sha256", "config_sha256", "checks", "signer_identity", "signature"}
    receipt = object_(receipt, "conformance.receipt", fields, errors)
    exact(receipt.get("schema_version"), "onnuri-jambonz-oss-conformance/v2", "conformance.receipt.schema_version", errors)
    exact(receipt.get("signer_identity"), CONFORMANCE_SIGNER_IDENTITY, "conformance.receipt.signer_identity", errors)
    exact(receipt.get("source_lock_sha256"), data.get("source_lock_sha256", "").removeprefix("sha256:"), "conformance.receipt.source_lock_sha256", errors)
    signature = object_(receipt.get("signature"), "conformance.receipt.signature", {"algorithm", "key_id", "value_b64"}, errors)
    exact(signature.get("algorithm"), "Ed25519", "conformance.receipt.signature.algorithm", errors)
    exact(signature.get("key_id"), CONFORMANCE_SIGNER_KEY_ID, "conformance.receipt.signature.key_id", errors)
    key = trusted_conformance_key()
    try:
        value = base64.b64decode(signature.get("value_b64", ""), validate=True)
        if key is None or len(value) != 64:
            raise ValueError("invalid trusted signature")
        key.verify(value, conformance_signature_payload(receipt))
    except (InvalidSignature, ValueError, TypeError):
        errors.append("conformance: independent signature verification failed")
    generated_at = timestamp(receipt.get("generated_at"), "conformance.receipt.generated_at", errors)
    if generated_at is not None and (generated_at > datetime.now(generated_at.tzinfo) + timedelta(minutes=5) or generated_at < datetime.now(generated_at.tzinfo) - timedelta(hours=24)):
        errors.append("conformance.receipt.generated_at: is stale or in the future")
    checks = receipt.get("checks")
    results = data.get("disqualifier_results")
    commands = CONFORMANCE_CHECKS
    if not isinstance(checks, dict) or set(checks) != set(commands) or not isinstance(results, dict):
        errors.append("conformance.receipt: checks are incomplete")
    else:
        for name, command in commands.items():
            check = checks.get(name)
            result = results.get(f"candidate_input_conformance_output_{name}")
            if not isinstance(check, dict) or set(check) != {"command", "command_identity", "exit_code", "result", "output_path", "output_sha256"} or check.get("command") != command or check.get("command_identity") != hashlib.sha256(command.encode()).hexdigest() or check.get("exit_code") != 0 or check.get("result") != "pass" or not isinstance(check.get("output_sha256"), str) or not INDEX_SHA.fullmatch(check["output_sha256"]):
                errors.append(f"conformance.receipt.{name}: invalid signed check")
            elif not isinstance(result, dict) or result.get("sha256") != "sha256:" + check["output_sha256"]:
                errors.append(f"conformance.receipt.{name}: signed output is not bound to manifest artifact")
    configs = receipt.get("config_sha256")
    if not isinstance(configs, dict) or not configs:
        errors.append("conformance.receipt.config_sha256: missing artifact bindings")
    else:
        for name, claimed in configs.items():
            if not isinstance(name, str) or not INDEX_SHA.fullmatch(str(claimed)):
                errors.append("conformance.receipt.config_sha256: invalid artifact binding")
                continue
            evidence_name = name.removeprefix("phase-c/")
            prefix = "phase-c-" if name.startswith("phase-c/") else "runtime-"
            expected_path = "evidence/" + prefix + evidence_name.replace("/", "-")
            entries = [entry for entry in index.values() if isinstance(entry, dict) and entry.get("path") == expected_path]
            if len(entries) != 1 or entries[0].get("sha256") != claimed:
                errors.append(f"conformance.receipt.config_sha256.{name}: does not bind indexed artifact bytes")


def validate_conformance_output_evidence(
    name: str,
    command: str,
    result: Any,
    index: dict[str, Any],
    root: Path,
    errors: Errors,
) -> None:
    if not isinstance(result, dict):
        errors.append(f"conformance.{name}: invalid raw output assertion")
        return
    entry = index.get(result.get("reference"))
    if not isinstance(entry, dict) or entry.get("content_type") != "text":
        errors.append(f"conformance.{name}: raw output must be indexed text evidence")
        return
    evidence = safe_file(root, entry.get("path"), f"conformance.{name}", errors)
    if evidence is None:
        return
    contents = read_hashed(evidence, MAX_TEXT_EVIDENCE_BYTES, f"conformance.{name}", errors, True)
    if contents is None:
        return
    if hashlib.sha256(contents).hexdigest() != str(result.get("sha256", "")).removeprefix("sha256:"):
        errors.append(f"conformance.{name}: raw output digest mismatch")
    if hashlib.sha256(command.encode("utf-8")).hexdigest().encode() not in contents:
        errors.append(f"conformance.{name}: raw output lacks deterministic command identity")


def validate_conformance_evidence(data: dict[str, Any], index: dict[str, Any], root: Path, errors: Errors) -> None:
    results = data.get("disqualifier_results")
    if not isinstance(results, dict):
        return
    for name, command in CONFORMANCE_CHECKS.items():
        result = results.get(f"candidate_input_conformance_output_{name}")
        if result is not None:
            validate_conformance_output_evidence(name, command, result, index, root, errors)

def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=duplicate_safe_object)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path); parser.add_argument("--bundle-root", type=Path, required=True); parser.add_argument("--as-of", required=True)
    args = parser.parse_args(); errors: Errors = []
    as_of = timestamp(args.as_of, "--as-of", errors)
    try: data = load_json(args.manifest)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc: print(f"manifest: cannot read valid unique-key JSON: {exc}", file=sys.stderr); return 2
    if as_of is None: print("\n".join(errors), file=sys.stderr); return 2
    try:
        import jsonschema
        schema = load_json(Path(__file__).with_name("candidate-manifest.schema.json"))
        errors.extend(f"schema: {error.message}" for error in jsonschema.Draft202012Validator(schema).iter_errors(data))
    except ImportError: print("jsonschema is required for CLI validation", file=sys.stderr); return 2
    errors.extend(validate_manifest(data, as_of)); validate_evidence(data, args.bundle_root, errors, as_of)
    validate_conformance_receipt(data, data.get("evidence_index", {}), args.bundle_root, errors)
    validate_bootstrap_manifest_evidence(data, data.get("evidence_index", {}), args.bundle_root, errors)
    validate_signed_candidate_boot_context(data, data.get("evidence_index", {}), args.bundle_root, errors)
    if errors: print("\n".join(sorted(set(errors))), file=sys.stderr); return 1
    print("candidate manifest valid"); return 0

if __name__ == "__main__": raise SystemExit(main())
