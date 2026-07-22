#!/usr/bin/env python3
"""Fail-closed local evidence sealer for the pinned G009 OSS candidate.

The supplied registry must already be running on loopback.  This program never
starts services, logs in, or reads credentials.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HERE = Path(__file__).resolve().parent
COPYRIGHT_PREFIX = re.compile(r"(?i)^copyright\s+(?:\(c\)\s*)?(?:\d{4}(?:-\d{4})?\s*)?")
SHA = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
FORBIDDEN = re.compile(r"jambonz-mini|commercial|license[ _-]?key|activation|trial|paid|entitlement|circumvention", re.I)
PERSONAL_EMAIL = re.compile(r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b")
PERSONAL_NAME = re.compile(r"^[A-Z][a-z]+(?:[ -][A-Z][a-z]+)+$")
NON_PERSONAL_IDENTITIES = {
    "Recova", "Recova Voice", "Jambonz", "FreeSWITCH", "Sofia-SIP", "SpanDSP",
    "PostgreSQL", "MariaDB", "Redis", "nginx", "Anchore", "Syft", "Grype",
}


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


def redact_personal_metadata(value: Any, key: str = "") -> Any:
    if isinstance(value, dict):
        return {
            child_key: redact_personal_metadata(child, str(child_key))
            for child_key, child in value.items()
        }
    if isinstance(value, list):
        return [redact_personal_metadata(child, key) for child in value]
    if isinstance(value, str) and contains_personal_metadata(value, key):
        return "REDACTED"
    return value

APPROVAL_REFERENCES = {
    f"evidence:evidence/approval-{role}.json"
    for role in ("architect", "critic", "qa")
}
REQUIRED_SOURCES = {"jambonz-feature-server", "jambonz-api-server", "sbc-inbound", "sbc-outbound", "sbc-call-router", "sbc-sip-sidecar", "sbc-rtpengine-sidecar", "drachtio-server", "freeswitch", "jambonz-freeswitch-modules", "spandsp", "sofia-sip", "rtpengine"}
RUNTIME_IMAGES = REQUIRED_SOURCES - {"jambonz-freeswitch-modules", "spandsp", "sofia-sip"}
BUILD_RECIPES = {
    **{name: "Dockerfile.node-app" for name in RUNTIME_IMAGES - {"drachtio-server", "freeswitch", "rtpengine"}},
    "drachtio-server": "Dockerfile.drachtio",
    "freeswitch": "Dockerfile.freeswitch",
    "rtpengine": "Dockerfile.rtpengine",
}
RUNTIME_LICENSES = {
    **{name: "MIT" for name in RUNTIME_IMAGES - {"freeswitch", "rtpengine"}},
    "freeswitch": "MPL-1.1 AND MIT AND LGPL-2.1-only",
    "rtpengine": "GPL-3.0",
}
CANDIDATE_RUNTIME_FILES = (
    "compose.yaml",
    "candidate.env.example",
    "bootstrap-database.sh",
    "10-g009-minimal-seed.sql",
    "20-g009-registration-template.sql",
    "verify-registration-egress-proof.js",
    "run-g008-live-smoke.py",
    "run-registration-transaction.js",
    "registration-sip-attestor.js",
    "drachtio-feature.xml",
    "drachtio-sip.xml",
    "f12-ingress-nginx.conf",
    "freeswitch-modules.conf.xml",
    "freeswitch-conf/freeswitch.xml",
    "freeswitch-conf/autoload_configs/console.conf.xml",
    "freeswitch-conf/autoload_configs/event_socket.conf.xml",
    "freeswitch-conf/autoload_configs/sofia.conf.xml",
    "sealed-secret-wrapper.sh",
)
PHASE_C_RUNTIME_FILES = (
    "startup-g008.sh",
    "backend.tf",
    "containment.tf",
    "crypto_gate.tf",
    "firewalls.tf",
    "iam.tf",
    "locals.tf",
    "network.tf",
    "observability.tf",
    "outputs.tf",
    "providers.tf",
    "secrets.tf",
    "variables.tf",
    "versions.tf",
    "workload.tf",
)
PHASE_C_EVIDENCE_PREFIX = "candidate_input_phase_c_configuration_"
PHASE_C_ROOT = HERE.parents[1] / "infra/onnuri-seoul-staging-phase-c-smoke"

FROZEN_RUNTIME_EVIDENCE = {
    "candidate_input_g008_live_smoke_runner": {
        "source": "run-g008-live-smoke.py",
        "evidence_name": "g008-live-smoke-runner.py",
        "sha256": "280d4b95eec76e605e42295d591ec64cb7b0ce8ca91dede49e9d7ba1d22d0ca9",
    },
    "candidate_input_runtime_compose": {
        "source": "compose.yaml",
        "evidence_name": "runtime-compose.yaml",
        "sha256": "340086636e82286f094db7b8c755a6c8191378d5c37db23c58b774fffeb1b95b",
    },
    "candidate_input_sealed_secret_wrapper": {
        "source": "sealed-secret-wrapper.sh",
        "evidence_name": "sealed-secret-wrapper.sh",
        "sha256": "2a09aba9970da289794b09400bfd72bf17a2f98ff6a9e311015ab828d7376b07",
    },
    "candidate_input_bootstrap_binding": {
        "source": "../../infra/onnuri-seoul-staging-phase-c-smoke/startup-g008.sh",
        "evidence_name": "phase-c-startup-g008.sh",
        "sha256": "181d7df7975679bd8fc5d80f8e6fc7df55ccaa5aefd41fefa2d7ad362ad5fdff",
    },
    "candidate_input_phase_c_live_preflight_trusted_keyset": {
        "source": "../../infra/onnuri-seoul-staging-phase-c-smoke/trusted_keys/phase_c_live_preflight_v1.json",
        "evidence_name": "runtime-phase-c-live-preflight-trusted-keyset.json",
        "sha256": "00645f3af8230c742951c12f17a713afde209de12182cd6e3722ac59445507aa",
    },
}
PHASE_C_RUNTIME_SHA256 = {
    "startup-g008.sh": "181d7df7975679bd8fc5d80f8e6fc7df55ccaa5aefd41fefa2d7ad362ad5fdff",
    "backend.tf": "4a3e917be1d0ffe925505b1bdaa4d205effb9bd142cf0ccb655b0204fa06a7a2",
    "containment.tf": "174f821de4bf18df83a0252fc1ff5f51962a0860c0de0843ee658b075686d967",
    "crypto_gate.tf": "07225e2ab4bf6b2bc2fb6ae1a1f7ce91b6e1e6a4c55ce8db0509c3fce7be8f1e",
    "firewalls.tf": "c1b3c6af27def65bd5c115dd90660402741b11bb8d7a37e75ecd52364a0a7e6a",
    "iam.tf": "894791c62712571c43605aaded6e737f50d3eb4b5d5c8a9084331bdec0871834",
    "locals.tf": "f725febc287a0fa64ce96228ee886384ec554cc10add04feadc8b215ac8eb678",
    "network.tf": "e920ab3827bd5548a7251294f21d7d66211e552462e59af343bf33810a328f99",
    "observability.tf": "8b7c8de24b86f42253fe10329141034ddb2618fca4db93915147f89e77292e01",
    "outputs.tf": "fdab75096a58ce62487390fb0170a69e1494c7aa002c920bc202e25737caef39",
    "providers.tf": "d44f95858aebade0afaa2b7908677e11e0aff018c4a42698e4f45eeb493fff71",
    "secrets.tf": "c18c551e42960ff57a3a18e1837e61fdde4ff2ad7cdcbeb5a163d978e59c8743",
    "variables.tf": "28a5edb24b788aef7db475b19cd4abdb5667e4e20ad8eaff974102f86c5303de",
    "versions.tf": "16031e61a9de9aab9358f537d68d5f41c6065bb626a65d84f0b8f5d195be4fe0",
    "workload.tf": "e33c6530fbf7e690f8d1b0d1583cac7b07e5f1c136e579757faef73af90d40fd",
}
RUNTIME_GENERATED_COMPOSE_CONFIGS = {"g009-upstream-schema"}
EXTERNAL_FROZEN_COMPOSE_CONFIGS = {
    "g008-live-smoke-runner": "/opt/g008/run-g008-live-smoke.py",
    "g008-trusted-keyset": "/opt/g008/trusted/phase_c_live_preflight_v1.json",
    "g009-registration-egress-verifier": "/opt/g009/verify-registration-egress-proof.js",
    "g009-registration-transaction-runner": "/opt/g009/run-registration-transaction.js",
    "g009-registration-sip-attestor": "/opt/g009/registration-sip-attestor.js",
}
CONFORMANCE_CHECKS = {
    "offline_default_deny": "pytest:offline-compose",
    "registration_request_cardinality": "pytest:registration-cardinality",
    "registration_no_retry_concurrency": "pytest:registration-no-retry-concurrency",
    "media_contract": "pytest:media-basic-l16-8000-mono-bidirectional",
    "call_deadline": "pytest:call-deadline-60s",
}
SUPPORT_IMAGES = {
    "mariadb",
    "redis",
    "facade",
    "recova-backend",
    "postgres",
    "recova-redis",
    "f12-ingress",
}
FIRST_PARTY_SUPPORT_SOURCE = "https://github.com/slit-company/recova-voice"
SOURCE_REVISION_LABEL = "org.opencontainers.image.revision"
SOURCE_TREE_LABEL = "org.recova.source-tree.sha256"
CONFORMANCE_SIGNER_IDENTITY = "recova-g008-phase-c-preflight-v1"
CONFORMANCE_SIGNER_KEY_ID = "recova-g008-phase-c-preflight-v1"
CONFORMANCE_SIGNER_ROLE = "phase-c-preflight"

class Refusal(ValueError):
    pass

def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()
def sha(data: bytes) -> str: return hashlib.sha256(data).hexdigest()
def review_payload_digest(manifest: dict[str, Any]) -> str:
    payload = {
        key: value
        for key, value in manifest.items()
        if key not in {"approvals", "review_payload_digest"}
    }
    evidence_index = payload.get("evidence_index")
    if isinstance(evidence_index, dict):
        payload["evidence_index"] = {
            reference: value
            for reference, value in evidence_index.items()
            if reference not in APPROVAL_REFERENCES
        }
    return digest(canonical(payload))
def canonical_patch_digest(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise Refusal("patch digest must be canonical sha256")
    return value
def digest(data: bytes) -> str: return "sha256:" + sha(data)
def unique(path: Path) -> Any:
    def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in pairs:
            if key in result: raise Refusal("duplicate JSON key")
            result[key] = value
        return result
    try: return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=hook)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc: raise Refusal("unreadable JSON input") from exc
def patch_content_digest(data: bytes, name: Any, commit: Any, patch_path: Any) -> str:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in pairs:
            if key in result: raise Refusal("duplicate JSON key")
            result[key] = value
        return result
    try: record = json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc: raise Refusal("invalid patch evidence") from exc
    if not isinstance(record, dict) or set(record) != {"name", "commit", "patch_path", "patch_sha256"}:
        raise Refusal("invalid patch evidence")
    if record.get("name") != name or record.get("commit") != commit or record.get("patch_path") != patch_path:
        raise Refusal("patch evidence identity mismatch")
    actual_digest = canonical_patch_digest(record.get("patch_sha256"))
    if not isinstance(patch_path, str):
        raise Refusal("invalid patch path")
    relative = PurePosixPath(patch_path)
    if "\\" in patch_path or relative.is_absolute() or not relative.parts or "." in relative.parts or ".." in relative.parts:
        raise Refusal("invalid patch path")
    patch = regular(HERE.joinpath(*relative.parts), "source patch")
    if digest(patch.read_bytes()) != actual_digest:
        raise Refusal("patch content digest mismatch")
    return actual_digest
def regular(path: Path, label: str) -> Path:
    try:
        if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode): raise OSError()
    except OSError as exc: raise Refusal(f"{label} must be a regular file") from exc
    return path
def redact_image_reference(value: str) -> str:
    host, separator, remainder = value.partition("/")
    if not separator:
        return "local-registry/" + value
    return "local-registry/" + remainder
def evidence_name(name: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,100}", name): raise Refusal("invalid evidence name")
    return name
def run(argv: list[str], *, text: bool = False) -> subprocess.CompletedProcess[Any]:
    command = Path(argv[0]).name + (f" {argv[1]}" if len(argv) > 1 else "")
    command_env = {
        key: value
        for key in ("PATH", "HOME", "XDG_CACHE_HOME", "DOCKER_HOST")
        if (value := os.environ.get(key))
    }
    try:
        result = subprocess.run(argv, check=False, capture_output=True, text=text, timeout=900, env=command_env)
    except (OSError, subprocess.SubprocessError) as exc:
        raise Refusal(f"required local command failed: {command}") from exc
    if result.returncode:
        raise Refusal(f"required local command failed: {command}")
    return result
POLICY_TERM = re.compile(r"commercial|license[ _-]?key|activation|trial|paid|entitlement|circumvention", re.I)
NEGATED_POLICY = re.compile(
    r"(?:[a-z_ -]*(?:commercial|license[ _-]?key|activation|trial|paid|entitlement|circumvention)[a-z_ -]*\s*(?:=|:)\s*false\b|"
    r"\b(?:no|not|without|neither)\s+(?:[a-z_ -]*(?:commercial|license[ _-]?key|activation|trial|paid|entitlement|circumvention)[a-z_ -]*)|"
    r"\blicense[ _-]?key[ _-]?free\b)",
    re.I,
)
def clean_text(data: bytes, label: str) -> None:
    try: text = data.decode("utf-8")
    except UnicodeDecodeError as exc: raise Refusal(f"{label} is not UTF-8") from exc
    if re.search(r"jambonz-mini", text, re.I):
        raise Refusal(f"forbidden term in {label}")
    for line in text.splitlines():
        if POLICY_TERM.search(line) and not NEGATED_POLICY.search(line):
            raise Refusal(f"affirmative forbidden policy claim in {label}")

def clean_phase_c_iac_text(data: bytes, label: str) -> None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Refusal(f"{label} is not UTF-8") from exc
    if re.search(r"jambonz-mini", text, re.I):
        raise Refusal(f"forbidden term in {label}")
def loopback_registry(value: str) -> urllib.parse.ParseResult:
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path.rstrip("/"):
        raise Refusal("registry URL must be a bare loopback HTTP(S) URL")
    if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}: raise Refusal("registry must be loopback")
    return parsed
def loopback_image_tag(registry: urllib.parse.ParseResult, name: str, commit: str) -> tuple[str, str, str]:
    if name not in RUNTIME_IMAGES or not COMMIT.fullmatch(commit):
        raise Refusal("invalid candidate image identity")
    repository = f"onnuri-jambonz-oss/{name}"
    return f"{registry.netloc}/{repository}:{commit}", repository, commit
def parse_pairs(values: list[str], label: str) -> dict[str, str]:
    result = {}
    for value in values:
        key, sep, path = value.partition("=")
        if not sep or not key or key in result: raise Refusal(f"invalid {label}")
        result[key] = path
    return result
def support_image_mappings(values: list[str]) -> dict[str, str]:
    images = parse_pairs(values, "support image mapping")
    if set(images) != SUPPORT_IMAGES:
        raise Refusal("candidate must contain exactly the G009 and G008 derivative support images")
    for image in images.values():
        if not re.fullmatch(r".+@sha256:[0-9a-f]{64}", image):
            raise Refusal("support image must use an immutable digest reference")
    return images
def copy_evidence(root: Path, name: str, data: bytes) -> tuple[str, str]:
    safe = evidence_name(name)
    relative = f"evidence/{safe}"
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() or target.is_symlink():
        existing = regular(target, "evidence target").read_bytes()
        if existing != data:
            raise Refusal("immutable evidence target content mismatch")
    else:
        target.write_bytes(data)
    os.chmod(target, 0o444)
    return "evidence:" + relative, digest(data)
def compose_local_config_dependencies(data: bytes) -> set[str]:
    clean_text(data, "compose configuration")
    lines = data.decode("utf-8").splitlines()
    section: str | None = None
    entry: str | None = None
    local_files: set[str] = set()
    declared_entries: dict[str, set[str]] = {"configs": set(), "secrets": set()}
    resolved_entries: dict[str, set[str]] = {"configs": set(), "secrets": set()}
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if indent == 0:
            section = stripped.removesuffix(":")
            entry = None
            continue
        if section in {"configs", "secrets"} and indent == 2:
            if not stripped.endswith(":") or stripped.count(":") != 1:
                raise Refusal("compose file/config declarations must use expanded mapping form")
            entry = stripped[:-1]
            declared_entries[section].add(entry)
            continue
        if section not in {"configs", "secrets"} or indent != 4 or not stripped.startswith("file:"):
            continue
        if entry is None:
            raise Refusal("compose file source has no named entry")
        resolved_entries[section].add(entry)
        value = stripped.partition(":")[2].strip().strip("'\"")
        if not value:
            raise Refusal("compose file source is empty")
        if section == "secrets":
            if not re.fullmatch(r"\$\{[A-Z][A-Z0-9_]*(?::\?[^}]*)?\}", value):
                raise Refusal("compose secret files must be supplied at runtime")
            continue
        if value.startswith("${"):
            if (
                entry not in RUNTIME_GENERATED_COMPOSE_CONFIGS
                or not re.fullmatch(r"\$\{[A-Z][A-Z0-9_]*(?::\?[^}]*)?\}", value)
            ):
                raise Refusal("unapproved runtime-generated compose config")
            continue
        if entry in EXTERNAL_FROZEN_COMPOSE_CONFIGS:
            if value != EXTERNAL_FROZEN_COMPOSE_CONFIGS[entry]:
                raise Refusal("external frozen compose config path mismatch")
            continue
        relative = PurePosixPath(value.removeprefix("./"))
        if (
            not value.startswith("./")
            or "\\" in value
            or relative.is_absolute()
            or not relative.parts
            or "." in relative.parts
            or ".." in relative.parts
        ):
            raise Refusal("compose local config path must be safe and repository-relative")
        local_files.add(relative.as_posix())
    for source_type in ("configs", "secrets"):
        if declared_entries[source_type] != resolved_entries[source_type]:
            raise Refusal(f"compose {source_type} must use explicit file sources")
    frozen_files = set(CANDIDATE_RUNTIME_FILES)
    if not local_files <= frozen_files:
        raise Refusal("compose references an unfrozen local config")
    return local_files

def frozen_runtime_evidence(root: Path) -> dict[str, dict[str, str]]:
    records: dict[str, dict[str, str]] = {}
    for record_name, item in FROZEN_RUNTIME_EVIDENCE.items():
        source = item["source"]
        if source in {"run-g008-live-smoke.py", "compose.yaml", "sealed-secret-wrapper.sh"}:
            source_root = HERE
            source_parts = (source,)
        elif source in {
            "../../infra/onnuri-seoul-staging-phase-c-smoke/startup-g008.sh",
            "../../infra/onnuri-seoul-staging-phase-c-smoke/trusted_keys/phase_c_live_preflight_v1.json",
        }:
            source_root = HERE.parents[1]
            source_parts = tuple(PurePosixPath(source).parts[2:])
        else:
            raise Refusal("unknown frozen runtime evidence source")
        candidate = source_root
        for part in source_parts:
            candidate = candidate / part
            if candidate.is_symlink():
                raise Refusal("frozen runtime evidence must not traverse symlinks")
        data = regular(candidate, "frozen runtime evidence").read_bytes()
        clean_text(data, f"frozen runtime evidence {source}")
        if sha(data) != item["sha256"]:
            raise Refusal(f"frozen runtime evidence hash mismatch: {source}")
        reference, value = copy_evidence(root, item["evidence_name"], data)
        records[record_name] = {
            "result": "pass",
            "reference": reference,
            "sha256": value,
        }
    return records
def repository_evidence(
    root: Path, sources: dict[str, dict[str, Any]]
) -> dict[str, dict[str, str]]:
    compose_data = regular(HERE / "compose.yaml", "compose configuration").read_bytes()
    compose_local_config_dependencies(compose_data)
    paths = [(f"runtime-{path.replace('/', '-')}", path) for path in CANDIDATE_RUNTIME_FILES]
    for name in sorted(sources):
        patch_path = sources[name].get("patch")
        if not isinstance(patch_path, str):
            raise Refusal("source patch path missing")
        paths.append((f"source-patch-{name}.patch", patch_path))
    records: dict[str, dict[str, str]] = {}
    seen_paths: set[str] = set()
    for evidence_file, relative_path in paths:
        relative = PurePosixPath(relative_path)
        if (
            "\\" in relative_path
            or relative.is_absolute()
            or not relative.parts
            or "." in relative.parts
            or ".." in relative.parts
            or relative_path in seen_paths
        ):
            raise Refusal("invalid or duplicate repository evidence path")
        seen_paths.add(relative_path)
        candidate = HERE
        for part in relative.parts:
            candidate = candidate / part
            if candidate.is_symlink():
                raise Refusal("repository evidence must not traverse symlinks")
        data = regular(candidate, "repository evidence").read_bytes()
        clean_text(data, f"repository evidence {relative_path}")
        reference, value = copy_evidence(root, evidence_file, data)
        records[f"candidate_input_{len(records):02d}"] = {
            "result": "pass",
            "reference": reference,
            "sha256": value,
        }
    return records

def phase_c_evidence(root: Path) -> dict[str, dict[str, str]]:
    records: dict[str, dict[str, str]] = {}
    for relative_path in PHASE_C_RUNTIME_FILES:
        candidate = PHASE_C_ROOT
        for part in PurePosixPath(relative_path).parts:
            candidate = candidate / part
            if candidate.is_symlink():
                raise Refusal("Phase C configuration must not traverse symlinks")
        data = regular(candidate, "Phase C configuration").read_bytes()
        if relative_path.endswith(".tf"):
            clean_phase_c_iac_text(data, f"Phase C configuration {relative_path}")
        else:
            clean_text(data, f"Phase C configuration {relative_path}")
        expected_sha256 = PHASE_C_RUNTIME_SHA256.get(relative_path)
        if expected_sha256 is None or sha(data) != expected_sha256:
            raise Refusal(f"Phase C configuration hash mismatch: {relative_path}")
        reference, value = copy_evidence(
            root, f"phase-c-{relative_path.replace('/', '-')}", data
        )
        records[PHASE_C_EVIDENCE_PREFIX + relative_path.replace("/", "-")] = {
            "result": "pass", "reference": reference, "sha256": value,
        }
    return records

def canonical_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise Refusal(f"{label} must be canonical sha256")
    return value


def conformance_command_identity(command: str) -> str:
    return sha(command.encode("utf-8"))


def conformance_output_path(receipt_path: Path, value: Any) -> Path:
    if not isinstance(value, str):
        raise Refusal("conformance output path must be a string")
    relative = PurePosixPath(value)
    if (
        "\\" in value
        or relative.is_absolute()
        or not relative.parts
        or "." in relative.parts
        or ".." in relative.parts
    ):
        raise Refusal("conformance output path must be normalized and relative")
    candidate = receipt_path.parent.joinpath(*relative.parts)
    if candidate.is_symlink() or not candidate.is_relative_to(receipt_path.parent):
        raise Refusal("conformance output must not traverse symlinks")
    return regular(candidate, "conformance raw output")

def trusted_conformance_key() -> Ed25519PublicKey:
    record = FROZEN_RUNTIME_EVIDENCE["candidate_input_phase_c_live_preflight_trusted_keyset"]
    keyset_path = HERE / record["source"]
    keyset_bytes = regular(keyset_path, "conformance trusted keyset").read_bytes()
    if sha(keyset_bytes) != record["sha256"]:
        raise Refusal("conformance trusted keyset hash mismatch")
    keyset = unique(keyset_path)
    keys = keyset.get("keys") if isinstance(keyset, dict) else None
    if not isinstance(keyset, dict) or keyset_bytes != canonical(keyset) or keyset.get("schema_version") != "recova-phase-c-live-preflight-keyset.v1" or not isinstance(keys, list):
        raise Refusal("invalid conformance trusted keyset")
    matches = [item for item in keys if isinstance(item, dict) and item.get("algorithm") == "Ed25519" and item.get("key_id") == CONFORMANCE_SIGNER_KEY_ID and item.get("role") == CONFORMANCE_SIGNER_ROLE and isinstance(item.get("public_key_base64url"), str) and isinstance(item.get("public_key_sha256"), str)]
    if len(matches) != 1:
        raise Refusal("conformance trusted signer is unavailable")
    try:
        encoded = matches[0]["public_key_base64url"]
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except (TypeError, ValueError) as exc:
        raise Refusal("invalid conformance trusted signer") from exc
    if len(raw) != 32 or sha(raw) != matches[0]["public_key_sha256"]:
        raise Refusal("invalid conformance trusted signer")
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise Refusal("invalid conformance trusted signer") from exc


def conformance_signature_payload(receipt: dict[str, Any]) -> bytes:
    return canonical({key: value for key, value in receipt.items() if key != "signature"})


def conformance_receipt(path: Path, source_lock: Path) -> bytes:
    receipt_path = regular(path, "conformance receipt")
    data = receipt_path.read_bytes()
    receipt = unique(receipt_path)
    required = {"schema_version", "generated_at", "source_lock_sha256", "config_sha256", "checks", "signer_identity", "signature"}
    if not isinstance(receipt, dict) or set(receipt) != required:
        raise Refusal("invalid conformance receipt shape")
    if data != canonical(receipt):
        raise Refusal("conformance receipt is not canonical JSON")
    if receipt.get("schema_version") != "onnuri-jambonz-oss-conformance/v2":
        raise Refusal("invalid conformance receipt schema")
    if receipt.get("signer_identity") != CONFORMANCE_SIGNER_IDENTITY:
        raise Refusal("conformance signer identity is not trusted")
    signature = receipt.get("signature")
    if not isinstance(signature, dict) or set(signature) != {"algorithm", "key_id", "value_b64"} or signature.get("algorithm") != "Ed25519" or signature.get("key_id") != CONFORMANCE_SIGNER_KEY_ID or not isinstance(signature.get("value_b64"), str):
        raise Refusal("invalid conformance signature")
    try:
        encoded_signature = base64.b64decode(signature["value_b64"], validate=True)
        if len(encoded_signature) != 64:
            raise ValueError("invalid signature length")
        trusted_conformance_key().verify(encoded_signature, conformance_signature_payload(receipt))
    except (InvalidSignature, ValueError) as exc:
        raise Refusal("conformance signature verification failed") from exc
    generated_at = receipt.get("generated_at")
    if not isinstance(generated_at, str):
        raise Refusal("invalid conformance receipt timestamp")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+00:00)", generated_at):
        raise Refusal("invalid conformance receipt timestamp")
    try:
        generated = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Refusal("invalid conformance receipt timestamp") from exc
    now = datetime.now(timezone.utc)
    if generated.tzinfo is None or generated.utcoffset() != timedelta(0) or generated > now or now - generated > timedelta(hours=24):
        raise Refusal("conformance receipt timestamp is not current UTC")
    if receipt.get("source_lock_sha256") != sha(regular(source_lock, "source lock").read_bytes()):
        raise Refusal("conformance receipt source lock hash mismatch")
    expected_configs = {}
    for root, paths in ((HERE, CANDIDATE_RUNTIME_FILES), (PHASE_C_ROOT, PHASE_C_RUNTIME_FILES)):
        for relative_path in paths:
            candidate = root
            for part in PurePosixPath(relative_path).parts:
                candidate = candidate / part
                if candidate.is_symlink():
                    raise Refusal("runtime configuration must not traverse symlinks")
            key = relative_path if root == HERE else f"phase-c/{relative_path}"
            expected_configs[key] = sha(regular(candidate, "runtime configuration").read_bytes())
    if receipt.get("config_sha256") != expected_configs:
        raise Refusal("conformance receipt configuration hashes mismatch")
    checks = receipt.get("checks")
    if not isinstance(checks, dict) or set(checks) != set(CONFORMANCE_CHECKS):
        raise Refusal("conformance receipt checks are incomplete")
    for name, command in CONFORMANCE_CHECKS.items():
        check = checks[name]
        if not isinstance(check, dict) or set(check) != {"command", "command_identity", "exit_code", "result", "output_path", "output_sha256"} or check.get("command") != command or check.get("command_identity") != conformance_command_identity(command) or type(check.get("exit_code")) is not int or check.get("exit_code") != 0 or check.get("result") != "pass" or not isinstance(check.get("output_sha256"), str) or not SHA.fullmatch(check["output_sha256"]):
            raise Refusal(f"invalid conformance check: {name}")
        output = conformance_output_path(receipt_path, check.get("output_path"))
        if sha(output.read_bytes()) != check["output_sha256"]:
            raise Refusal(f"conformance raw output hash mismatch: {name}")
    return data


def conformance_output_evidence(root: Path, receipt_path: Path) -> dict[str, dict[str, str]]:
    receipt = unique(regular(receipt_path, "conformance receipt"))
    checks = receipt.get("checks")
    if not isinstance(checks, dict):
        raise Refusal("conformance receipt checks are incomplete")
    records: dict[str, dict[str, str]] = {}
    for name in sorted(CONFORMANCE_CHECKS):
        output = conformance_output_path(receipt_path, checks[name].get("output_path"))
        reference, value = copy_evidence(root, f"conformance-{name}.raw", output.read_bytes())
        records[f"candidate_input_conformance_output_{name}"] = {
            "result": "pass", "reference": reference, "sha256": value,
        }
    return records

def backend_reachability_receipt(path: Path, image: str) -> bytes:
    receipt_path = regular(path, "backend reachability receipt")
    data = receipt_path.read_bytes()
    receipt = unique(receipt_path)
    if data != canonical(receipt):
        raise Refusal("backend reachability receipt is not canonical JSON")
    if not isinstance(receipt, dict) or set(receipt) != {
        "vulnerability_id",
        "bytes_scanned",
        "files_scanned",
        "image_manifest_digest",
        "matches",
        "passed",
        "patterns",
        "scan_complete",
        "scanner_source_sha256",
        "schema_version",
        "source_type",
    }:
        raise Refusal("invalid backend reachability receipt shape")
    expected_digest = image.rsplit("@", 1)[-1]
    if (
        receipt.get("schema_version") != "recova.backend-glibc-reachability/v1"
        or receipt.get("vulnerability_id") != "CVE-2026-5450"
        or receipt.get("image_manifest_digest") != expected_digest
        or receipt.get("matches") != []
        or receipt.get("passed") is not True
        or receipt.get("scan_complete") is not True
        or type(receipt.get("files_scanned")) is not int
        or receipt["files_scanned"] <= 0
        or type(receipt.get("bytes_scanned")) is not int
        or receipt["bytes_scanned"] <= 0
        or receipt.get("source_type") not in {"oci-archive", "unpacked-filesystem"}
        or receipt.get("patterns") != [{
            "id": "scanf-malloc-character-explicit-width",
            "syntax": "%[argument$][*]['I]*<width>m[cCsS[]",
            "minimum_offending_width": 1025,
        }]
        or not isinstance(receipt.get("scanner_source_sha256"), str)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", receipt["scanner_source_sha256"])
    ):
        raise Refusal("backend reachability receipt does not prove complete zero-match scan")
    return data

def archive_image_config_digest(path: Path, tag: str) -> str:
    archive = regular(path, "image archive")
    try:
        with tarfile.open(archive, mode="r:*") as bundle:
            members = {member.name: member for member in bundle.getmembers()}
            if len(members) != len(bundle.getmembers()):
                raise Refusal("image archive contains duplicate members")

            def member_bytes(name: str) -> bytes:
                member = members.get(name)
                if member is None or not member.isfile() or member.issym() or member.islnk():
                    raise Refusal("image archive descriptor is missing or unsafe")
                stream = bundle.extractfile(member)
                if stream is None:
                    raise Refusal("image archive descriptor is unreadable")
                return stream.read()

            if "oci-layout" in members:
                index = json.loads(member_bytes("index.json"))
                descriptors = index.get("manifests", []) if isinstance(index, dict) else []
                matches = []
                image_tag = tag.rsplit(":", 1)[-1]
                for item in descriptors:
                    if not isinstance(item, dict):
                        continue
                    annotations = item.get("annotations", {})
                    if not isinstance(annotations, dict):
                        continue
                    ref_name = annotations.get("org.opencontainers.image.ref.name")
                    containerd_name = annotations.get("io.containerd.image.name")
                    if ref_name == tag or (
                        ref_name == image_tag and containerd_name == tag
                    ):
                        matches.append(item)
                if len(matches) != 1:
                    raise Refusal("OCI archive does not contain exactly one requested image")
                manifest_digest = canonical_sha256(matches[0].get("digest"), "OCI manifest digest")
                manifest_data = member_bytes("blobs/sha256/" + manifest_digest.removeprefix("sha256:"))
                if digest(manifest_data) != manifest_digest:
                    raise Refusal("OCI manifest digest mismatch")
                manifest = json.loads(manifest_data)
                config_digest = canonical_sha256(
                    manifest.get("config", {}).get("digest") if isinstance(manifest, dict) else None,
                    "OCI config digest",
                )
                config_data = member_bytes("blobs/sha256/" + config_digest.removeprefix("sha256:"))
                if digest(config_data) != config_digest:
                    raise Refusal("OCI config digest mismatch")
                return config_digest

            manifest = json.loads(member_bytes("manifest.json"))
            matches = [
                item for item in manifest
                if isinstance(item, dict) and tag in item.get("RepoTags", [])
            ] if isinstance(manifest, list) else []
            if len(matches) != 1:
                raise Refusal("image archive does not contain exactly one requested image")
            config_name = matches[0].get("Config")
            if not isinstance(config_name, str) or not re.fullmatch(r"[0-9a-f]{64}\.json", config_name):
                raise Refusal("image archive config descriptor is not canonical")
            config_data = member_bytes(config_name)
            config_digest = "sha256:" + config_name.removesuffix(".json")
            if digest(config_data) != config_digest:
                raise Refusal("image archive config digest mismatch")
            return config_digest
    except (OSError, tarfile.TarError, UnicodeError, json.JSONDecodeError) as exc:
        raise Refusal("invalid image archive") from exc
def validated_image_config_digest(
    inspected_id: Any,
    distribution_digest: str,
    registry_config_digest: str,
    archive_config_digest: str,
) -> str:
    inspected = canonical_sha256(inspected_id, "inspected image identity")
    distribution = canonical_sha256(
        distribution_digest, "distribution manifest digest"
    )
    registry_config = canonical_sha256(
        registry_config_digest, "registry config digest"
    )
    archive_config = canonical_sha256(
        archive_config_digest, "archive config digest"
    )
    if archive_config != registry_config or inspected not in {
        distribution,
        registry_config,
    }:
        raise Refusal("tagged image config digest mismatch")
    return archive_config
def http_manifest(
    registry: urllib.parse.ParseResult, repository: str, tag: str
) -> tuple[str, str]:
    if not re.fullmatch(r"[a-z0-9][a-z0-9._/-]*", repository) or not re.fullmatch(r"[A-Za-z0-9._-]+", tag): raise Refusal("invalid image reference")
    url = registry.geturl().rstrip("/") + "/v2/" + repository + "/manifests/" + urllib.parse.quote(tag, safe="")
    request = urllib.request.Request(url, headers={"Accept": "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            manifest_digest = canonical_sha256(
                response.headers.get("Docker-Content-Digest", ""),
                "distribution manifest digest",
            )
            manifest_data = response.read()
    except (urllib.error.URLError, OSError) as exc: raise Refusal("registry manifest lookup failed") from exc
    if digest(manifest_data) != manifest_digest:
        raise Refusal("registry manifest body digest mismatch")
    try:
        manifest = json.loads(manifest_data)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise Refusal("registry returned invalid image manifest") from exc
    config_digest = canonical_sha256(
        manifest.get("config", {}).get("digest") if isinstance(manifest, dict) else None,
        "image config digest",
    )
    return manifest_digest, config_digest

def build_evidence_index(root: Path) -> dict[str, dict[str, str]]:
    evidence: dict[str, dict[str, str]] = {}
    for file in (root / "evidence").iterdir():
        data = regular(file, "sealed evidence").read_bytes()
        if file.suffix == ".tar":
            content_type = "application/x-tar"
        elif file.name.endswith("-sbom.json"):
            content_type = "application/vnd.anchore.syft+json"
        elif file.name.endswith("-vulnerabilities.json"):
            content_type = "application/vnd.anchore.grype+json"
        else:
            content_type = "text"
            if file.name.startswith("phase-c-") and file.name.endswith(".tf"):
                clean_phase_c_iac_text(data, f"sealed evidence {file.name}")
            else:
                clean_text(data, f"sealed evidence {file.name}")
        if file.name.endswith(("-notices.json", "-sbom.json")):
            try:
                document = json.loads(data)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise Refusal("support notices and SBOM must be JSON") from exc
            if contains_personal_metadata(document):
                raise Refusal("personal metadata is forbidden in support notices or SBOM")
        evidence["evidence:evidence/" + file.name] = {
            "path": "evidence/" + file.name,
            "sha256": sha(data),
            "content_type": content_type,
        }
    return evidence
def inspect(tag: str, source: dict[str, Any]) -> tuple[dict[str, Any], str]:
    raw = run(["docker", "image", "inspect", tag]).stdout
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise Refusal("duplicate key in docker inspect output")
            result[key] = value
        return result
    try:
        parsed = json.loads(raw, object_pairs_hook=reject_duplicates)
        info = parsed[0]
    except (json.JSONDecodeError, IndexError, TypeError) as exc:
        raise Refusal("docker inspect returned invalid data") from exc
    if info.get("Os") != "linux" or info.get("Architecture") != "amd64": raise Refusal("image is not linux/amd64")
    labels = info.get("Config", {}).get("Labels", {}) or {}
    if not isinstance(labels, dict):
        raise Refusal("image labels are invalid")
    if labels.get("org.opencontainers.image.revision") != source["commit"]: raise Refusal("image source commit label mismatch")
    if labels.get("org.opencontainers.image.source") != source["repository"]: raise Refusal("image source label mismatch")
    patch = canonical_patch_digest(labels.get("org.recova.patch.sha256"))
    if patch != canonical_patch_digest(source["patch_content_sha256"]): raise Refusal("image patch label mismatch")
    expected_license = RUNTIME_LICENSES.get(source.get("name"))
    runtime_license = labels.get("org.opencontainers.image.licenses")
    if (
        expected_license is None
        or not isinstance(runtime_license, str)
        or not runtime_license
        or runtime_license != expected_license
    ):
        raise Refusal("runtime OCI license label mismatch")
    base = labels.get("org.recova.base.digest")
    if not isinstance(base, str) or not re.fullmatch(r".+@sha256:[0-9a-f]{64}", base): raise Refusal("image lacks immutable base label")
    config = info.get("Id", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", config): raise Refusal("invalid Docker config ID")
    return info, base
def scan_image(tag: str, sbom_path: Path) -> tuple[bytes, bytes]:
    sbom_path.parent.mkdir(parents=True, exist_ok=True)
    run(["syft", tag, "-o", f"json={sbom_path}"])
    vulnerability = run(["grype", f"sbom:{sbom_path}", "-o", "json"]).stdout
    raw_sbom = regular(sbom_path, "syft SBOM").read_bytes()
    try:
        sbom_document = json.loads(raw_sbom)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Refusal("syft SBOM must be JSON") from exc
    sbom = canonical(redact_personal_metadata(sbom_document)).removesuffix(b"\n")
    sbom_path.write_bytes(sbom)
    return sbom, vulnerability
def command_json(argv: list[str], label: str) -> tuple[dict[str, Any], bytes]:
    raw = run(argv).stdout
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise Refusal(f"duplicate key in {label} JSON")
            result[key] = value
        return result
    try:
        parsed = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, TypeError) as exc:
        raise Refusal(f"invalid {label} JSON") from exc
    if not isinstance(parsed, dict):
        raise Refusal(f"invalid {label} JSON")
    return parsed, raw

def scanner_metadata(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    syft, _ = command_json(["syft", "version", "-o", "json"], "syft version")
    grype, _ = command_json(["grype", "version", "-o", "json"], "grype version")
    database, _ = command_json(["grype", "db", "status", "-o", "json"], "grype database status")
    syft_version = syft.get("version")
    grype_version = grype.get("version")
    if not isinstance(syft_version, str) or not syft_version or not isinstance(grype_version, str) or not grype_version:
        raise Refusal("scanner version is missing")
    source = database.get("from")
    checksum = database.get("checksum")
    if not isinstance(checksum, str) and isinstance(source, str):
        values = urllib.parse.parse_qs(urllib.parse.urlparse(source).query)
        candidate = values.get("checksum", [None])[0]
        if isinstance(candidate, str):
            checksum = candidate
    built = database.get("built")
    schema_version = database.get("schemaVersion")
    if (
        not isinstance(checksum, str)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}|[0-9a-f]{64}", checksum)
        or not isinstance(built, str)
        or not built
        or not isinstance(schema_version, str)
        or not schema_version
        or database.get("valid") is not True
    ):
        raise Refusal("grype database identity is incomplete")
    identity = {
        "schema_version": schema_version,
        "source": source,
        "built": built,
        "checksum": checksum,
        "valid": True,
    }
    database_ref, database_sha = copy_evidence(
        root,
        "scanner-grype-db-identity.json",
        canonical(identity),
    )
    return {
        "syft_version": syft_version,
        "grype_version": grype_version,
        "grype_db_identity_reference": database_ref,
        "grype_db_identity_sha256": database_sha,
    }, identity

def acceptance_record(
    image_name: str,
    scanner: dict[str, Any],
    database: dict[str, Any],
    acceptances: dict[str, dict[str, Any]],
) -> bytes:
    decisions = {
        key: decision
        for key, decision in acceptances.items()
        if dict(urllib.parse.parse_qsl(key, strict_parsing=True)).get("image") == image_name
    }
    return canonical({
        "image": image_name,
        "scanner": {
            "grype_version": scanner["grype_version"],
            "grype_db_identity": database,
        },
        "decisions": decisions,
    })

def support_image_provenance(name: str, labels: dict[str, str]) -> dict[str, str]:
    source = labels.get("org.opencontainers.image.source")
    if not isinstance(source, str):
        raise Refusal("support image lacks an OCI source label")
    parsed = urllib.parse.urlsplit(source)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.strip("/")
    ):
        raise Refusal("support image OCI source label is invalid")
    if name in {"facade", "recova-backend"} and source != FIRST_PARTY_SUPPORT_SOURCE:
        raise Refusal(f"{name} OCI source label mismatch")

    revision = labels.get(SOURCE_REVISION_LABEL)
    source_tree = labels.get(SOURCE_TREE_LABEL)
    if name == "facade":
        if source_tree not in {None, ""} or not isinstance(revision, str) or not SHA.fullmatch(revision):
            raise Refusal("facade must use its canonical OCI revision source-tree sha256")
        provenance_type = "source_tree_sha256"
        provenance_label = SOURCE_REVISION_LABEL
        provenance_value = "sha256:" + revision
    elif name == "recova-backend":
        if source_tree is not None or not isinstance(revision, str) or not SHA.fullmatch(revision):
            raise Refusal("recova-backend must use its exact source snapshot revision label")
        provenance_type = "source_tree_sha256"
        provenance_label = SOURCE_REVISION_LABEL
        provenance_value = "sha256:" + revision
    else:
        if source_tree is not None or not isinstance(revision, str):
            raise Refusal("support image must use immutable source provenance")
        if COMMIT.fullmatch(revision):
            provenance_type = "git_revision"
            provenance_value = revision
        else:
            snapshot = revision.removeprefix("sha256:")
            if not SHA.fullmatch(snapshot):
                raise Refusal("support image must use immutable source provenance")
            provenance_type = "source_image_digest"
            provenance_value = "sha256:" + snapshot
            if not revision.startswith("sha256:"):
                raise Refusal("source image digest label must be canonical sha256")
        provenance_label = SOURCE_REVISION_LABEL
    return {
        "label": provenance_label,
        "type": provenance_type,
        "value": provenance_value,
    }


def inspect_support_image(image: str, name: str | None = None) -> tuple[dict[str, Any], dict[str, str]]:
    if not re.fullmatch(r".+@sha256:[0-9a-f]{64}", image):
        raise Refusal("support image must use an immutable digest reference")
    raw = run(["docker", "image", "inspect", image]).stdout
    try:
        info = json.loads(raw)[0]
    except (json.JSONDecodeError, IndexError, TypeError) as exc:
        raise Refusal("docker inspect returned invalid support image") from exc
    if info.get("Os") != "linux" or info.get("Architecture") != "amd64":
        raise Refusal("support image is not linux/amd64")
    labels = info.get("Config", {}).get("Labels", {}) or {}
    if not isinstance(labels, dict) or any(not isinstance(key, str) or not isinstance(value, str) for key, value in labels.items()):
        raise Refusal("support image labels are invalid")
    base = labels.get("org.recova.base.digest")
    license_spdx = labels.get("org.opencontainers.image.licenses")
    if not isinstance(base, str) or not re.fullmatch(r".+@sha256:[0-9a-f]{64}", base):
        raise Refusal("support image lacks immutable base label")
    if not isinstance(license_spdx, str) or not license_spdx:
        raise Refusal("support image lacks an SPDX license label")
    if name is not None:
        support_image_provenance(name, labels)
    return info, labels
ACCEPTANCE_IDENTITY_FIELDS = ("image", "vulnerability", "artifact_name", "artifact_version", "artifact_type")
def finding_acceptance_key(image_name: str, finding: dict[str, Any]) -> str:
    vulnerability = finding.get("vulnerability")
    artifact = finding.get("artifact")
    values = (image_name, vulnerability.get("id") if isinstance(vulnerability, dict) else None, artifact.get("name") if isinstance(artifact, dict) else None, artifact.get("version") if isinstance(artifact, dict) else None, artifact.get("type") if isinstance(artifact, dict) else None)
    if not all(isinstance(value, str) and value for value in values):
        raise Refusal("invalid Critical/High vulnerability identity")
    return urllib.parse.urlencode(list(zip(ACCEPTANCE_IDENTITY_FIELDS, values)))

def finding_acceptance_digest(finding: dict[str, Any]) -> str:
    vulnerability = finding.get("vulnerability")
    artifact = finding.get("artifact")
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
        raise Refusal("invalid Critical/High vulnerability identity")
    if projection["fix_state"] is not None and not isinstance(projection["fix_state"], str):
        raise Refusal("invalid Critical/High vulnerability fix state")
    if projection["fix_versions"] is None or any(not isinstance(version, str) or not version for version in projection["fix_versions"]):
        raise Refusal("invalid Critical/High vulnerability fix versions")
    return sha(canonical(projection))


def validate_acceptance_key(key: Any) -> None:
    if not isinstance(key, str):
        raise Refusal("invalid vulnerability acceptance identity")
    try:
        parsed = urllib.parse.parse_qsl(key, keep_blank_values=True, strict_parsing=True)
    except ValueError as exc:
        raise Refusal("invalid vulnerability acceptance identity") from exc
    if tuple(name for name, _ in parsed) != ACCEPTANCE_IDENTITY_FIELDS or any(not value for _, value in parsed) or urllib.parse.urlencode(parsed) != key:
        raise Refusal("invalid vulnerability acceptance identity")
def validate_acceptance_decision(approved: Any) -> dict[str, str]:
    if not isinstance(approved, dict) or set(approved) != {"reason", "expires_at", "finding_sha256"}:
        raise Refusal("invalid vulnerability acceptance")
    if not isinstance(approved["reason"], str) or not approved["reason"] or not isinstance(approved["finding_sha256"], str) or not SHA.fullmatch(approved["finding_sha256"]):
        raise Refusal("invalid vulnerability acceptance")
    try:
        expiry = datetime.fromisoformat(approved["expires_at"].replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise Refusal("invalid vulnerability acceptance expiry") from exc
    if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
        raise Refusal("expired vulnerability acceptance")
    return approved

def acceptance_expiry(
    now: datetime,
    acceptances: dict[str, dict[str, Any]],
    used_acceptances: set[str],
) -> datetime:
    expiry = now + timedelta(days=7)
    for key in used_acceptances:
        decision = validate_acceptance_decision(acceptances.get(key))
        candidate = datetime.fromisoformat(
            decision["expires_at"].replace("Z", "+00:00")
        )
        expiry = min(expiry, candidate.astimezone(timezone.utc))
    return expiry

def vulnerabilities(
    image_name: str,
    data: bytes,
    acceptances: dict[str, dict[str, Any]],
    used_acceptances: set[str] | None = None,
) -> tuple[int, int]:
    try: findings = json.loads(data).get("matches", [])
    except (json.JSONDecodeError, AttributeError) as exc: raise Refusal("invalid grype JSON") from exc
    critical = high = 0
    for finding in findings:
        severity = str(finding.get("vulnerability", {}).get("severity", "")).upper()
        if severity not in {"CRITICAL", "HIGH"}: continue
        critical += severity == "CRITICAL"; high += severity == "HIGH"
        key = finding_acceptance_key(image_name, finding)
        approved = validate_acceptance_decision(acceptances.get(key))
        if approved["finding_sha256"] != finding_acceptance_digest(finding):
            raise Refusal("mismatched vulnerability acceptance")
        if used_acceptances is not None:
            used_acceptances.add(key)
    return critical, high
def require_exact_acceptance_coverage(
    acceptances: dict[str, dict[str, Any]],
    used_acceptances: set[str],
) -> None:
    if set(acceptances) != used_acceptances:
        raise Refusal("vulnerability acceptance set does not exactly match severe findings")
def freeswitch_contributions(sources: dict[str, dict[str, Any]]) -> list[dict[str, str]]:
    required = (
        ("jambonz-freeswitch-modules", "mod_audio_fork", "MIT"),
        ("spandsp", "spandsp runtime library", "LGPL-2.1-only AND GPL-2.0-only"),
        ("sofia-sip", "Sofia-SIP runtime library", "LGPL-2.1-only"),
    )
    return [
        {
            "source_name": name,
            "source_commit": sources[name]["commit"],
            "contribution": contribution,
            "license_mode": license_mode,
            "reference": sources[name]["license_reference"],
            "sha256": sources[name]["license_sha256"],
        }
        for name, contribution, license_mode in required
    ]

def seal(args: argparse.Namespace) -> dict[str, Any]:
    registry = loopback_registry(args.registry)
    receipt_path, lock_path = regular(args.source_receipt, "source receipt"), regular(args.source_lock, "source lock")
    receipt, lock = unique(receipt_path), unique(lock_path)
    if not isinstance(receipt, dict) or receipt.get("schema_version") != "recova-jambonz-oss-source-evidence/v1": raise Refusal("invalid source receipt")
    receipt_without_digest = {
        key: value for key, value in receipt.items() if key != "receipt_sha256"
    }
    if (
        set(receipt) != {
            "schema_version",
            "source_lock_sha256",
            "sources",
            "receipt_sha256",
        }
        or receipt.get("receipt_sha256") != sha(canonical(receipt_without_digest))
    ):
        raise Refusal("source receipt self-digest mismatch")
    if receipt.get("source_lock_sha256") != sha(lock_path.read_bytes()): raise Refusal("source receipt does not bind source lock")
    locked = {item.get("name"): item for item in lock.get("sources", []) if isinstance(item, dict)}
    received = {item.get("name"): item for item in receipt.get("sources", []) if isinstance(item, dict)}
    if set(locked) != REQUIRED_SOURCES or set(received) != REQUIRED_SOURCES: raise Refusal("candidate must contain exactly thirteen sources")
    conformance_data = conformance_receipt(args.conformance_receipt, lock_path)
    tags = parse_pairs(args.image, "image mapping")
    if set(tags) != RUNTIME_IMAGES: raise Refusal("candidate must contain exactly ten image mappings")
    support_images = support_image_mappings(args.support_image)
    backend_reachability_data = backend_reachability_receipt(
        args.backend_reachability_receipt, support_images["recova-backend"]
    )
    contracts = {key: regular(Path(value), "contract") for key, value in parse_pairs(args.contract, "contract").items()}
    if set(contracts) != {"license", "topology", "runtime"}:
        raise Refusal("license, topology, and runtime contracts are required")
    acceptance_data: dict[str, dict[str, Any]] = {}
    if args.acceptances:
        raw = unique(regular(args.acceptances, "acceptance file"))
        if not isinstance(raw, dict): raise Refusal("acceptance file must be an object")
        for key, decision in raw.items():
            validate_acceptance_key(key)
            validate_acceptance_decision(decision)
        acceptance_data = raw
    output = args.output.resolve()
    if output.exists() or output.is_symlink(): raise Refusal("output path must not already exist")
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".seal-", dir=output.parent))
    try:
        # Copy source evidence and required operator review artifacts before deriving references.
        receipt_ref, receipt_sha = copy_evidence(stage, "source-evidence-receipt.json", receipt_path.read_bytes())
        source_records = []
        for name in sorted(REQUIRED_SOURCES):
            item, received_item = locked[name], received[name]
            if item.get("commit") != received_item.get("commit") or item.get("repository") != received_item.get("repository"): raise Refusal("receipt source identity mismatch")
            refs = received_item.get("references", {})
            if not isinstance(refs, dict) or set(refs) != {"tree", "submodules", "license", "patch"}: raise Refusal("source receipt references incomplete")
            copied = {}
            patch_content_sha = None
            tree_archive_sha = None
            for category, record in refs.items():
                path = receipt_path.parent / record.get("path", "")
                data = regular(path, "source evidence").read_bytes()
                if record.get("sha256") != sha(data): raise Refusal("source evidence hash mismatch")
                copied[category] = copy_evidence(stage, f"sources-{name}-{category}.json", data)
                if category == "tree":
                    tree_record = unique(path)
                    if (
                        not isinstance(tree_record, dict)
                        or set(tree_record) != {
                            "name",
                            "repository",
                            "commit",
                            "archive_sha256",
                        }
                        or tree_record.get("name") != name
                        or tree_record.get("repository") != item["repository"]
                        or tree_record.get("commit") != item["commit"]
                        or not isinstance(tree_record.get("archive_sha256"), str)
                        or not SHA.fullmatch(tree_record["archive_sha256"])
                    ):
                        raise Refusal("invalid source tree evidence")
                    tree_archive_sha = "sha256:" + tree_record["archive_sha256"]
                if category == "patch":
                    patch_content_sha = patch_content_digest(data, name, item.get("commit"), item.get("patch"))
            if patch_content_sha is None: raise Refusal("source patch evidence missing")
            if tree_archive_sha is None:
                raise Refusal("source tree evidence missing")
            source_records.append({"name": name, "repository": item["repository"], "commit": item["commit"], "upstream_tree_sha256": tree_archive_sha, "source_tree_reference": copied["tree"][0], "source_tree_sha256": copied["tree"][1], "submodules_reference": copied["submodules"][0], "submodules_sha256": copied["submodules"][1], "submodules": received_item.get("submodules", []), "license_spdx": item["license_spdx"], "license_reference": copied["license"][0], "license_sha256": copied["license"][1], "patch_reference": copied["patch"][0], "patch_sha256": copied["patch"][1], "patch_content_sha256": patch_content_sha})
        by_source = {record["name"]: record for record in source_records}
        recipes = {
            recipe: copy_evidence(stage, f"recipes-{recipe}", regular(HERE / recipe, "build recipe").read_bytes())
            for recipe in set(BUILD_RECIPES.values())
        }
        topology_ref, topology_sha = copy_evidence(stage, "contract-topology.txt", contracts["topology"].read_bytes())
        for name, path in contracts.items(): clean_text(path.read_bytes(), f"contract {name}")
        module = by_source["jambonz-freeswitch-modules"]
        module["conditional_mit"] = {"selected_license":"MIT","dedicated_freeswitch":True,"dynamic_load":"mod_audio_fork","incoming_call_control":"jambonz-feature-server/outbound-esl","reference":topology_ref,"sha256":topology_sha,"topology_reference":topology_ref,"topology_sha256":topology_sha}
        scanner, database = scanner_metadata(stage)
        used_acceptances: set[str] = set()
        images = []
        for name in sorted(RUNTIME_IMAGES):
            source = by_source[name]; tag = tags[name]; info, base = inspect(tag, source)
            loopback_tag, repository, image_tag = loopback_image_tag(registry, name, source["commit"])
            run(["docker", "tag", tag, loopback_tag])
            run(["docker", "push", loopback_tag])
            distribution, registry_config_digest = http_manifest(registry, repository, image_tag)
            image_ref = "local-registry/" + repository + "@" + distribution
            sbom_path = stage / "evidence" / f"{name}-sbom.json"
            sbom, vuln = scan_image(tag, sbom_path)
            os.chmod(sbom_path, 0o444)
            critical, high = vulnerabilities(name, vuln, acceptance_data, used_acceptances)
            sbom_ref = "evidence:evidence/" + sbom_path.name; sbom_sha = digest(sbom)
            vuln_ref, vuln_sha = copy_evidence(stage, f"{name}-vulnerabilities.json", vuln)
            runtime_license = info["Config"]["Labels"]["org.opencontainers.image.licenses"]
            notice = canonical({"source": name, "license_spdx": source["license_spdx"], "runtime_oci_license": runtime_license, "license_evidence": source["license_reference"]}); notice_ref, notice_sha = copy_evidence(stage, f"{name}-notices.json", notice)
            recipe_ref, recipe_sha = recipes[BUILD_RECIPES[name]]
            archive = stage / f".{name}.tar"
            run(["docker", "save", "--output", str(archive), loopback_tag])
            archive_config_digest = archive_image_config_digest(archive, loopback_tag)
            archive_config_digest = validated_image_config_digest(
                info.get("Id"),
                distribution,
                registry_config_digest,
                archive_config_digest,
            )
            provenance = canonical({"source":name,"commit":source["commit"],"source_tree_sha256":source["upstream_tree_sha256"],"image_config_digest":archive_config_digest,"distribution_manifest":distribution,"runtime_oci_license":runtime_license,"base_image":redact_image_reference(base),"build_recipe_reference":recipe_ref,"build_recipe_sha256":recipe_sha}); prov_ref, prov_sha = copy_evidence(stage, f"{name}-provenance.json", provenance)
            archive_data = regular(archive, "network-denied archive").read_bytes()
            archive_ref, archive_sha = copy_evidence(stage, f"{name}-network-denied.tar", archive_data)
            archive.unlink()
            archive_record = canonical({"name":name,"archive_reference":archive_ref,"archive_sha256":archive_sha,"mode":"0444","network_denied":True})
            archive_record_ref, archive_record_sha = copy_evidence(stage, f"{name}-network-denied-archive.json", archive_record)
            contributions = freeswitch_contributions(by_source) if name == "freeswitch" else []
            acceptance_ref, acceptance_sha = copy_evidence(
                stage,
                f"{name}-vulnerability-acceptance.json",
                acceptance_record(name, scanner, database, acceptance_data),
            )
            images.append({"name":name,"source_name":name,"source_commit":source["commit"],"platform":"linux/amd64","image":image_ref,"base_images":[redact_image_reference(base)],"build_mode":"source_only","build_recipe_reference":recipe_ref,"build_recipe_sha256":recipe_sha,"build_provenance_reference":prov_ref,"build_provenance_sha256":prov_sha,"network_archive_reference":archive_ref,"network_archive_sha256":archive_sha,"network_archive_record_reference":archive_record_ref,"network_archive_record_sha256":archive_record_sha,"source_contributions":contributions,"notices_reference":notice_ref,"notices_sha256":notice_sha,"sbom_reference":sbom_ref,"sbom_sha256":sbom_sha,"vulnerability_reference":vuln_ref,"vulnerability_sha256":vuln_sha,"scanner":scanner,"vulnerability_acceptance_reference":acceptance_ref,"vulnerability_acceptance_sha256":acceptance_sha,"vulnerability_summary":{"critical":critical,"high":high,"unaccepted_critical":0,"unaccepted_high":0}})
        support_images_manifest = []
        for name in sorted(support_images):
            image = support_images[name]
            _, labels = inspect_support_image(image, name)
            labels_data = canonical(labels)
            clean_text(labels_data, f"support image {name} OCI labels")
            source_provenance = support_image_provenance(name, labels)
            provenance_data = canonical(
                {
                    "image": image,
                    "name": name,
                    "source": labels["org.opencontainers.image.source"],
                    "source_provenance": source_provenance,
                }
            )
            provenance_ref, provenance_sha = copy_evidence(
                stage, f"support-{name}-source-provenance.json", provenance_data
            )
            oci_license = canonical(
                {
                    "name": name,
                    "image": image,
                    "license_spdx": labels["org.opencontainers.image.licenses"],
                    "oci_labels_sha256": digest(canonical(redact_personal_metadata(labels))),
                }
            )
            oci_license_ref, oci_license_sha = copy_evidence(
                stage, f"support-{name}-oci-license.json", oci_license
            )
            notice = canonical({"name":name,"image":image,"oci_labels":redact_personal_metadata(labels)})
            notice_ref, notice_sha = copy_evidence(stage, f"support-{name}-notices.json", notice)
            sbom_path = stage / "evidence" / f"support-{name}-sbom.json"
            sbom, vuln = scan_image(image, sbom_path)
            os.chmod(sbom_path, 0o444)
            critical, high = vulnerabilities(name, vuln, acceptance_data, used_acceptances)
            vuln_ref, vuln_sha = copy_evidence(stage, f"support-{name}-vulnerabilities.json", vuln)
            acceptance_ref, acceptance_sha = copy_evidence(
                stage,
                f"support-{name}-vulnerability-acceptance.json",
                acceptance_record(name, scanner, database, acceptance_data),
            )
            archive = stage / f".support-{name}.tar"
            run(["docker", "save", "--output", str(archive), image])
            archive_data = regular(archive, "support network-denied archive").read_bytes()
            archive_ref, archive_sha = copy_evidence(
                stage, f"support-{name}-network-denied.tar", archive_data
            )
            archive.unlink()
            archive_record = canonical(
                {
                    "name": name,
                    "archive_reference": archive_ref,
                    "archive_sha256": archive_sha,
                    "mode": "0444",
                    "network_denied": True,
                }
            )
            archive_record_ref, archive_record_sha = copy_evidence(
                stage,
                f"support-{name}-network-denied-archive.json",
                archive_record,
            )
            support_images_manifest.append({"name":name,"image":image,"platform":"linux/amd64","source":labels["org.opencontainers.image.source"],"source_provenance":source_provenance,"source_provenance_reference":provenance_ref,"source_provenance_sha256":provenance_sha,"base_images":[redact_image_reference(labels["org.recova.base.digest"])],"license_spdx":labels["org.opencontainers.image.licenses"],"oci_license_reference":oci_license_ref,"oci_license_sha256":oci_license_sha,"notices_reference":notice_ref,"notices_sha256":notice_sha,"sbom_reference":"evidence:evidence/" + sbom_path.name,"sbom_sha256":digest(sbom),"vulnerability_reference":vuln_ref,"vulnerability_sha256":vuln_sha,"scanner":scanner,"vulnerability_acceptance_reference":acceptance_ref,"vulnerability_acceptance_sha256":acceptance_sha,"vulnerability_summary":{"critical":critical,"high":high,"unaccepted_critical":0,"unaccepted_high":0},"network_archive_reference":archive_ref,"network_archive_sha256":archive_sha,"network_archive_record_reference":archive_record_ref,"network_archive_record_sha256":archive_record_sha})
        require_exact_acceptance_coverage(acceptance_data, used_acceptances)
        approvals = {}
        for name in ("architect", "critic", "qa"):
            pending = canonical(
                {
                    "schema_version": "onnuri-jambonz-oss-approval/v1",
                    "role": name,
                    "identity": f"pending-{name}",
                    "independent": False,
                    "decision": "pending",
                    "review_payload_digest": None,
                    "source_lock_sha256": digest(lock_path.read_bytes()),
                    "approved_at": None,
                    "findings": [],
                }
            )
            ref, value = copy_evidence(stage, f"approval-{name}.json", pending)
            approvals[name] = {
                "identity": f"pending-{name}",
                "independent": False,
                "decision": "pending",
                "reference": ref,
                "sha256": value,
            }
        runtime_ref, runtime_sha = copy_evidence(stage, "contract-runtime.txt", contracts["runtime"].read_bytes())
        license_ref, license_sha = copy_evidence(stage, "contract-license.txt", contracts["license"].read_bytes())
        source_lock_ref, source_lock_sha = copy_evidence(stage, "source-lock.json", lock_path.read_bytes())
        repository_inputs = {
            "candidate_input_source_lock": {
                "result": "pass",
                "reference": source_lock_ref,
                "sha256": source_lock_sha,
            },
            "candidate_input_conformance": {
                "result": "pass",
                "reference": copy_evidence(
                    stage, "conformance-receipt.json", conformance_data
                )[0],
                "sha256": digest(conformance_data),
            },
            "candidate_input_backend_reachability": {
                "result": "pass",
                "reference": copy_evidence(
                    stage,
                    "backend-glibc-reachability-receipt.json",
                    backend_reachability_data,
                )[0],
                "sha256": digest(backend_reachability_data),
            },
            **repository_evidence(stage, locked),
            **phase_c_evidence(stage),
            **conformance_output_evidence(stage, args.conformance_receipt),
            **frozen_runtime_evidence(stage),
        }
        now = datetime.now(timezone.utc)
        expires_at = acceptance_expiry(now, acceptance_data, used_acceptances)
        disqualifiers = {"open_source": {"result":"pass","reference":license_ref,"sha256":license_sha}, "runtime": {"result":"pass","reference":runtime_ref,"sha256":runtime_sha}, **repository_inputs}
        manifest = {
            "schema_version": "onnuri-jambonz-oss-candidate/v1",
            "candidate_generation": "jambonz-oss-0.9.x",
            "source_lock_sha256": digest(lock_path.read_bytes()),
            "sources": source_records,
            "images": images,
            "support_images": support_images_manifest,
            "license_policy": {
                "all_third_party_components_open_source": True,
                "first_party_support_boundary": "LicenseRef-Recova-Proprietary",
                "runtime_license_key_required": False,
                "activation_service_required": False,
                "trial_or_paid_entitlement_used": False,
                "commercial_image_used": False,
                "circumvention_used": False,
            },
            "runtime_contract": {
                "inbound": {"timing": "pre_answer", "verbs": ["answer", "listen"]},
                "outbound": {"timing": "post_answer", "verbs": ["listen"]},
                "listen": {
                    "ws_auth": "Basic",
                    "encoding": "L16",
                    "sample_rate_hz": 8000,
                    "channels": 1,
                    "direction": "bidirectional",
                },
                "receipt_signing": {
                    "dispatch": {
                        "algorithm": "ES256",
                        "key_id": "dispatch-es256",
                        "trust_domain": "recova.dispatch",
                    },
                    "media": {
                        "algorithm": "ES256",
                        "key_id": "media-es256",
                        "trust_domain": "recova.media",
                    },
                },
                "registration": {
                    "mode": "one_register_then_unregister",
                    "automatic_retry": False,
                    "max_concurrency": 1,
                    "receipt_binding_fields": [
                        "tenant_digest",
                        "account_digest",
                        "envelope_digest",
                        "candidate_digest",
                        "operation",
                        "prior_receipt_digest",
                    ],
                    "operations": [
                        {
                            "operation": "register",
                            "challenge_aware": True,
                            "max_wire_transmissions": 2,
                            "automatic_retry": False,
                            "max_concurrency": 1,
                            "terminal_deadline_seconds": 32,
                            "causal_predecessor": "authority_receipt_digest",
                        },
                        {
                            "operation": "unregister",
                            "challenge_aware": True,
                            "max_wire_transmissions": 2,
                            "automatic_retry": False,
                            "max_concurrency": 1,
                            "terminal_deadline_seconds": 32,
                            "causal_predecessor": "register_receipt_digest",
                        },
                    ],
                },
                "calls": {
                    "automatic_retry": False,
                    "max_concurrency": 1,
                    "maximum_attempts": 3,
                    "contingency_attempts": 1,
                    "contingency_authority_required": True,
                    "contingency_direction_bound": True,
                    "target_scope": "single_owned_destination",
                    "target_binding": "execution_request_owned_target_sha256_and_destination_hmac_digest",
                },
                "timers": {
                    "register_terminal_deadline_seconds": 32,
                    "call_deadline_seconds": 60,
                },
                "teardown": {
                    "unregister_required": True,
                    "active_call_hangup_required": True,
                    "execution_containment_required": True,
                    "secret_erasure_required": True,
                    "failure_cleanup_required": True,
                },
            },
            "management_exposure": {"default_deny": True, "local_only": True},
            "storage_contract": {
                "ephemeral": True,
                "raw_logs": False,
                "cdr": False,
                "recordings": False,
                "backups": False,
                "exports": False,
            },
            "acquisition_receipt": {
                "reference": receipt_ref,
                "sha256": receipt_sha,
                "acquired_at": now.isoformat(),
                "expires_at": expires_at.isoformat(),
            },
            "approvals": approvals,
            "disqualifier_results": disqualifiers,
        }
        manifest["evidence_index"] = build_evidence_index(stage)
        manifest["review_payload_digest"] = review_payload_digest(manifest)
        (stage / "candidate-manifest.json").write_bytes(canonical(manifest)); os.chmod(stage / "candidate-manifest.json", 0o444)
        receipt_out = {"manifest_sha256":sha((stage / "candidate-manifest.json").read_bytes()),"review_status":"pending","review_payload_digest":manifest["review_payload_digest"],"image_manifest_digests":{image["name"]:image["image"].rsplit("@",1)[1] for image in images}}
        (stage / "seal-receipt.json").write_bytes(canonical(receipt_out)); os.chmod(stage / "seal-receipt.json", 0o444)
        os.replace(stage, output)
        return receipt_out
    except Exception:
        shutil.rmtree(stage, ignore_errors=True); raise

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-receipt", type=Path, required=True); parser.add_argument("--source-lock", type=Path, default=HERE / "source-lock.json")
    parser.add_argument("--registry", required=True); parser.add_argument("--image", action="append", default=[], required=True); parser.add_argument("--support-image", action="append", default=[], required=True); parser.add_argument("--contract", action="append", default=[], required=True)
    parser.add_argument("--acceptances", type=Path); parser.add_argument("--conformance-receipt", type=Path, required=True); parser.add_argument("--backend-reachability-receipt", type=Path, required=True); parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try: print(json.dumps(seal(args), sort_keys=True, separators=(",", ":")))
    except (Refusal, OSError, ValueError) as exc: print(f"refused: {exc}"); return 2
    return 0
if __name__ == "__main__": raise SystemExit(main())
