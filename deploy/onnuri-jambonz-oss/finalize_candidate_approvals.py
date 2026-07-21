#!/usr/bin/env python3
"""Finalize a frozen G009 review request with digest-bound independent approvals."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import jsonschema

import verify_candidate as verifier

ROLES = ("architect", "critic", "qa")
APPROVAL_SCHEMA_VERSION = "onnuri-jambonz-oss-approval/v1"


class Refusal(ValueError):
    pass


def regular(path: Path, label: str) -> Path:
    try:
        if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
            raise OSError
    except OSError as exc:
        raise Refusal(f"{label} must be a regular file") from exc
    return path


def unique_json(path: Path, label: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise Refusal(f"duplicate key in {label}")
            result[key] = value
        return result

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise Refusal(f"invalid {label}") from exc
    if not isinstance(value, dict):
        raise Refusal(f"{label} must be an object")
    return value


def parse_pairs(values: list[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        role, separator, path = value.partition("=")
        if not separator or role not in ROLES or role in result or not path:
            raise Refusal("invalid approval mapping")
        result[role] = Path(path)
    if set(result) != set(ROLES):
        raise Refusal("architect, critic, and qa approvals are required")
    return result


def timestamp(value: Any, label: str, now: datetime) -> str:
    if not isinstance(value, str):
        raise Refusal(f"{label} must be an RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Refusal(f"{label} must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None or parsed > now + timedelta(minutes=5):
        raise Refusal(f"{label} is not current")
    if parsed < now - timedelta(hours=24):
        raise Refusal(f"{label} is stale")
    return parsed.astimezone(timezone.utc).isoformat()


def validate_approval(
    role: str,
    value: dict[str, Any],
    manifest: dict[str, Any],
    now: datetime,
) -> dict[str, Any]:
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
    if set(value) != fields:
        raise Refusal(f"{role} approval has an invalid shape")
    if value["schema_version"] != APPROVAL_SCHEMA_VERSION or value["role"] != role:
        raise Refusal(f"{role} approval identity mismatch")
    identity = value["identity"]
    if not isinstance(identity, str) or not identity or identity.startswith("pending-"):
        raise Refusal(f"{role} approval identity is invalid")
    if value["independent"] is not True or value["decision"] != "approved":
        raise Refusal(f"{role} approval is not affirmative and independent")
    if value["review_payload_digest"] != manifest.get("review_payload_digest"):
        raise Refusal(f"{role} approval does not bind the frozen review payload")
    if value["source_lock_sha256"] != manifest.get("source_lock_sha256"):
        raise Refusal(f"{role} approval does not bind the source lock")
    findings = value["findings"]
    if not isinstance(findings, list) or any(
        not isinstance(item, str) or not item for item in findings
    ):
        raise Refusal(f"{role} approval findings are invalid")
    normalized = dict(value)
    normalized["approved_at"] = timestamp(value["approved_at"], f"{role}.approved_at", now)
    return normalized


def atomic_read_only_write(path: Path, data: bytes) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o444)
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def validate_pending_seal_receipt(
    receipt: dict[str, Any], manifest: dict[str, Any], manifest_data: bytes
) -> None:
    image_manifest_digests = {
        image["name"]: image["image"].rsplit("@", 1)[1]
        for image in manifest.get("images", [])
        if isinstance(image, dict)
        and isinstance(image.get("name"), str)
        and isinstance(image.get("image"), str)
        and "@" in image["image"]
    }
    expected = {
        "manifest_sha256": hashlib.sha256(manifest_data).hexdigest(),
        "review_status": "pending",
        "review_payload_digest": manifest.get("review_payload_digest"),
        "image_manifest_digests": image_manifest_digests,
    }
    if receipt != expected:
        raise Refusal("pending seal receipt does not bind the candidate bundle")


def finalize(
    bundle: Path,
    output: Path,
    approvals: dict[str, Path],
) -> dict[str, Any]:
    bundle = bundle.resolve(strict=True)
    if bundle.is_symlink() or not bundle.is_dir():
        raise Refusal("bundle must be a non-symlink directory")
    output = output.resolve()
    if output.exists() or output.is_symlink():
        raise Refusal("output path must not already exist")
    output.parent.mkdir(parents=True, exist_ok=True)

    stage = Path(tempfile.mkdtemp(prefix=".finalize-", dir=output.parent))
    shutil.rmtree(stage)
    try:
        shutil.copytree(bundle, stage, symlinks=True)
        if any(path.is_symlink() for path in stage.rglob("*")):
            raise Refusal("bundle must not contain symlinks")

        manifest_path = regular(stage / "candidate-manifest.json", "candidate manifest")
        receipt_path = regular(stage / "seal-receipt.json", "seal receipt")
        manifest = unique_json(manifest_path, "candidate manifest")
        receipt = unique_json(receipt_path, "seal receipt")
        validate_pending_seal_receipt(receipt, manifest, manifest_path.read_bytes())
        expected_digest = verifier.review_payload_digest(manifest)
        if manifest.get("review_payload_digest") != expected_digest:
            raise Refusal("review request payload digest mismatch")
        current = manifest.get("approvals")
        index = manifest.get("evidence_index")
        if not isinstance(current, dict) or not isinstance(index, dict):
            raise Refusal("review request approval structure is missing")

        now = datetime.now(timezone.utc)
        documents: dict[str, dict[str, Any]] = {}
        identities: set[str] = set()
        for role in ROLES:
            entry = current.get(role)
            if not isinstance(entry, dict):
                raise Refusal(f"missing pending {role} approval")
            expected_reference = f"evidence:evidence/approval-{role}.json"
            if entry.get("reference") != expected_reference:
                raise Refusal(f"{role} approval reference mismatch")
            document = validate_approval(
                role,
                unique_json(
                    regular(approvals[role], f"{role} approval"),
                    f"{role} approval",
                ),
                manifest,
                now,
            )
            if document["identity"] in identities:
                raise Refusal("approval identities must be distinct")
            identities.add(document["identity"])
            documents[role] = document

        for role, document in documents.items():
            reference = f"evidence:evidence/approval-{role}.json"
            entry = index.get(reference)
            if (
                not isinstance(entry, dict)
                or entry.get("path") != f"evidence/approval-{role}.json"
            ):
                raise Refusal(f"{role} approval index entry mismatch")
            target = regular(stage / entry["path"], f"pending {role} approval")
            data = verifier.canonical_json(document)
            atomic_read_only_write(target, data)
            value = "sha256:" + hashlib.sha256(data).hexdigest()
            entry["sha256"] = value.removeprefix("sha256:")
            entry["content_type"] = "text"
            current[role] = {
                "identity": document["identity"],
                "independent": True,
                "decision": "approved",
                "reference": reference,
                "sha256": value,
            }

        if verifier.review_payload_digest(manifest) != expected_digest:
            raise Refusal("approval finalization changed the frozen review payload")
        schema = unique_json(
            Path(__file__).with_name("candidate-manifest.schema.json"),
            "candidate schema",
        )
        try:
            jsonschema.validate(instance=manifest, schema=schema)
        except jsonschema.ValidationError as exc:
            raise Refusal(f"final manifest schema failure: {exc.message}") from exc
        errors = verifier.validate_manifest(manifest, now)
        verifier.validate_evidence(manifest, stage, errors, now)
        if errors:
            raise Refusal(
                "final manifest verification failed: "
                + "; ".join(sorted(set(errors)))
            )

        manifest_data = verifier.canonical_json(manifest)
        atomic_read_only_write(manifest_path, manifest_data)
        receipt.update(
            {
                "manifest_sha256": hashlib.sha256(manifest_data).hexdigest(),
                "review_status": "approved",
                "review_payload_digest": expected_digest,
            }
        )
        atomic_read_only_write(receipt_path, verifier.canonical_json(receipt))
        os.replace(stage, output)
        return {
            "manifest_sha256": receipt["manifest_sha256"],
            "review_payload_digest": expected_digest,
            "review_status": "approved",
        }
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--approval", action="append", default=[], required=True)
    args = parser.parse_args()
    try:
        result = finalize(args.bundle, args.output, parse_pairs(args.approval))
    except (OSError, Refusal, ValueError) as exc:
        print(f"refused: {exc}")
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
