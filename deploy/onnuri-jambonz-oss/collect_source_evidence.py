#!/usr/bin/env python3
"""Collect hash-only evidence for the pinned public G009 source set."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

COMMIT = re.compile(r"[0-9a-f]{40}\Z")
FIELDS = {
    "name",
    "directory",
    "repository",
    "commit",
    "license_spdx",
    "license_paths",
    "patch",
}


class Refusal(ValueError):
    pass


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")


def load_unique(path: Path) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in items:
            if key in value:
                raise Refusal(f"duplicate key: {key}")
            value[key] = item
        return value

    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise Refusal("source lock is unreadable") from error


def relative(value: object, label: str) -> PurePosixPath:
    if not isinstance(value, str):
        raise Refusal(f"{label} must be a relative path")
    path = PurePosixPath(value)
    if (
        not path.parts
        or path.is_absolute()
        or "\\" in value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise Refusal(f"{label} must be a normalized relative path")
    return path


def regular(root: Path, value: object, label: str) -> Path:
    rel = relative(value, label)
    path = root.joinpath(*rel.parts)
    try:
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
        mode = path.lstat().st_mode
    except (OSError, ValueError) as error:
        raise Refusal(f"{label} is outside the approved root") from error
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise Refusal(f"{label} must be a regular non-symlink file")
    return path


def directory(root: Path, value: object, label: str) -> Path:
    rel = relative(value, label)
    path = root.joinpath(*rel.parts)
    try:
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
        mode = path.lstat().st_mode
    except (OSError, ValueError) as error:
        raise Refusal(f"{label} is outside the approved root") from error
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        raise Refusal(f"{label} must be a non-symlink directory")
    return path


def git(root: Path, *arguments: str, binary: bool = False) -> bytes | str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=False,
        capture_output=True,
        text=not binary,
        timeout=120,
        env={**os.environ, "LC_ALL": "C", "TZ": "UTC"},
    )
    if result.returncode != 0:
        raise Refusal("pinned git operation failed")
    return result.stdout


def archive_digest(root: Path) -> str:
    data = git(root, "archive", "--format=tar", "HEAD", binary=True)
    assert isinstance(data, bytes)
    return digest(data)


def submodules(root: Path) -> list[dict[str, str]]:
    output = git(root, "submodule", "status", "--recursive")
    assert isinstance(output, str)
    records: list[dict[str, str]] = []
    for raw in output.splitlines():
        if not raw:
            continue
        if raw[0] != " ":
            raise Refusal("submodule is not initialized at its pinned commit")
        fields = raw[1:].split()
        if len(fields) < 2 or COMMIT.fullmatch(fields[0]) is None:
            raise Refusal("submodule status is malformed")
        submodule_path = relative(fields[1], "submodule path")
        checkout = directory(root, str(submodule_path), "submodule path")
        actual = git(checkout, "rev-parse", "HEAD")
        assert isinstance(actual, str)
        if actual.strip() != fields[0]:
            raise Refusal("submodule checkout does not match gitlink")
        records.append(
            {
                "path": str(submodule_path),
                "commit": fields[0],
                "tree_sha256": f"sha256:{archive_digest(checkout)}",
            }
        )
    return records


def write_exclusive(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        raise Refusal("evidence output already exists")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def collect(lock_path: Path, source_root: Path, output_root: Path) -> dict[str, object]:
    if source_root.is_symlink() or not source_root.is_absolute():
        raise Refusal("source root must be an absolute non-symlink directory")
    if output_root.exists() or output_root.is_symlink() or not output_root.is_absolute():
        raise Refusal("output root must be a new absolute path")
    deployment_root = lock_path.resolve(strict=True).parent
    lock = load_unique(lock_path)
    if not isinstance(lock, dict) or set(lock) != {"schema_version", "sources"}:
        raise Refusal("source lock shape is invalid")
    if lock.get("schema_version") != "recova-jambonz-oss-source-lock/v1":
        raise Refusal("source lock version is invalid")
    sources = lock.get("sources")
    if not isinstance(sources, list) or not sources:
        raise Refusal("source lock must contain sources")

    names: set[str] = set()
    summary: list[dict[str, object]] = []
    for item in sources:
        if not isinstance(item, dict) or set(item) != FIELDS:
            raise Refusal("source entry shape is invalid")
        name = item["name"]
        commit = item["commit"]
        if (
            not isinstance(name, str)
            or name in names
            or not isinstance(commit, str)
            or COMMIT.fullmatch(commit) is None
        ):
            raise Refusal("source identity is invalid")
        names.add(name)
        checkout = directory(source_root, item["directory"], "source directory")
        actual = git(checkout, "rev-parse", "HEAD")
        assert isinstance(actual, str)
        if actual.strip() != commit:
            raise Refusal("source checkout commit mismatch")
        remote = git(checkout, "remote", "get-url", "origin")
        assert isinstance(remote, str)
        if remote.strip().removesuffix(".git") != str(item["repository"]).removesuffix(".git"):
            raise Refusal("source remote mismatch")

        patch = regular(deployment_root, item["patch"], "source patch")
        patch_bytes = patch.read_bytes()
        current_diff = git(
            checkout,
            "diff",
            "--binary",
            "--no-ext-diff",
            "--no-textconv",
            binary=True,
        )
        assert isinstance(current_diff, bytes)
        if current_diff != patch_bytes:
            raise Refusal("working tree does not exactly match the approved patch")

        license_records: list[dict[str, str]] = []
        license_paths = item["license_paths"]
        if not isinstance(license_paths, list) or not license_paths:
            raise Refusal("source license paths are invalid")
        for license_path in license_paths:
            license_file = regular(checkout, license_path, "license path")
            license_records.append(
                {"path": str(relative(license_path, "license path")), "sha256": digest(license_file.read_bytes())}
            )
        module_records = submodules(checkout)
        tree_record = {
            "name": name,
            "repository": item["repository"],
            "commit": commit,
            "archive_sha256": archive_digest(checkout),
        }
        patch_record = {
            "name": name,
            "commit": commit,
            "patch_path": item["patch"],
            "patch_sha256": "sha256:" + digest(patch_bytes),
        }
        license_record = {
            "name": name,
            "license_spdx": item["license_spdx"],
            "files": license_records,
        }
        records = {
            "tree": canonical(tree_record),
            "submodules": canonical({"name": name, "submodules": module_records}),
            "license": canonical(license_record),
            "patch": canonical(patch_record),
        }
        references: dict[str, dict[str, str]] = {}
        for category, data in records.items():
            relative_output = f"sources/{name}/{category}.json"
            write_exclusive(output_root / relative_output, data)
            references[category] = {
                "path": relative_output,
                "sha256": digest(data),
            }
        summary.append(
            {
                **tree_record,
                "license_spdx": item["license_spdx"],
                "submodules": module_records,
                "references": references,
            }
        )

    receipt_without_digest: dict[str, object] = {
        "schema_version": "recova-jambonz-oss-source-evidence/v1",
        "source_lock_sha256": digest(lock_path.read_bytes()),
        "sources": summary,
    }
    receipt = {
        **receipt_without_digest,
        "receipt_sha256": digest(canonical(receipt_without_digest)),
    }
    write_exclusive(output_root / "source-evidence-receipt.json", canonical(receipt))
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=Path(__file__).with_name("source-lock.json"))
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        receipt = collect(args.lock, args.source_root, args.output_root)
    except (OSError, Refusal, subprocess.SubprocessError) as error:
        print(f"refused: {error}")
        return 2
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
