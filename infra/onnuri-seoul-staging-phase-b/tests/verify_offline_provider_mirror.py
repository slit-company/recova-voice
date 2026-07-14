#!/usr/bin/env python3
"""Verify an existing Terraform provider mirror without running Terraform."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

PROVIDER_ADDRESS = "registry.terraform.io/hashicorp/google"
PROVIDER_VERSION = "7.39.0"
PLATFORMS = ("darwin_arm64", "linux_amd64", "windows_amd64")


class VerificationError(ValueError):
    """Raised when a local mirror, lock file, or CLI configuration is unsafe."""


def _read(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        raise VerificationError(f"cannot read {path}: {error}") from error


def _read_json(path: Path) -> object:
    try:
        return json.loads(_read(path).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"metadata is not valid UTF-8 JSON: {path.name}") from error


def _without_comments(text: str) -> str:
    return "\n".join(line.split("#", 1)[0].split("//", 1)[0] for line in text.splitlines())


def verify_cli_config(cli_config: Path, mirror: Path) -> None:
    """Require exactly the closed filesystem-mirror configuration shape."""
    try:
        text = _read(cli_config).decode("utf-8")
    except UnicodeDecodeError as error:
        raise VerificationError("CLI configuration is not UTF-8") from error

    source = _without_comments(text)
    forbidden = ("network_mirror", "dev_overrides", "credentials", "credential", "token", "endpoint")
    if any(re.search(rf"\b{word}\b", source, re.IGNORECASE) for word in forbidden):
        raise VerificationError("CLI configuration contains a forbidden provider-installation setting")

    expected_path = str(mirror.resolve())
    pattern = re.compile(
        r"^\s*provider_installation\s*\{\s*"
        r"filesystem_mirror\s*\{\s*"
        r'path\s*=\s*"(?P<path>[^"\\]+)"\s*'
        r"include\s*=\s*\[\s*\"registry\.terraform\.io/hashicorp/google\"\s*\]\s*\}\s*"
        r"direct\s*\{\s*exclude\s*=\s*\[\s*\"\*/\*\"\s*\]\s*\}\s*\}\s*$",
        re.DOTALL,
    )
    match = pattern.fullmatch(source)
    if match is None or match.group("path") != expected_path:
        raise VerificationError("CLI configuration must contain only the closed Google filesystem mirror and direct exclusion")


def _lock_checksums(lockfile: Path) -> set[str]:
    try:
        text = _read(lockfile).decode("utf-8")
    except UnicodeDecodeError as error:
        raise VerificationError("lock file is not UTF-8") from error

    blocks = re.findall(r'provider\s+"([^"]+)"\s*\{(.*?)\n\}', text, re.DOTALL)
    if len(blocks) != 1 or blocks[0][0] != PROVIDER_ADDRESS:
        raise VerificationError("lock file must contain exactly the Google provider")
    body = blocks[0][1]
    if re.search(r'(?m)^\s*version\s*=\s*"7\.39\.0"\s*$', body) is None:
        raise VerificationError("lock file must pin Google provider 7.39.0")
    checksums = set(re.findall(r'"zh:([0-9a-f]{64})"', body))
    if not checksums:
        raise VerificationError("lock file has no SHA-256 zip checksums")
    return checksums


def _provider_directory(mirror: Path) -> Path:
    return mirror / "registry.terraform.io" / "hashicorp" / "google"


def _expected_artifact(mirror: Path, platform: str) -> Path:
    return _provider_directory(mirror) / f"terraform-provider-google_{PROVIDER_VERSION}_{platform}.zip"


def _validate_metadata(mirror: Path) -> None:
    directory = _provider_directory(mirror)
    index = _read_json(directory / "index.json")
    if index != {"versions": {PROVIDER_VERSION: {}}}:
        raise VerificationError("index.json must describe only Google provider 7.39.0")

    version = _read_json(directory / f"{PROVIDER_VERSION}.json")
    if not isinstance(version, dict) or set(version) != {"archives"}:
        raise VerificationError("version metadata must contain only archives")
    archives = version["archives"]
    if not isinstance(archives, dict) or set(archives) != set(PLATFORMS):
        raise VerificationError("version metadata must describe exactly the required platforms")
    for platform in PLATFORMS:
        archive = archives[platform]
        expected_name = _expected_artifact(mirror, platform).name
        if not isinstance(archive, dict) or set(archive) != {"url", "hashes"}:
            raise VerificationError(f"version metadata has an invalid {platform} archive")
        if archive["url"] != expected_name:
            raise VerificationError(f"version metadata has an invalid {platform} package URL")
        if not isinstance(archive["hashes"], list) or not archive["hashes"] or not all(
            isinstance(value, str) and value for value in archive["hashes"]
        ):
            raise VerificationError(f"version metadata has invalid {platform} hashes")


def verify_mirror(mirror: Path, cli_config: Path, lockfile: Path) -> None:
    """Check packed mirror bytes and reject every extra mirror artifact."""
    mirror = mirror.resolve()
    if not mirror.is_dir():
        raise VerificationError("provider mirror directory is missing")
    verify_cli_config(cli_config, mirror)
    checksums = _lock_checksums(lockfile)
    expected = {
        _provider_directory(mirror) / "index.json",
        _provider_directory(mirror) / f"{PROVIDER_VERSION}.json",
        *(_expected_artifact(mirror, platform) for platform in PLATFORMS),
    }
    entries = set(mirror.rglob("*"))
    if any(path.is_symlink() for path in entries):
        raise VerificationError("provider mirror must not contain symbolic links")
    actual = {path for path in entries if path.is_file()}
    if actual != expected:
        raise VerificationError("provider mirror must contain exactly the packed metadata and three required Google package artifacts")
    _validate_metadata(mirror)
    for platform in PLATFORMS:
        artifact = _expected_artifact(mirror, platform)
        digest = hashlib.sha256(_read(artifact)).hexdigest()
        if digest not in checksums:
            raise VerificationError(f"package checksum is not pinned by the lock file: {artifact.name}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mirror", required=True, type=Path)
    parser.add_argument("--cli-config", required=True, type=Path)
    parser.add_argument("--lockfile", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        verify_mirror(args.mirror, args.cli_config, args.lockfile)
    except VerificationError as error:
        print(f"OFFLINE_PROVIDER_MIRROR: {error}", file=sys.stderr)
        return 1
    print("OFFLINE_PROVIDER_MIRROR: verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
