#!/usr/bin/env python3
"""Generate fail-closed CVE-2026-5450 reachability evidence for a backend image."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA_VERSION = "recova.backend-glibc-reachability/v1"
DIGEST_PREFIX = "sha256:"
CHUNK_SIZE = 1024 * 1024
PATTERNS = [
    {
        "id": "scanf-malloc-character-explicit-width",
        "syntax": "%[argument$][*]['I]*<width>m[cCsS[]",
        "minimum_offending_width": 1025,
    }
]
_CONVERSIONS = frozenset(b"cCsS[")
_FLAGS = frozenset(b"*'I")


class VerificationError(Exception):
    """The input cannot be proven to have been scanned completely."""


@dataclass(frozen=True)
class FileRecord:
    path: str
    size: int
    device: int
    inode: int
    mtime_ns: int


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json(data: bytes, label: str) -> Any:
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"{label}: malformed JSON: {exc}") from exc


def _validate_digest(value: str) -> str:
    if not isinstance(value, str) or not value.startswith(DIGEST_PREFIX):
        raise VerificationError("image manifest digest must be sha256:<64 lowercase hex characters>")
    hexdigest = value[len(DIGEST_PREFIX):]
    if len(hexdigest) != 64 or any(char not in "0123456789abcdef" for char in hexdigest):
        raise VerificationError("image manifest digest must be sha256:<64 lowercase hex characters>")
    return hexdigest


def _safe_relative(raw: str, label: str) -> str:
    if not isinstance(raw, str) or not raw or "\x00" in raw or "\\" in raw:
        raise VerificationError(f"{label}: invalid path")
    path = PurePosixPath(raw)
    parts = list(path.parts)
    while parts and parts[0] == ".":
        parts.pop(0)
    if path.is_absolute() or not parts or any(part in ("", ".", "..") for part in parts):
        raise VerificationError(f"{label}: path traversal or non-canonical path: {raw!r}")
    return "/".join(parts)


def _width_over_limit(digits: bytes) -> tuple[bool, int]:
    normalized = digits.lstrip(b"0") or b"0"
    over = len(normalized) > 4 or (len(normalized) == 4 and normalized > b"1024")
    try:
        width = int(normalized)
    except ValueError as exc:
        raise VerificationError("scanf field width is too large to report canonically") from exc
    return over, width


def find_offending_formats(data: bytes, path: str) -> list[dict[str, Any]]:
    """Find valid scanf allocation conversions without interpreting binary data as text."""
    matches: list[dict[str, Any]] = []
    index = 0
    length = len(data)
    while index < length:
        start = data.find(b"%", index)
        if start < 0:
            break
        cursor = start + 1
        if cursor < length and data[cursor] == ord("%"):
            index = cursor + 1
            continue

        positional_start = cursor
        while cursor < length and 48 <= data[cursor] <= 57:
            cursor += 1
        if cursor < length and data[cursor] == ord("$") and cursor > positional_start:
            if data[positional_start:cursor].lstrip(b"0") in (b"", b"0"):
                index = start + 1
                continue
            cursor += 1
        else:
            cursor = positional_start

        seen_flags: set[int] = set()
        valid = True
        while cursor < length and data[cursor] in _FLAGS:
            flag = data[cursor]
            if flag in seen_flags:
                valid = False
                break
            seen_flags.add(flag)
            cursor += 1
        if not valid:
            index = start + 1
            continue

        width_start = cursor
        while cursor < length and 48 <= data[cursor] <= 57:
            cursor += 1
        if cursor == width_start or cursor >= length or data[cursor] != ord("m"):
            index = start + 1
            continue
        digits = data[width_start:cursor]
        cursor += 1
        if cursor >= length or data[cursor] not in _CONVERSIONS:
            index = start + 1
            continue
        end = cursor + 1
        over, width = _width_over_limit(digits)
        if over:
            token = data[start:end].decode("ascii")
            matches.append(
                {
                    "byte_offset": start,
                    "conversion": chr(data[cursor]),
                    "format": token,
                    "path": path,
                    "width": width,
                }
            )
        index = end
    return matches


def _path_text(relative: Path) -> str:
    try:
        return relative.as_posix().encode("utf-8", "strict").decode("utf-8")
    except UnicodeError as exc:
        raise VerificationError("filesystem contains a path that is not valid UTF-8") from exc


def _snapshot(root: Path) -> tuple[list[FileRecord], tuple[tuple[str, str, int, int], ...]]:
    files: list[FileRecord] = []
    entries: list[tuple[str, str, int, int]] = []
    def refuse_walk_error(error: OSError) -> None:
        raise VerificationError(f"cannot enumerate complete filesystem: {error}")
    try:
        for directory, names, filenames in os.walk(
            root, topdown=True, onerror=refuse_walk_error, followlinks=False
        ):
            names.sort()
            filenames.sort()
            directory_path = Path(directory)
            retained: list[str] = []
            for name in names:
                candidate = directory_path / name
                info = candidate.lstat()
                relative = _path_text(candidate.relative_to(root))
                if stat.S_ISLNK(info.st_mode):
                    entries.append((relative, "symlink", info.st_size, info.st_mtime_ns))
                elif stat.S_ISDIR(info.st_mode):
                    if info.st_mode & 0o444 == 0 or info.st_mode & 0o111 == 0:
                        raise VerificationError(f"unreadable directory refused: {relative}")
                    entries.append((relative, "directory", info.st_size, info.st_mtime_ns))
                    retained.append(name)
                else:
                    raise VerificationError(f"special filesystem entry refused: {relative}")
            names[:] = retained
            for name in filenames:
                candidate = directory_path / name
                info = candidate.lstat()
                relative = _path_text(candidate.relative_to(root))
                if stat.S_ISLNK(info.st_mode):
                    entries.append((relative, "symlink", info.st_size, info.st_mtime_ns))
                    continue
                if not stat.S_ISREG(info.st_mode):
                    raise VerificationError(f"special filesystem entry refused: {relative}")
                record = FileRecord(relative, info.st_size, info.st_dev, info.st_ino, info.st_mtime_ns)
                files.append(record)
                entries.append((relative, "regular", info.st_size, info.st_mtime_ns))
    except (OSError, UnicodeError) as exc:
        raise VerificationError(f"cannot enumerate complete filesystem: {exc}") from exc
    files.sort(key=lambda item: item.path)
    entries.sort()
    return files, tuple(entries)


def _read_exact_regular(root: Path, record: FileRecord) -> bytes:
    path = root.joinpath(*PurePosixPath(record.path).parts)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        current = path.lstat()
        if current.st_mode & 0o444 == 0:
            raise VerificationError(f"unreadable regular file refused: {record.path}")
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        expected = (record.device, record.inode, record.size, record.mtime_ns)
        if not stat.S_ISREG(before.st_mode) or identity != expected:
            raise VerificationError(f"filesystem changed before scan completed: {record.path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, CHUNK_SIZE)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        after = os.fstat(descriptor)
        if total != record.size or (after.st_size, after.st_mtime_ns) != (before.st_size, before.st_mtime_ns):
            raise VerificationError(f"incomplete or changing file refused: {record.path}")
        return b"".join(chunks)
    except VerificationError:
        raise
    except OSError as exc:
        raise VerificationError(f"cannot read complete regular file {record.path}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def scan_directory(root: Path) -> tuple[int, int, list[dict[str, Any]]]:
    try:
        root_info = root.lstat()
    except OSError as exc:
        raise VerificationError(f"cannot inspect input root: {exc}") from exc
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise VerificationError("unpacked input must be a real directory, not a symlink")
    if root_info.st_mode & 0o444 == 0 or root_info.st_mode & 0o111 == 0:
        raise VerificationError("unpacked input root is unreadable")
    records, initial = _snapshot(root)
    matches: list[dict[str, Any]] = []
    byte_count = 0
    for record in records:
        data = _read_exact_regular(root, record)
        byte_count += len(data)
        matches.extend(find_offending_formats(data, record.path))
    _, final = _snapshot(root)
    if final != initial:
        raise VerificationError("filesystem changed or scan coverage became incomplete during scan")
    matches.sort(key=lambda item: (item["path"], item["byte_offset"], item["format"]))
    return len(records), byte_count, matches


def _copy_member(archive: tarfile.TarFile, member: tarfile.TarInfo, destination: Path, label: str) -> None:
    source = archive.extractfile(member)
    if source is None:
        raise VerificationError(f"{label}: regular member has no data: {member.name}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    with destination.open("xb") as output:
        while True:
            chunk = source.read(CHUNK_SIZE)
            if not chunk:
                break
            output.write(chunk)
            total += len(chunk)
    if total != member.size:
        raise VerificationError(f"{label}: incomplete member: {member.name}")


def _extract_oci_archive(archive_path: Path, workspace: Path, digest_hex: str) -> Path:
    oci = workspace / "oci"
    oci.mkdir()
    seen: set[str] = set()
    try:
        with tarfile.open(archive_path, mode="r:*") as archive:
            for member in archive:
                relative = _safe_relative(member.name, "OCI archive")
                if relative in seen:
                    raise VerificationError(f"OCI archive: duplicate path: {relative}")
                seen.add(relative)
                destination = oci.joinpath(*PurePosixPath(relative).parts)
                if member.isdir():
                    destination.mkdir(parents=True, exist_ok=True)
                elif member.isreg():
                    _copy_member(archive, member, destination, "OCI archive")
                else:
                    raise VerificationError(f"OCI archive: link or special member refused: {relative}")
    except (OSError, tarfile.TarError) as exc:
        raise VerificationError(f"cannot read immutable OCI archive: {exc}") from exc

    layout_path = oci / "oci-layout"
    index_path = oci / "index.json"
    manifest_path = oci / "blobs" / "sha256" / digest_hex
    try:
        layout_data = _load_json(layout_path.read_bytes(), "oci-layout")
        index_data = _load_json(index_path.read_bytes(), "index.json")
        manifest_bytes = manifest_path.read_bytes()
    except OSError as exc:
        raise VerificationError(f"OCI archive is incomplete: {exc}") from exc
    if layout_data != {"imageLayoutVersion": "1.0.0"}:
        raise VerificationError("OCI archive has an invalid oci-layout")
    if hashlib.sha256(manifest_bytes).hexdigest() != digest_hex:
        raise VerificationError("supplied image manifest digest does not match manifest bytes")
    if not isinstance(index_data, dict) or not isinstance(index_data.get("manifests"), list):
        raise VerificationError("OCI index is malformed")
    supplied = DIGEST_PREFIX + digest_hex
    supplied_count = 0
    for position, descriptor in enumerate(index_data["manifests"]):
        if not isinstance(descriptor, dict) or set(("digest", "size")) - set(descriptor):
            raise VerificationError(f"OCI index descriptor {position} is malformed")
        _validate_digest(descriptor["digest"])
        size = descriptor["size"]
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise VerificationError(f"OCI index descriptor {position} has invalid size")
        if descriptor["digest"] == supplied:
            supplied_count += 1
            if size != len(manifest_bytes):
                raise VerificationError("OCI index manifest size does not match manifest bytes")
    if supplied_count != 1:
        raise VerificationError("OCI index must reference the supplied manifest digest exactly once")

    manifest = _load_json(manifest_bytes, "image manifest")
    if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 2 or not isinstance(manifest.get("layers"), list):
        raise VerificationError("OCI image manifest is malformed")
    config = manifest.get("config")
    if not isinstance(config, dict) or set(("digest", "size")) - set(config):
        raise VerificationError("OCI image config descriptor is malformed")
    config_hex = _validate_digest(config["digest"])
    config_size = config["size"]
    if not isinstance(config_size, int) or isinstance(config_size, bool) or config_size < 0:
        raise VerificationError("OCI image config descriptor has invalid size")
    config_path = oci / "blobs" / "sha256" / config_hex
    try:
        config_info = config_path.stat()
    except OSError as exc:
        raise VerificationError(f"OCI image config is missing: {exc}") from exc
    if not stat.S_ISREG(config_info.st_mode) or config_info.st_size != config_size:
        raise VerificationError("OCI image config size or type mismatch")
    if _hash_file(config_path) != config_hex:
        raise VerificationError("OCI image config digest mismatch")
    root = workspace / "rootfs"
    root.mkdir()
    for position, descriptor in enumerate(manifest["layers"]):
        if not isinstance(descriptor, dict) or set(("digest", "size")) - set(descriptor):
            raise VerificationError(f"OCI layer descriptor {position} is malformed")
        layer_digest = descriptor["digest"]
        layer_hex = _validate_digest(layer_digest)
        size = descriptor["size"]
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise VerificationError(f"OCI layer descriptor {position} has invalid size")
        layer_path = oci / "blobs" / "sha256" / layer_hex
        try:
            layer_info = layer_path.stat()
        except OSError as exc:
            raise VerificationError(f"OCI layer {position} is missing: {exc}") from exc
        if not stat.S_ISREG(layer_info.st_mode) or layer_info.st_size != size:
            raise VerificationError(f"OCI layer {position} size or type mismatch")
        if _hash_file(layer_path) != layer_hex:
            raise VerificationError(f"OCI layer {position} digest mismatch")
        _apply_layer(layer_path, root, position)
    return root


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise VerificationError(f"cannot hash non-regular file: {path}")
            while chunk := source.read(CHUNK_SIZE):
                digest.update(chunk)
                total += len(chunk)
            after = os.fstat(source.fileno())
    except VerificationError:
        raise
    except OSError as exc:
        raise VerificationError(f"cannot hash complete file {path}: {exc}") from exc
    if total != before.st_size or (after.st_size, after.st_mtime_ns) != (before.st_size, before.st_mtime_ns):
        raise VerificationError(f"incomplete or changing file refused while hashing: {path}")
    return digest.hexdigest()


def _remove_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)


def _ensure_parents(root: Path, relative: str) -> Path:
    destination = root
    parts = PurePosixPath(relative).parts
    for part in parts[:-1]:
        destination = destination / part
        if destination.exists() and not destination.is_dir():
            _remove_path(destination)
        destination.mkdir(exist_ok=True)
    return root.joinpath(*parts)


def _apply_layer(layer_path: Path, root: Path, position: int) -> None:
    seen: set[str] = set()
    root_marker_seen = False
    label = f"OCI layer {position}"
    try:
        with tarfile.open(layer_path, mode="r:*") as layer:
            for member in layer:
                if member.name in (".", "./"):
                    if not member.isdir():
                        raise VerificationError(f"{label}: root marker must be a directory entry")
                    if root_marker_seen:
                        raise VerificationError(f"{label}: duplicate path: .")
                    root_marker_seen = True
                    continue
                relative = _safe_relative(member.name, label)
                if relative in seen:
                    raise VerificationError(f"{label}: duplicate path: {relative}")
                seen.add(relative)
                pure = PurePosixPath(relative)
                basename = pure.name
                if basename == ".wh..wh..opq":
                    directory = root.joinpath(*pure.parts[:-1])
                    if directory.exists():
                        for child in directory.iterdir():
                            _remove_path(child)
                    continue
                if basename.startswith(".wh."):
                    target_name = basename[4:]
                    if not target_name:
                        raise VerificationError(f"{label}: malformed whiteout: {relative}")
                    target = root.joinpath(*pure.parts[:-1], target_name)
                    if target.exists() or target.is_symlink():
                        _remove_path(target)
                    continue
                destination = _ensure_parents(root, relative)
                if member.isdir():
                    if destination.exists() and not destination.is_dir():
                        _remove_path(destination)
                    destination.mkdir(parents=True, exist_ok=True)
                else:
                    if destination.exists() or destination.is_symlink():
                        _remove_path(destination)
                    if member.isreg():
                        _copy_member(layer, member, destination, label)
                    elif member.issym():
                        # Record no filesystem object: later members cannot follow this link.
                        pass
                    elif member.islnk():
                        target_relative = _safe_relative(member.linkname, f"{label} hardlink")
                        target = root.joinpath(*PurePosixPath(target_relative).parts)
                        if not target.is_file() or target.is_symlink():
                            raise VerificationError(f"{label}: unresolved hardlink: {relative}")
                        shutil.copyfile(target, destination)
                    else:
                        raise VerificationError(f"{label}: special member refused: {relative}")
    except VerificationError:
        raise
    except (OSError, tarfile.TarError) as exc:
        raise VerificationError(f"{label}: malformed or incomplete data: {exc}") from exc


def build_evidence(source: Path, image_digest: str) -> dict[str, Any]:
    digest_hex = _validate_digest(image_digest)
    scanner_hash = _hash_file(Path(__file__))
    if source.is_symlink():
        raise VerificationError("input source symlink refused")
    if source.is_dir():
        files, bytes_scanned, matches = scan_directory(source)
        source_type = "unpacked-filesystem"
    elif source.is_file():
        with tempfile.TemporaryDirectory(prefix="recova-glibc-scan-") as temporary:
            root = _extract_oci_archive(source, Path(temporary), digest_hex)
            files, bytes_scanned, matches = scan_directory(root)
        source_type = "oci-archive"
    else:
        raise VerificationError("input source must be an unpacked directory or regular OCI archive")
    if _hash_file(Path(__file__)) != scanner_hash:
        raise VerificationError("scanner source changed before evidence was completed")
    return {
        "vulnerability_id": "CVE-2026-5450",
        "bytes_scanned": bytes_scanned,
        "files_scanned": files,
        "image_manifest_digest": image_digest,
        "matches": matches,
        "passed": not matches,
        "patterns": PATTERNS,
        "scan_complete": True,
        "scanner_source_sha256": DIGEST_PREFIX + scanner_hash,
        "schema_version": SCHEMA_VERSION,
        "source_type": source_type,
    }


def _write_output(path: Path, payload: bytes) -> None:
    if path.is_symlink():
        raise VerificationError("output symlink refused")
    temporary = path.with_name(path.name + ".tmp")
    try:
        with temporary.open("xb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise VerificationError(f"cannot write complete evidence: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="unpacked filesystem directory or OCI image-layout tar archive")
    parser.add_argument("--image-manifest-digest", required=True)
    parser.add_argument("--output", type=Path, help="write canonical JSON atomically instead of stdout")
    args = parser.parse_args(argv)
    try:
        evidence = build_evidence(args.source, args.image_manifest_digest)
        payload = canonical_json(evidence)
        if args.output is None:
            sys.stdout.buffer.write(payload)
        else:
            _write_output(args.output, payload)
        return 0 if evidence["passed"] else 1
    except VerificationError as exc:
        print(f"verification refused: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"verification refused: cannot write complete evidence: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
