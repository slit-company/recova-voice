from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import verify_backend_glibc_reachability as verifier

DIGEST = "sha256:" + "a" * 64


def add_bytes(archive: tarfile.TarFile, name: str, data: bytes) -> None:
    member = tarfile.TarInfo(name)
    member.size = len(data)
    member.mtime = 0
    member.mode = 0o644
    archive.addfile(member, io.BytesIO(data))


def tar_bytes(entries: list[tuple[str, bytes]], *, root_directory: bool = False) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
        if root_directory:
            root = tarfile.TarInfo("./")
            root.type = tarfile.DIRTYPE
            root.mtime = 0
            root.mode = 0o755
            archive.addfile(root)
        for name, data in entries:
            add_bytes(archive, name, data)
    return output.getvalue()


def make_oci_archive(
    directory: Path,
    files: list[tuple[str, bytes]],
    *,
    layer_root_directory: bool = False,
) -> tuple[Path, str]:
    layer = tar_bytes(files, root_directory=layer_root_directory)
    layer_digest = hashlib.sha256(layer).hexdigest()
    config = b"{}"
    config_digest = hashlib.sha256(config).hexdigest()
    manifest = verifier.canonical_json(
        {
            "config": {
                "digest": "sha256:" + config_digest,
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "size": len(config),
            },
            "layers": [
                {
                    "digest": "sha256:" + layer_digest,
                    "mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "size": len(layer),
                }
            ],
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "schemaVersion": 2,
        }
    )
    manifest_digest = hashlib.sha256(manifest).hexdigest()
    index = verifier.canonical_json(
        {
            "manifests": [
                {
                    "digest": "sha256:" + manifest_digest,
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "size": len(manifest),
                }
            ],
            "schemaVersion": 2,
        }
    )
    archive_path = directory / "image.tar"
    with tarfile.open(archive_path, mode="w", format=tarfile.PAX_FORMAT) as archive:
        add_bytes(archive, "oci-layout", b'{"imageLayoutVersion":"1.0.0"}')
        add_bytes(archive, "index.json", index)
        add_bytes(archive, "blobs/sha256/" + config_digest, config)
        add_bytes(archive, "blobs/sha256/" + layer_digest, layer)
        add_bytes(archive, "blobs/sha256/" + manifest_digest, manifest)
    return archive_path, "sha256:" + manifest_digest


class FormatDetectionTests(unittest.TestCase):
    def test_boundary_widths_and_conversion_forms(self) -> None:
        data = (
            b"%1024mc "
            b"%1025mc "
            b"%2$1025mC "
            b"%*'I2048ms "
            b"%0001025mS "
            b"%1025m[ "
            b"%%9999ms"
        )
        matches = verifier.find_offending_formats(data, "fixture.bin")
        self.assertEqual(
            [match["format"] for match in matches],
            ["%1025mc", "%2$1025mC", "%*'I2048ms", "%0001025mS", "%1025m["],
        )
        self.assertEqual([match["width"] for match in matches], [1025, 1025, 2048, 1025, 1025])
        self.assertTrue(all(match["path"] == "fixture.bin" for match in matches))

    def test_binary_offsets_are_byte_offsets(self) -> None:
        matches = verifier.find_offending_formats(b"\x00\xffA%1025ms\x00", "binary")
        self.assertEqual(matches[0]["byte_offset"], 3)
        self.assertEqual(matches[0]["conversion"], "s")

    def test_invalid_or_non_malloc_formats_do_not_match(self) -> None:
        data = b"%0$2048ms %2$$2048ms %2048s %mS %1025md %**1025ms"
        self.assertEqual(verifier.find_offending_formats(data, "invalid"), [])


class FilesystemEvidenceTests(unittest.TestCase):
    def test_scans_every_regular_file_and_emits_canonical_deterministic_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "nested").mkdir()
            (root / "clean.bin").write_bytes(b"\x00%1024ms\xff")
            (root / "nested" / "bad.bin").write_bytes(b"prefix%1025mC")

            first = verifier.build_evidence(root, DIGEST)
            second = verifier.build_evidence(root, DIGEST)

            self.assertEqual(first, second)
            self.assertEqual(first["schema_version"], verifier.SCHEMA_VERSION)
            self.assertEqual(first["image_manifest_digest"], DIGEST)
            self.assertEqual(first["files_scanned"], 2)
            self.assertEqual(first["bytes_scanned"], 9 + 13)
            self.assertTrue(first["scan_complete"])
            self.assertFalse(first["passed"])
            self.assertEqual(first["matches"][0]["path"], "nested/bad.bin")
            self.assertEqual(
                first["scanner_source_sha256"],
                "sha256:" + hashlib.sha256((ROOT / "verify_backend_glibc_reachability.py").read_bytes()).hexdigest(),
            )
            encoded = verifier.canonical_json(first)
            self.assertEqual(encoded, verifier.canonical_json(json.loads(encoded)))
            self.assertTrue(encoded.endswith(b"\n"))

    def test_clean_scan_passes_and_child_symlink_is_never_followed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "root"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            (root / "inside").write_bytes(b"clean")
            (outside / "bad").write_bytes(b"%9999ms")
            try:
                (root / "escape").symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks are unavailable")

            evidence = verifier.build_evidence(root, DIGEST)
            self.assertTrue(evidence["passed"])
            self.assertEqual(evidence["files_scanned"], 1)
            self.assertEqual(evidence["bytes_scanned"], 5)
            self.assertEqual(evidence["matches"], [])

    def test_root_symlink_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "root"
            root.mkdir()
            alias = base / "alias"
            try:
                alias.symlink_to(root, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks are unavailable")
            with self.assertRaises(verifier.VerificationError):
                verifier.build_evidence(alias, DIGEST)

    def test_unreadable_file_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "unreadable"
            target.write_bytes(b"clean")
            target.chmod(0)
            try:
                with self.assertRaisesRegex(verifier.VerificationError, "unreadable"):
                    verifier.build_evidence(root, DIGEST)
            finally:
                target.chmod(0o600)

    def test_special_file_fails_closed(self) -> None:
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFOs are unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.mkfifo(root / "pipe")
            with self.assertRaisesRegex(verifier.VerificationError, "special"):
                verifier.build_evidence(root, DIGEST)

    def test_invalid_image_digest_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            for digest in ("", "sha256:ABC", "sha512:" + "a" * 64, "sha256:" + "g" * 64):
                with self.subTest(digest=digest), self.assertRaises(verifier.VerificationError):
                    verifier.build_evidence(Path(temporary), digest)


class OciArchiveEvidenceTests(unittest.TestCase):
    def test_exact_manifest_archive_is_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive, digest = make_oci_archive(Path(temporary), [("app/clean", b"ok"), ("app/bad", b"%1025m[")])
            evidence = verifier.build_evidence(archive, digest)
            self.assertEqual(evidence["source_type"], "oci-archive")
            self.assertEqual(evidence["image_manifest_digest"], digest)
            self.assertEqual(evidence["files_scanned"], 2)
            self.assertEqual(evidence["bytes_scanned"], 9)
            self.assertFalse(evidence["passed"])
            self.assertEqual(evidence["matches"][0]["path"], "app/bad")

    def test_layer_root_directory_marker_is_ignored_safely(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive, digest = make_oci_archive(
                Path(temporary),
                [("app/clean", b"ok")],
                layer_root_directory=True,
            )
            evidence = verifier.build_evidence(archive, digest)
            self.assertTrue(evidence["passed"])
            self.assertEqual(evidence["files_scanned"], 1)
            self.assertEqual(evidence["bytes_scanned"], 2)
            self.assertEqual(evidence["matches"], [])

    def test_wrong_exact_manifest_digest_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive, _ = make_oci_archive(Path(temporary), [("app/clean", b"ok")])
            with self.assertRaises(verifier.VerificationError):
                verifier.build_evidence(archive, DIGEST)

    def test_layer_traversal_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive, digest = make_oci_archive(Path(temporary), [("../escape", b"bad")])
            with self.assertRaisesRegex(verifier.VerificationError, "traversal"):
                verifier.build_evidence(archive, digest)

    def test_outer_archive_duplicate_path_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "duplicate.tar"
            with tarfile.open(archive_path, mode="w") as archive:
                add_bytes(archive, "oci-layout", b"{}")
                add_bytes(archive, "oci-layout", b"{}")
            with self.assertRaisesRegex(verifier.VerificationError, "duplicate path"):
                verifier.build_evidence(archive_path, DIGEST)

    def test_outer_archive_symlink_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "symlink.tar"
            with tarfile.open(archive_path, mode="w") as archive:
                member = tarfile.TarInfo("oci-layout")
                member.type = tarfile.SYMTYPE
                member.linkname = "../outside"
                archive.addfile(member)
            with self.assertRaisesRegex(verifier.VerificationError, "link or special"):
                verifier.build_evidence(archive_path, DIGEST)

    def test_truncated_or_incomplete_archive_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive, digest = make_oci_archive(Path(temporary), [("app/clean", b"ok")])
            data = archive.read_bytes()
            archive.write_bytes(data[: len(data) // 2])
            with self.assertRaises(verifier.VerificationError):
                verifier.build_evidence(archive, digest)


class CliTests(unittest.TestCase):
    def test_cli_returns_one_and_writes_evidence_when_matches_exist(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            root.mkdir()
            (root / "bad").write_bytes(b"%1025ms")
            output = Path(temporary) / "evidence.json"
            status = verifier.main([str(root), "--image-manifest-digest", DIGEST, "--output", str(output)])
            self.assertEqual(status, 1)
            self.assertFalse(json.loads(output.read_bytes())["passed"])

    def test_cli_does_not_create_evidence_for_refused_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            root.mkdir()
            output = Path(temporary) / "evidence.json"
            status = verifier.main([str(root), "--image-manifest-digest", "invalid", "--output", str(output)])
            self.assertEqual(status, 2)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
