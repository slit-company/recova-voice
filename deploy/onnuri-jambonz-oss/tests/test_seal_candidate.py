"""Hermetic unit checks for the candidate sealer's fail-closed primitives."""
from __future__ import annotations

import argparse
import base64
import importlib.util
import hashlib
import io
import json
import stat
import subprocess
import tempfile
import tarfile
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from pathlib import PurePosixPath
from unittest import TestCase
from unittest.mock import MagicMock, patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SPEC = importlib.util.spec_from_file_location("seal_candidate", Path(__file__).parents[1] / "seal_candidate.py")
assert SPEC and SPEC.loader
seal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(seal)
VERIFY_SPEC = importlib.util.spec_from_file_location("verify_candidate_manifest", Path(__file__).parents[1] / "verify_candidate_manifest.py")
assert VERIFY_SPEC and VERIFY_SPEC.loader
verify = importlib.util.module_from_spec(VERIFY_SPEC)
VERIFY_SPEC.loader.exec_module(verify)
sys.modules["verify_candidate_manifest"] = verify
FINALIZE_SPEC = importlib.util.spec_from_file_location(
    "finalize_candidate_approvals",
    Path(__file__).parents[1] / "finalize_candidate_approvals.py",
)
assert FINALIZE_SPEC and FINALIZE_SPEC.loader
finalize = importlib.util.module_from_spec(FINALIZE_SPEC)
FINALIZE_SPEC.loader.exec_module(finalize)

class SealCandidateTests(TestCase):
    def test_finalizer_requires_exact_pending_seal_receipt_binding(self) -> None:
        manifest_data = b'{"candidate":"frozen"}'
        manifest = {
            "review_payload_digest": "a" * 64,
            "images": [
                {"name": "api", "image": "registry.invalid/api@sha256:" + "b" * 64}
            ],
        }
        receipt = {
            "manifest_sha256": __import__("hashlib").sha256(manifest_data).hexdigest(),
            "review_status": "pending",
            "review_payload_digest": "a" * 64,
            "image_manifest_digests": {"api": "sha256:" + "b" * 64},
        }
        finalize.validate_pending_seal_receipt(receipt, manifest, manifest_data)
        receipt["review_status"] = "approved"
        with self.assertRaises(finalize.Refusal):
            finalize.validate_pending_seal_receipt(receipt, manifest, manifest_data)

    def test_distribution_digest_is_not_oci_config_digest(self) -> None:
        source = {"name": "jambonz-feature-server", "commit": "a" * 40, "repository": "https://github.com/example/project", "patch_content_sha256": "sha256:" + "b" * 64}
        inspected = [{"Os":"linux", "Architecture":"amd64", "Id":"sha256:" + "c" * 64, "Config":{"Labels":{"org.opencontainers.image.revision":"a" * 40, "org.opencontainers.image.source":"https://github.com/example/project", "org.opencontainers.image.licenses":"MIT", "org.recova.patch.sha256":"sha256:" + "b" * 64, "org.recova.base.digest":"base@sha256:" + "d" * 64}}}]
        with patch.object(seal, "run", return_value=MagicMock(stdout=json.dumps(inspected))):
            info, _ = seal.inspect("127.0.0.1:5000/example:tag", source)
        self.assertEqual(info["Id"], "sha256:" + "c" * 64)

        config_digest = "sha256:" + "c" * 64
        manifest_data = seal.canonical({
            "schemaVersion": 2,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": 2,
            },
            "layers": [],
        })
        manifest_digest = seal.digest(manifest_data)
        self.assertNotEqual(manifest_digest, config_digest)
        registry = seal.loopback_registry("http://127.0.0.1:5000")
        response = MagicMock()
        response.headers = {"Docker-Content-Digest": manifest_digest}
        response.read.return_value = manifest_data
        response.__enter__.return_value = response
        with patch.object(seal.urllib.request, "urlopen", return_value=response):
            self.assertEqual(
                seal.http_manifest(registry, "example", "tag"),
                (manifest_digest, config_digest),
            )
    def test_image_identity_accepts_manifest_or_config_digest_only(self) -> None:
        manifest = "sha256:" + "a" * 64
        config = "sha256:" + "b" * 64
        for inspected in (manifest, config):
            self.assertEqual(
                seal.validated_image_config_digest(
                    inspected,
                    manifest,
                    config,
                    config,
                ),
                config,
            )
        for values in (
            ("sha256:" + "c" * 64, manifest, config, config),
            (manifest, manifest, config, "sha256:" + "c" * 64),
        ):
            with self.assertRaises(seal.Refusal):
                seal.validated_image_config_digest(*values)

    def test_oci_archive_fixture_binds_config_descriptor_not_manifest_digest(self) -> None:
        tag = "example:fixture"
        config_data = b"{}"
        config_digest = seal.digest(config_data)
        manifest_data = seal.canonical({
            "schemaVersion": 2,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": len(config_data),
            },
            "layers": [],
        })
        manifest_digest = seal.digest(manifest_data)
        index_data = seal.canonical({
            "schemaVersion": 2,
            "manifests": [{
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": manifest_digest,
                "size": len(manifest_data),
                "annotations": {"org.opencontainers.image.ref.name": tag},
            }],
        })
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "fixture.tar"
            with tarfile.open(archive, "w") as bundle:
                for name, data in (
                    ("oci-layout", b'{"imageLayoutVersion":"1.0.0"}'),
                    ("index.json", index_data),
                    ("blobs/sha256/" + manifest_digest.removeprefix("sha256:"), manifest_data),
                    ("blobs/sha256/" + config_digest.removeprefix("sha256:"), config_data),
                ):
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    bundle.addfile(member, io.BytesIO(data))
            self.assertNotEqual(manifest_digest, config_digest)
            self.assertEqual(
                seal.archive_image_config_digest(archive, tag),
                config_digest,
            )
            containerd_index = json.loads(index_data)
            containerd_index["manifests"][0]["annotations"] = {
                "org.opencontainers.image.ref.name": "fixture",
                "io.containerd.image.name": tag,
            }
            containerd_data = seal.canonical(containerd_index)
            with tarfile.open(archive, "w") as bundle:
                for name, data in (
                    ("oci-layout", b'{"imageLayoutVersion":"1.0.0"}'),
                    ("index.json", containerd_data),
                    ("blobs/sha256/" + manifest_digest.removeprefix("sha256:"), manifest_data),
                    ("blobs/sha256/" + config_digest.removeprefix("sha256:"), config_data),
                ):
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    bundle.addfile(member, io.BytesIO(data))
            self.assertEqual(
                seal.archive_image_config_digest(archive, tag),
                config_digest,
            )
            containerd_index["manifests"][0]["annotations"][
                "io.containerd.image.name"
            ] = "other:fixture"
            containerd_data = seal.canonical(containerd_index)
            with tarfile.open(archive, "w") as bundle:
                for name, data in (
                    ("oci-layout", b'{"imageLayoutVersion":"1.0.0"}'),
                    ("index.json", containerd_data),
                    ("blobs/sha256/" + manifest_digest.removeprefix("sha256:"), manifest_data),
                    ("blobs/sha256/" + config_digest.removeprefix("sha256:"), config_data),
                ):
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    bundle.addfile(member, io.BytesIO(data))
            with self.assertRaises(seal.Refusal):
                seal.archive_image_config_digest(archive, tag)

    def test_repository_configuration_and_patch_evidence_is_hashed_and_indexed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            stage = root / "stage"
            repository.mkdir()
            (repository / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
            patches = repository / "patches"
            patches.mkdir()
            (patches / "public.patch").write_text("diff --git a/a b/a\n", encoding="utf-8")
            sources = {"public": {"patch": "patches/public.patch"}}
            with (
                patch.object(seal, "HERE", repository),
                patch.object(seal, "CANDIDATE_RUNTIME_FILES", ("compose.yaml",)),
            ):
                assertions = seal.repository_evidence(stage, sources)
                index = seal.build_evidence_index(stage)

            by_path = {entry["path"]: entry for entry in index.values()}
            expected = {
                "evidence/runtime-compose.yaml": b"services: {}\n",
                "evidence/source-patch-public.patch": b"diff --git a/a b/a\n",
            }
            self.assertEqual(set(by_path), set(expected))
            for path, data in expected.items():
                self.assertEqual(by_path[path]["sha256"], seal.sha(data))
                reference = "evidence:" + path
                self.assertIn(reference, index)
                self.assertIn(
                    seal.digest(data),
                    {record["sha256"] for record in assertions.values()},
                )

            (repository / "compose.yaml").unlink()
            (repository / "compose.yaml").symlink_to(repository / "missing")
            with (
                patch.object(seal, "HERE", repository),
                patch.object(seal, "CANDIDATE_RUNTIME_FILES", ("compose.yaml",)),
                self.assertRaises(seal.Refusal),
            ):
                seal.repository_evidence(root / "unsafe-stage", sources)
            (repository / "compose.yaml").unlink()
            (repository / "compose.yaml").write_bytes(b"\xff")
            with (
                patch.object(seal, "HERE", repository),
                patch.object(seal, "CANDIDATE_RUNTIME_FILES", ("compose.yaml",)),
                self.assertRaises(seal.Refusal),
            ):
                seal.repository_evidence(root / "non-utf8-stage", sources)

    def test_compose_local_config_closure_rejects_unfrozen_dependencies(self) -> None:
        compose = b"""services: {}
configs:
  frozen:
    file: ./frozen.conf
  generated:
    file: ${GENERATED_CONFIG_FILE:?required}
secrets:
  credential:
    file: ${CREDENTIAL_FILE:?required}
"""
        with (
            patch.object(seal, "CANDIDATE_RUNTIME_FILES", ("compose.yaml", "frozen.conf")),
            patch.object(seal, "RUNTIME_GENERATED_COMPOSE_CONFIGS", {"generated"}),
        ):
            self.assertEqual(
                seal.compose_local_config_dependencies(compose),
                {"frozen.conf"},
            )
            with self.assertRaises(seal.Refusal):
                seal.compose_local_config_dependencies(
                    compose.replace(b"./frozen.conf", b"./unindexed.conf")
                )
            with self.assertRaises(seal.Refusal):
                seal.compose_local_config_dependencies(
                    compose.replace(b"./frozen.conf", b"../frozen.conf")
                )
            with self.assertRaises(seal.Refusal):
                seal.compose_local_config_dependencies(
                    compose.replace(
                        b"  frozen:\n    file: ./frozen.conf",
                        b"  frozen: {file: ./frozen.conf}",
                    )
                )
            with self.assertRaises(seal.Refusal):
                seal.compose_local_config_dependencies(
                    compose.replace(b"${CREDENTIAL_FILE:?required}", b"./secret.txt")
                )
            with self.assertRaises(seal.Refusal):
                seal.compose_local_config_dependencies(
                    compose.replace(
                        b"${GENERATED_CONFIG_FILE:?required}",
                        b"${UNAPPROVED_CONFIG_FILE:?required}",
                    ).replace(b"  generated:", b"  unapproved:")
                )
            external = compose.replace(
                b"  frozen:\n    file: ./frozen.conf",
                b"  frozen:\n    file: ../../infra/trusted.json",
            )
            with patch.object(
                seal,
                "EXTERNAL_FROZEN_COMPOSE_CONFIGS",
                {"frozen": "../../infra/trusted.json"},
            ):
                self.assertEqual(
                    seal.compose_local_config_dependencies(external), set()
                )
                with self.assertRaises(seal.Refusal):
                    seal.compose_local_config_dependencies(
                        external.replace(b"../../infra/trusted.json", b"../../infra/other.json")
                    )

    def test_frozen_runtime_evidence_uses_canonical_sources_names_and_hashes(self) -> None:
        original_here = seal.HERE
        sources = {
            "run-g008-live-smoke.py": original_here / "run-g008-live-smoke.py",
            "compose.yaml": original_here / "compose.yaml",
            "sealed-secret-wrapper.sh": original_here / "sealed-secret-wrapper.sh",
            "../../infra/onnuri-seoul-staging-phase-c-smoke/startup-g008.sh": original_here.parents[1] / "infra/onnuri-seoul-staging-phase-c-smoke/startup-g008.sh",
            "../../infra/onnuri-seoul-staging-phase-c-smoke/trusted_keys/phase_c_live_preflight_v1.json": original_here.parents[1] / "infra/onnuri-seoul-staging-phase-c-smoke/trusted_keys/phase_c_live_preflight_v1.json",
        }
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            here = repository / "deploy/onnuri-jambonz-oss"
            here.mkdir(parents=True)
            for source, path in sources.items():
                target = here / source if not source.startswith("../") else repository / "/".join(PurePosixPath(source).parts[2:])
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(path.read_bytes())
            stage = repository / "stage"
            with patch.object(seal, "HERE", here):
                records = seal.frozen_runtime_evidence(stage)
            self.assertEqual(set(records), set(seal.FROZEN_RUNTIME_EVIDENCE))
            index = seal.build_evidence_index(stage)
            for record in records.values():
                indexed = index[record["reference"]]
                self.assertEqual("sha256:" + indexed["sha256"], record["sha256"])
            self.assertEqual(
                seal.FROZEN_RUNTIME_EVIDENCE[
                    "candidate_input_g008_live_smoke_runner"
                ]["sha256"], hashlib.sha256((original_here / "run-g008-live-smoke.py").read_bytes()).hexdigest())
            (here / "compose.yaml").write_bytes((here / "compose.yaml").read_bytes() + b"\n")
            with (
                patch.object(seal, "HERE", here),
                self.assertRaises(seal.Refusal),
            ):
                seal.frozen_runtime_evidence(repository / "tampered-stage")

    def test_phase_c_and_frozen_runtime_evidence_share_startup_artifact_idempotently(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage = root / "stage"
            with patch.object(seal, "PHASE_C_ROOT", seal.PHASE_C_ROOT):
                phase_c_records = seal.phase_c_evidence(stage)
            frozen_records = seal.frozen_runtime_evidence(stage)
            startup_record = seal.PHASE_C_EVIDENCE_PREFIX + "startup-g008.sh"
            self.assertEqual(
                phase_c_records[startup_record]["reference"],
                frozen_records["candidate_input_bootstrap_binding"]["reference"],
            )
            self.assertEqual(
                phase_c_records[startup_record]["sha256"],
                frozen_records["candidate_input_bootstrap_binding"]["sha256"],
            )

    def test_conformance_receipt_binds_phase_c_inputs_and_indexed_raw_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_lock = root / "source-lock.json"
            source_lock.write_bytes(b'{"sources":[]}\n')
            config = root / "compose.yaml"
            config.write_bytes(b"services: {}\n")
            phase_c = root / "phase-c"
            phase_c.mkdir()
            files = {"compose.yaml": config}
            for name in seal.PHASE_C_RUNTIME_FILES:
                path = phase_c / name
                path.write_text(name + "\n", encoding="utf-8")
                files[f"phase-c/{name}"] = path
            checks = {}
            for name, command in seal.CONFORMANCE_CHECKS.items():
                output = root / f"{name}.raw"
                output.write_text(seal.conformance_command_identity(command) + "\npassed\n", encoding="utf-8")
                checks[name] = {
                    "command": command,
                    "command_identity": seal.conformance_command_identity(command),
                    "exit_code": 0,
                    "result": "pass",
                    "output_path": output.name,
                    "output_sha256": seal.sha(output.read_bytes()),
                }
            signer = Ed25519PrivateKey.generate()
            receipt = {
                "schema_version": "onnuri-jambonz-oss-conformance/v2",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "source_lock_sha256": seal.sha(source_lock.read_bytes()),
                "config_sha256": {name: seal.sha(path.read_bytes()) for name, path in files.items()},
                "checks": checks,
                "signer_identity": seal.CONFORMANCE_SIGNER_IDENTITY,
            }
            receipt["signature"] = {
                "algorithm": "Ed25519",
                "key_id": seal.CONFORMANCE_SIGNER_KEY_ID,
                "value_b64": base64.b64encode(signer.sign(seal.conformance_signature_payload(receipt))).decode(),
            }
            receipt_path = root / "conformance.json"
            receipt_data = seal.canonical(receipt)
            receipt_path.write_bytes(receipt_data)
            with patch.object(seal, "HERE", root), patch.object(seal, "CANDIDATE_RUNTIME_FILES", ("compose.yaml",)), patch.object(seal, "PHASE_C_ROOT", phase_c), patch.object(seal, "trusted_conformance_key", return_value=signer.public_key()):
                self.assertEqual(seal.conformance_receipt(receipt_path, source_lock), receipt_data)
                (phase_c / "startup-g008.sh").write_text("changed\n", encoding="utf-8")
                with self.assertRaises(seal.Refusal):
                    seal.conformance_receipt(receipt_path, source_lock)
                (phase_c / "startup-g008.sh").write_text("startup-g008.sh\n", encoding="utf-8")
                output = root / "offline_default_deny.raw"
                output.write_text("tampered\n", encoding="utf-8")
                with self.assertRaises(seal.Refusal):
                    seal.conformance_receipt(receipt_path, source_lock)
                output.write_text(seal.conformance_command_identity(seal.CONFORMANCE_CHECKS["offline_default_deny"]) + "\npassed\n", encoding="utf-8")
                receipt["signer_identity"] = "self-asserted"
                receipt["signature"]["value_b64"] = base64.b64encode(signer.sign(seal.conformance_signature_payload(receipt))).decode()
                receipt_path.write_bytes(seal.canonical(receipt))
                with self.assertRaises(seal.Refusal):
                    seal.conformance_receipt(receipt_path, source_lock)

    def test_phase_c_evidence_freezes_launcher_and_terraform(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            phase_c = root / "phase-c"
            phase_c.mkdir()
            for name in seal.PHASE_C_RUNTIME_FILES:
                source = seal.PHASE_C_ROOT / name
                target = phase_c / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source.read_bytes())
            with patch.object(seal, "PHASE_C_ROOT", phase_c):
                records = seal.phase_c_evidence(root / "stage")
            expected_references = {
                name: "evidence:evidence/phase-c-" + name.replace("/", "-")
                for name in seal.PHASE_C_RUNTIME_FILES
            }
            self.assertEqual(
                {
                    name.removeprefix(seal.PHASE_C_EVIDENCE_PREFIX): record["reference"]
                    for name, record in records.items()
                },
                expected_references,
            )
            self.assertEqual(set(records), {
                seal.PHASE_C_EVIDENCE_PREFIX + name.replace("/", "-")
                for name in seal.PHASE_C_RUNTIME_FILES
            })
            launcher = phase_c / "startup-g008.sh"
            launcher.write_text("tampered\n", encoding="utf-8")
            with (
                patch.object(seal, "PHASE_C_ROOT", phase_c),
                self.assertRaises(seal.Refusal),
            ):
                seal.phase_c_evidence(root / "changed")
            launcher.write_bytes((seal.PHASE_C_ROOT / "startup-g008.sh").read_bytes())
            (phase_c / "containment.tf").write_text("jambonz-mini\n", encoding="utf-8")
            with (
                patch.object(seal, "PHASE_C_ROOT", phase_c),
                self.assertRaises(seal.Refusal),
            ):
                seal.phase_c_evidence(root / "forbidden-iac")

    def test_backend_reachability_receipt_rejects_invalid_or_wrong_image_proof(self) -> None:
        image = "registry.invalid/backend@sha256:" + "a" * 64
        receipt = {
            "vulnerability_id": "CVE-2026-5450",
            "bytes_scanned": 4096,
            "files_scanned": 3,
            "image_manifest_digest": "sha256:" + "a" * 64,
            "matches": [],
            "passed": True,
            "patterns": [{
                "id": "scanf-malloc-character-explicit-width",
                "syntax": "%[argument$][*]['I]*<width>m[cCsS[]",
                "minimum_offending_width": 1025,
            }],
            "scan_complete": True,
            "scanner_source_sha256": "sha256:" + "b" * 64,
            "schema_version": "recova.backend-glibc-reachability/v1",
            "source_type": "oci-archive",
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "receipt.json"
            encoded = seal.canonical(receipt)
            path.write_bytes(encoded)
            self.assertEqual(
                seal.backend_reachability_receipt(path, image),
                encoded,
            )
            malformed = b"{"
            nonzero = {**receipt, "matches": [{"path": "app"}], "passed": False}
            wrong_image = {
                **receipt,
                "image_manifest_digest": "sha256:" + "c" * 64,
            }
            mismatch = {**receipt, "scanner_source_sha256": "b" * 64}
            for mutation in (
                malformed,
                seal.canonical(nonzero),
                seal.canonical(wrong_image),
                seal.canonical(mismatch),
            ):
                with self.subTest(mutation=mutation):
                    path.write_bytes(mutation)
                    with self.assertRaises(seal.Refusal):
                        seal.backend_reachability_receipt(path, image)

    def test_wrong_arch_or_label_refuses(self) -> None:
        source = {"name": "jambonz-feature-server", "commit": "a" * 40, "repository": "https://github.com/example/project", "patch_content_sha256": "sha256:" + "b" * 64}
        bad = [{"Os":"linux", "Architecture":"arm64", "Config":{"Labels":{}}}]
        with patch.object(seal, "run", return_value=MagicMock(stdout=json.dumps(bad))):
            with self.assertRaises(seal.Refusal): seal.inspect("tag", source)

    def test_runtime_oci_license_labels_are_exact_unique_and_source_matched(self) -> None:
        source = {
            "name": "freeswitch",
            "commit": "a" * 40,
            "repository": "https://github.com/example/project",
            "patch_content_sha256": "sha256:" + "b" * 64,
        }
        labels = {
            "org.opencontainers.image.revision": source["commit"],
            "org.opencontainers.image.source": source["repository"],
            "org.opencontainers.image.licenses": seal.RUNTIME_LICENSES["freeswitch"],
            "org.recova.patch.sha256": source["patch_content_sha256"],
            "org.recova.base.digest": "base@sha256:" + "d" * 64,
        }
        inspected = [{"Os":"linux","Architecture":"amd64","Id":"sha256:" + "c" * 64,"Config":{"Labels":labels}}]
        with patch.object(seal, "run", return_value=MagicMock(stdout=json.dumps(inspected))):
            seal.inspect("tag", source)
        for bad_license in (None, "", "MIT", "MPL-1.1 AND MIT"):
            mutated = json.loads(json.dumps(inspected))
            if bad_license is None:
                del mutated[0]["Config"]["Labels"]["org.opencontainers.image.licenses"]
            else:
                mutated[0]["Config"]["Labels"]["org.opencontainers.image.licenses"] = bad_license
            with (
                self.subTest(license=bad_license),
                patch.object(seal, "run", return_value=MagicMock(stdout=json.dumps(mutated))),
                self.assertRaises(seal.Refusal),
            ):
                seal.inspect("tag", source)
        with (
            patch.object(seal, "run", return_value=MagicMock(stdout=json.dumps(inspected))),
            self.assertRaises(seal.Refusal),
        ):
            seal.inspect("tag", {**source, "name": "rtpengine"})
        duplicate = json.dumps(inspected).replace(
            '"org.opencontainers.image.licenses":',
            '"org.opencontainers.image.licenses":"MIT","org.opencontainers.image.licenses":',
            1,
        )
        with (
            patch.object(seal, "run", return_value=MagicMock(stdout=duplicate)),
            self.assertRaises(seal.Refusal),
        ):
            seal.inspect("tag", source)

    def test_patch_evidence_binds_actual_patch_bytes_not_its_wrapper_digest(self) -> None:
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            patch_path = "patches/drachtio-server.patch"
            patch_file = root / patch_path
            patch_file.parent.mkdir(parents=True)
            patch_file.write_bytes(b"")
            evidence = json.dumps({
                "name": "drachtio-server",
                "commit": "a" * 40,
                "patch_path": patch_path,
                "patch_sha256": "sha256:" + seal.sha(b""),
            }).encode()
            with patch.object(seal, "HERE", root):
                self.assertEqual(
                    seal.patch_content_digest(evidence, "drachtio-server", "a" * 40, patch_path),
                    "sha256:" + seal.sha(b""),
                )
                for mutation in (
                    evidence.replace(b"drachtio-server", b"other-server"),
                    evidence.replace(b'"patch_sha256": "sha256:', b'"patch_sha256": "sha256:0'),
                ):
                    with self.subTest(mutation=mutation), self.assertRaises(seal.Refusal):
                        seal.patch_content_digest(mutation, "drachtio-server", "a" * 40, patch_path)
    def test_forbidden_contract_and_nonloopback_registry_refuse(self) -> None:
        with self.assertRaises(seal.Refusal): seal.clean_text(b"requires a paid entitlement", "contract")
        with self.assertRaises(seal.Refusal): seal.loopback_registry("https://registry.example.com")
        with self.assertRaises(seal.Refusal): seal.loopback_registry("http://user:token@127.0.0.1:5000")
    def test_explicit_negative_policy_claims_are_allowed_but_affirmative_use_refuses(self) -> None:
        seal.clean_text(
            b"commercial_image_used=false\nruntime_license_key_required=false\n"
            b"activation_service_required=false\ntrial_or_paid_entitlement_used=false\n"
            b"circumvention_used=false\n",
            "reviewed contract",
        )
        with self.assertRaises(seal.Refusal):
            seal.clean_text(b"activation service is used", "reviewed contract")

    def test_local_input_is_retagged_to_the_supplied_loopback_registry(self) -> None:
        registry = seal.loopback_registry("http://127.0.0.1:5000")
        tag, repository, image_tag = seal.loopback_image_tag(
            registry, "freeswitch", "a" * 40
        )
        self.assertEqual(tag, "127.0.0.1:5000/onnuri-jambonz-oss/freeswitch:" + "a" * 40)
        self.assertEqual(repository, "onnuri-jambonz-oss/freeswitch")
        self.assertEqual(image_tag, "a" * 40)
    def test_unqualified_immutable_base_label_is_redacted_without_network_identity(self) -> None:
        self.assertEqual(
            seal.redact_image_reference("debian:12-slim@sha256:" + "a" * 64),
            "local-registry/debian:12-slim@sha256:" + "a" * 64,
        )
    def test_freeswitch_dependencies_are_source_only_and_contributed(self) -> None:
        self.assertEqual(len(seal.REQUIRED_SOURCES), 13)
        self.assertEqual(len(seal.RUNTIME_IMAGES), 10)
        self.assertNotIn("jambonz-freeswitch-modules", seal.RUNTIME_IMAGES)
        self.assertNotIn("spandsp", seal.RUNTIME_IMAGES)
        self.assertNotIn("sofia-sip", seal.RUNTIME_IMAGES)
        sources = {
            "jambonz-freeswitch-modules": {
                "commit": "30f21899869fe445776078ddbc3e70dcb0ae6309",
                "license_reference": "evidence:evidence/cyrenity-license.json",
                "license_sha256": "sha256:" + "a" * 64,
            },
            "spandsp": {
                "commit": "e29ef78944d905b935d1306fa622e2eb2dc8ad75",
                "license_reference": "evidence:evidence/spandsp-license.json",
                "license_sha256": "sha256:" + "b" * 64,
            },
            "sofia-sip": {
                "commit": "6198851a610b7889c17e2d98fb84617bc1dd7aec",
                "license_reference": "evidence:evidence/sofia-license.json",
                "license_sha256": "sha256:" + "c" * 64,
            },
        }
        self.assertEqual(
            seal.freeswitch_contributions(sources),
            [
                {"source_name": "jambonz-freeswitch-modules", "source_commit": sources["jambonz-freeswitch-modules"]["commit"], "contribution": "mod_audio_fork", "license_mode": "MIT", "reference": sources["jambonz-freeswitch-modules"]["license_reference"], "sha256": sources["jambonz-freeswitch-modules"]["license_sha256"]},
                {"source_name": "spandsp", "source_commit": sources["spandsp"]["commit"], "contribution": "spandsp runtime library", "license_mode": "LGPL-2.1-only AND GPL-2.0-only", "reference": sources["spandsp"]["license_reference"], "sha256": sources["spandsp"]["license_sha256"]},
                {"source_name": "sofia-sip", "source_commit": sources["sofia-sip"]["commit"], "contribution": "Sofia-SIP runtime library", "license_mode": "LGPL-2.1-only", "reference": sources["sofia-sip"]["license_reference"], "sha256": sources["sofia-sip"]["license_sha256"]},
            ],
        )

    def test_runtime_images_have_exact_dedicated_build_recipe_mapping(self) -> None:
        self.assertEqual(set(seal.BUILD_RECIPES), seal.RUNTIME_IMAGES)
        self.assertEqual(seal.BUILD_RECIPES["drachtio-server"], "Dockerfile.drachtio")
        self.assertEqual(seal.BUILD_RECIPES["freeswitch"], "Dockerfile.freeswitch")
        self.assertEqual(seal.BUILD_RECIPES["rtpengine"], "Dockerfile.rtpengine")
        for name in seal.RUNTIME_IMAGES - {"drachtio-server", "freeswitch", "rtpengine"}:
            self.assertEqual(seal.BUILD_RECIPES[name], "Dockerfile.node-app")

    def test_build_recipe_must_be_a_non_symlink_regular_file(self) -> None:
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            recipe = root / "Dockerfile.node-app"
            recipe.write_text("FROM scratch\n")
            self.assertEqual(seal.regular(recipe, "build recipe"), recipe)
            recipe.unlink()
            recipe.symlink_to(root / "missing")
            with self.assertRaises(seal.Refusal):
                seal.regular(recipe, "build recipe")
    def test_grype_receives_the_actual_saved_sbom_path(self) -> None:
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as temporary:
            sbom_path = Path(temporary) / "evidence" / "image-sbom.json"
            calls: list[list[str]] = []

            def fake_run(argv: list[str], **_: object) -> MagicMock:
                calls.append(argv)
                if argv[0] == "syft":
                    Path(argv[-1].removeprefix("json=")).write_bytes(b'{"artifacts":[]}')
                    return MagicMock(stdout=b"ignored")
                return MagicMock(stdout=b'{"matches":[]}')

            with patch.object(seal, "run", side_effect=fake_run):
                sbom, vulnerability = seal.scan_image("unqualified-local-tag", sbom_path)
            self.assertEqual(sbom, b'{"artifacts":[]}')
            self.assertEqual(vulnerability, b'{"matches":[]}')
            self.assertEqual(calls[0], ["syft", "unqualified-local-tag", "-o", f"json={sbom_path}"])
            self.assertEqual(calls[1], ["grype", f"sbom:{sbom_path}", "-o", "json"])

    def test_critical_requires_structured_current_acceptance(self) -> None:
        finding = {"vulnerability":{"id":"CVE-1", "severity":"Critical"}, "artifact":{"name":"package", "version":"1.0", "type":"deb"}}
        with self.assertRaises(seal.Refusal): seal.vulnerabilities("freeswitch", json.dumps({"matches":[finding]}).encode(), {})

    def test_distinct_artifacts_with_one_cve_are_independently_accepted(self) -> None:
        first = {"vulnerability":{"id":"CVE-1", "severity":"Critical"}, "artifact":{"name":"package-a", "version":"1.0", "type":"deb"}}
        second = {"vulnerability":{"id":"CVE-1", "severity":"High"}, "artifact":{"name":"package-b", "version":"2.0", "type":"rpm"}}
        acceptances = {
            seal.finding_acceptance_key("freeswitch", first): self.acceptance(first),
            seal.finding_acceptance_key("freeswitch", second): self.acceptance(second),
        }
        self.assertEqual(seal.vulnerabilities("freeswitch", json.dumps({"matches":[first, second]}).encode(), acceptances), (1, 1))

    def test_acquisition_expiry_uses_earliest_used_acceptance_or_seven_days(self) -> None:
        now = datetime.now(timezone.utc)
        early = now + timedelta(days=2)
        late = now + timedelta(days=5)
        acceptances = {
            "early": {
                "reason": "reviewed",
                "expires_at": early.isoformat(),
                "finding_sha256": "a" * 64,
            },
            "late": {
                "reason": "reviewed",
                "expires_at": late.isoformat(),
                "finding_sha256": "b" * 64,
            },
            "unused": {
                "reason": "reviewed",
                "expires_at": (now + timedelta(hours=1)).isoformat(),
                "finding_sha256": "c" * 64,
            },
        }
        self.assertEqual(
            seal.acceptance_expiry(now, acceptances, {"early", "late"}),
            early,
        )
        self.assertEqual(seal.acceptance_expiry(now, {}, set()), now + timedelta(days=7))

    def test_acceptance_cannot_cross_image_boundaries(self) -> None:
        finding = {"vulnerability":{"id":"CVE-1", "severity":"Critical"}, "artifact":{"name":"package", "version":"1.0", "type":"deb"}}
        acceptances = {seal.finding_acceptance_key("freeswitch", finding): self.acceptance(finding)}
        with self.assertRaises(seal.Refusal):
            seal.vulnerabilities("drachtio-server", json.dumps({"matches":[finding]}).encode(), acceptances)

    def test_missing_expired_and_hash_mismatched_acceptances_refuse(self) -> None:
        finding = {"vulnerability":{"id":"CVE-1", "severity":"High"}, "artifact":{"name":"package", "version":"1.0", "type":"deb"}}
        key = seal.finding_acceptance_key("freeswitch", finding)
        cases = (
            {},
            {key: {**self.acceptance(finding), "expires_at":"2000-01-01T00:00:00Z"}},
            {key: {**self.acceptance(finding), "finding_sha256":"0" * 64}},
        )
        for acceptances in cases:
            with self.subTest(acceptances=acceptances), self.assertRaises(seal.Refusal):
                seal.vulnerabilities("freeswitch", json.dumps({"matches":[finding]}).encode(), acceptances)

    def test_acceptance_digest_ignores_nondeterministic_grype_metadata(self) -> None:
        finding = {"vulnerability":{"id":"CVE-1", "severity":"High", "fix":{"state":"fixed", "versions":["2.0", "1.5"]}}, "artifact":{"name":"package", "version":"1.0", "type":"deb"}, "matchDetails":[{"searchedBy":"distro"}]}
        changed = {**finding, "matchDetails":[{"searchedBy":"cpe"}], "relatedVulnerabilities":[{"id":"GHSA-1"}]}
        self.assertEqual(seal.finding_acceptance_digest(finding), seal.finding_acceptance_digest(changed))
        self.assertEqual(seal.vulnerabilities("freeswitch", json.dumps({"matches":[changed]}).encode(), {seal.finding_acceptance_key("freeswitch", finding): self.acceptance(finding)}), (0, 1))

    def test_zero_critical_and_high_findings_are_valid(self) -> None:
        finding = {"vulnerability":{"id":"CVE-1", "severity":"Medium"}, "artifact":{"name":"package", "version":"1.0", "type":"deb"}}
        self.assertEqual(seal.vulnerabilities("freeswitch", json.dumps({"matches":[finding]}).encode(), {}), (0, 0))
    def test_unused_or_missing_severe_acceptance_refuses_exact_coverage(self) -> None:
        with self.assertRaises(seal.Refusal):
            seal.require_exact_acceptance_coverage({"unused": {}}, set())
        with self.assertRaises(seal.Refusal):
            seal.require_exact_acceptance_coverage({}, {"missing"})
        seal.require_exact_acceptance_coverage({"used": {}}, {"used"})

    def test_legacy_vulnerability_id_acceptance_keys_refuse(self) -> None:
        with self.assertRaises(seal.Refusal):
            seal.validate_acceptance_key("CVE-1")

    @staticmethod
    def acceptance(finding: dict[str, object]) -> dict[str, str]:
        return {"reason":"reviewed exception", "expires_at":"2999-01-01T00:00:00Z", "finding_sha256":seal.finding_acceptance_digest(finding)}

    def test_evidence_is_hashed_read_only_and_idempotent_for_identical_bytes(self) -> None:
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            reference, value = seal.copy_evidence(root, "receipt.json", b"{}")
            target = root / "evidence" / "receipt.json"
            self.assertEqual(reference, "evidence:evidence/receipt.json")
            self.assertEqual(value, "sha256:" + seal.sha(b"{}"))
            self.assertEqual(
                seal.copy_evidence(root, "receipt.json", b"{}"),
                (reference, value),
            )
            with self.assertRaises(seal.Refusal):
                seal.copy_evidence(root, "receipt.json", b'{"different":true}')
            self.assertFalse(stat.S_IMODE(target.stat().st_mode) & stat.S_IWUSR)

    def test_command_execution_uses_argv_not_shell(self) -> None:
        completed = subprocess.CompletedProcess(["syft"], 0, b"{}", b"")
        with patch.object(seal.subprocess, "run", return_value=completed) as mocked:
            seal.run(["syft", "image", "-o", "json"])
        self.assertEqual(mocked.call_args.args[0], ["syft", "image", "-o", "json"])
        self.assertNotIn("shell", mocked.call_args.kwargs)
    def test_patch_digest_requires_one_canonical_oci_label_representation(self) -> None:
        valid = "sha256:" + "a" * 64
        self.assertEqual(seal.canonical_patch_digest(valid), valid)
        for invalid in ("a" * 64, "SHA256:" + "a" * 64, "sha256:" + "A" * 64):
            with self.subTest(invalid=invalid), self.assertRaises(seal.Refusal):
                seal.canonical_patch_digest(invalid)

    def test_support_image_attestation_requires_immutable_linux_amd64_image(self) -> None:
        image = "registry.invalid/mariadb@sha256:" + "a" * 64
        inspected = [{"Os":"linux", "Architecture":"amd64", "Config":{"Labels":{"org.opencontainers.image.source":"https://example.invalid","org.opencontainers.image.licenses":"MIT","org.recova.base.digest":"base@sha256:" + "b" * 64}}}]
        with patch.object(seal, "run", return_value=MagicMock(stdout=json.dumps(inspected))):
            _, labels = seal.inspect_support_image(image)
        self.assertEqual(labels["org.opencontainers.image.licenses"], "MIT")
        with self.assertRaises(seal.Refusal):
            seal.inspect_support_image("registry.invalid/mariadb:latest")

    def test_scanner_metadata_binds_canonical_database_identity(self) -> None:
        from tempfile import TemporaryDirectory
        responses = {
            ("syft", "version", "-o", "json"): b'{"version":"1.2.3"}',
            ("grype", "version", "-o", "json"): b'{"version":"4.5.6"}',
            ("grype", "db", "status", "-o", "json"): b'{"schemaVersion":"v6.1.8","from":"https://example.invalid/db?checksum=sha256%3Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","built":"2026-07-16T00:00:00Z","valid":true}',
        }

        def fake_run(argv: list[str], **_: object) -> MagicMock:
            return MagicMock(stdout=responses[tuple(argv)])

        with TemporaryDirectory() as temporary, patch.object(seal, "run", side_effect=fake_run):
            metadata, database_identity = seal.scanner_metadata(Path(temporary))
            database = seal.canonical(database_identity)
            self.assertEqual(metadata["syft_version"], "1.2.3")
            self.assertEqual(metadata["grype_version"], "4.5.6")
            self.assertEqual(metadata["grype_db_identity_sha256"], seal.digest(database))
            self.assertEqual(database_identity["checksum"], "sha256:" + "a" * 64)
            self.assertEqual(
                (
                    Path(temporary)
                    / "evidence"
                    / "scanner-grype-db-identity.json"
                ).read_bytes(),
                database,
            )
    def test_mocked_seal_round_trip_rejects_tampered_security_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence_dir = root / "source-evidence"
            evidence_dir.mkdir()
            lock_sources, receipt_sources = [], []
            for name in sorted(seal.REQUIRED_SOURCES):
                commit = verify.FREESWITCH_CONTRIBUTIONS.get(name, ("a" * 40,))[0]
                license_spdx = verify.REQUIRED_LICENSES[name]
                refs = {}
                for category in ("tree", "submodules", "license", "patch"):
                    if category == "patch":
                        content = seal.canonical(
                            {
                                "name": name,
                                "commit": commit,
                                "patch_path": f"patches/{name}.patch",
                                "patch_sha256": "sha256:" + "b" * 64,
                            }
                        )
                    elif category == "tree":
                        content = seal.canonical(
                            {
                                "name": name,
                                "repository": "https://github.com/example/" + name,
                                "commit": commit,
                                "archive_sha256": "a" * 64,
                            }
                        )
                    else:
                        content = seal.canonical({"name": name, "category": category})
                    filename = f"{name}-{category}.json"
                    (evidence_dir / filename).write_bytes(content)
                    refs[category] = {"path": f"source-evidence/{filename}", "sha256": seal.sha(content)}
                lock_sources.append({"name": name, "repository": "https://github.com/example/" + name, "commit": commit, "license_spdx": license_spdx, "patch": f"patches/{name}.patch"})
                receipt_sources.append({"name": name, "repository": "https://github.com/example/" + name, "commit": commit, "submodules": [], "references": refs})
            lock_path = root / "source-lock.json"
            lock_path.write_bytes(seal.canonical({"sources": lock_sources}))
            receipt_path = root / "source-receipt.json"
            receipt_without_digest = {
                "schema_version": "recova-jambonz-oss-source-evidence/v1",
                "source_lock_sha256": seal.sha(lock_path.read_bytes()),
                "sources": receipt_sources,
            }
            receipt_path.write_bytes(
                seal.canonical(
                    {
                        **receipt_without_digest,
                        "receipt_sha256": seal.sha(seal.canonical(receipt_without_digest)),
                    }
                )
            )
            contracts = {}
            for name in ("license", "topology", "runtime"):
                path = root / f"{name}.txt"
                path.write_text(f"{name} reviewed evidence\n")
                contracts[name] = f"{name}={path}"
            conformance_path = root / "conformance-receipt.json"
            conformance_outputs = {}
            for name, command in seal.CONFORMANCE_CHECKS.items():
                output = root / f"{name}.raw"
                output.write_text(
                    seal.conformance_command_identity(command) + "\npassed\n",
                    encoding="utf-8",
                )
                conformance_outputs[name] = {
                    "command": command,
                    "command_identity": seal.conformance_command_identity(command),
                    "exit_code": 0,
                    "result": "pass",
                    "output_path": output.name,
                    "output_sha256": seal.sha(output.read_bytes()),
                }
            conformance_signer = Ed25519PrivateKey.generate()
            conformance_receipt = {
                "schema_version": "onnuri-jambonz-oss-conformance/v2",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "source_lock_sha256": seal.sha(lock_path.read_bytes()),
                "config_sha256": {
                    **{
                        relative_path: seal.sha((Path(seal.HERE) / relative_path).read_bytes())
                        for relative_path in seal.CANDIDATE_RUNTIME_FILES
                    },
                    **{
                        f"phase-c/{relative_path}": seal.sha(
                            (seal.PHASE_C_ROOT / relative_path).read_bytes()
                        )
                        for relative_path in seal.PHASE_C_RUNTIME_FILES
                    },
                },
                "checks": conformance_outputs,
                "signer_identity": seal.CONFORMANCE_SIGNER_IDENTITY,
            }
            conformance_receipt["signature"] = {
                "algorithm": "Ed25519",
                "key_id": seal.CONFORMANCE_SIGNER_KEY_ID,
                "value_b64": base64.b64encode(
                    conformance_signer.sign(
                        seal.conformance_signature_payload(conformance_receipt)
                    )
                ).decode(),
            }
            conformance_path.write_bytes(seal.canonical(conformance_receipt))
            backend_reachability_path = root / "backend-reachability.json"
            backend_reachability_path.write_bytes(
                seal.canonical(
                    {
                        "vulnerability_id": "CVE-2026-5450",
                        "bytes_scanned": 4096,
                        "files_scanned": 3,
                        "image_manifest_digest": "sha256:" + "c" * 64,
                        "matches": [],
                        "passed": True,
                        "patterns": [{
                            "id": "scanf-malloc-character-explicit-width",
                            "syntax": "%[argument$][*]['I]*<width>m[cCsS[]",
                            "minimum_offending_width": 1025,
                        }],
                        "scan_complete": True,
                        "scanner_source_sha256": "sha256:" + "b" * 64,
                        "schema_version": "recova.backend-glibc-reachability/v1",
                        "source_type": "oci-archive",
                    }
                )
            )
            args = argparse.Namespace(
                registry="http://127.0.0.1:5000",
                source_receipt=receipt_path,
                source_lock=lock_path,
                image=[f"{name}=local/{name}:test" for name in sorted(seal.RUNTIME_IMAGES)],
                support_image=[f"{name}=registry.invalid/{name}@sha256:" + "c" * 64 for name in sorted(seal.SUPPORT_IMAGES)],
                contract=list(contracts.values()),
                acceptances=None,
                conformance_receipt=conformance_path,
                backend_reachability_receipt=backend_reachability_path,
                output=root / "bundle",
            )

            def fake_scan(_image: str, sbom_path: Path) -> tuple[bytes, bytes]:
                sbom, vulnerability = b'{"artifacts":[]}', b'{"matches":[]}'
                sbom_path.parent.mkdir(parents=True, exist_ok=True)
                sbom_path.write_bytes(sbom)
                return sbom, vulnerability

            def fake_run(argv: list[str], **_: object) -> MagicMock:
                if argv[:2] == ["docker", "save"]:
                    Path(argv[argv.index("--output") + 1]).write_bytes(b"archive")
                return MagicMock(stdout=b"")

            database_raw = b'{"built":"2026-07-16T00:00:00Z","checksum":"abc"}'
            database = {"built": "2026-07-16T00:00:00Z", "checksum": "abc"}

            def fake_scanner(stage: Path) -> tuple[dict[str, object], dict[str, str]]:
                reference, value = seal.copy_evidence(stage, "scanner-grype-db-status.json", database_raw)
                return {
                    "syft_version": "1.2.3",
                    "grype_version": "4.5.6",
                    "grype_db_identity_reference": reference,
                    "grype_db_identity_sha256": value,
                }, database

            def fake_inspect(
                _tag: str, source: dict[str, object]
            ) -> tuple[dict[str, object], str]:
                return {
                    "Id": "sha256:" + "9" * 64,
                    "Config": {
                        "Labels": {
                            "org.opencontainers.image.licenses": seal.RUNTIME_LICENSES[
                                str(source["name"])
                            ]
                        }
                    },
                }, "base@sha256:" + "d" * 64
            def fake_support_inspect(
                image: str,
                expected_name: str,
            ) -> tuple[dict[str, object], dict[str, str]]:
                name = image.rsplit("/", 1)[-1].split("@", 1)[0]
                self.assertEqual(name, expected_name)
                labels = {
                    "org.recova.base.digest": "base@sha256:" + "d" * 64,
                    "org.opencontainers.image.licenses": verify.SUPPORT_OCI_LICENSES[
                        name
                    ],
                    "org.opencontainers.image.source": (
                        seal.FIRST_PARTY_SUPPORT_SOURCE
                        if name in {"facade", "recova-backend"}
                        else f"https://github.com/example/{name}"
                    ),
                }
                if name == "facade":
                    labels[seal.SOURCE_REVISION_LABEL] = "a" * 64
                elif name == "recova-backend":
                    labels[seal.SOURCE_REVISION_LABEL] = "a" * 64
                else:
                    labels[seal.SOURCE_REVISION_LABEL] = "a" * 40
                return {}, labels
            with (
                patch.object(seal, "run", side_effect=fake_run),
                patch.object(seal, "inspect", side_effect=fake_inspect),
                patch.object(
                    seal,
                    "inspect_support_image",
                    side_effect=fake_support_inspect,
                ),
                patch.object(seal, "scan_image", side_effect=fake_scan),
                patch.object(seal, "scanner_metadata", side_effect=fake_scanner),
                patch.object(seal, "http_manifest", return_value=("sha256:" + "e" * 64, "sha256:" + "9" * 64)),
                patch.object(seal, "patch_content_digest", return_value="sha256:" + "b" * 64),
                patch.object(seal, "archive_image_config_digest", return_value="sha256:" + "9" * 64),
                patch.object(seal, "repository_evidence", return_value={}),
                patch.object(
                    seal,
                    "trusted_conformance_key",
                    return_value=conformance_signer.public_key(),
                ),
            ):
                seal.seal(args)
            pending_manifest = json.loads(
                (args.output / "candidate-manifest.json").read_text()
            )
            self.assertEqual(
                {item["decision"] for item in pending_manifest["approvals"].values()},
                {"pending"},
            )
            backend_result = pending_manifest["disqualifier_results"][
                "candidate_input_backend_reachability"
            ]
            self.assertEqual(backend_result["result"], "pass")
            self.assertEqual(
                pending_manifest["evidence_index"][backend_result["reference"]]["sha256"],
                backend_result["sha256"].removeprefix("sha256:"),
            )
            self.assertEqual(
                pending_manifest["review_payload_digest"],
                verify.review_payload_digest(pending_manifest),
            )
            self.assertIn(
                "candidate_input_conformance",
                pending_manifest["disqualifier_results"],
            )
            self.assertIn("receipt_signing", pending_manifest["runtime_contract"])
            self.assertIn(
                "operations",
                pending_manifest["runtime_contract"]["registration"],
            )
            self.assertEqual(
                {item["name"] for item in pending_manifest["support_images"]},
                seal.SUPPORT_IMAGES,
            )
            for support_record in pending_manifest["support_images"]:
                self.assertIn("network_archive_reference", support_record)
                self.assertIn("oci_license_reference", support_record)
            for image_record in pending_manifest["images"]:
                expected_license = seal.RUNTIME_LICENSES[image_record["name"]]
                provenance_path = (
                    args.output
                    / pending_manifest["evidence_index"][
                        image_record["build_provenance_reference"]
                    ]["path"]
                )
                notices_path = (
                    args.output
                    / pending_manifest["evidence_index"][
                        image_record["notices_reference"]
                    ]["path"]
                )
                self.assertEqual(
                    json.loads(provenance_path.read_text())["runtime_oci_license"],
                    expected_license,
                )
                self.assertEqual(
                    json.loads(notices_path.read_text())["runtime_oci_license"],
                    expected_license,
                )

            approval_paths = {}
            now = datetime.now(timezone.utc).isoformat()
            for role in ("architect", "critic", "qa"):
                approval_path = root / f"approval-{role}.json"
                approval_path.write_bytes(
                    seal.canonical(
                        {
                            "schema_version": "onnuri-jambonz-oss-approval/v1",
                            "role": role,
                            "identity": f"independent-{role}",
                            "independent": True,
                            "decision": "approved",
                            "review_payload_digest": pending_manifest[
                                "review_payload_digest"
                            ],
                            "source_lock_sha256": pending_manifest[
                                "source_lock_sha256"
                            ],
                            "approved_at": now,
                            "findings": [],
                        }
                    )
                )
                approval_paths[role] = approval_path

            final_bundle = root / "final-bundle"
            finalize.finalize(args.output, final_bundle, approval_paths)
            manifest = json.loads(
                (final_bundle / "candidate-manifest.json").read_text()
            )
            schema = json.loads(
                (Path(__file__).parents[1] / "candidate-manifest.schema.json").read_text()
            )
            import jsonschema
            self.assertEqual(
                list(jsonschema.Draft202012Validator(schema).iter_errors(manifest)),
                [],
            )
            as_of = datetime.now(timezone.utc)
            derivative_verify = finalize.verifier
            self.assertEqual(derivative_verify.validate_manifest(manifest, as_of), [])
            evidence_errors: list[str] = []
            derivative_verify.validate_evidence(manifest, final_bundle, evidence_errors, as_of)
            self.assertEqual(evidence_errors, [])
            for field, image_name in (
                ("network_archive_sha256", manifest["images"][0]["name"]),
                ("grype_version", manifest["images"][0]["name"]),
                ("image", manifest["support_images"][0]["name"]),
                ("vulnerability_acceptance_sha256", manifest["images"][0]["name"]),
            ):
                tampered = json.loads(json.dumps(manifest))
                target = next(
                    item
                    for item in tampered["images"] + tampered["support_images"]
                    if item["name"] == image_name
                )
                if field == "grype_version":
                    target["scanner"][field] = "tampered"
                elif field == "image":
                    target[field] = (
                        "registry.invalid/tampered@sha256:" + "f" * 64
                    )
                else:
                    target[field] = "sha256:" + "f" * 64
                tampered["review_payload_digest"] = (
                    derivative_verify.review_payload_digest(tampered)
                )
                errors = derivative_verify.validate_manifest(tampered, as_of)
                evidence_errors = []
                derivative_verify.validate_evidence(
                    tampered, final_bundle, evidence_errors, as_of
                )
                self.assertTrue(errors or evidence_errors, field)
