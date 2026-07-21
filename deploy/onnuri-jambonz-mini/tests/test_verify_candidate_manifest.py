"""Hermetic contract tests for immutable candidate-manifest intake."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
DEPLOY_DIR = HERE.parent
VERIFIER_PATH = DEPLOY_DIR / "verify_candidate_manifest.py"
SCHEMA_PATH = DEPLOY_DIR / "candidate-manifest.schema.json"
AS_OF = "2030-06-15T12:00:00Z"
SYNTHETIC_DIGEST_A = "sha256:" + "a" * 64
SYNTHETIC_DIGEST_B = "sha256:" + "b" * 64
SYNTHETIC_DIGEST_C = "sha256:" + "c" * 64


def load_verifier():
    spec = importlib.util.spec_from_file_location("candidate_manifest_verifier_under_test", VERIFIER_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("could not create verifier import specification")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VERIFIER = load_verifier()


def disabled_store() -> dict[str, object]:
    return {
        "enabled": False,
        "persistence": "disabled",
        "contains_registration_secret": False,
        "encrypted_at_rest": False,
        "raw_data_enabled": False,
        "backup_enabled": False,
        "replication_enabled": False,
        "export_enabled": False,
        "deletion_behavior": "not_applicable",
    }


def evidence_result(name: str) -> dict[str, str]:
    return {
        "result": "pass",
        "evidence_reference": f"evidence:synthetic/disqualifier/{name}",
        "evidence_digest": SYNTHETIC_DIGEST_C,
    }


def valid_manifest() -> dict[str, object]:
    disqualifiers = {
        name: evidence_result(name)
        for name in (
            "license_provenance",
            "registration_secret_persistence",
            "raw_logging",
            "cdr_storage",
            "recording",
            "backup_replication_export",
            "public_management",
            "rtp_bounds",
            "hook_semantics",
            "ws_auth",
            "media_codec",
            "timer_behavior",
        )
    }
    return {
        "schema_version": "onnuri-jambonz-candidate/v1",
        "candidate": {
            "release": "10.2.2",
            "source_image": {
                "provider": "gcp",
                "project": "synthetic-project",
                "name": "synthetic-image",
                "immutable_image_id": "8849856699999487269",
                "export_sha256": VERIFIER.STOCK_EXPORT_SHA256,
            },
            "derivative": {
                "final_disk_sha256": SYNTHETIC_DIGEST_B,
                "rootfs_tree_sha256": SYNTHETIC_DIGEST_C,
                "hardening_receipt_reference": "evidence:synthetic/hardening-receipt",
                "hardening_receipt_digest": SYNTHETIC_DIGEST_A,
                "one_shot_receipt_reference": "evidence:synthetic/one-shot-receipt",
                "one_shot_receipt_digest": SYNTHETIC_DIGEST_B,
            },
            "license": {
                "spdx_id": "LicenseRef-Synthetic-Test-Only",
                "entitlement_reference": "evidence:synthetic/license",
                "entitlement_digest": SYNTHETIC_DIGEST_A,
                "status": "approved",
            },
            "provenance": {
                "publisher": "synthetic-publisher",
                "statement_reference": "evidence:synthetic/provenance",
                "statement_digest": SYNTHETIC_DIGEST_A,
                "signature_status": "verified",
                "sbom_reference": "evidence:synthetic/sbom",
                "sbom_digest": SYNTHETIC_DIGEST_B,
            },
            "vulnerability_report": {
                "reference": "evidence:synthetic/vulnerability-report",
                "digest": SYNTHETIC_DIGEST_C,
                "tool": "synthetic-scanner",
                "database": {
                    "name": "synthetic-db",
                    "version": "2030.06.01",
                    "updated_at": "2030-06-14T12:00:00Z",
                },
            },
            "supported_architectures": ["arm64"],
            "component_topology": {
                "components": [
                    {
                        "name": "synthetic-app",
                        "role": "application",
                        "artifact_digest": SYNTHETIC_DIGEST_A,
                    }
                ],
                "connections": [],
            },
        },
        "runtime_contract": {
            "hooks": {
                "inbound_initial_application": {
                    "timing": "pre_answer",
                    "ordered_verbs": ["answer", "listen"],
                    "failure_behavior": "no_answer_or_listen",
                    "synchronous_authority_response": True,
                },
                "outbound_call": {
                    "timing": "post_answer",
                    "emits_listen_after_authority": True,
                    "synchronous_authority_response": True,
                },
            },
            "listen": {
                "ws_auth": {
                    "scheme": "basic",
                    "username_source": "fixed_non_secret",
                    "password_source": "opaque_media_authority",
                },
                "sample_rate_hz": 8000,
                "encoding": "L16",
                "channels": 1,
                "direction": "bidirectional",
            },
            "registration_secret_persistence": {
                "classification": "S1",
                "external_runtime_only": True,
                "encrypted_ephemeral_mysql": False,
                "destroy_with_process_and_disk": True,
            },
        },
        "storage_contract": {
            name: disabled_store()
            for name in ("mysql", "influxdb", "redis", "logs", "cdr", "recordings")
        },
        "network_contract": {
            "local_rtp_pool": {
                "protocol": "udp",
                "port_start": 30000,
                "port_end": 30099,
                "bounded": True,
                "host_sdp_exact_narrowing": True,
            }
        },
        "management_exposure": {
            "mode": "disabled",
            "public_admin": False,
            "portal_enabled": False,
        },
        "artifact_acquisition_receipt": {
            "receipt_reference": "evidence:synthetic/acquisition-receipt",
            "receipt_digest": SYNTHETIC_DIGEST_B,
            "acquired_by": "synthetic-offline-acquirer",
            "acquired_at": "2030-06-11T12:00:00Z",
            "expires_at": "2030-07-15T12:00:00Z",
            "store_generation": "synthetic-immutable-generation",
            "authorized_readers_reference": "evidence:synthetic/authorized-readers",
            "signature_status": "verified",
            "acquisition_access_closed": True,
        },
        "renewed_review": {
            "architect": {
                "identity": "synthetic-architect-reviewer",
                "independent": True,
                "decision": "approved",
                "review_reference": "evidence:synthetic/architect-review",
                "review_digest": SYNTHETIC_DIGEST_A,
                "reviewed_at": "2030-06-12T12:00:00Z",
            },
            "critic": {
                "identity": "synthetic-critic-reviewer",
                "independent": True,
                "decision": "approved",
                "review_reference": "evidence:synthetic/critic-review",
                "review_digest": SYNTHETIC_DIGEST_B,
                "reviewed_at": "2030-06-13T12:00:00Z",
            },
            "qa": {
                "identity": "synthetic-qa-reviewer",
                "independent": True,
                "decision": "approved",
                "review_reference": "evidence:synthetic/qa-review",
                "review_digest": SYNTHETIC_DIGEST_C,
                "reviewed_at": "2030-06-14T12:00:00Z",
            },
        },
        "disqualifier_results": disqualifiers,
    }


class CandidateManifestVerifierTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    def write_bundle(
        self, directory: Path, manifest: dict[str, object], index_mutator: object | None = None
    ) -> tuple[Path, Path, Path]:
        bundle_root = directory / "bundle"
        bundle_root.mkdir()
        evidence_errors: list[str] = []
        assertions = VERIFIER.evidence_assertions(manifest, evidence_errors)
        self.assertEqual(evidence_errors, [])
        entries: dict[str, object] = {}
        for number, (reference, (_, kind)) in enumerate(sorted(assertions.items())):
            relative_path = f"evidence/{number:02d}.txt"
            evidence_path = bundle_root / relative_path
            evidence_path.parent.mkdir(exist_ok=True)
            evidence_path.write_text(f"synthetic evidence for {reference}\n", encoding="utf-8")
            digest = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
            entries[reference] = {
                "path": relative_path,
                "sha256": digest,
                "kind": kind,
                "verification_status": "verified",
                "content_type": "text",
            }
        for reference, entry in entries.items():
            digest = "sha256:" + entry["sha256"]
            candidate_data = manifest.get("candidate", {})
            provenance = candidate_data.get("provenance", {})
            derivative = candidate_data.get("derivative", {})
            vulnerability = candidate_data.get("vulnerability_report", {})
            receipt = manifest.get("artifact_acquisition_receipt", {})
            bindings = (
                (candidate_data.get("license", {}), "entitlement_reference", "entitlement_digest"),
                (provenance, "statement_reference", "statement_digest"),
                (provenance, "sbom_reference", "sbom_digest"),
                (derivative, "hardening_receipt_reference", "hardening_receipt_digest"),
                (derivative, "one_shot_receipt_reference", "one_shot_receipt_digest"),
                (vulnerability, "reference", "digest"),
                (receipt, "receipt_reference", "receipt_digest"),
            )
            for container, reference_field, digest_field in bindings:
                if reference == container.get(reference_field) and VERIFIER.SHA256.fullmatch(str(container.get(digest_field, ""))):
                    container[digest_field] = digest
            for role in ("architect", "critic", "qa"):
                review = manifest.get("renewed_review", {}).get(role, {})
                if reference == review.get("review_reference") and VERIFIER.SHA256.fullmatch(str(review.get("review_digest", ""))):
                    review["review_digest"] = digest
            for result in manifest.get("disqualifier_results", {}).values():
                if reference == result.get("evidence_reference") and VERIFIER.SHA256.fullmatch(str(result.get("evidence_digest", ""))):
                    result["evidence_digest"] = digest
        manifest_path = directory / "candidate.json"
        manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        manifest_path.write_bytes(manifest_bytes)
        index = {
            "schema_version": VERIFIER.INDEX_SCHEMA_VERSION,
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "source_image_id": manifest.get("candidate", {}).get("source_image", {}).get("immutable_image_id", "8849856699999487269"),
            "source_export_sha256": manifest.get("candidate", {}).get("source_image", {}).get("export_sha256", "sha256:" + "1" * 64),
            "final_disk_sha256": manifest.get("candidate", {}).get("derivative", {}).get("final_disk_sha256", "sha256:" + "2" * 64),
            "rootfs_tree_sha256": manifest.get("candidate", {}).get("derivative", {}).get("rootfs_tree_sha256", "sha256:" + "3" * 64),
            "receipt_store_generation": manifest.get("artifact_acquisition_receipt", {}).get("store_generation", "synthetic-generation"),
            "evidence": entries,
            "redaction_attestations": {},
        }
        if index_mutator is not None:
            index_mutator(index, bundle_root)
        index_path = directory / "evidence-index.json"
        index_path.write_text(json.dumps(index), encoding="utf-8")
        return manifest_path, index_path, bundle_root

    def run_cli(self, manifest: dict[str, object] | None = None, *, raw: str | None = None, as_of: str = AS_OF, index_mutator: object | None = None) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = valid_manifest() if manifest is None else manifest
            manifest_path, index_path, bundle_root = self.write_bundle(root, candidate, index_mutator)
            if raw is not None:
                manifest_path.write_text(raw, encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(VERIFIER_PATH), str(manifest_path), "--evidence-index", str(index_path), "--bundle-root", str(bundle_root), "--as-of", as_of],
                cwd=directory,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
                env={"PATH": os.environ.get("PATH", "")},
            )

    def assert_rejected(self, manifest: dict[str, object], message: str) -> None:
        first = self.run_cli(manifest)
        second = self.run_cli(manifest)
        self.assertEqual((first.returncode, first.stdout, first.stderr), (second.returncode, second.stdout, second.stderr))
        self.assertEqual(first.returncode, 1, first)
        self.assertIn(message, first.stderr)
        self.assertEqual(first.stdout, "")

    def test_valid_synthetic_manifest_matches_schema_and_is_accepted(self) -> None:
        manifest = valid_manifest()
        self.assertEqual(set(manifest), set(self.schema["required"]))
        self.assertFalse(set(manifest) - set(self.schema["properties"]))
        result = self.run_cli(manifest)
        self.assertEqual(result.returncode, 0, result)
        self.assertEqual(result.stdout, "candidate manifest valid\n")
        self.assertEqual(result.stderr, "")
    def test_evidence_index_binds_manifest_and_every_evidence_file(self) -> None:
        reference = "evidence:synthetic/license"

        def bad_manifest_hash(index: dict[str, object], _: Path) -> None:
            index["manifest_sha256"] = "0" * 64
        def bad_final_disk_digest(index: dict[str, object], _: Path) -> None:
            index["final_disk_sha256"] = SYNTHETIC_DIGEST_A

        def bad_generation(index: dict[str, object], _: Path) -> None:
            index["receipt_store_generation"] = "other-generation"


        def missing(index: dict[str, object], _: Path) -> None:
            del index["evidence"][reference]

        def extra(index: dict[str, object], _: Path) -> None:
            index["evidence"]["evidence:synthetic/extra"] = {
                "path": "evidence/extra.txt", "sha256": "0" * 64, "kind": "disqualifier", "verification_status": "verified"
            }

        def unsupported(index: dict[str, object], _: Path) -> None:
            index["evidence"][reference].update({"sha256": "A" * 64, "kind": "unsupported", "verification_status": "unverified"})
        def bad_kind(index: dict[str, object], _: Path) -> None:
            index["evidence"][reference]["kind"] = "unsupported"

        def bad_status(index: dict[str, object], _: Path) -> None:
            index["evidence"][reference]["verification_status"] = "unverified"


        cases = (
            (bad_manifest_hash, "does not match manifest bytes"),
            (missing, "missing reference"),
            (extra, "extra reference"),
            (unsupported, "invalid format"),
            (bad_final_disk_digest, "does not match candidate derivative chain"),
            (bad_generation, "does not match acquisition receipt"),
            (bad_kind, "unsupported value"),
            (bad_status, "expected 'verified'"),
        )
        for mutator, expected in cases:
            with self.subTest(expected=expected):
                result = self.run_cli(valid_manifest(), index_mutator=mutator)
                self.assertEqual(result.returncode, 1, result)
                self.assertIn(expected, result.stderr)

    def test_evidence_index_rejects_byte_path_and_file_attacks(self) -> None:
        reference = "evidence:synthetic/license"

        def tamper(index: dict[str, object], root: Path) -> None:
            (root / index["evidence"][reference]["path"]).write_text("tampered", encoding="utf-8")

        def traversal(index: dict[str, object], _: Path) -> None:
            index["evidence"][reference]["path"] = "../outside.txt"

        def duplicate(index: dict[str, object], _: Path) -> None:
            index["evidence"][reference]["path"] = index["evidence"]["evidence:synthetic/provenance"]["path"]
        def outside(index: dict[str, object], root: Path) -> None:
            index["evidence"][reference]["path"] = str(root.parent / "outside.txt")


        def symlink(index: dict[str, object], root: Path) -> None:
            target = root / index["evidence"][reference]["path"]
            target.unlink()
            target.symlink_to(root / "evidence/01.txt")

        def directory(index: dict[str, object], root: Path) -> None:
            target = root / index["evidence"][reference]["path"]
            target.unlink()
            target.mkdir()

        cases = (
            (tamper, "does not match evidence bytes"),
            (traversal, "must be a normalized bundle-relative path"),
            (duplicate, "duplicate evidence path"),
            (symlink, "symlinks are forbidden"),
            (directory, "must name a regular file"),
            (outside, "must be a normalized bundle-relative path"),
        )
        for mutator, expected in cases:
            with self.subTest(expected=expected):
                result = self.run_cli(valid_manifest(), index_mutator=mutator)
                self.assertEqual(result.returncode, 1, result)
                self.assertIn(expected, result.stderr)

    def test_indexed_text_evidence_is_redaction_scanned_and_opaque_evidence_needs_attestation(self) -> None:
        reference = "evidence:synthetic/license"

        def sensitive(index: dict[str, object], root: Path) -> None:
            path = root / index["evidence"][reference]["path"]
            path.write_text("password=not-allowed\n", encoding="utf-8")
            index["evidence"][reference]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()

        result = self.run_cli(valid_manifest(), index_mutator=sensitive)
        self.assertEqual(result.returncode, 1, result)
        self.assertIn("secret or raw signaling/media data is forbidden", result.stderr)

        def opaque_without_attestation(index: dict[str, object], _: Path) -> None:
            index["evidence"][reference]["content_type"] = "opaque"

        result = self.run_cli(valid_manifest(), index_mutator=opaque_without_attestation)
        self.assertEqual(result.returncode, 1, result)
        self.assertIn("opaque evidence requires an independently approved digest-bound redaction attestation", result.stderr)

        def attested_opaque(index: dict[str, object], root: Path) -> None:
            target = index["evidence"][reference]
            target["content_type"] = "opaque"
            attestation_path = root / "evidence/redaction-attestation.txt"
            attestation_path.write_text("independent redaction approval\n", encoding="utf-8")
            attestation_digest = hashlib.sha256(attestation_path.read_bytes()).hexdigest()
            attestation_reference = "evidence:synthetic/redaction-attestation"
            index["redaction_attestations"][target["sha256"]] = {
                "reference": attestation_reference,
                "digest": "sha256:" + attestation_digest,
                "independent": True,
                "decision": "approved",
            }
            index["evidence"][attestation_reference] = {
                "path": "evidence/redaction-attestation.txt",
                "sha256": attestation_digest,
                "kind": "redaction_attestation",
                "verification_status": "verified",
                "content_type": "text",
            }

        result = self.run_cli(valid_manifest(), index_mutator=attested_opaque)
        self.assertEqual(result.returncode, 0, result)
    def test_duplicate_json_key_is_parse_error(self) -> None:
        encoded = json.dumps(valid_manifest())
        duplicate = encoded.replace(
            '"schema_version":',
            '"schema_version": "onnuri-jambonz-candidate/v1", "schema_version":',
            1,
        )
        result = self.run_cli(raw=duplicate)
        self.assertEqual(result.returncode, 2, result)
        self.assertIn("duplicate JSON key: schema_version", result.stderr)

    def test_unknown_and_missing_fields_are_rejected(self) -> None:
        unknown = valid_manifest()
        unknown["candidate"]["synthetic_extra"] = False
        self.assert_rejected(unknown, "candidate: unknown field synthetic_extra")

        missing = valid_manifest()
        del missing["candidate"]["source_image"]
        self.assert_rejected(missing, "candidate: missing field source_image")

    def test_unresolved_values_are_rejected(self) -> None:
        for value in ("pending", "unknown", "unresolved", "TBD", "TODO", "n/a"):
            with self.subTest(value=value):
                manifest = valid_manifest()
                manifest["candidate"]["release"] = value
                self.assert_rejected(manifest, "unresolved value is forbidden")

    def test_phone_credential_sip_sdp_and_audio_leakage_are_rejected(self) -> None:
        leak_values = {
            "phone-looking": "+1 000 000 0000",
            "credential": "password=synthetic-credential-material",
            "sip": "sip:synthetic-user@invalid.example",
            "sdp": "v=0\no=synthetic 1 1 IN IP4 192.0.2.1\nm=audio 1 RTP/AVP 0",
            "audio": "data:audio/wav;base64,U1lOVEhFVElD",
        }
        for leak, value in leak_values.items():
            with self.subTest(leak=leak):
                manifest = valid_manifest()
                manifest["candidate"]["release"] = value
                expected = "phone-looking data is forbidden" if leak == "phone-looking" else "secret or raw signaling/media data is forbidden"
                self.assert_rejected(manifest, expected)

    def test_entitlement_digest_is_required_and_index_bound(self) -> None:
        manifest = valid_manifest()
        del manifest["candidate"]["license"]["entitlement_digest"]
        self.assert_rejected(manifest, "candidate.license: missing field entitlement_digest")

    def test_gcp_source_identity_is_distinct_from_export_and_derivative_digests(self) -> None:
        manifest = valid_manifest()
        self.assertEqual(manifest["candidate"]["source_image"]["immutable_image_id"], "8849856699999487269")
        manifest["candidate"]["source_image"]["provider"] = "oci"
        self.assert_rejected(manifest, "candidate.source_image.provider: expected 'gcp'")
        manifest = valid_manifest()
        manifest["candidate"]["source_image"]["export_sha256"] = manifest["candidate"]["derivative"]["final_disk_sha256"]
        self.assert_rejected(manifest, "candidate.source_image.export_sha256: expected")

        manifest = valid_manifest()
        del manifest["candidate"]["derivative"]["final_disk_sha256"]
        self.assert_rejected(manifest, "candidate.derivative: missing field final_disk_sha256")

        manifest = valid_manifest()
        del manifest["renewed_review"]["qa"]
        self.assert_rejected(manifest, "renewed_review: missing field qa")
    def test_acquisition_and_review_time_bounds(self) -> None:
        cases = (
            (("artifact_acquisition_receipt", "expires_at"), "2030-06-15T12:00:00Z", "receipt is expired"),
            (("artifact_acquisition_receipt", "acquired_at"), "2030-06-16T12:00:00Z", "is after validation time"),
            (("renewed_review", "architect", "reviewed_at"), "2030-06-16T12:00:00Z", "is after validation time"),
            (("renewed_review", "critic", "reviewed_at"), "2030-06-10T12:00:00Z", "renewed review predates acquisition"),
        )
        for path, value, expected in cases:
            with self.subTest(path=path):
                manifest = valid_manifest()
                target = manifest
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                self.assert_rejected(manifest, expected)

    def test_independent_reviewer_identities_must_differ(self) -> None:
        manifest = valid_manifest()
        manifest["renewed_review"]["critic"]["identity"] = manifest["renewed_review"]["architect"]["identity"]
        self.assert_rejected(manifest, "Architect, Critic, and QA identities must differ")

    def test_all_approval_gates_fail_closed(self) -> None:
        cases = (
            (("candidate", "license", "status"), "rejected", "expected 'approved'"),
            (("candidate", "provenance", "signature_status"), "unverified", "expected 'verified'"),
            (("renewed_review", "architect", "decision"), "rejected", "expected 'approved'"),
            (("renewed_review", "critic", "independent"), False, "expected True"),
            (("disqualifier_results", "media_codec", "result"), "fail", "expected 'pass'"),
        )
        for path, value, expected in cases:
            with self.subTest(path=path):
                manifest = valid_manifest()
                target = manifest
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                self.assert_rejected(manifest, expected)

    def test_public_management_recording_backup_and_export_are_rejected(self) -> None:
        cases = (
            (("management_exposure", "public_admin"), True, "expected False"),
            (("management_exposure", "portal_enabled"), True, "expected False"),
            (("storage_contract", "recordings", "enabled"), True, "recordings must be disabled"),
            (("storage_contract", "logs", "backup_enabled"), True, "expected False"),
            (("storage_contract", "cdr", "export_enabled"), True, "expected False"),
            (("storage_contract", "redis", "replication_enabled"), True, "expected False"),
        )
        for path, value, expected in cases:
            with self.subTest(path=path):
                manifest = valid_manifest()
                target = manifest
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                self.assert_rejected(manifest, expected)

    def test_secret_persistence_class_mismatch_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["runtime_contract"]["registration_secret_persistence"]["external_runtime_only"] = False
        self.assert_rejected(manifest, "S1 requires external-only use and no MySQL persistence")

        manifest = valid_manifest()
        persistence = manifest["runtime_contract"]["registration_secret_persistence"]
        persistence.update({"classification": "S2", "external_runtime_only": False, "encrypted_ephemeral_mysql": True})
        self.assert_rejected(manifest, "S2 requires registration secret only in encrypted ephemeral MySQL")

    def test_invalid_topology_is_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["candidate"]["component_topology"]["connections"] = [
            {"from": "synthetic-app", "to": "undeclared-component", "purpose": "control"}
        ]
        self.assert_rejected(manifest, "connection references an undeclared component")

    def test_rtp_pool_cannot_exceed_one_hundred_ports(self) -> None:
        manifest = valid_manifest()
        manifest["network_contract"]["local_rtp_pool"]["port_end"] = 30100
        self.assert_rejected(manifest, "pool exceeds the 100-port local bound")

    def test_supplier_media_evidence_is_rejected_as_an_extra_stable_candidate_field(self) -> None:
        self.assertFalse("supplier_media_evidence" in self.schema["required"])
        self.assertFalse("supplier_media_evidence" in self.schema["properties"])
        self.assertFalse(self.schema["additionalProperties"])

        manifest = valid_manifest()
        manifest["supplier_media_evidence"] = {
            "reference": "evidence:synthetic/supplier-authoritative-media",
            "digest": SYNTHETIC_DIGEST_A,
            "reviewed_at": "2030-06-10T12:00:00Z",
            "expires_at": "2030-07-15T12:00:00Z",
        }
        self.assert_rejected(manifest, "$: unknown field supplier_media_evidence")

    def test_selection_is_impossible_without_closed_immutable_acquisition(self) -> None:
        cases = (
            ("receipt_reference", None, "missing field receipt_reference"),
            ("receipt_digest", "sha256:not-a-digest", "invalid format"),
            ("signature_status", "unverified", "expected 'verified'"),
            ("acquisition_access_closed", False, "expected True"),
            ("store_generation", "pending", "unresolved value is forbidden"),
        )
        for field, value, expected in cases:
            with self.subTest(field=field):
                manifest = valid_manifest()
                receipt = manifest["artifact_acquisition_receipt"]
                if value is None:
                    del receipt[field]
                else:
                    receipt[field] = value
                self.assert_rejected(manifest, expected)

    def test_invalid_validation_time_is_deterministic_usage_error(self) -> None:
        first = self.run_cli(valid_manifest(), as_of="not-a-time")
        second = self.run_cli(valid_manifest(), as_of="not-a-time")
        self.assertEqual((first.returncode, first.stderr), (second.returncode, second.stderr))
        self.assertEqual(first.returncode, 2, first)
        self.assertIn("--as-of: invalid RFC 3339 timestamp", first.stderr)

    def test_verifier_uses_no_network_or_child_processes(self) -> None:
        tree = ast.parse(VERIFIER_PATH.read_text(encoding="utf-8"), filename=str(VERIFIER_PATH))
        imported_roots = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported_roots.update(
            node.module.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        )
        self.assertTrue(imported_roots.isdisjoint({"asyncio", "http", "os", "requests", "socket", "subprocess", "urllib"}))

        with tempfile.TemporaryDirectory() as directory:
            manifest_path, index_path, bundle_root = self.write_bundle(Path(directory), valid_manifest())
            with (
                mock.patch.object(sys, "argv", [str(VERIFIER_PATH), str(manifest_path), "--evidence-index", str(index_path), "--bundle-root", str(bundle_root), "--as-of", AS_OF]),
                mock.patch.object(socket, "socket", side_effect=AssertionError("network use forbidden")),
                mock.patch.object(socket, "create_connection", side_effect=AssertionError("network use forbidden")),
                mock.patch.object(subprocess, "Popen", side_effect=AssertionError("process use forbidden")),
                mock.patch.object(subprocess, "run", side_effect=AssertionError("process use forbidden")),
                mock.patch.object(os, "system", side_effect=AssertionError("process use forbidden")),
                mock.patch.object(os, "popen", side_effect=AssertionError("process use forbidden")),
            ):
                self.assertEqual(VERIFIER.main(), 0)


if __name__ == "__main__":
    unittest.main()
