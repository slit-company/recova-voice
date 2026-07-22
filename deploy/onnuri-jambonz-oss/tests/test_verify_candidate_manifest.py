import base64
import hashlib
import json
import importlib.util
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

MODULE = Path(__file__).parents[1] / "verify_candidate_manifest.py"
spec = importlib.util.spec_from_file_location("verify_candidate_manifest", MODULE)
verifier = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(verifier)

CORE = sorted(verifier.CORE)
RUNTIME_IMAGES = sorted(verifier.RUNTIME_IMAGES)
REQUIRED_SOURCES = sorted(verifier.REQUIRED_SOURCES)
DIGEST = "sha256:" + "a" * 64
COMMIT = "b" * 40
PATCH_CONTENT_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()


def evidence_reference(category, name):
    return f"evidence:{category}/{name}.txt"


def valid_manifest():
    sources = []
    refs = {}
    for name in REQUIRED_SOURCES:
        source = {
            "name": name,
            "repository": f"https://github.com/jambonz/{name}",
            "commit": verifier.FREESWITCH_CONTRIBUTIONS.get(name, (COMMIT,))[0],
            "upstream_tree_sha256": DIGEST,
            "source_tree_reference": evidence_reference("trees", name),
            "source_tree_sha256": DIGEST,
            "submodules_reference": evidence_reference("submodules", name),
            "submodules_sha256": DIGEST,
            "submodules": [],
            "license_spdx": verifier.REQUIRED_LICENSES[name],
            "license_reference": evidence_reference("licenses", name),
            "license_sha256": DIGEST,
            "patch_reference": evidence_reference("patches", name),
            "patch_sha256": DIGEST,
            "patch_content_sha256": PATCH_CONTENT_DIGEST,
        }
        for field, digest_field in (
            ("source_tree_reference", "source_tree_sha256"),
            ("submodules_reference", "submodules_sha256"),
            ("license_reference", "license_sha256"),
            ("patch_reference", "patch_sha256"),
        ):
            refs[source[field]] = source[digest_field]
        if name == "jambonz-freeswitch-modules":
            source["conditional_mit"] = {
                "selected_license": "MIT",
                "dedicated_freeswitch": True,
                "dynamic_load": "mod_audio_fork",
                "incoming_call_control": "jambonz-feature-server/outbound-esl",
                "reference": "evidence:licenses/cyrenity-choice.txt",
                "sha256": DIGEST,
                "topology_reference": "evidence:topology/cyrenity-freeswitch-esl.txt",
                "topology_sha256": DIGEST,
            }
            refs.update({
                source["conditional_mit"]["reference"]: DIGEST,
                source["conditional_mit"]["topology_reference"]: DIGEST,
            })
        sources.append(source)

    images = []
    for name in RUNTIME_IMAGES:
        recipe_reference = f"evidence:evidence/recipes-{verifier.BUILD_RECIPES[name]}"
        image = {
            "name": name,
            "source_name": name,
            "source_commit": verifier.FREESWITCH_CONTRIBUTIONS.get(name, (COMMIT,))[0],
            "platform": "linux/amd64",
            "image": f"registry.example/{name}@{DIGEST}",
            "base_images": [f"registry.example/base@{DIGEST}"],
            "build_mode": "source_only",
            "build_recipe_reference": recipe_reference,
            "build_recipe_sha256": DIGEST,
            "build_provenance_reference": evidence_reference("builds", name),
            "build_provenance_sha256": DIGEST,
            "network_archive_reference": evidence_reference("archives", name),
            "network_archive_sha256": DIGEST,
            "network_archive_record_reference": evidence_reference("archive-records", name),
            "network_archive_record_sha256": DIGEST,
            "source_contributions": [],
            "notices_reference": evidence_reference("notices", name),
            "notices_sha256": DIGEST,
            "sbom_reference": evidence_reference("sbom", name),
            "sbom_sha256": DIGEST,
            "vulnerability_reference": evidence_reference("vulns", name),
            "vulnerability_sha256": DIGEST,
            "scanner": {
                "syft_version": "1.0.0",
                "grype_version": "1.0.0",
                "grype_db_identity_reference": evidence_reference("grype-db", name),
                "grype_db_identity_sha256": DIGEST,
            },
            "vulnerability_acceptance_reference": evidence_reference("acceptances", name),
            "vulnerability_acceptance_sha256": DIGEST,
            "vulnerability_summary": {"critical": 0, "high": 0, "unaccepted_critical": 0, "unaccepted_high": 0},
        }
        if name == "freeswitch":
            image["source_contributions"] = [
                {
                    "source_name": source_name,
                    "source_commit": commit,
                    "contribution": contribution,
                    "license_mode": license_mode,
                    "reference": evidence_reference("licenses", source_name),
                    "sha256": DIGEST,
                }
                for source_name, (commit, contribution, license_mode) in verifier.FREESWITCH_CONTRIBUTIONS.items()
            ]
            refs.update({contribution["reference"]: DIGEST for contribution in image["source_contributions"]})
        for field, digest_field in (
            ("build_recipe_reference", "build_recipe_sha256"),
            ("build_provenance_reference", "build_provenance_sha256"),
            ("network_archive_reference", "network_archive_sha256"),
            ("network_archive_record_reference", "network_archive_record_sha256"),
            ("notices_reference", "notices_sha256"),
            ("sbom_reference", "sbom_sha256"),
            ("vulnerability_reference", "vulnerability_sha256"),
            ("vulnerability_acceptance_reference", "vulnerability_acceptance_sha256"),
        ):
            refs[image[field]] = image[digest_field]
        refs[image["scanner"]["grype_db_identity_reference"]] = image["scanner"]["grype_db_identity_sha256"]
        images.append(image)
    support_images = []
    for name in sorted(verifier.SUPPORT_IMAGES):
        first_party = name in {"facade", "recova-backend"}
        source = (
            verifier.FIRST_PARTY_SUPPORT_SOURCE
            if first_party
            else f"https://github.com/recova-support/{name}"
        )
        if name == "facade":
            provenance = {
                "label": verifier.SOURCE_REVISION_LABEL,
                "type": "source_tree_sha256",
                "value": DIGEST,
            }
        elif name == "recova-backend":
            provenance = {
                "label": verifier.SOURCE_REVISION_LABEL,
                "type": "source_tree_sha256",
                "value": DIGEST,
            }
        else:
            provenance = {
                "label": verifier.SOURCE_REVISION_LABEL,
                "type": "git_revision",
                "value": COMMIT,
            }
        support = {
            "name": name, "image": f"registry.example/{name}@{DIGEST}", "platform": "linux/amd64",
            "source": source,
            "source_provenance": provenance,
            "source_provenance_reference": evidence_reference("support-source-provenance", name),
            "source_provenance_sha256": DIGEST,
            "base_images": [f"local-registry/registry.example/base@{DIGEST}"],
            "license_spdx": verifier.SUPPORT_OCI_LICENSES[name],
            "oci_license_reference": evidence_reference("support-oci-license", name),
            "oci_license_sha256": DIGEST,
            "notices_reference": evidence_reference("support-notices", name), "notices_sha256": DIGEST,
            "sbom_reference": evidence_reference("support-sbom", name), "sbom_sha256": DIGEST,
            "vulnerability_reference": evidence_reference("support-vulns", name), "vulnerability_sha256": DIGEST,
            "scanner": {"syft_version": "1.0.0", "grype_version": "1.0.0", "grype_db_identity_reference": evidence_reference("support-grype-db", name), "grype_db_identity_sha256": DIGEST},
            "vulnerability_acceptance_reference": evidence_reference("support-acceptances", name), "vulnerability_acceptance_sha256": DIGEST,
            "vulnerability_summary": {"critical": 0, "high": 0, "unaccepted_critical": 0, "unaccepted_high": 0},
            "network_archive_reference": evidence_reference("support-archives", name),
            "network_archive_sha256": DIGEST,
            "network_archive_record_reference": evidence_reference("support-archive-records", name),
            "network_archive_record_sha256": DIGEST,
        }
        for field, digest_field in (
            ("source_provenance_reference", "source_provenance_sha256"),
            ("oci_license_reference", "oci_license_sha256"),
            ("notices_reference", "notices_sha256"),
            ("sbom_reference", "sbom_sha256"),
            ("vulnerability_reference", "vulnerability_sha256"),
            ("vulnerability_acceptance_reference", "vulnerability_acceptance_sha256"),
            ("network_archive_reference", "network_archive_sha256"),
            ("network_archive_record_reference", "network_archive_record_sha256"),
        ):
            refs[support[field]] = support[digest_field]
        refs[support["scanner"]["grype_db_identity_reference"]] = support["scanner"]["grype_db_identity_sha256"]
        support_images.append(support)

    refs.update({
        "evidence:receipt.txt": DIGEST,
        "evidence:architect.txt": DIGEST,
        "evidence:critic.txt": DIGEST,
        "evidence:qa.txt": DIGEST,
        "evidence:checks.txt": DIGEST,
        "evidence:conformance-receipt.json": DIGEST,
        **{
            f"evidence:conformance-{name}.raw": DIGEST
            for name in verifier.CONFORMANCE_CHECKS
        },
        **{
            reference: "sha256:" + expected_sha256
            for _name, (reference, expected_sha256) in verifier.FROZEN_RUNTIME_EVIDENCE.items()
        },
    })
    for name, expected_sha256 in verifier.PHASE_C_EVIDENCE.items():
        refs[f"evidence:evidence/phase-c-{name}"] = "sha256:" + expected_sha256
    manifest = {
        "schema_version": verifier.SCHEMA_VERSION,
        "candidate_generation": verifier.GENERATION,
        "source_lock_sha256": DIGEST,
        "sources": sources,
        "images": images,
        "support_images": support_images,
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
            "listen": {"ws_auth": "Basic", "encoding": "L16", "sample_rate_hz": 8000, "channels": 1, "direction": "bidirectional"},
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
            "calls": {"automatic_retry": False, "max_concurrency": 1, "maximum_attempts": 3, "contingency_attempts": 1, "contingency_authority_required": True, "contingency_direction_bound": True, "target_scope": "single_owned_destination", "target_binding": "execution_request_owned_target_sha256_and_destination_hmac_digest"},
            "timers": {"register_terminal_deadline_seconds": 32, "call_deadline_seconds": 60},
            "teardown": {"unregister_required": True, "active_call_hangup_required": True, "execution_containment_required": True, "secret_erasure_required": True, "failure_cleanup_required": True},
        },
        "management_exposure": {"default_deny": True, "local_only": True},
        "storage_contract": {"ephemeral": True, "raw_logs": False, "cdr": False, "recordings": False, "backups": False, "exports": False},
        "acquisition_receipt": {"reference": "evidence:receipt.txt", "sha256": DIGEST, "acquired_at": "2026-01-01T00:00:00Z", "expires_at": "2027-01-01T00:00:00Z"},
        "approvals": {role: {"identity": role, "independent": True, "decision": "approved", "reference": f"evidence:{role}.txt", "sha256": DIGEST} for role in ("architect", "critic", "qa")},
        "disqualifier_results": {
            "license": {"result": "pass", "reference": "evidence:checks.txt", "sha256": DIGEST},
            "candidate_input_conformance": {
                "result": "pass",
                "reference": "evidence:conformance-receipt.json",
                "sha256": DIGEST,
            },
            **{
                f"candidate_input_conformance_output_{name}": {
                    "result": "pass",
                    "reference": f"evidence:conformance-{name}.raw",
                    "sha256": DIGEST,
                }
                for name in verifier.CONFORMANCE_CHECKS
            },
            **{
                "candidate_input_phase_c_configuration_" + name: {
                    "result": "pass",
                    "reference": f"evidence:evidence/phase-c-{name}",
                    "sha256": "sha256:" + expected_sha256,
                }
                for name, expected_sha256 in verifier.PHASE_C_EVIDENCE.items()
            },
            **{
                name: {
                    "result": "pass",
                    "reference": reference,
                    "sha256": "sha256:" + expected_sha256,
                }
                for name, (reference, expected_sha256) in verifier.FROZEN_RUNTIME_EVIDENCE.items()
            },
        },
        "evidence_index": {ref: {"path": ref.removeprefix("evidence:"), "sha256": digest.removeprefix("sha256:"), "content_type": "text"} for ref, digest in refs.items()},
    }
    manifest["review_payload_digest"] = verifier.review_payload_digest(manifest)
    return manifest


class VerifyCandidateManifestTests(unittest.TestCase):
    def assert_invalid(self, manifest):
        errors = verifier.validate_manifest(manifest, datetime(2026, 7, 15, tzinfo=timezone.utc))
        self.assertTrue(errors, "manifest unexpectedly validated")

    def test_phase_c_launcher_and_terraform_evidence_is_required(self):
        manifest = valid_manifest()
        record = "candidate_input_phase_c_configuration_startup-g008.sh"
        reference = manifest["disqualifier_results"][record]["reference"]
        manifest["disqualifier_results"].pop(record)
        manifest["evidence_index"].pop(reference)
        manifest["review_payload_digest"] = verifier.review_payload_digest(manifest)
        self.assert_invalid(manifest)

    def test_signed_conformance_and_boot_binding_evidence_are_required(self):
        for record in (
            "candidate_input_conformance",
            "candidate_input_conformance_output_offline_default_deny",
            "candidate_input_bootstrap_binding",
        ):
            manifest = valid_manifest()
            reference = manifest["disqualifier_results"][record]["reference"]
            manifest["disqualifier_results"].pop(record)
            manifest["evidence_index"].pop(reference)
            manifest["review_payload_digest"] = verifier.review_payload_digest(manifest)
            with self.subTest(record=record):
                self.assert_invalid(manifest)

    def test_conformance_rejects_missing_tampered_and_synthesized_raw_output(self):
        record = "candidate_input_conformance_output_offline_default_deny"
        reference = "evidence:conformance.raw"
        output = hashlib.sha256(b"pytest:offline-compose").hexdigest().encode() + b"\npass\n"
        digest = hashlib.sha256(output).hexdigest()
        data = {
            "disqualifier_results": {
                record: {
                    "result": "pass",
                    "reference": reference,
                    "sha256": "sha256:" + digest,
                }
            }
        }
        index = {
            reference: {
                "path": "conformance.raw",
                "sha256": digest,
                "content_type": "text",
            }
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.joinpath("conformance.raw").write_bytes(output)
            errors = []
            verifier.validate_conformance_output_evidence(
                "offline_default_deny",
                verifier.CONFORMANCE_CHECKS["offline_default_deny"],
                data["disqualifier_results"][record],
                index,
                root,
                errors,
            )
            self.assertEqual(errors, [])
            root.joinpath("conformance.raw").write_bytes(b"tampered")
            errors = []
            verifier.validate_conformance_output_evidence(
                "offline_default_deny",
                verifier.CONFORMANCE_CHECKS["offline_default_deny"],
                data["disqualifier_results"][record],
                index,
                root,
                errors,
            )
            self.assertTrue(errors)
        data["disqualifier_results"].pop(record)
        errors = []
        verifier.validate_conformance_evidence(data, index, Path("/nonexistent"), errors)
        self.assertEqual(errors, [])

    def test_conformance_rejects_unsigned_self_signed_and_cross_candidate_receipts(self):
        manifest = valid_manifest()
        receipt = {
            "schema_version": "onnuri-jambonz-oss-conformance/v2",
            "generated_at": "2026-07-15T00:00:00Z",
            "source_lock_sha256": manifest["source_lock_sha256"].removeprefix("sha256:"),
            "config_sha256": {},
            "checks": {},
            "signer_identity": verifier.CONFORMANCE_SIGNER_IDENTITY,
        }
        signer = Ed25519PrivateKey.generate()
        receipt["signature"] = {
            "algorithm": "Ed25519",
            "key_id": verifier.CONFORMANCE_SIGNER_KEY_ID,
            "value_b64": base64.b64encode(signer.sign(verifier.conformance_signature_payload(receipt))).decode(),
        }
        receipt_bytes = verifier.canonical_json(receipt)
        reference = "evidence:conformance-receipt.json"
        manifest["disqualifier_results"]["candidate_input_conformance"] = {"result": "pass", "reference": reference, "sha256": "sha256:" + hashlib.sha256(receipt_bytes).hexdigest()}
        manifest["evidence_index"][reference] = {"path": "conformance-receipt.json", "sha256": hashlib.sha256(receipt_bytes).hexdigest(), "content_type": "text"}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.joinpath("conformance-receipt.json").write_bytes(receipt_bytes)
            errors = []
            verifier.validate_conformance_receipt(manifest, manifest["evidence_index"], root, errors)
            self.assertTrue(errors)
            receipt.pop("signature")
            root.joinpath("conformance-receipt.json").write_bytes(verifier.canonical_json(receipt))
            errors = []
            verifier.validate_conformance_receipt(manifest, manifest["evidence_index"], root, errors)
            self.assertTrue(errors)

    def test_valid_synthetic_full_topology_manifest(self):
        self.assertEqual(verifier.validate_manifest(valid_manifest(), datetime(2026, 7, 15, tzinfo=timezone.utc)), [])

    def test_frozen_hash_constants_match_current_runner_and_phase_c_sources(self):
        root = Path(__file__).parents[3]
        self.assertEqual(
            verifier.FROZEN_RUNTIME_EVIDENCE["candidate_input_g008_live_smoke_runner"][1],
            hashlib.sha256((root / "deploy/onnuri-jambonz-oss/run-g008-live-smoke.py").read_bytes()).hexdigest(),
        )
        for name, expected_sha256 in verifier.PHASE_C_EVIDENCE.items():
            self.assertEqual(
                expected_sha256,
                hashlib.sha256((root / "infra/onnuri-seoul-staging-phase-c-smoke" / name).read_bytes()).hexdigest(),
                name,
            )

    def test_schema_requires_exact_frozen_runner_and_keyset_hashes(self):
        import jsonschema

        schema = json.loads(
            (Path(__file__).parents[1] / "candidate-manifest.schema.json").read_text()
        )
        validator = jsonschema.Draft202012Validator(schema)
        manifest = valid_manifest()

        for record_name in (
            "candidate_input_g008_live_smoke_runner",
            "candidate_input_runtime_compose",
            "candidate_input_sealed_secret_wrapper",
            "candidate_input_bootstrap_binding",
            "candidate_input_phase_c_live_preflight_trusted_keyset",
        ):
            omitted = json.loads(json.dumps(manifest))
            reference = omitted["disqualifier_results"][record_name]["reference"]
            omitted["disqualifier_results"].pop(record_name)
            omitted["evidence_index"].pop(reference)
            omitted["review_payload_digest"] = verifier.review_payload_digest(omitted)
            omitted_errors = list(validator.iter_errors(omitted))
            self.assertTrue(
                any(
                    list(error.absolute_path) == ["disqualifier_results"]
                    and record_name in error.message
                    for error in omitted_errors
                ),
                record_name,
            )

            tampered = json.loads(json.dumps(manifest))
            tampered["disqualifier_results"][record_name]["sha256"] = (
                "sha256:" + "f" * 64
            )
            tampered["review_payload_digest"] = verifier.review_payload_digest(tampered)
            tampered_errors = list(validator.iter_errors(tampered))
            self.assertTrue(
                any(
                    list(error.absolute_path)
                    == ["disqualifier_results", record_name, "sha256"]
                    for error in tampered_errors
                ),
                record_name,
            )

            unindexed = json.loads(json.dumps(manifest))
            reference = unindexed["disqualifier_results"][record_name]["reference"]
            unindexed["evidence_index"].pop(reference)
            unindexed["review_payload_digest"] = verifier.review_payload_digest(unindexed)
            unindexed_errors = list(validator.iter_errors(unindexed))
            self.assertTrue(
                any(
                    list(error.absolute_path) == ["evidence_index"]
                    and reference in error.message
                    for error in unindexed_errors
                ),
                record_name,
            )

            index_tampered = json.loads(json.dumps(manifest))
            index_tampered["evidence_index"][reference]["sha256"] = "f" * 64
            index_tampered["review_payload_digest"] = verifier.review_payload_digest(
                index_tampered
            )
            index_errors = list(validator.iter_errors(index_tampered))
            self.assertTrue(
                any(
                    list(error.absolute_path)
                    == ["evidence_index", reference, "sha256"]
                    for error in index_errors
                ),
                record_name,
            )

        review_tampered = json.loads(json.dumps(manifest))
        review_tampered["disqualifier_results"][
            "candidate_input_g008_live_smoke_runner"
        ]["sha256"] = "sha256:" + "f" * 64
        self.assertNotEqual(
            review_tampered["review_payload_digest"],
            verifier.review_payload_digest(review_tampered),
        )
    def test_redaction_scan_distinguishes_hashes_from_phone_numbers(self):
        errors = []
        verifier.scan_value(
            {
                "digest": "782320ea73dacd9da6faec02a84bf651cd51117edf7227d90bb6c7c77fcf147a",
                "timestamp": "2026-07-16T16:35:00Z",
                "scanner_unix_time": "1784139280",
            },
            "",
            errors,
        )
        self.assertEqual(errors, [])
        for phone in ("010-1234-5678", "+82 10 1234 5678", "01012345678"):
            errors = []
            verifier.scan_value(phone, "phone", errors)
            self.assertTrue(errors, phone)

    def test_license_key_prohibitions_fail_closed(self):
        for field in ("runtime_license_key_required", "activation_service_required", "trial_or_paid_entitlement_used", "commercial_image_used", "circumvention_used"):
            manifest = valid_manifest()
            manifest["license_policy"][field] = True
            with self.subTest(field=field):
                self.assert_invalid(manifest)

    def test_required_media_images_sources_and_licenses_fail_closed(self):
        self.assertEqual(len(REQUIRED_SOURCES), 13)
        self.assertEqual(len(RUNTIME_IMAGES), 10)
        self.assertNotIn("jambonz-freeswitch-modules", RUNTIME_IMAGES)
        self.assertNotIn("spandsp", RUNTIME_IMAGES)
        self.assertNotIn("sofia-sip", RUNTIME_IMAGES)
        for mutate in (
            lambda m: m["images"].pop(),
            lambda m: m["sources"].pop(),
            lambda m: m["sources"].__setitem__(0, {**m["sources"][0], "license_spdx": "Apache-2.0"}),
            lambda m: m["images"].__setitem__(0, {**m["images"][0], "image": "registry.example/mutable:latest"}),
            lambda m: m["images"].__setitem__(0, {**m["images"][0], "base_images": ["debian:latest"]}),
        ):
            manifest = valid_manifest()
            mutate(manifest)
            self.assert_invalid(manifest)

    def test_freeswitch_contribution_provenance_fails_closed(self):
        mutations = (
            lambda m: next(image for image in m["images"] if image["name"] == "freeswitch").__setitem__("source_contributions", []),
            lambda m: next(image for image in m["images"] if image["name"] == "freeswitch")["source_contributions"].pop(),
            lambda m: next(image for image in m["images"] if image["name"] == "freeswitch")["source_contributions"][1].__setitem__("source_commit", COMMIT),
            lambda m: next(image for image in m["images"] if image["name"] == "freeswitch")["source_contributions"][1].__setitem__("license_mode", "MIT"),
            lambda m: next(image for image in m["images"] if image["name"] == "freeswitch")["source_contributions"][2].__setitem__("contribution", "other"),
            lambda m: next(image for image in m["images"] if image["name"] == "freeswitch")["source_contributions"].append(next(image for image in m["images"] if image["name"] == "freeswitch")["source_contributions"][0].copy()),
            lambda m: m["images"][0].__setitem__("source_contributions", [next(image for image in m["images"] if image["name"] == "freeswitch")["source_contributions"][0].copy()]),
        )
        for mutate in mutations:
            manifest = valid_manifest()
            mutate(manifest)
            self.assert_invalid(manifest)

    def test_source_build_contribution_and_vulnerability_failures(self):
        mutations = (
            lambda m: m["sources"][0].__setitem__("patch_sha256", "pending"),
            lambda m: m["sources"][0].__setitem__("patch_content_sha256", "pending"),
            lambda m: next(source for source in m["sources"] if source["name"] == "jambonz-freeswitch-modules").pop("conditional_mit"),
            lambda m: next(source for source in m["sources"] if source["name"] == "jambonz-freeswitch-modules")["conditional_mit"].__setitem__("incoming_call_control", "direct-sip"),
            lambda m: next(source for source in m["sources"] if source["name"] == "spandsp").__setitem__("commit", COMMIT),
            lambda m: m["images"][0].__setitem__("build_mode", "binary_reuse"),
        )
        for mutate in mutations:
            manifest = valid_manifest()
            mutate(manifest)
            self.assert_invalid(manifest)
    def test_recipe_mapping_and_fields_fail_closed(self):
        mutations = (
            lambda m: m["images"][0].pop("build_recipe_reference"),
            lambda m: m["images"][0].__setitem__("build_recipe_sha256", "pending"),
            lambda m: next(image for image in m["images"] if image["name"] == "freeswitch").__setitem__(
                "build_recipe_reference", "evidence:evidence/recipes-Dockerfile.node-app"
            ),
        )
        for mutate in mutations:
            manifest = valid_manifest()
            mutate(manifest)
            with self.subTest(mutate=mutate):
                self.assert_invalid(manifest)

    def test_recipe_provenance_and_evidence_bytes_fail_closed(self):
        manifest = valid_manifest()
        image = next(image for image in manifest["images"] if image["name"] == "drachtio-server")
        recipe_ref = image["build_recipe_reference"]
        provenance_ref = image["build_provenance_reference"]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            recipe_entry = manifest["evidence_index"][recipe_ref]
            recipe_path = root / recipe_entry["path"]
            recipe_path.parent.mkdir(parents=True, exist_ok=True)
            recipe = b"FROM scratch\n"
            recipe_path.write_bytes(recipe)
            recipe_entry["sha256"] = hashlib.sha256(recipe).hexdigest()
            image["build_recipe_sha256"] = "sha256:" + recipe_entry["sha256"]
            source = next(
                source
                for source in manifest["sources"]
                if source["name"] == image["source_name"]
            )
            provenance = {
                "source": image["source_name"],
                "commit": image["source_commit"],
                "source_tree_sha256": source["upstream_tree_sha256"],
                "image_config_digest": DIGEST,
                "distribution_manifest": DIGEST,
                "base_image": image["base_images"][0],
                "build_recipe_reference": recipe_ref,
                "build_recipe_sha256": image["build_recipe_sha256"],
                "runtime_oci_license": verifier.RUNTIME_OCI_LICENSES[image["name"]],
            }
            provenance_bytes = verifier.canonical_json(provenance)
            provenance_entry = manifest["evidence_index"][provenance_ref]
            provenance_path = root / provenance_entry["path"]
            provenance_path.parent.mkdir(parents=True, exist_ok=True)
            provenance_path.write_bytes(provenance_bytes)
            provenance_entry["sha256"] = hashlib.sha256(provenance_bytes).hexdigest()
            image["build_provenance_sha256"] = "sha256:" + provenance_entry["sha256"]
            errors = []
            verifier.validate_build_recipe_evidence(
                {"images": [image], "sources": manifest["sources"]},
                manifest["evidence_index"],
                root,
                errors,
            )
            self.assertEqual(errors, [])
            recipe_path.write_bytes(b"mutated recipe\n")
            errors = []
            verifier.validate_evidence(
                {"images": [image], "evidence_index": {recipe_ref: recipe_entry, provenance_ref: provenance_entry}},
                root,
                errors,
            )
            self.assertTrue(errors)
            provenance["build_recipe_reference"] = "evidence:evidence/recipes-Dockerfile.node-app"
            provenance_path.write_text(json.dumps(provenance))
            errors = []
            verifier.validate_build_recipe_evidence(
                {"images": [image], "sources": manifest["sources"]},
                manifest["evidence_index"],
                root,
                errors,
            )
            self.assertTrue(errors)
    def test_patch_evidence_identity_and_content_digest_fail_closed(self):
        manifest = valid_manifest()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for source in manifest["sources"]:
                entry = manifest["evidence_index"][source["patch_reference"]]
                record = {
                    "name": source["name"],
                    "commit": source["commit"],
                    "patch_path": f"patches/{source['name']}.patch",
                    "patch_sha256": source["patch_content_sha256"],
                }
                content = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
                path = root / entry["path"]
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
                entry["sha256"] = hashlib.sha256(content).hexdigest()
            errors = []
            verifier.validate_patch_evidence(manifest, manifest["evidence_index"], root, errors)
            self.assertEqual(errors, [])
            source = manifest["sources"][0]
            path = root / manifest["evidence_index"][source["patch_reference"]]["path"]
            record = json.loads(path.read_text())
            record["patch_sha256"] = DIGEST
            path.write_text(json.dumps(record))
            errors = []
            verifier.validate_patch_evidence(manifest, manifest["evidence_index"], root, errors)
            self.assertTrue(errors)
            record["patch_sha256"] = source["patch_content_sha256"]
            record["commit"] = "c" * 40
            path.write_text(json.dumps(record))
            errors = []
            verifier.validate_patch_evidence(manifest, manifest["evidence_index"], root, errors)
            self.assertTrue(errors)

    def test_source_receipt_binds_exact_source_lock_digest(self):
        manifest = valid_manifest()
        reference = manifest["acquisition_receipt"]["reference"]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            entry = manifest["evidence_index"][reference]
            path = root / entry["path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(
                verifier.canonical_json(
                    {
                        "schema_version": "recova-jambonz-oss-source-evidence/v1",
                        "source_lock_sha256": "a" * 64,
                    }
                )
            )
            errors = []
            verifier.validate_source_lock_binding(
                manifest,
                manifest["evidence_index"],
                root,
                errors,
            )
            self.assertEqual(errors, [])
            manifest["source_lock_sha256"] = "sha256:" + "b" * 64
            errors = []
            verifier.validate_source_lock_binding(
                manifest,
                manifest["evidence_index"],
                root,
                errors,
            )
            self.assertTrue(errors)
    def test_archive_scanner_and_canonical_acceptance_evidence_bind_summary(self):
        manifest = valid_manifest()
        image = next(image for image in manifest["images"] if image["name"] == "freeswitch")
        archive = b"immutable-image-archive"
        image["network_archive_sha256"] = (
            "sha256:" + hashlib.sha256(archive).hexdigest()
        )
        database = {"built": "2026-07-01T00:00:00Z", "checksum": "a" * 64}
        grype = {"matches": []}
        acceptance = {"image": image["name"], "scanner": {"grype_version": image["scanner"]["grype_version"], "grype_db_identity": database}, "decisions": {}}
        archive_record = {"name": image["name"], "archive_reference": image["network_archive_reference"], "archive_sha256": "sha256:" + hashlib.sha256(archive).hexdigest(), "mode": "0444", "network_denied": True}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            index = {}
            def add(ref, content_type, content):
                path = root / ref.removeprefix("evidence:")
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
                index[ref] = {"path": str(path.relative_to(root)), "sha256": hashlib.sha256(content).hexdigest(), "content_type": content_type}
            add(image["network_archive_reference"], "application/x-tar", archive)
            add(image["network_archive_record_reference"], "text", verifier.canonical_json(archive_record))
            add(image["sbom_reference"], "application/vnd.anchore.syft+json", b'{"artifacts":"' + b"x" * (2 * 1_048_576) + b'"}')
            add(image["vulnerability_reference"], "application/vnd.anchore.grype+json", verifier.canonical_json(grype))
            add(image["scanner"]["grype_db_identity_reference"], "text", verifier.canonical_json(database))
            add(image["vulnerability_acceptance_reference"], "text", verifier.canonical_json(acceptance))
            errors = []
            verifier.validate_image_evidence({"images": [image]}, index, root, datetime(2026, 7, 15, tzinfo=timezone.utc), errors)
            self.assertEqual(errors, [])
            archive_record["network_denied"] = False
            path = root / index[image["network_archive_record_reference"]]["path"]
            path.write_bytes(verifier.canonical_json(archive_record))
            errors = []
            verifier.validate_image_evidence({"images": [image]}, index, root, datetime(2026, 7, 15, tzinfo=timezone.utc), errors)
            self.assertTrue(errors)
            archive_record["network_denied"] = True
            path.write_bytes(verifier.canonical_json(archive_record))
            acceptance["scanner"]["grype_version"] = "tampered"
            path = root / index[image["vulnerability_acceptance_reference"]]["path"]
            path.write_bytes(verifier.canonical_json(acceptance))
            errors = []
            verifier.validate_image_evidence({"images": [image]}, index, root, datetime(2026, 7, 15, tzinfo=timezone.utc), errors)
            self.assertTrue(errors)

    def test_runtime_contract_and_expired_acquisition_fail(self):
        manifest = valid_manifest()
        manifest["runtime_contract"]["inbound"]["timing"] = "post_answer"
        self.assert_invalid(manifest)
        manifest = valid_manifest()
        manifest["acquisition_receipt"]["expires_at"] = "2026-01-01T00:00:00Z"
        self.assert_invalid(manifest)

    def test_acquisition_expiry_cannot_exceed_any_acceptance_expiry(self):
        manifest = valid_manifest()
        image = manifest["images"][0]
        reference = image["vulnerability_acceptance_reference"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            entry = manifest["evidence_index"][reference]
            path = root / entry["path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            acceptance = {
                "image": image["name"],
                "scanner": {},
                "decisions": {
                    "later": {
                        "reason": "reviewed",
                        "expires_at": "2026-08-01T00:00:00Z",
                        "finding_sha256": "a" * 64,
                    },
                    "earlier": {
                        "reason": "reviewed",
                        "expires_at": "2026-07-20T00:00:00Z",
                        "finding_sha256": "b" * 64,
                    },
                },
            }
            path.write_bytes(verifier.canonical_json(acceptance))
            candidate = {
                "acquisition_receipt": manifest["acquisition_receipt"],
                "images": [image],
                "support_images": [],
            }
            manifest["acquisition_receipt"]["expires_at"] = "2026-07-21T00:00:00Z"
            errors = []
            verifier.validate_acceptance_expiry_bound(
                candidate, manifest["evidence_index"], root, errors
            )
            self.assertTrue(errors)
            manifest["acquisition_receipt"]["expires_at"] = "2026-07-20T00:00:00Z"
            errors = []
            verifier.validate_acceptance_expiry_bound(
                candidate, manifest["evidence_index"], root, errors
            )
            self.assertEqual(errors, [])

    def test_exact_membership_zero_unaccepted_and_runtime_bounds_fail_closed(self):
        mutations = (
            lambda m: m.__setitem__("source_lock_sha256", "pending"),
            lambda m: m["support_images"][1].__setitem__(
                "name", m["support_images"][0]["name"]
            ),
            lambda m: m["images"][0]["vulnerability_summary"].__setitem__(
                "unaccepted_high", 1
            ),
            lambda m: m["runtime_contract"]["registration"]["operations"][0].__setitem__(
                "max_wire_transmissions", 3
            ),
            lambda m: m["runtime_contract"]["registration"]["operations"][0].__setitem__(
                "max_wire_responses", 2
            ),
            lambda m: m["runtime_contract"]["registration"].__setitem__(
                "mode", "one_shot"
            ),
            lambda m: m["runtime_contract"]["registration"].__setitem__(
                "duplicate_exact_idempotent", True
            ),
            lambda m: m["runtime_contract"]["registration"].__setitem__(
                "automatic_retry", True
            ),
            lambda m: m["runtime_contract"]["registration"].__setitem__(
                "max_concurrency", 2
            ),
            lambda m: m["runtime_contract"]["calls"].__setitem__(
                "automatic_retry", True
            ),
            lambda m: m["runtime_contract"]["timers"].__setitem__(
                "call_deadline_seconds", 59
            ),
        )
        for mutate in mutations:
            manifest = valid_manifest()
            mutate(manifest)
            with self.subTest(mutate=mutate):
                self.assert_invalid(manifest)

    def test_unknown_duplicate_and_placeholder_values_fail(self):
        manifest = valid_manifest()
        manifest["images"][1]["name"] = manifest["images"][0]["name"]
        self.assert_invalid(manifest)
        manifest = valid_manifest()
        manifest["sources"][0]["name"] = "unknown-source"
        self.assert_invalid(manifest)
        manifest = valid_manifest()
        manifest["sources"][0]["repository"] = "https://github.com/jambonz/pending-source"
        self.assert_invalid(manifest)

    def test_g008_support_set_fields_and_exact_licenses_fail_closed(self):
        mutations = (
            lambda m: m["support_images"].pop(),
            lambda m: m["support_images"][0].pop("oci_license_reference"),
            lambda m: m["support_images"][0].pop("network_archive_reference"),
            lambda m: m["support_images"][0].__setitem__("license_spdx", "MIT"),
            lambda m: m["support_images"][0].__setitem__("name", "unrelated"),
        )
        for mutate in mutations:
            manifest = valid_manifest()
            mutate(manifest)
            manifest["review_payload_digest"] = verifier.review_payload_digest(manifest)
            with self.subTest(mutate=mutate):
                self.assert_invalid(manifest)

    def test_g008_registration_receipt_binding_and_es256_contract_fail_closed(self):
        mutations = (
            lambda m: m["runtime_contract"]["registration"].__setitem__("mode", "one_shot"),
            lambda m: m["runtime_contract"]["registration"].__setitem__("max_wire_responses", 2),
            lambda m: m["runtime_contract"]["registration"]["operations"].reverse(),
            lambda m: m["runtime_contract"]["registration"]["operations"][1].__setitem__(
                "causal_predecessor", "authority_receipt_digest"
            ),
            lambda m: m["runtime_contract"]["registration"]["receipt_binding_fields"].pop(),
            lambda m: m["runtime_contract"]["receipt_signing"]["dispatch"].__setitem__(
                "algorithm", "HS256"
            ),
            lambda m: m["runtime_contract"]["receipt_signing"]["media"].__setitem__(
                "trust_domain", "recova.dispatch"
            ),
        )
        for mutate in mutations:
            manifest = valid_manifest()
            mutate(manifest)
            manifest["review_payload_digest"] = verifier.review_payload_digest(manifest)
            with self.subTest(mutate=mutate):
                self.assert_invalid(manifest)

    def test_text_evidence_allows_markers_and_env_placeholders_but_rejects_secrets(self):
        def errors_for(
            content: bytes,
            reference: str = "evidence:evidence.txt",
        ) -> list[str]:
            digest = hashlib.sha256(content).hexdigest()
            data = {
                "disqualifier_results": {
                    "candidate_input": {
                        "result": "pass",
                        "reference": reference,
                        "sha256": "sha256:" + digest,
                    }
                },
                "evidence_index": {
                    reference: {
                        "path": "evidence.txt",
                        "sha256": digest,
                        "content_type": "text",
                    }
                },
            }
            with tempfile.TemporaryDirectory() as temporary:
                Path(temporary, "evidence.txt").write_bytes(content)
                errors = []
                verifier.validate_evidence(data, Path(temporary), errors)
                return errors

        safe = b'password: "${SIP_PASSWORD}"\n# TODO remains unresolved in source\n'
        self.assertEqual(errors_for(safe), [])
        for unsafe in (
            b"password: actual-credential-value\n",
            b'{"token":"actual-credential-value"}\n',
            b"-----BEGIN PRIVATE KEY-----\n",
            b"sip:alice@example.invalid\n",
            b"010-1234-5678\n",
            b"v=0\nm=audio 4000 RTP/AVP 0\n",
            b"RTP packet payload bytes\n",
        ):
            with self.subTest(unsafe=unsafe):
                self.assertTrue(errors_for(unsafe))
        source_reference = "evidence:evidence/runtime-config.txt"
        source_safe = (
            b'sip:example.invalid\n'
            b'v=0\nm=audio 4000 RTP/AVP 0\n'
            b'RTP packet payload bytes\n'
            b'password: "${SIP_PASSWORD}"\n'
        )
        self.assertEqual(
            errors_for(source_safe, source_reference),
            [],
        )
        for unsafe in (
            b"password: actual-credential-value\n",
            b"authorization: Basic dXNlcjpwYXNz\n",
            b"-----BEGIN PRIVATE KEY-----\n",
            b"010-1234-5678\n",
        ):
            with self.subTest(source_unsafe=unsafe):
                self.assertTrue(errors_for(unsafe, source_reference))

    def test_evidence_index_requires_exact_asserted_reference_set(self):
        manifest = valid_manifest()
        reference = next(iter(manifest["evidence_index"]))
        manifest["evidence_index"].pop(reference)
        errors = []
        verifier.validate_evidence(manifest, Path("/nonexistent"), errors)
        self.assertIn(
            "evidence_index: must contain exactly all asserted evidence references",
            errors,
        )

        manifest = valid_manifest()
        manifest["evidence_index"]["evidence:extra.txt"] = {
            "path": "extra.txt",
            "sha256": "a" * 64,
            "content_type": "text",
        }
        errors = []
        verifier.validate_evidence(manifest, Path("/nonexistent"), errors)
        self.assertIn(
            "evidence_index: must contain exactly all asserted evidence references",
            errors,
        )

    def test_support_oci_license_evidence_binds_exact_image(self):
        support = valid_manifest()["support_images"][0]
        labels = {
            "org.opencontainers.image.licenses": support["license_spdx"],
            "org.recova.base.digest": f"registry.example/base@{DIGEST}",
        }
        support["base_images"] = [verifier.redact_image_reference(labels["org.recova.base.digest"])]
        notice = verifier.canonical_json(
            {"name": support["name"], "image": support["image"], "oci_labels": labels}
        )
        oci_license = {
            "name": support["name"],
            "image": support["image"],
            "license_spdx": support["license_spdx"],
            "oci_labels_sha256": "sha256:"
            + hashlib.sha256(verifier.canonical_json(labels)).hexdigest(),
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            notice_path = root / "notice.json"
            license_path = root / "license.json"
            notice_path.write_bytes(notice)
            license_path.write_bytes(verifier.canonical_json(oci_license))
            provenance_path = root / "provenance.json"
            provenance_path.write_bytes(
                verifier.canonical_json(
                    {
                        "image": support["image"],
                        "name": support["name"],
                        "source": support["source"],
                        "source_provenance": support["source_provenance"],
                    }
                )
            )
            index = {
                support["source_provenance_reference"]: {
                    "path": "provenance.json",
                    "content_type": "text",
                },
                support["notices_reference"]: {
                    "path": "notice.json",
                    "content_type": "text",
                },
                support["oci_license_reference"]: {
                    "path": "license.json",
                    "content_type": "text",
                },
            }
            errors = []
            verifier.validate_support_evidence(
                {"support_images": [support]}, index, root, errors
            )
            self.assertEqual(errors, [])
            oci_license["image"] = f"registry.example/unrelated@{DIGEST}"
            license_path.write_bytes(verifier.canonical_json(oci_license))
            errors = []
            verifier.validate_support_evidence(
                {"support_images": [support]}, index, root, errors
            )
            self.assertTrue(errors)
    def test_evidence_traversal_digest_mismatch_and_secret_fail(self):
        manifest = valid_manifest()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for entry in manifest["evidence_index"].values():
                file = root / entry["path"]
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text("clean evidence")
                entry["sha256"] = hashlib.sha256(b"clean evidence").hexdigest()
            for ref, entry in manifest["evidence_index"].items():
                self.assertIn(ref, verifier.evidence_assertions(manifest))
            errors = []
            manifest["evidence_index"]["evidence:receipt.txt"]["path"] = "../receipt.txt"
            verifier.validate_evidence(manifest, root, errors)
            self.assertTrue(errors)
        manifest = valid_manifest()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for entry in manifest["evidence_index"].values():
                file = root / entry["path"]
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text("token=raw-secret")
            errors = []
            verifier.validate_evidence(manifest, root, errors)
            self.assertTrue(any("forbidden" in error for error in errors))

    def test_rejects_personal_metadata_but_permits_organizational_identity(self):
        self.assertTrue(verifier.contains_personal_metadata({"author": "Ada Lovelace"}))
        self.assertTrue(verifier.contains_personal_metadata({"maintainer": "ada@example.com"}))
        self.assertTrue(
            verifier.contains_personal_metadata(
                {"licenses": [{"copyright": "Copyright 1843-1852 Ada Lovelace"}]}
            )
        )
        self.assertTrue(verifier.contains_personal_metadata({"licenses": [{"copyright": "ada@example.com"}]}))
        self.assertFalse(verifier.contains_personal_metadata({"name": "Recova Voice"}))


if __name__ == "__main__":
    unittest.main()
