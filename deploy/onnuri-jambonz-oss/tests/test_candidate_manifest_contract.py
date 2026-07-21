from __future__ import annotations

import copy
import json
import re
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import verify_candidate as verifier

DIGEST = "sha256:" + "0" * 64
IMAGE = "example.invalid/image@" + DIGEST
REFERENCE = "evidence:evidence/item"
NODE_APP_DOCKERFILE = ROOT / "Dockerfile.node-app"
DRACHTIO_DOCKERFILE = ROOT / "Dockerfile.drachtio"


def support(name: str) -> dict[str, object]:
    scanner = {
        "syft_version": "1", "grype_version": "1",
        "grype_db_identity_reference": REFERENCE,
        "grype_db_identity_sha256": DIGEST,
    }
    value: dict[str, object] = {
        "name": name, "image": IMAGE, "platform": "linux/amd64",
        "base_images": [IMAGE], "license_spdx": "MIT",
        "scanner": scanner,
        "vulnerability_summary": {
            "critical": 0, "high": 0,
            "unaccepted_critical": 0, "unaccepted_high": 0,
        },
    }
    for reference_field, digest_field in verifier.SUPPORT_EVIDENCE:
        value[reference_field] = REFERENCE + "-" + reference_field
        value[digest_field] = DIGEST
    return value


def candidate() -> dict[str, object]:
    value: dict[str, object] = {
        "runtime_contract": {
            "receipt_signing": copy.deepcopy(verifier.SIGNING),
            "registration": {
                "mode": "one_register_then_unregister",
                "automatic_retry": False,
                "max_concurrency": 1,
                "receipt_binding_fields": list(verifier.BINDING_FIELDS),
                "operations": copy.deepcopy(verifier.OPERATIONS),
            },
        },
        "support_images": [support(name) for name in sorted(verifier.SUPPORT_IMAGES)],
    }
    value["review_payload_digest"] = verifier.g009.review_payload_digest(value)
    return value


class CandidateManifestContractTests(unittest.TestCase):
    def errors(self, value: dict[str, object]) -> list[str]:
        value["review_payload_digest"] = verifier.g009.review_payload_digest(value)
        with mock.patch.object(verifier.g009, "validate_manifest", return_value=[]):
            return verifier.validate_manifest(value, datetime.now(timezone.utc))

    def test_schema_is_closed_and_requires_exact_support_set_and_evidence(self) -> None:
        schema = json.loads((ROOT / "candidate-manifest.schema.json").read_text())
        support_schema = schema["properties"]["support_images"]
        self.assertEqual((support_schema["minItems"], support_schema["maxItems"]), (7, 7))
        self.assertFalse(schema["$defs"]["support_image"]["additionalProperties"])
        self.assertEqual(set(schema["$defs"]["support_image"]["properties"]["name"]["enum"]), verifier.SUPPORT_IMAGES)
        required = set(schema["$defs"]["support_image"]["required"])
        for reference_field, digest_field in verifier.SUPPORT_EVIDENCE:
            self.assertIn(reference_field, required)
            self.assertIn(digest_field, required)
        runtime_reference = schema["properties"]["runtime_contract"]["$ref"]
        self.assertEqual(runtime_reference, "#/$defs/runtime_contract")
        runtime_schema = schema["$defs"][runtime_reference.rsplit("/", 1)[-1]]
        registration_schema = runtime_schema["properties"]["registration"]
        registration = candidate()["runtime_contract"]["registration"]
        self.assertEqual(
            list(jsonschema.Draft202012Validator(registration_schema).iter_errors(registration)),
            [],
        )
        for index in range(2):
            operation_mutations = []
            value = copy.deepcopy(registration); del value["operations"][index]["max_wire_transmissions"]; operation_mutations.append(value)
            value = copy.deepcopy(registration); value["operations"][index]["max_wire_transmissions"] = 3; operation_mutations.append(value)
            value = copy.deepcopy(registration); del value["operations"][index]["max_wire_transmissions"]; value["operations"][index]["max_wire_responses"] = 2; operation_mutations.append(value)
            value = copy.deepcopy(registration); value["operations"][index]["challenge_aware"] = False; operation_mutations.append(value)
            value = copy.deepcopy(registration); value["operations"][index]["automatic_retry"] = True; operation_mutations.append(value)
            value = copy.deepcopy(registration); value["operations"][index]["max_concurrency"] = 2; operation_mutations.append(value)
            value = copy.deepcopy(registration); value["operations"][index]["causal_predecessor"] = "register_receipt_digest" if index == 0 else "authority_receipt_digest"; operation_mutations.append(value)
            for mutated in operation_mutations:
                self.assertTrue(
                    list(jsonschema.Draft202012Validator(registration_schema).iter_errors(mutated))
                )
        for field, widened in (("automatic_retry", True), ("max_concurrency", 2)):
            mutated = copy.deepcopy(registration)
            mutated[field] = widened
            self.assertTrue(
                list(jsonschema.Draft202012Validator(registration_schema).iter_errors(mutated))
            )

    def test_runtime_dockerfiles_keep_exact_platform_provenance_and_license_labels(self) -> None:
        expected_labels = {
            NODE_APP_DOCKERFILE: {
                "org.opencontainers.image.source": "$SOURCE_REPOSITORY",
                "org.opencontainers.image.revision": "$SOURCE_COMMIT",
                "org.opencontainers.image.licenses": "MIT",
                "org.recova.patch.sha256": "sha256:$SOURCE_PATCH_SHA256",
                "org.recova.base.digest": (
                    "node:24-alpine@sha256:"
                    "4ba75f835bb8802193e4c114572113d4b26f95f6f094f4b5229d2a77773e0afc"
                ),
            },
            DRACHTIO_DOCKERFILE: {
                "org.opencontainers.image.source": "https://github.com/drachtio/drachtio-server",
                "org.opencontainers.image.revision": "4bf0f5796b6a09e2789594a2d8f257ffd61f1d02",
                "org.opencontainers.image.licenses": "MIT",
                "org.recova.patch.sha256": "sha256:$SOURCE_PATCH_SHA256",
                "org.recova.base.digest": (
                    "debian:12-slim@sha256:"
                    "63a496b5d3b99214b39f5ed70eb71a61e590a77979c79cbee4faf991f8c0783e"
                ),
            },
        }
        for path, labels in expected_labels.items():
            with self.subTest(path=path.name):
                final_stage = "FROM " + path.read_text().rsplit("\nFROM ", 1)[-1]
                self.assertRegex(final_stage, r"\AFROM --platform=linux/amd64 ")
                for label, value in labels.items():
                    self.assertEqual(final_stage.count(f'{label}="{value}"'), 1)
                self.assertEqual(
                    re.findall(
                        r'org\.opencontainers\.image\.licenses="([^"]*)"',
                        final_stage,
                    ),
                    ["MIT"],
                )

    def test_rejects_missing_extra_mutable_and_missing_evidence(self) -> None:
        missing = candidate()
        missing["support_images"] = missing["support_images"][:-1]
        self.assertTrue(self.errors(missing))
        extra = candidate()
        extra["support_images"].append(support("unexpected"))
        self.assertTrue(self.errors(extra))
        mutable = candidate()
        mutable["support_images"][0]["image"] = "example.invalid/image:latest"
        self.assertTrue(self.errors(mutable))
        incomplete = candidate()
        del incomplete["support_images"][0]["sbom_reference"]
        self.assertTrue(self.errors(incomplete))

    def test_rejects_same_signing_key_or_domain(self) -> None:
        for field in ("key_id", "trust_domain"):
            value = candidate()
            signing = value["runtime_contract"]["receipt_signing"]
            signing["media"][field] = signing["dispatch"][field]
            self.assertTrue(self.errors(value), field)

    def test_rejects_registration_cardinality_transmission_retry_concurrency_and_causality_widening(self) -> None:
        mutations = []
        value = candidate(); value["runtime_contract"]["registration"]["operations"].pop(); mutations.append(value)
        for index in range(2):
            value = candidate(); del value["runtime_contract"]["registration"]["operations"][index]["max_wire_transmissions"]; mutations.append(value)
            value = candidate(); value["runtime_contract"]["registration"]["operations"][index]["max_wire_transmissions"] = 3; mutations.append(value)
            value = candidate(); del value["runtime_contract"]["registration"]["operations"][index]["max_wire_transmissions"]; value["runtime_contract"]["registration"]["operations"][index]["max_wire_responses"] = 2; mutations.append(value)
            value = candidate(); value["runtime_contract"]["registration"]["operations"][index]["challenge_aware"] = False; mutations.append(value)
            value = candidate(); value["runtime_contract"]["registration"]["operations"][index]["automatic_retry"] = True; mutations.append(value)
            value = candidate(); value["runtime_contract"]["registration"]["operations"][index]["max_concurrency"] = 2; mutations.append(value)
            value = candidate(); value["runtime_contract"]["registration"]["operations"][index]["causal_predecessor"] = "register_receipt_digest" if index == 0 else "authority_receipt_digest"; mutations.append(value)
        value = candidate(); value["runtime_contract"]["registration"]["automatic_retry"] = True; mutations.append(value)
        value = candidate(); value["runtime_contract"]["registration"]["max_concurrency"] = 2; mutations.append(value)
        value = candidate(); value["runtime_contract"]["registration"]["receipt_binding_fields"].remove("candidate_digest"); mutations.append(value)
        for value in mutations:
            self.assertTrue(self.errors(value))


if __name__ == "__main__":
    unittest.main()
