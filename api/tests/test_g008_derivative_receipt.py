from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

MODULE_PATH = Path(__file__).parents[2] / "deploy" / "onnuri-jambonz-oss" / "g008_derivative_receipt.py"
SPEC = importlib.util.spec_from_file_location("g008_derivative_receipt", MODULE_PATH)
assert SPEC and SPEC.loader
receipt_tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(receipt_tool)

NOW = datetime(2026, 7, 16, 12, 0, tzinfo=UTC)


class G008DerivativeReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate.json"
        self.metadata = self.root / "images.json"
        self.receipt_path = self.root / "receipt.json"
        self.private_path = self.root / "private.pem"
        self.public_path = self.root / "public.pem"
        self.key = Ed25519PrivateKey.generate()
        self.private_path.write_bytes(
            self.key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        self.public_path.write_bytes(
            self.key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        self._write_canonical(self.candidate, {"candidate_generation": "g009", "sealed": True})
        self.images = [self._image(name, index) for index, name in enumerate(receipt_tool.REQUIRED_IMAGES, 1)]
        self._write_canonical(self.metadata, {"images": self.images})

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _image(name: str, index: int) -> dict[str, object]:
        digit = format(index, "x")
        return {
            "name": name,
            "image": f"registry.example/recova/{name}@sha256:{digit * 64}",
            "platform": "linux/amd64",
            "labels": {
                "org.opencontainers.image.source": (
                    receipt_tool.BACKEND_SOURCE
                    if name in {"recova-backend", "facade"}
                    else f"https://github.com/recova/{name}"
                ),
                **(
                    {"org.opencontainers.image.revision": digit * 64}
                    if name == "recova-backend"
                    else (
                        {"org.recova.source-tree.sha256": digit * 64}
                        if name == "facade"
                        else {"org.opencontainers.image.revision": digit * 40}
                    )
                ),
                "org.opencontainers.image.licenses": "Apache-2.0",
                "org.recova.base.digest": f"registry.example/base/{name}@sha256:{(digit * 2)[:1] * 64}",
            },
            "sbom_sha256": "sha256:" + format(index + 4, "x") * 64,
            "vulnerability_sha256": "sha256:" + format(index + 8, "x") * 64,
        }

    @staticmethod
    def _write_canonical(path: Path, value: object) -> None:
        path.write_bytes(receipt_tool.canonical_json(value))

    def _create(self) -> dict[str, object]:
        receipt = receipt_tool.create_receipt(
            self.candidate,
            self.metadata,
            self.private_path,
            "g008-release-operator",
            "2026-07-16T11:50:00Z",
            "2026-07-16T12:10:00Z",
            "2026-07-16T11:55:00Z",
            "2026-07-16T12:05:00Z",
        )
        self._write_canonical(self.receipt_path, receipt)
        return receipt

    def _resign(self, receipt: dict[str, object]) -> None:
        payload = receipt["payload"]
        assert isinstance(payload, dict)
        receipt["signature"]["value_b64"] = __import__("base64").b64encode(
            self.key.sign(receipt_tool.canonical_json(payload))
        ).decode("ascii")
        self._write_canonical(self.receipt_path, receipt)

    def test_create_and_verify_binds_candidate_images_evidence_and_key(self) -> None:
        receipt = self._create()
        verified = receipt_tool.verify_receipt(self.receipt_path, self.candidate, self.public_path, NOW)
        self.assertEqual(verified, receipt)
        payload = receipt["payload"]
        self.assertEqual(payload["candidate_manifest_sha256"], receipt_tool.sha256(self.candidate.read_bytes()))
        self.assertEqual([item["name"] for item in payload["images"]], list(receipt_tool.REQUIRED_IMAGES))
        self.assertTrue(all(item["image_receipt_sha256"] == receipt_tool.image_receipt_digest(item) for item in payload["images"]))
        self.assertEqual(self.receipt_path.read_bytes(), receipt_tool.canonical_json(receipt))

    def test_create_rejects_missing_duplicate_or_unknown_images(self) -> None:
        cases = [
            self.images[:-1],
            [*self.images[:-1], copy.deepcopy(self.images[0])],
            [*self.images[:-1], dict(copy.deepcopy(self.images[-1]), name="unknown")],
        ]
        for images in cases:
            with self.subTest(names=[item["name"] for item in images]):
                self._write_canonical(self.metadata, {"images": images})
                with self.assertRaises(receipt_tool.ReceiptError):
                    self._create()

    def test_create_rejects_mutable_refs_wrong_platform_and_wrong_labels(self) -> None:
        mutations = (
            lambda image: image.update(image="registry.example/recova/backend:latest"),
            lambda image: image.update(image="registry.example/recova/backend:release@sha256:" + "a" * 64),
            lambda image: image.update(platform="linux/arm64"),
            lambda image: image["labels"].update({"org.opencontainers.image.revision": "main"}),
            lambda image: image["labels"].update({"org.recova.base.digest": "python:latest"}),
            lambda image: image["labels"].update({"org.opencontainers.image.source": "https://user:secret@example.com/src"}),
            lambda image: image["labels"].update({"secret": "must-not-be-accepted"}),
        )
        for mutate in mutations:
            images = copy.deepcopy(self.images)
            mutate(images[0])
            self._write_canonical(self.metadata, {"images": images})
            with self.subTest(mutation=mutate), self.assertRaises(receipt_tool.ReceiptError):
                self._create()

    def test_verifier_rejects_signature_and_evidence_hash_mismatch(self) -> None:
        original = self._create()
        for mutation in (
            lambda receipt: receipt["payload"]["images"][0].update(sbom_sha256="sha256:" + "f" * 64),
            lambda receipt: receipt["payload"]["images"][0].update(vulnerability_sha256="sha256:" + "e" * 64),
            lambda receipt: receipt["signature"].update(value_b64="A" * 88),
        ):
            changed = copy.deepcopy(original)
            mutation(changed)
            self._write_canonical(self.receipt_path, changed)
            with self.subTest(mutation=mutation), self.assertRaises(receipt_tool.ReceiptError):
                receipt_tool.verify_receipt(self.receipt_path, self.candidate, self.public_path, NOW)

    def test_verifier_rejects_invalid_per_image_receipt_digest_even_when_resigned(self) -> None:
        receipt = self._create()
        receipt["payload"]["images"][0]["image_receipt_sha256"] = "sha256:" + "f" * 64
        self._resign(receipt)
        with self.assertRaisesRegex(receipt_tool.ReceiptError, "receipt digest mismatch"):
            receipt_tool.verify_receipt(self.receipt_path, self.candidate, self.public_path, NOW)

    def test_verifier_rejects_candidate_mismatch(self) -> None:
        self._create()
        self._write_canonical(self.candidate, {"candidate_generation": "different", "sealed": True})
        with self.assertRaisesRegex(receipt_tool.ReceiptError, "candidate manifest digest mismatch"):
            receipt_tool.verify_receipt(self.receipt_path, self.candidate, self.public_path, NOW)

    def test_verifier_rejects_stale_or_not_yet_open_live_window(self) -> None:
        self._create()
        for instant in (
            datetime(2026, 7, 16, 11, 54, tzinfo=UTC),
            datetime(2026, 7, 16, 12, 6, tzinfo=UTC),
        ):
            with self.subTest(instant=instant), self.assertRaisesRegex(receipt_tool.ReceiptError, "live window"):
                receipt_tool.verify_receipt(self.receipt_path, self.candidate, self.public_path, instant)

    def test_creation_rejects_issue_expiry_not_covering_live_window(self) -> None:
        with self.assertRaisesRegex(receipt_tool.ReceiptError, "cover"):
            receipt_tool.create_receipt(
                self.candidate,
                self.metadata,
                self.private_path,
                "operator",
                "2026-07-16T11:56:00Z",
                "2026-07-16T12:04:00Z",
                "2026-07-16T11:55:00Z",
                "2026-07-16T12:05:00Z",
            )

    def test_verifier_rejects_wrong_key_and_noncanonical_receipts(self) -> None:
        receipt = self._create()
        other_key = Ed25519PrivateKey.generate().public_key()
        other_public = self.root / "other-public.pem"
        other_public.write_bytes(
            other_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        )
        with self.assertRaisesRegex(receipt_tool.ReceiptError, "fingerprint"):
            receipt_tool.verify_receipt(self.receipt_path, self.candidate, other_public, NOW)
        self.receipt_path.write_text(json.dumps(receipt, indent=2), encoding="utf-8")
        with self.assertRaisesRegex(receipt_tool.ReceiptError, "not canonical"):
            receipt_tool.verify_receipt(self.receipt_path, self.candidate, self.public_path, NOW)


if __name__ == "__main__":
    unittest.main()
