from __future__ import annotations

import base64
import copy
import importlib.util
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


receipt_tool = load_module("g008_derivative_receipt", ROOT / "g008_derivative_receipt.py")
sealer = load_module("seal_candidate_provenance", ROOT / "seal_candidate.py")
NOW = datetime(2026, 7, 16, 12, 0, tzinfo=UTC)


class G008DerivativeReceiptProvenanceTests(unittest.TestCase):
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
        self.write(self.candidate, {"candidate_generation": "g009", "sealed": True})
        self.images = [self.image(name, index) for index, name in enumerate(receipt_tool.REQUIRED_IMAGES, 1)]
        self.write(self.metadata, {"images": self.images})

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def image(name: str, index: int) -> dict[str, object]:
        digit = format(index, "x")
        backend = name == "recova-backend"
        return {
            "name": name,
            "image": f"registry.example/recova/{name}@sha256:{digit * 64}",
            "platform": "linux/amd64",
            "labels": {
                "org.opencontainers.image.source": (
                    receipt_tool.BACKEND_SOURCE if backend else f"https://github.com/example/{name}"
                ),
                "org.opencontainers.image.revision": digit * (64 if backend else 40),
                "org.opencontainers.image.licenses": "Apache-2.0",
                "org.recova.base.digest": f"registry.example/base/{name}@sha256:{digit * 64}",
            },
            "sbom_sha256": "sha256:" + format(index + 4, "x") * 64,
            "vulnerability_sha256": "sha256:" + format(index + 8, "x") * 64,
        }

    @staticmethod
    def write(path: Path, value: object) -> None:
        path.write_bytes(receipt_tool.canonical_json(value))

    def create(self) -> dict[str, object]:
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
        self.write(self.receipt_path, receipt)
        return receipt

    def resign(self, receipt: dict[str, object]) -> None:
        payload = receipt["payload"]
        assert isinstance(payload, dict)
        signature = receipt["signature"]
        assert isinstance(signature, dict)
        signature["value_b64"] = base64.b64encode(
            self.key.sign(receipt_tool.canonical_json(payload))
        ).decode("ascii")
        self.write(self.receipt_path, receipt)

    def test_backend_snapshot_is_typed_and_bound_as_source_tree_sha256(self) -> None:
        receipt = self.create()
        verified = receipt_tool.verify_receipt(
            self.receipt_path, self.candidate, self.public_path, NOW
        )
        backend = verified["payload"]["images"][0]
        self.assertEqual(
            backend["source_provenance"],
            {
                "label": "org.opencontainers.image.revision",
                "type": "source_tree_sha256",
                "value": "sha256:" + "1" * 64,
            },
        )
        self.assertEqual(
            backend["image_receipt_sha256"], receipt_tool.image_receipt_digest(backend)
        )

    def test_create_rejects_backend_commit_wrong_source_and_malformed_snapshot(self) -> None:
        mutations = (
            lambda labels: labels.update({"org.opencontainers.image.revision": "1" * 40}),
            lambda labels: labels.update({"org.opencontainers.image.revision": "A" * 64}),
            lambda labels: labels.update({"org.opencontainers.image.source": "https://github.com/example/fork"}),
        )
        for mutate in mutations:
            images = copy.deepcopy(self.images)
            mutate(images[0]["labels"])
            self.write(self.metadata, {"images": images})
            with self.subTest(mutation=mutate), self.assertRaises(receipt_tool.ReceiptError):
                self.create()

    def test_create_accepts_immutable_source_image_digest_for_non_git_support_image(self) -> None:
        images = copy.deepcopy(self.images)
        images[1]["labels"]["org.opencontainers.image.revision"] = "sha256:" + "2" * 64
        self.write(self.metadata, {"images": images})
        receipt = self.create()
        self.assertEqual(
            receipt["payload"]["images"][1]["source_provenance"],
            {
                "label": "org.opencontainers.image.revision",
                "type": "source_image_digest",
                "value": "sha256:" + "2" * 64,
            },
        )

    def test_verifier_rejects_resigned_provenance_type_value_and_label_tampering(self) -> None:
        original = self.create()
        mutations = (
            lambda provenance: provenance.update({"type": "git_revision"}),
            lambda provenance: provenance.update({"value": "sha256:" + "f" * 64}),
            lambda provenance: provenance.update({"label": "org.recova.source-tree.sha256"}),
        )
        for mutate in mutations:
            receipt = copy.deepcopy(original)
            provenance = receipt["payload"]["images"][0]["source_provenance"]
            mutate(provenance)
            receipt["payload"]["images"][0]["image_receipt_sha256"] = receipt_tool.image_receipt_digest(
                receipt["payload"]["images"][0]
            )
            self.resign(receipt)
            with self.subTest(mutation=mutate), self.assertRaisesRegex(
                receipt_tool.ReceiptError, "source provenance mismatch"
            ):
                receipt_tool.verify_receipt(
                    self.receipt_path, self.candidate, self.public_path, NOW
                )

    def test_sealer_requires_exact_first_party_source_and_typed_label(self) -> None:
        base = {
            "org.opencontainers.image.source": sealer.FIRST_PARTY_SUPPORT_SOURCE,
            "org.opencontainers.image.revision": "a" * 64,
        }
        self.assertEqual(
            sealer.support_image_provenance("recova-backend", base),
            {
                "label": "org.opencontainers.image.revision",
                "type": "source_tree_sha256",
                "value": "sha256:" + "a" * 64,
            },
        )
        facade = {
            "org.opencontainers.image.source": sealer.FIRST_PARTY_SUPPORT_SOURCE,
            "org.opencontainers.image.revision": "b" * 64,
        }
        self.assertEqual(
            sealer.support_image_provenance("facade", facade)["type"],
            "source_tree_sha256",
        )
        self.assertEqual(
            sealer.support_image_provenance(
                "f12-ingress",
                {
                    "org.opencontainers.image.source": "https://github.com/nginx/nginx",
                    "org.opencontainers.image.revision": "sha256:" + "c" * 64,
                },
            ),
            {
                "label": "org.opencontainers.image.revision",
                "type": "source_image_digest",
                "value": "sha256:" + "c" * 64,
            },
        )
        for name, labels in (
            ("recova-backend", dict(base, **{"org.opencontainers.image.source": "https://github.com/example/fork"})),
            ("recova-backend", {**base, "org.recova.source-tree.sha256": "b" * 64}),
            ("facade", {**facade, "org.opencontainers.image.revision": "b" * 40}),
        ):
            with self.subTest(name=name, labels=labels), self.assertRaises(sealer.Refusal):
                sealer.support_image_provenance(name, labels)


if __name__ == "__main__":
    unittest.main()
