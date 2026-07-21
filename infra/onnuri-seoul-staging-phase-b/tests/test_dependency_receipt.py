import base64
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("dependency_receipt", HERE.parent / "dependency_receipt.py")
receipt = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(receipt)


class DependencyReceiptTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.private = Ed25519PrivateKey.generate()
        self.private_bytes = self.private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        self.public_bytes = self.private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self.payload = {
            "contract_version": receipt.CONTRACT_VERSION,
            "project_id": "slit-497603",
            "region": "asia-northeast3",
            "subnet_ipv4_cidr": "10.73.96.0/24",
            "state_backend_bucket": "phase-b-state",
            "state_backend_prefix": "onnuri/phase-b",
            "state_generation": 17,
            "state_serial": 4,
            "canonical_state_sha256": "a" * 64,
            "canonical_output_sha256": "b" * 64,
            "canonical_source_sha256": "c" * 64,
            "ingress_deny_rule_self_link": "https://www.googleapis.com/compute/v1/projects/slit-497603/global/firewalls/deny-ingress",
            "egress_deny_rule_self_link": "https://www.googleapis.com/compute/v1/projects/slit-497603/global/firewalls/deny-egress",
            "issued_at": "2026-07-16T00:00:00Z",
            "expires_at": "2026-07-17T00:00:00Z",
            "signer_key_id": "phase-b-leader-1",
        }
        self.scope = {name: self.payload[name] for name in receipt.SCOPE_FIELDS}
        self._write("manifest.json", self.payload)
        self._write("private.json", {"key_id": self.payload["signer_key_id"], "private_key_b64": base64.b64encode(self.private_bytes).decode("ascii")})
        self._write("trusted.json", {"key_id": self.payload["signer_key_id"], "public_key_b64": base64.b64encode(self.public_bytes).decode("ascii")})
        self._write("scope.json", self.scope)
        Path(self.root / "receipt.json").write_bytes(receipt.sign(str(self.root / "manifest.json"), str(self.root / "private.json")))

    def tearDown(self):
        self.temporary.cleanup()

    def _write(self, name, value):
        (self.root / name).write_bytes(receipt.canonical_json(value))

    def _verify(self, name="receipt.json", now="2026-07-16T12:00:00Z"):
        receipt.verify(str(self.root / name), str(self.root / "trusted.json"), str(self.root / "scope.json"), now)

    def _assert_rejected(self, raw):
        (self.root / "candidate.json").write_bytes(raw)
        with self.assertRaises(receipt.ReceiptError):
            self._verify("candidate.json")

    def test_sign_and_verify_canonical_receipt(self):
        self._verify()

    def test_rejects_tampering(self):
        candidate = json.loads((self.root / "receipt.json").read_bytes())
        candidate["payload"]["state_serial"] = 5
        self._assert_rejected(receipt.canonical_json(candidate))

    def test_rejects_expired_receipt(self):
        with self.assertRaisesRegex(receipt.ReceiptError, "expired"):
            self._verify(now="2026-07-17T00:00:00Z")

    def test_rejects_unknown_and_duplicate_json_keys(self):
        candidate = json.loads((self.root / "receipt.json").read_bytes())
        candidate["unexpected"] = "value"
        self._assert_rejected(receipt.canonical_json(candidate))
        self._assert_rejected(b'{"payload":{},"payload":{},"signature_b64":""}')

    def test_rejects_wrong_scope_and_noncanonical_receipt(self):
        self._write("wrong-scope.json", {**self.scope, "region": "us-central1"})
        with self.assertRaisesRegex(receipt.ReceiptError, "scope"):
            receipt.verify(str(self.root / "receipt.json"), str(self.root / "trusted.json"), str(self.root / "wrong-scope.json"), "2026-07-16T12:00:00Z")
        raw = (self.root / "receipt.json").read_bytes()
        self._assert_rejected(raw.replace(b",", b", ", 1))

    def test_rejects_missing_payload_field(self):
        candidate = json.loads((self.root / "receipt.json").read_bytes())
        del candidate["payload"]["canonical_source_sha256"]
        self._assert_rejected(receipt.canonical_json(candidate))


if __name__ == "__main__":
    unittest.main()
