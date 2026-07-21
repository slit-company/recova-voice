import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).parent
SPEC = importlib.util.spec_from_file_location("audit", HERE / "audit_static_source_policy.py")
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


class StaticPolicyAuditTests(unittest.TestCase):
    def make_case(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        policy = json.loads((HERE / "source_policy_manifest.json").read_text())
        entries = []
        for relative in policy["required_paths"]:
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if relative.endswith("/outputs.tf"):
                content = "\n".join(
                    f'output "{name}" {{ value = "synthetic" }}'
                    for name in policy["allowed_active_outputs"]
                )
            elif relative.endswith("README.md") or relative.endswith("decision.md"):
                content = "open-confirmations-pending offline"
            else:
                content = ""
            target.write_text(content)
            entries.append({"path": relative, "state": "present", "sha256": hashlib.sha256(content.encode()).hexdigest()})
        expected = root / "expected.json"
        expected.write_text(json.dumps({"entry_count": 39, "entries": entries}))
        policy_path = root / "policy.json"
        policy_path.write_text(json.dumps(policy))
        return temporary, root, policy_path, expected

    def test_accepts_matching_complete_inventory(self):
        temporary, root, policy, expected = self.make_case()
        with temporary:
            self.assertEqual([], audit.audit(root, policy, expected, hashlib.sha256(expected.read_bytes()).hexdigest()))

    def test_rejects_hash_drift(self):
        temporary, root, policy, expected = self.make_case()
        with temporary:
            (root / "infra/onnuri-seoul-staging-phase-b/versions.tf").write_text("changed")
            findings = audit.audit(root, policy, expected, hashlib.sha256(expected.read_bytes()).hexdigest())
            self.assertIn((audit.RULE_HASH, "infra/onnuri-seoul-staging-phase-b/versions.tf"), findings)

    def test_rejects_active_output_block(self):
        temporary, root, policy, expected = self.make_case()
        with temporary:
            target = root / "infra/onnuri-seoul-staging-phase-b/network.tf"
            data = target.read_bytes() + b'output "bad" {}'
            target.write_bytes(data)
            entries = json.loads(expected.read_text())["entries"]
            for entry in entries:
                if entry["path"] == "infra/onnuri-seoul-staging-phase-b/network.tf":
                    entry["sha256"] = hashlib.sha256(data).hexdigest()
            expected.write_text(json.dumps({"entry_count": 39, "entries": entries}))
            findings = audit.audit(root, policy, expected, hashlib.sha256(expected.read_bytes()).hexdigest())
            self.assertIn((audit.RULE_TERRAFORM, "infra/onnuri-seoul-staging-phase-b/network.tf"), findings)


if __name__ == "__main__":
    unittest.main()
