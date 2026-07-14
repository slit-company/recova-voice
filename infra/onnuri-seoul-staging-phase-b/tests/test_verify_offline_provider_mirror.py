from __future__ import annotations

import hashlib
import json
import importlib.util
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("verify_offline_provider_mirror.py")
SPEC = importlib.util.spec_from_file_location("verify_offline_provider_mirror", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
mirror_verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mirror_verifier)


class OfflineProviderMirrorTests(unittest.TestCase):
    def make_fixture(self) -> tuple[tempfile.TemporaryDirectory[str], Path, Path, Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        mirror = root / "mirror"
        checksums = []
        archives = {}
        provider_directory = mirror_verifier._provider_directory(mirror)
        provider_directory.mkdir(parents=True, exist_ok=True)
        for platform in mirror_verifier.PLATFORMS:
            artifact = mirror_verifier._expected_artifact(mirror, platform)
            artifact.write_bytes(f"package-{platform}".encode())
            checksums.append(hashlib.sha256(artifact.read_bytes()).hexdigest())
            archives[platform] = {
                "url": artifact.name,
                "hashes": [f"h1:fixture-{platform}"],
            }
        (provider_directory / "index.json").write_text(
            json.dumps({"versions": {mirror_verifier.PROVIDER_VERSION: {}}}),
            encoding="utf-8",
        )
        (provider_directory / f"{mirror_verifier.PROVIDER_VERSION}.json").write_text(
            json.dumps({"archives": archives}),
            encoding="utf-8",
        )

        lockfile = root / ".terraform.lock.hcl"
        lockfile.write_text(
            'provider "registry.terraform.io/hashicorp/google" {\n'
            '  version = "7.39.0"\n'
            '  hashes = [\n'
            + "".join(f'    "zh:{checksum}",\n' for checksum in checksums)
            + "  ]\n}\n",
            encoding="utf-8",
        )
        config = root / "terraformrc"
        config.write_text(
            "provider_installation {\n"
            "  filesystem_mirror {\n"
            f'    path = "{mirror.resolve()}"\n'
            '    include = ["registry.terraform.io/hashicorp/google"]\n'
            "  }\n"
            "  direct {\n"
            '    exclude = ["*/*"]\n'
            "  }\n"
            "}\n",
            encoding="utf-8",
        )
        return temporary, mirror, config, lockfile

    def test_accepts_exact_google_packages_pinned_by_lockfile(self) -> None:
        temporary, mirror, config, lockfile = self.make_fixture()
        with temporary:
            mirror_verifier.verify_mirror(mirror, config, lockfile)

    def test_rejects_extra_provider_artifact(self) -> None:
        temporary, mirror, config, lockfile = self.make_fixture()
        with temporary:
            extra = mirror / "registry.terraform.io/hashicorp/random/3.6.0/darwin_arm64/random.zip"
            extra.parent.mkdir(parents=True)
            extra.write_bytes(b"not allowed")
            with self.assertRaisesRegex(mirror_verifier.VerificationError, "exactly"):
                mirror_verifier.verify_mirror(mirror, config, lockfile)

    def test_rejects_direct_fallback(self) -> None:
        temporary, mirror, config, lockfile = self.make_fixture()
        with temporary:
            config.write_text(
                config.read_text(encoding="utf-8").replace('exclude = ["*/*"]', 'exclude = []'),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(mirror_verifier.VerificationError, "closed Google"):
                mirror_verifier.verify_mirror(mirror, config, lockfile)

    def test_rejects_unpinned_package_checksum(self) -> None:
        temporary, mirror, config, lockfile = self.make_fixture()
        with temporary:
            lockfile.write_text(
                lockfile.read_text(encoding="utf-8").replace("zh:", "h1:", 1),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(mirror_verifier.VerificationError, "checksum"):
                mirror_verifier.verify_mirror(mirror, config, lockfile)
    def test_rejects_invalid_packed_metadata(self) -> None:
        temporary, mirror, config, lockfile = self.make_fixture()
        with temporary:
            index = mirror_verifier._provider_directory(mirror) / "index.json"
            index.write_text('{"versions": {"7.39.1": {}}}', encoding="utf-8")
            with self.assertRaisesRegex(mirror_verifier.VerificationError, "index.json"):
                mirror_verifier.verify_mirror(mirror, config, lockfile)

    def test_rejects_symbolic_link_in_mirror(self) -> None:
        temporary, mirror, config, lockfile = self.make_fixture()
        with temporary:
            link = mirror_verifier._provider_directory(mirror) / "unexpected-link"
            link.symlink_to("index.json")
            with self.assertRaisesRegex(mirror_verifier.VerificationError, "symbolic links"):
                mirror_verifier.verify_mirror(mirror, config, lockfile)


class FrozenProviderInterfaceTests(unittest.TestCase):
    def test_provider_interface_uses_only_frozen_variables(self) -> None:
        phase_root = MODULE_PATH.parents[1]
        provider = (phase_root / "providers.tf").read_text(encoding="utf-8")
        variables = (phase_root / "variables.tf").read_text(encoding="utf-8")
        example = (phase_root / "terraform.tfvars.example").read_text(encoding="utf-8")

        self.assertNotIn("required_providers", provider)
        self.assertIn("project                     = var.project_id", provider)
        self.assertIn("region                      = var.region", provider)
        self.assertIn("impersonate_service_account = var.deployer_service_account", provider)
        for name in ("project_id", "region", "subnet_ipv4_cidr", "deployer_service_account"):
            self.assertIn(f'variable "{name}"', variables)
            self.assertIn(f"{name}", example)
        self.assertIn('var.project_id == "slit-497603"', variables)
        self.assertIn('var.region == "asia-northeast3"', variables)
        self.assertIn(
            'var.deployer_service_account == "REPLACE_WITH_G0_APPROVED_DEPLOYER_SERVICE_ACCOUNT"',
            variables,
        )

if __name__ == "__main__":
    unittest.main()
