from __future__ import annotations

import hashlib
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
        for platform in mirror_verifier.PLATFORMS:
            artifact = mirror_verifier._expected_artifact(mirror, platform)
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_bytes(f"package-{platform}".encode())
            checksums.append(hashlib.sha256(artifact.read_bytes()).hexdigest())

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


if __name__ == "__main__":
    unittest.main()
