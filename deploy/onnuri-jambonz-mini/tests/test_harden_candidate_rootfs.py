"""Synthetic offline coverage for the candidate rootfs hardener."""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).parents[1] / "harden_candidate_rootfs.py"
spec = importlib.util.spec_from_file_location("harden_candidate_rootfs", MODULE)
assert spec is not None and spec.loader is not None
hardener = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hardener)
ARCHIVE_SHA256 = "106c4544fdd0450d7f9c4383f0d8028c490ee949173bc0ce1c507c3339400c73"
OBSERVED_SENTINELS = dict(hardener.OBSERVED_SENTINELS)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def stock_receipt(sentinels: dict[str, bytes]) -> dict[str, object]:
    return {
        "schema_version": hardener.RECEIPT_SCHEMA,
        "stock_identity": "jambonz-mini",
        "release": "10.2.2",
        "export_digest": ARCHIVE_SHA256,
        "acquisition_receipt_digest": hardener.ACQUISITION_RECEIPT_SHA256,
        "source_image_id": hardener.SOURCE_IMAGE_ID,
        "sealed_patch_manifest_digest": hardener.SEALED_PATCH_MANIFEST_SHA256,
        "kernel_backport_manifest_digest": hardener.KERNEL_BACKPORT_MANIFEST_SHA256,
        "post_patch_package_versions": {"jambonz-mini": "10.2.2", "rtpengine": "10.2.2"},
        "sentinels": {name: sha(value) for name, value in sentinels.items()},
    }


class HardenCandidateRootfsTests(unittest.TestCase):
    def make_root(self) -> tuple[tempfile.TemporaryDirectory[str], Path, Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name) / "rootfs"
        root.mkdir()
        sentinels = {"etc/stock-identity": b"sealed stock identity\n", "etc/rtpengine/rtpengine.conf": b"public stock config\n"}
        for name, content in sentinels.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        status = root / "var/lib/dpkg/status"
        status.parent.mkdir(parents=True, exist_ok=True)
        status.write_text(
            "Package: jambonz-mini\nStatus: install ok installed\nVersion: 10.2.2\n\n"
            "Package: rtpengine\nStatus: install ok installed\nVersion: 10.2.2\n",
            encoding="utf-8",
        )
        grub = root / "boot/grub/grub.cfg"
        grub.parent.mkdir(parents=True)
        grub.write_text(
            "\n".join(
                [
                    f"menuentry {hardener.OLD_KERNEL_RELEASE}",
                    f"linux /boot/vmlinuz-{hardener.OLD_KERNEL_RELEASE}",
                    f"initrd /boot/initrd.img-{hardener.OLD_KERNEL_RELEASE}",
                    f"menuentry fallback-{hardener.OLD_KERNEL_RELEASE}",
                    f"linux /boot/vmlinuz-{hardener.OLD_KERNEL_RELEASE}",
                    f"initrd /boot/initrd.img-{hardener.OLD_KERNEL_RELEASE}",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        modules = root / "etc/modules"
        modules.parent.mkdir(parents=True, exist_ok=True)
        modules.write_text("nft_rtpengine\nloop\n", encoding="utf-8")
        for executable in ("/usr/bin/node", "/usr/bin/rtpengine", "/usr/sbin/mariadbd", "/usr/bin/redis-server", hardener.FREESWITCH_BIN, hardener.DRACHTIO_BIN):
            path = root / executable.lstrip("/")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("#!/bin/false\n", encoding="ascii")
            path.chmod(0o755)
        for script in hardener.APP_SCRIPTS.values():
            path = root / hardener.APP_ROOT.lstrip("/") / script
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("#!/usr/bin/node\n", encoding="ascii")
            path.chmod(0o755)
        for name in hardener.DELETE_PATHS:
            path = root / name
            path.mkdir(parents=True, exist_ok=True)
            (path / "state").write_text("synthetic", encoding="ascii")
        for name in ("nested/.git", "nested/tests", "nested/fixtures", "nested/cache"):
            path = root / name
            path.mkdir(parents=True, exist_ok=True)
        wants = root / "etc/systemd/system/multi-user.target.wants"
        wants.mkdir(parents=True, exist_ok=True)
        (wants / "nginx.service").symlink_to("/dev/null")
        hardener.OBSERVED_SENTINELS = {name: sha(content) for name, content in sentinels.items()}
        receipt = Path(temporary.name) / "stock.json"
        receipt.write_bytes(hardener.canonical(stock_receipt(sentinels)))
        return temporary, root, receipt

    def test_hardens_and_is_idempotent(self) -> None:
        temporary, root, receipt = self.make_root()
        with temporary:
            first = hardener.harden(root, hardener.validate_stock_receipt(str(receipt)))
            bytes_before = (root / hardener.DERIVATIVE_RECEIPT).read_bytes()
            second = hardener.harden(root, hardener.validate_stock_receipt(str(receipt)))
            self.assertEqual(first, second)
            self.assertEqual(bytes_before, (root / hardener.DERIVATIVE_RECEIPT).read_bytes())
            self.assertEqual(first["stock_export_digest"], ARCHIVE_SHA256)
            grub_text = (root / "boot/grub/grub.cfg").read_text(encoding="utf-8")
            self.assertIn(hardener.KERNEL_RELEASE, grub_text)
            self.assertNotIn(hardener.OLD_KERNEL_RELEASE, grub_text)
            self.assertNotIn("nft_rtpengine", (root / "etc/modules").read_text(encoding="utf-8"))
            self.assertIn("loop", (root / "etc/modules").read_text(encoding="utf-8"))
            for name in hardener.DELETE_PATHS:
                if name == "var/log":
                    self.assertTrue((root / name).is_dir(), name)
                    self.assertEqual(list((root / name).iterdir()), [])
                else:
                    self.assertFalse((root / name).exists(), name)
            for name in ("nested/.git", "nested/tests", "nested/fixtures"):
                self.assertTrue((root / name).exists(), name)
            self.assertFalse((root / "etc/systemd/system/multi-user.target.wants/nginx.service").exists())

    def test_units_are_executable_hardened_and_not_noops(self) -> None:
        temporary, root, receipt = self.make_root()
        with temporary:
            hardener.harden(root, hardener.validate_stock_receipt(str(receipt)))
            expected_users = {
                "recova-mariadb.service": "mysql",
                "recova-redis.service": "redis",
            }
            for unit in hardener.RUNTIME_UNITS:
                content = (root / "etc/systemd/system" / unit).read_text(encoding="ascii")
                self.assertIn("ExecStart=", content, unit)
                self.assertIn("EnvironmentFile=", content, unit)
                self.assertIn(f"User={expected_users.get(unit, 'jambonz')}", content, unit)
                self.assertIn("NoNewPrivileges=yes", content, unit)
                self.assertIn("StandardOutput=null", content, unit)
            sidecar = (root / "etc/systemd/system/recova-sbc-sip-sidecar.service").read_text()
            self.assertIn("Restart=no", sidecar)
            self.assertIn("WorkingDirectory=/home/jambonz/apps/sbc-sip-sidecar", sidecar)
            self.assertIn("ExecStart=/usr/bin/env RECOVA_ONE_SHOT_REGISTER=1 /usr/bin/node --jitless /home/jambonz/apps/sbc-sip-sidecar/app.js", sidecar)
            mariadb = (root / "etc/systemd/system/recova-mariadb.service").read_text()
            self.assertIn("--datadir=/run/recova-mariadb/mysql", mariadb)
            self.assertIn("--skip-log-bin", mariadb)
            redis = (root / "etc/systemd/system/recova-redis.service").read_text()
            self.assertIn("--save ''", redis)
            self.assertIn("--appendonly no", redis)
    def test_containment_units_use_one_shot_credentials_and_distinct_runtimes(self) -> None:
        temporary, root, receipt = self.make_root()
        with temporary:
            hardener.harden(root, hardener.validate_stock_receipt(str(receipt)))
            runtime_dirs: set[str] = set()
            for unit in hardener.RUNTIME_UNITS:
                content = (root / "etc/systemd/system" / unit).read_text(encoding="ascii")
                name = unit.removeprefix("recova-").removesuffix(".service")
                self.assertIn(f"EnvironmentFile=/run/recova-credentials/{name}.env", content)
                self.assertNotIn("/etc/recova/runtime.env", content)
                self.assertIn("LimitCORE=0", content)
                self.assertIn("ProtectProc=invisible", content)
                self.assertIn("Requires=nftables.service", content)
                self.assertIn("After=nftables.service", content)
                runtime_dir = next(line for line in content.splitlines() if line.startswith("RuntimeDirectory="))
                self.assertNotIn(runtime_dir, runtime_dirs)
                runtime_dirs.add(runtime_dir)
            sidecar = (root / "etc/systemd/system/recova-sbc-sip-sidecar.service").read_text(encoding="ascii")
            self.assertIn("Environment=RECOVA_ONE_SHOT_REGISTER=1", sidecar)
            self.assertIn("ExecStart=/usr/bin/env RECOVA_ONE_SHOT_REGISTER=1", sidecar)
            self.assertNotIn("RECOVA_ONE_SHOT_REGISTER=", (root / "etc/recova/runtime-contract.conf").read_text())
            self.assertFalse((root / "etc/recova/runtime.env").exists())
            for service in ("recova-freeswitch.service", "recova-drachtio.service"):
                content = (root / "etc/systemd/system" / service).read_text(encoding="ascii")
                self.assertIn("Environment=RECOVA_LOG_OUTPUT=/dev/null", content)
                self.assertIn("Environment=RECOVA_CDR_OUTPUT=/dev/null", content)

    def test_nftables_entrypoint_is_enabled_before_telephony_units(self) -> None:
        temporary, root, receipt = self.make_root()
        with temporary:
            hardener.harden(root, hardener.validate_stock_receipt(str(receipt)))
            self.assertEqual(
                (root / "etc/nftables.conf").read_text(encoding="ascii"),
                'include "/etc/nftables.d/*.nft"\n',
            )
            link = root / "etc/systemd/system/multi-user.target.wants/nftables.service"
            self.assertTrue(link.is_symlink())
            self.assertEqual(link.readlink(), Path("/lib/systemd/system/nftables.service"))
            rules = (root / "etc/nftables.d/recova-default-deny.nft").read_text(encoding="ascii")
            self.assertIn("flush ruleset", rules)
            self.assertIn("policy drop", rules)
            self.assertIn("iif lo accept", rules)
            self.assertIn("oif lo accept", rules)

    def test_exact_sensitive_and_stale_kernel_deletions_preserve_required_paths(self) -> None:
        temporary, root, receipt = self.make_root()
        with temporary:
            for relative in hardener.SENSITIVE_FILE_PATHS:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("sensitive", encoding="ascii")
            for release in ("6.1.0", "6.8.0"):
                (root / "lib/modules" / release).mkdir(parents=True)
                (root / "usr/src" / f"linux-headers-{release}").mkdir(parents=True)
                (root / "boot").mkdir(exist_ok=True)
                (root / "boot" / f"vmlinuz-{release}").write_text(release, encoding="ascii")
            guest_agent = root / "usr/bin/google_authorized_keys"
            guest_agent.parent.mkdir(parents=True, exist_ok=True)
            guest_agent.write_text("retain", encoding="ascii")
            hardener.harden(root, hardener.validate_stock_receipt(str(receipt)))
            for relative in hardener.SENSITIVE_FILE_PATHS:
                self.assertFalse((root / relative).exists(), relative)
            self.assertFalse((root / "lib/modules/6.1.0").exists())
            self.assertFalse((root / "usr/src/linux-headers-6.1.0").exists())
            self.assertFalse((root / "boot/vmlinuz-6.1.0").exists())
            self.assertTrue((root / "lib/modules/6.8.0").exists())
            self.assertFalse((root / "usr/src/linux-headers-6.8.0").exists())
            self.assertTrue((root / "boot/vmlinuz-6.8.0").exists())
            self.assertTrue(guest_agent.exists())
            derivative = json.loads((root / hardener.DERIVATIVE_RECEIPT).read_text())
            self.assertIn("etc/recova/runtime.env", derivative["deleted_paths"])
            self.assertIn("lib/modules/6.1.0", derivative["deleted_paths"])
            self.assertIn("usr/src", derivative["deleted_paths"])
            self.assertIn("hardened:recova-sbc-sip-sidecar-one-shot-register", derivative["mutations"])

    def test_stale_kernel_cleanup_handles_usr_merged_layout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "usr/lib/modules/6.1.0-49-cloud-amd64").mkdir(parents=True)
            (root / "usr/lib/modules/6.1.0-50-cloud-amd64").mkdir(parents=True)
            (root / "lib").symlink_to("usr/lib")
            (root / "boot").mkdir()
            for release in ("6.1.0-49-cloud-amd64", "6.1.0-50-cloud-amd64"):
                (root / "boot" / f"vmlinuz-{release}").write_text(release, encoding="ascii")

            deleted = hardener.remove_stale_kernels(root)

            self.assertIn("usr/lib/modules/6.1.0-49-cloud-amd64", deleted)
            self.assertFalse((root / "boot/vmlinuz-6.1.0-49-cloud-amd64").exists())
            self.assertTrue((root / "boot/vmlinuz-6.1.0-50-cloud-amd64").exists())

    def test_rtp_and_firewall_are_bounded_with_no_broad_listener(self) -> None:
        temporary, root, receipt = self.make_root()
        with temporary:
            hardener.harden(root, hardener.validate_stock_receipt(str(receipt)))
            config = (root / "etc/rtpengine/rtpengine.conf").read_text()
            unit = (root / "etc/systemd/system/recova-rtpengine.service").read_text()
            rules = (root / "etc/nftables.d/recova-default-deny.nft").read_text()
            self.assertIn("${RECOVA_PRIVATE_INTERFACE}", unit)
            self.assertIn("${RECOVA_PUBLIC_INTERFACE}", unit)
            self.assertIn("127.0.0.1:2223", config)
            self.assertIn("port-min = 40000", config)
            self.assertIn("port-max = 40099", config)
            self.assertNotRegex(config, r"(?i)(record|curl|metadata|http|0\.0\.0\.0)")
            self.assertIn("policy drop", rules)
            self.assertNotRegex(rules, r"0\.0\.0\.0/0|\b[0-9]{1,5}-[0-9]{1,5}\b")

    def test_refuses_unpurged_disabled_packages(self) -> None:
        temporary, root, receipt = self.make_root()
        with temporary:
            status = root / "var/lib/dpkg/status"
            status.write_text(
                status.read_text(encoding="utf-8")
                + "\nPackage: grafana\nStatus: install ok installed\nVersion: 12.4.0\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(hardener.HardeningError, "disabled packages must be purged"):
                hardener.harden(root, hardener.validate_stock_receipt(str(receipt)))

    def test_observed_acquisition_bindings_are_fixed(self) -> None:
        self.assertEqual(hardener.ARCHIVE_SHA256, ARCHIVE_SHA256)
        self.assertEqual(hardener.ACQUISITION_RECEIPT_SHA256, "2efa15251a1828af0ef7798f1265044db21dedd5a092feb8fcbf1818d3fffeb2")
        self.assertEqual(hardener.SEALED_PATCH_MANIFEST_SHA256, "8d2c7deaff80817313aae5918a9f44f8272849929443160981b96caa23132e3f")
        self.assertEqual(OBSERVED_SENTINELS["etc/os-release"], "59a77b5f2666d9c85c489bd1911a6eebbd91ef22fe48b90a3b75f1b21f3844d4")
        self.assertIn("home/jambonz/apps/ecosystem.config.js", OBSERVED_SENTINELS)
    def test_refuses_wrong_archive_identity_tampered_sentinel_and_symlink(self) -> None:
        temporary, root, receipt = self.make_root()
        with temporary:
            invalid = stock_receipt({"etc/stock-identity": b"sealed stock identity\n"})
            invalid["export_digest"] = "d" * 64
            bad = Path(temporary.name) / "bad.json"
            bad.write_bytes(hardener.canonical(invalid))
            with self.assertRaises(hardener.HardeningError):
                hardener.validate_stock_receipt(str(bad))
            (root / "etc/stock-identity").write_text("tampered", encoding="ascii")
            with self.assertRaisesRegex(hardener.HardeningError, "sentinel mismatch"):
                hardener.harden(root, hardener.validate_stock_receipt(str(receipt)))
            with self.assertRaises(hardener.HardeningError):
                hardener.safe_relative("../outside")

    def test_allows_only_the_stock_os_release_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "usr/lib/os-release"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"PRETTY_NAME=Debian\n")
            link = root / "etc/os-release"
            link.parent.mkdir(parents=True)
            link.symlink_to("/usr/lib/os-release")

            self.assertEqual(hardener.read_regular(root, "etc/os-release"), target.read_bytes())

            link.unlink()
            link.symlink_to("/etc/passwd")
            with self.assertRaisesRegex(hardener.HardeningError, "symlink refused"):
                hardener.read_regular(root, "etc/os-release")

    def test_allows_only_the_stock_redis_executable_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "usr/bin/redis-check-rdb"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"#!/bin/false\n")
            target.chmod(0o755)
            link = root / "usr/bin/redis-server"
            link.symlink_to("redis-check-rdb")

            hardener.require_executable(root, "/usr/bin/redis-server")

            link.unlink()
            link.symlink_to("../../etc/passwd")
            with self.assertRaisesRegex(hardener.HardeningError, "symlink refused"):
                hardener.require_executable(root, "/usr/bin/redis-server")

    def test_remove_tree_unlinks_descendant_symlinks_without_following(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            target = Path(directory) / "outside"
            tree = root / "usr/src"
            tree.mkdir(parents=True)
            target.write_text("preserve", encoding="ascii")
            (tree / "outside-link").symlink_to(target)

            self.assertTrue(hardener.remove_tree(root, "usr/src"))
            self.assertEqual(target.read_text(encoding="ascii"), "preserve")
            self.assertFalse(tree.exists())
            (root / "lib64").symlink_to("usr/lib64")
            self.assertEqual(hardener.remove_forbidden_descendants(root), [])
            self.assertTrue((root / "lib64").is_symlink())

    def test_source_has_no_subprocess_or_network(self) -> None:
        tree = ast.parse(MODULE.read_text(encoding="utf-8"))
        forbidden = {"subprocess", "socket", "requests", "urllib", "http", "ftplib", "telnetlib"}
        imports = {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom)) for alias in node.names}
        self.assertFalse(imports & forbidden)


if __name__ == "__main__":
    unittest.main()
