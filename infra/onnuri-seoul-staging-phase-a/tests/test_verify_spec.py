"""Hermetic tests for the provider-free Phase A verifier."""

from __future__ import annotations

import json
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest import mock
from urllib import request

PHASE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PHASE_ROOT))
import verify_spec as verifier  # noqa: E402


class DeniedNetworkProbe(RuntimeError):
    pass


class VerifySpecTests(unittest.TestCase):
    def test_canonical_spec_matches_closed_model(self) -> None:
        actual = json.loads(
            (PHASE_ROOT / "control-spec.json").read_text(encoding="utf-8")
        )
        self.assertEqual(actual, verifier._expected_spec())
        self.assertEqual(
            actual["controls"]["sip_ingress"]["fixture"]["source_cidr"],
            "61.78.32.184/32",
        )
        self.assertEqual(
            actual["controls"]["sip_egress"]["provenance"]["outbound_proxy"],
            "61.78.32.184:5060/UDP",
        )
        self.assertIsNone(actual["controls"]["rtp_ingress"]["peer"])
        self.assertIsNone(actual["controls"]["rtp_egress"]["ports"])

    def test_control_model_rejects_enabled_extra_and_address_mutations(self) -> None:
        mutations = []

        enabled = verifier._expected_spec()
        enabled["controls"]["sip_ingress"]["disabled"] = False
        mutations.append(enabled)

        extra = verifier._expected_spec()
        extra["controls"]["unexpected"] = {}
        mutations.append(extra)

        address = verifier._expected_spec()
        address["controls"]["sip_egress"]["provenance"][
            "outbound_proxy"
        ] = "192.0.2.1:5060/UDP"
        mutations.append(address)

        rtp = verifier._expected_spec()
        rtp["controls"]["rtp_ingress"]["peer"] = "192.0.2.1"
        mutations.append(rtp)

        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(
                verifier.VerificationError
            ) as caught:
                verifier.validate_control_model(mutation)
            self.assertEqual(caught.exception.exit_code, verifier.EXIT_SPEC)

    def test_schema_mutation_is_exit_65(self) -> None:
        schema = json.loads(
            (PHASE_ROOT / "control-spec.schema.json").read_text(encoding="utf-8")
        )
        schema["$defs"]["rtpControl"]["properties"]["peer"] = {"type": "string"}
        with tempfile.TemporaryDirectory(dir=PHASE_ROOT) as directory:
            mutated = Path(directory) / "mutated-schema.json"
            mutated.write_text(json.dumps(schema), encoding="utf-8")
            with mock.patch.object(verifier, "SCHEMA_PATH", mutated):
                with self.assertRaises(verifier.VerificationError) as caught:
                    verifier.validate_schema_and_spec()
        self.assertEqual(caught.exception.exit_code, verifier.EXIT_SPEC)

    def test_static_surfaces_are_approved(self) -> None:
        verifier.validate_static_surfaces()

    def test_unapproved_network_import_is_exit_69(self) -> None:
        with tempfile.TemporaryDirectory(dir=PHASE_ROOT) as directory:
            fixture = Path(directory) / "unapproved_network.py"
            fixture.write_text("import http.client\n", encoding="utf-8")
            with self.assertRaises(verifier.VerificationError) as caught:
                verifier.scan_python_surface(fixture, "network_test")
        self.assertEqual(caught.exception.exit_code, verifier.EXIT_CAPABILITY)

    def test_unapproved_process_spawn_is_exit_69(self) -> None:
        with tempfile.TemporaryDirectory(dir=PHASE_ROOT) as directory:
            fixture = Path(directory) / "unapproved_process.py"
            fixture.write_text(
                "import subprocess\nsubprocess.run(['true'])\n", encoding="utf-8"
            )
            with self.assertRaises(verifier.VerificationError) as caught:
                verifier.scan_python_surface(fixture, "network_test")
        self.assertEqual(caught.exception.exit_code, verifier.EXIT_CAPABILITY)

    def test_alias_dynamic_import_and_os_process_bypasses_are_exit_69(self) -> None:
        fixtures = (
            (
                "network_alias.py",
                "import socket as s\n"
                "def test_socket_and_url_probes_pass_only_when_intercepted():\n"
                "    s.create_connection(('192.0.2.1', 9))\n",
                "network_test",
            ),
            (
                "process_alias.py",
                "import subprocess as sp\n"
                "def _run_bash():\n"
                "    sp.run(['true'], shell=False, env={}, cwd='.')\n",
                "validator_test",
            ),
            (
                "dynamic_import.py",
                "import importlib\n"
                "def escape():\n"
                "    importlib.import_module('socket')\n",
                "verifier",
            ),
            (
                "os_system.py",
                "import os\n" "def escape():\n" "    os.system('true')\n",
                "verifier",
            ),
            (
                "assigned_os_system.py",
                "import os\n"
                "danger = os.system\n"
                "def escape():\n"
                "    danger('true')\n",
                "verifier",
            ),
            (
                "getattr_import.py",
                "import importlib\n"
                "loader = getattr(importlib, 'import_module')\n"
                "def escape():\n"
                "    loader('socket')\n",
                "verifier",
            ),
            (
                "unguarded_assigned_socket.py",
                "import socket\n"
                "connector = socket.create_connection\n"
                "def test_socket_and_url_probes_pass_only_when_intercepted():\n"
                "    connector(('192.0.2.1', 9))\n",
                "network_test",
            ),
        )
        with tempfile.TemporaryDirectory(dir=PHASE_ROOT) as directory:
            for name, source, surface in fixtures:
                fixture = Path(directory) / name
                fixture.write_text(source, encoding="utf-8")
                with self.subTest(name=name), self.assertRaises(
                    verifier.VerificationError
                ) as caught:
                    verifier.scan_python_surface(fixture, surface)
                self.assertEqual(caught.exception.exit_code, verifier.EXIT_CAPABILITY)

    def test_prohibited_environment_names_are_exit_66(self) -> None:
        for name in ("gOoGlE_Credential", "GCP_SERVICE_ACCOUNT_KEY"):
            with self.subTest(name=name), self.assertRaises(
                verifier.VerificationError
            ) as caught:
                verifier.validate_environment({name: "not-inspected"})
            self.assertEqual(caught.exception.exit_code, verifier.EXIT_ENVIRONMENT)

    def test_invalid_and_symlinked_evidence_paths_are_exit_64(self) -> None:
        for value in ("", "/absolute", "../escape", "dot.name", "back\\slash"):
            with self.subTest(value=value), self.assertRaises(
                verifier.VerificationError
            ) as caught:
                verifier.resolve_evidence_directory(value)
            self.assertEqual(caught.exception.exit_code, verifier.EXIT_INTERFACE)

        with tempfile.TemporaryDirectory(dir=PHASE_ROOT) as target_directory:
            target = Path(target_directory)
            link = PHASE_ROOT / f"verify-spec-link-{target.name}"
            link.symlink_to(target, target_is_directory=True)
            try:
                with self.assertRaises(verifier.VerificationError) as caught:
                    verifier.resolve_evidence_directory(link.name)
                self.assertEqual(caught.exception.exit_code, verifier.EXIT_INTERFACE)
            finally:
                link.unlink()

    def test_socket_and_url_probes_pass_only_when_intercepted(self) -> None:
        def deny(*_args: object, **_kwargs: object) -> None:
            raise DeniedNetworkProbe("blocked before connection")

        with mock.patch.object(socket.socket, "connect", deny), mock.patch.object(
            socket, "create_connection", deny
        ), mock.patch.object(request, "urlopen", deny):
            with self.assertRaises(DeniedNetworkProbe):
                socket.create_connection(("192.0.2.1", 9))
            with self.assertRaises(DeniedNetworkProbe):
                request.urlopen("http://192.0.2.1/")

    def test_direct_run_without_wrapper_context_cannot_emit_evidence(self) -> None:
        safe_environment = {
            "PATH": os.defpath,
            "PYTHON": os.fspath(Path(os.sys.executable).resolve()),
        }
        with tempfile.TemporaryDirectory(
            prefix="verify-spec-direct-", dir=PHASE_ROOT
        ) as directory:
            evidence_directory = Path(directory)
            with mock.patch.dict(os.environ, safe_environment, clear=True):
                with self.assertRaises(verifier.VerificationError) as caught:
                    verifier.run(["--evidence-dir", evidence_directory.name])
            self.assertEqual(caught.exception.exit_code, verifier.EXIT_INFRASTRUCTURE)
            self.assertEqual(list(evidence_directory.iterdir()), [])

    def test_direct_cli_rejects_even_forged_wrapper_environment(self) -> None:
        runtime = (
            f"{os.sys.implementation.name}-"
            f"{os.sys.version_info.major}.{os.sys.version_info.minor}"
        )
        environment = {
            "ONNURI_PHASE_A_WRAPPER_CONTRACT": "validated-v1",
            "ONNURI_PHASE_A_RUNTIME_IDENTITY": runtime,
        }
        with mock.patch.dict(os.environ, environment, clear=True):
            self.assertEqual(verifier.main(), verifier.EXIT_INFRASTRUCTURE)

    def test_wrapper_context_writes_revalidated_content_addressed_evidence(
        self,
    ) -> None:
        runtime = f"{os.sys.implementation.name}-{os.sys.version_info.major}.{os.sys.version_info.minor}"
        safe_environment = {
            "PATH": os.defpath,
            "PYTHON": os.fspath(Path(os.sys.executable).resolve()),
            "ONNURI_PHASE_A_WRAPPER_CONTRACT": "validated-v1",
            "ONNURI_PHASE_A_RUNTIME_IDENTITY": runtime,
        }
        with tempfile.TemporaryDirectory(
            prefix="verify-spec-evidence-", dir=PHASE_ROOT
        ) as directory:
            evidence_directory = Path(directory)
            with mock.patch.dict(os.environ, safe_environment, clear=True):
                output = verifier.run(["--evidence-dir", evidence_directory.name])
            self.assertEqual(output.parent, evidence_directory)
            evidence_bytes = output.read_bytes()
            self.assertTrue(evidence_bytes.endswith(b"\n"))
            evidence = json.loads(evidence_bytes)
            self.assertEqual(output.name, f"sha256-{evidence['evidence_sha256']}.json")
            self.assertEqual(evidence["phase"], "A")
            self.assertEqual(
                [entry["id"] for entry in evidence["stage_results"]],
                list(verifier.STAGES),
            )

    def test_tampered_persisted_digest_is_removed_and_exit_70(self) -> None:
        evidence = verifier.build_evidence()
        original_replace = verifier.os.replace

        def replace_then_tamper(
            source: object, destination: object, **kwargs: object
        ) -> None:
            original_replace(source, destination, **kwargs)
            directory_fd = kwargs["dst_dir_fd"]
            file_fd = os.open(
                destination,
                os.O_RDWR | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            with os.fdopen(file_fd, "r+b") as handle:
                persisted = json.loads(handle.read())
                persisted["evidence_sha256"] = "0" * 64
                handle.seek(0)
                handle.write(verifier._canonical_json(persisted) + b"\n")
                handle.truncate()

        with tempfile.TemporaryDirectory(dir=PHASE_ROOT) as directory:
            evidence_directory = Path(directory)
            with mock.patch.object(
                verifier.os, "replace", side_effect=replace_then_tamper
            ):
                with self.assertRaises(verifier.VerificationError) as caught:
                    verifier.write_evidence(evidence_directory, evidence)
            self.assertEqual(caught.exception.exit_code, verifier.EXIT_INFRASTRUCTURE)
            self.assertEqual(list(evidence_directory.iterdir()), [])

    def test_evidence_directory_replacement_is_exit_70(self) -> None:
        evidence = verifier.build_evidence()
        original_replace = verifier.os.replace
        with tempfile.TemporaryDirectory(dir=PHASE_ROOT) as directory:
            evidence_directory = Path(directory)
            backup = evidence_directory.with_name(f"{evidence_directory.name}-backup")
            swapped = False

            def replace_then_swap(
                source: object, destination: object, **kwargs: object
            ) -> None:
                nonlocal swapped
                original_replace(source, destination, **kwargs)
                os.rename(evidence_directory, backup)
                evidence_directory.mkdir()
                swapped = True

            try:
                with mock.patch.object(
                    verifier.os, "replace", side_effect=replace_then_swap
                ):
                    with self.assertRaises(verifier.VerificationError) as caught:
                        verifier.write_evidence(evidence_directory, evidence)
                self.assertEqual(
                    caught.exception.exit_code, verifier.EXIT_INFRASTRUCTURE
                )
                self.assertEqual(list(evidence_directory.iterdir()), [])
                self.assertEqual(list(backup.iterdir()), [])
            finally:
                if swapped:
                    evidence_directory.rmdir()
                    os.rename(backup, evidence_directory)

    def test_prewrite_directory_replacement_is_exit_70(self) -> None:
        evidence = verifier.build_evidence()
        with tempfile.TemporaryDirectory(dir=PHASE_ROOT) as directory:
            evidence_directory = Path(directory)
            original = os.stat(evidence_directory, follow_symlinks=False)
            expected_identity = (original.st_dev, original.st_ino)
            backup = evidence_directory.with_name(f"{evidence_directory.name}-backup")
            os.rename(evidence_directory, backup)
            evidence_directory.mkdir()
            try:
                with self.assertRaises(verifier.VerificationError) as caught:
                    verifier.write_evidence(
                        evidence_directory, evidence, expected_identity
                    )
                self.assertEqual(
                    caught.exception.exit_code, verifier.EXIT_INFRASTRUCTURE
                )
                self.assertEqual(list(evidence_directory.iterdir()), [])
                self.assertEqual(list(backup.iterdir()), [])
            finally:
                evidence_directory.rmdir()
                os.rename(backup, evidence_directory)

    def test_stale_source_snapshot_is_removed_and_exit_70(self) -> None:
        evidence = verifier.build_evidence()
        evidence["source_files"][0]["sha256"] = "0" * 64
        digest_input = {
            key: value for key, value in evidence.items() if key != "evidence_sha256"
        }
        evidence["evidence_sha256"] = verifier.hashlib.sha256(
            verifier._canonical_json(digest_input)
        ).hexdigest()
        with tempfile.TemporaryDirectory(dir=PHASE_ROOT) as directory:
            evidence_directory = Path(directory)
            with self.assertRaises(verifier.VerificationError) as caught:
                verifier.write_evidence(evidence_directory, evidence)
            self.assertEqual(caught.exception.exit_code, verifier.EXIT_INFRASTRUCTURE)
            self.assertEqual(list(evidence_directory.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
