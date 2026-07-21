"""Black-box contract tests for the paired no-traffic validators."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
PHASE_ROOT = REPOSITORY_ROOT / "infra" / "onnuri-seoul-staging-phase-a"
BASH_VALIDATOR = REPOSITORY_ROOT / "scripts" / "validate_onnuri_seoul_no_traffic.sh"
POWERSHELL_VALIDATOR = (
    REPOSITORY_ROOT / "scripts" / "validate_onnuri_seoul_no_traffic.ps1"
)
EXPECTED_STAGES = [
    "interface",
    "environment_guard",
    "evidence_path",
    "static_surface",
    "schema",
    "control_model",
    "network_deny",
    "unit_contract",
    "evidence_write",
]
EXPECTED_EVIDENCE_KEYS = {
    "artifact_id",
    "evidence_schema_version",
    "evidence_sha256",
    "phase",
    "review_identities",
    "source_files",
    "spec_sha256",
    "stage_results",
    "validator_contract_version",
    "verifier_runtime_version",
}
EXPECTED_SOURCE_PATHS = sorted(
    [
        "context/005-onnuri-seoul-staging-phase-a-operator-contract.md",
        "infra/onnuri-seoul-staging-phase-a/README.md",
        "infra/onnuri-seoul-staging-phase-a/control-spec.json",
        "infra/onnuri-seoul-staging-phase-a/control-spec.schema.json",
        "infra/onnuri-seoul-staging-phase-a/tests/test_validator_contract.py",
        "infra/onnuri-seoul-staging-phase-a/tests/test_verify_spec.py",
        "infra/onnuri-seoul-staging-phase-a/verify_spec.py",
        "scripts/validate_onnuri_seoul_no_traffic.ps1",
        "scripts/validate_onnuri_seoul_no_traffic.sh",
    ],
    key=lambda path: path.encode("utf-8"),
)
EXPECTED_REVIEW_IDENTITIES = [
    {
        "role": "planner",
        "sha256": "45b2b1bbc087be243c4cba620fe6b7eddf5029bd81b9a49334aba0264945ebbd",
    },
    {
        "role": "architect",
        "sha256": "0b6134537b6d962ba3057ffeb2e400baa25267385fcbd0f9305c997cc4555ed6",
    },
    {
        "role": "critic",
        "sha256": "24e8714fe1b3b7762d282acf65fba5905a589417d3c9dca38bb6bfb0e43d350a",
    },
]


class ValidatorContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.bash = shutil.which("bash")
        cls.pwsh = shutil.which("pwsh")
        cls.python = Path(sys.executable).resolve()

    def _require_runners(self) -> tuple[str, str, str]:
        self.assertIsNotNone(self.bash, "bash is required for validator parity")
        self.assertIsNotNone(self.pwsh, "pwsh is required for validator parity")
        self.assertTrue(self.python.is_file(), "the shared Python runtime is required")
        return str(self.bash), str(self.pwsh), str(self.python)

    @classmethod
    def _environment(cls, python: str, **extra: str) -> dict[str, str]:
        path_entries: list[str] = []
        for executable in (cls.bash, cls.pwsh, python):
            if executable:
                parent = str(Path(executable).resolve().parent)
                if parent not in path_entries:
                    path_entries.append(parent)
        for entry in os.defpath.split(os.pathsep):
            if entry and entry not in path_entries:
                path_entries.append(entry)
        environment = {
            "PATH": os.pathsep.join(path_entries),
            "PYTHON": python,
        }
        environment.update(extra)
        return environment

    def _run_bash(
        self, arguments: list[str], environment: dict[str, str]
    ) -> subprocess.CompletedProcess[str]:
        bash, _, _ = self._require_runners()
        return subprocess.run(
            [bash, str(BASH_VALIDATOR), *arguments],
            cwd=REPOSITORY_ROOT,
            env=environment,
            shell=False,
            check=False,
            capture_output=True,
            text=True,
        )

    def _run_powershell(
        self, arguments: list[str], environment: dict[str, str]
    ) -> subprocess.CompletedProcess[str]:
        _, pwsh, _ = self._require_runners()
        return subprocess.run(
            [pwsh, "-NoProfile", "-File", str(POWERSHELL_VALIDATOR), *arguments],
            cwd=REPOSITORY_ROOT,
            env=environment,
            shell=False,
            check=False,
            capture_output=True,
            text=True,
        )

    def _assert_exit_for_both(
        self, arguments: list[str], environment: dict[str, str], expected: int
    ) -> None:
        bash = self._run_bash(arguments, environment)
        powershell = self._run_powershell(arguments, environment)
        self.assertEqual(bash.returncode, expected, bash.stderr)
        self.assertEqual(powershell.returncode, expected, powershell.stderr)
        self.assertEqual(bash.stdout, powershell.stdout)
        self.assertEqual(bash.stderr, powershell.stderr)

    def _read_evidence(
        self, result: subprocess.CompletedProcess[str], evidence_dir: Path
    ) -> bytes:
        self.assertEqual(result.returncode, 0, result.stderr)
        relative_path = result.stdout.strip()
        self.assertTrue(relative_path)
        self.assertFalse(Path(relative_path).is_absolute())
        evidence_path = PHASE_ROOT / relative_path
        self.assertEqual(evidence_path.parent, evidence_dir)
        self.assertTrue(evidence_path.is_file())
        evidence_bytes = evidence_path.read_bytes()
        evidence = json.loads(evidence_bytes)
        self.assertEqual(
            evidence_path.name, f"sha256-{evidence['evidence_sha256']}.json"
        )
        return evidence_bytes

    def test_required_runners_are_available(self) -> None:
        self._require_runners()

    def test_help_is_the_only_successful_non_evidence_interface(self) -> None:
        _, _, python = self._require_runners()
        environment = self._environment(python)
        bash = self._run_bash(["--help"], environment)
        powershell = self._run_powershell(["--help"], environment)
        self.assertEqual(bash.returncode, 0, bash.stderr)
        self.assertEqual(powershell.returncode, 0, powershell.stderr)
        self.assertIn("--evidence-dir", bash.stdout)
        self.assertIn("--evidence-dir", powershell.stdout)

    def test_invalid_interface_and_evidence_paths_fail_closed(self) -> None:
        _, _, python = self._require_runners()
        environment = self._environment(python)
        invalid_arguments = [
            [],
            ["--Help"],
            ["--help", "--evidence-dir", "evidence"],
            ["--unknown"],
            ["--evidence-dir"],
            ["--evidence-dir", ""],
            ["--evidence-dir", "./evidence"],
            ["--evidence-dir", "evidence/"],
            ["--evidence-dir", "evidence//nested"],
            ["--evidence-dir", "evidence/../other"],
            ["--evidence-dir", "/evidence"],
            ["--evidence-dir", "C:/evidence"],
            ["--evidence-dir", "\\\\evidence\\other"],
            ["--evidence-dir", "evidence\\other"],
            ["--evidence-dir", "evidence.with-dot"],
            ["--evidence-dir", "evidence", "--help"],
        ]
        for arguments in invalid_arguments:
            with self.subTest(arguments=arguments):
                self._assert_exit_for_both(arguments, environment, 64)

    def test_mixed_case_prohibited_environment_names_fail_before_verification(
        self,
    ) -> None:
        _, _, python = self._require_runners()
        for name in ("gOoGlE_Test", "GcP_Service_Account_Key"):
            with self.subTest(name=name), tempfile.TemporaryDirectory(
                prefix="validator-contract-environment-", dir=PHASE_ROOT
            ) as temporary_directory:
                evidence_dir = Path(temporary_directory)
                environment = self._environment(python, **{name: "present"})
                self._assert_exit_for_both(
                    ["--evidence-dir", evidence_dir.name], environment, 66
                )
                self.assertEqual(list(evidence_dir.iterdir()), [])

    def test_missing_shared_python_is_infrastructure_failure(self) -> None:
        self._require_runners()
        with tempfile.TemporaryDirectory(
            prefix="validator-contract-runtime-", dir=PHASE_ROOT
        ) as temporary_directory:
            evidence_dir = Path(temporary_directory)
            missing_python = str(PHASE_ROOT / "missing-python-runtime")
            environment = self._environment(missing_python)
            self._assert_exit_for_both(
                ["--evidence-dir", evidence_dir.name], environment, 70
            )
            self.assertEqual(list(evidence_dir.iterdir()), [])

    def test_exit_zero_non_python_runtime_is_infrastructure_failure(self) -> None:
        self._require_runners()
        no_op_runtime = shutil.which("true")
        self.assertIsNotNone(no_op_runtime)
        with tempfile.TemporaryDirectory(
            prefix="validator-contract-no-op-", dir=PHASE_ROOT
        ) as temporary_directory:
            evidence_dir = Path(temporary_directory)
            environment = self._environment(str(no_op_runtime))
            self._assert_exit_for_both(
                ["--evidence-dir", evidence_dir.name], environment, 70
            )
            self.assertEqual(list(evidence_dir.iterdir()), [])

    def test_symlinked_evidence_directory_fails_closed(self) -> None:
        _, _, python = self._require_runners()
        environment = self._environment(python)
        with tempfile.TemporaryDirectory(
            prefix="validator-contract-target-", dir=PHASE_ROOT
        ) as target_directory:
            target = Path(target_directory)
            link = PHASE_ROOT / f"validator-contract-link-{target.name}"
            link.symlink_to(target, target_is_directory=True)
            try:
                self._assert_exit_for_both(
                    ["--evidence-dir", link.name], environment, 64
                )
                self.assertEqual(list(target.iterdir()), [])
            finally:
                link.unlink()

    def test_successful_validators_write_byte_identical_redacted_evidence(self) -> None:
        _, _, python = self._require_runners()
        environment = self._environment(python)
        with tempfile.TemporaryDirectory(
            prefix="validator-contract-bash-", dir=PHASE_ROOT
        ) as bash_directory, tempfile.TemporaryDirectory(
            prefix="validator-contract-powershell-", dir=PHASE_ROOT
        ) as powershell_directory:
            bash_evidence_dir = Path(bash_directory)
            powershell_evidence_dir = Path(powershell_directory)
            bash_result = self._run_bash(
                ["--evidence-dir", bash_evidence_dir.name], environment
            )
            powershell_result = self._run_powershell(
                ["--evidence-dir", powershell_evidence_dir.name], environment
            )
            bash_evidence = self._read_evidence(bash_result, bash_evidence_dir)
            powershell_evidence = self._read_evidence(
                powershell_result, powershell_evidence_dir
            )

        self.assertEqual(bash_evidence, powershell_evidence)
        self._assert_evidence_contract(bash_evidence)

    def _assert_evidence_contract(self, evidence_bytes: bytes) -> None:
        self.assertTrue(evidence_bytes.endswith(b"\n"))
        evidence = json.loads(evidence_bytes)
        self.assertEqual(set(evidence), EXPECTED_EVIDENCE_KEYS)
        for key in EXPECTED_EVIDENCE_KEYS - {
            "review_identities",
            "source_files",
            "stage_results",
        }:
            self.assertIsInstance(evidence[key], str)
            self.assertTrue(evidence[key])

        expected_runtime = f"{sys.implementation.name}-{sys.version_info.major}.{sys.version_info.minor}"
        self.assertEqual(evidence["verifier_runtime_version"], expected_runtime)
        self.assertEqual(evidence["phase"], "A")
        self.assertEqual(
            evidence["stage_results"],
            [{"id": stage, "status": "pass"} for stage in EXPECTED_STAGES],
        )
        self.assertEqual(evidence["review_identities"], EXPECTED_REVIEW_IDENTITIES)

        self.assertEqual(
            [entry["path"] for entry in evidence["source_files"]],
            EXPECTED_SOURCE_PATHS,
        )
        for entry in evidence["source_files"]:
            self.assertEqual(set(entry), {"path", "sha256"})
            source_bytes = (REPOSITORY_ROOT / entry["path"]).read_bytes()
            self.assertEqual(entry["sha256"], hashlib.sha256(source_bytes).hexdigest())

        spec_bytes = (PHASE_ROOT / "control-spec.json").read_bytes()
        self.assertEqual(
            evidence["spec_sha256"], hashlib.sha256(spec_bytes).hexdigest()
        )
        digest_input = {
            key: value for key, value in evidence.items() if key != "evidence_sha256"
        }
        canonical = json.dumps(
            digest_input,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        digest = hashlib.sha256(canonical).hexdigest()
        self.assertEqual(evidence["evidence_sha256"], digest)
        self.assertEqual(
            evidence_bytes,
            json.dumps(
                evidence,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n",
        )
