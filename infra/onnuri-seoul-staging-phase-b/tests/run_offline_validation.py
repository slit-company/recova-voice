#!/usr/bin/env python3
"""Fail-closed local Terraform validation with macOS network denial."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

SANDBOX_PROFILE = "(version 1) (allow default) (deny network*)"
TERRAFORM_COMMANDS = (("version",), ("fmt", "-check", "-recursive"), ("init", "-backend=false", "-lockfile=readonly"), ("validate",), ("test",))
REJECTED_PREFIXES = ("GOOGLE_", "GCLOUD_", "CLOUDSDK_", "TF_", "TF_VAR_")
REJECTED_MARKERS = ("proxy", "credential", "token", "secret")


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def inherited_environment_errors(environment):
    return sorted(key for key in environment if key.upper().startswith(REJECTED_PREFIXES) or any(marker in key.lower() for marker in REJECTED_MARKERS))


def scrubbed_environment(cli_config, data_dir, home_dir):
    path = os.environ.get("PATH", "")
    return {"PATH": path, "HOME": str(home_dir), "TMPDIR": str(home_dir), "LC_ALL": "C", "TZ": "UTC", "CHECKPOINT_DISABLE": "1", "TF_CLI_CONFIG_FILE": str(cli_config), "TF_DATA_DIR": str(data_dir)}


def command_result(command, cwd, environment):
    result = subprocess.run(command, cwd=cwd, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    return result.returncode, result.stdout


def preflight(args):
    blockers = []
    if sha256(args.expected_manifest) != args.expected_manifest_sha:
        blockers.append("EXPECTED_MANIFEST_SHA")
    if Path(args.sandbox_exec) != Path("/usr/bin/sandbox-exec") or not Path(args.sandbox_exec).is_file():
        blockers.append("SANDBOX")
    if not Path(args.terraform_bin).is_file():
        blockers.append("TERRAFORM_BIN")
    if not Path(args.mirror).is_dir():
        blockers.append("MIRROR")
    if not Path(args.cli_config).is_file():
        blockers.append("CLI_CONFIG")
    if inherited_environment_errors(os.environ):
        blockers.append("INHERITED_ENV")
    return blockers


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--expected-manifest", required=True)
    parser.add_argument("--expected-manifest-sha", required=True)
    parser.add_argument("--mirror", required=True)
    parser.add_argument("--cli-config", required=True)
    parser.add_argument("--terraform-bin", required=True)
    parser.add_argument("--sandbox-exec", required=True)
    parser.add_argument("--evidence-dir", required=True)
    args = parser.parse_args(argv)
    repo_root = Path(args.repo_root).resolve()
    evidence_dir = Path(args.evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    audit_script = repo_root / "infra/onnuri-seoul-staging-phase-b/tests/audit_static_source_policy.py"
    policy = repo_root / "infra/onnuri-seoul-staging-phase-b/tests/source_policy_manifest.json"
    audit_code, audit_output = command_result((sys.executable, "-B", str(audit_script), "--repo-root", str(repo_root), "--manifest", str(policy), "--expected-manifest", args.expected_manifest, "--expected-manifest-sha", args.expected_manifest_sha), repo_root, {"PATH": os.environ.get("PATH", ""), "LC_ALL": "C", "TZ": "UTC"})
    blockers = preflight(args)
    commands = [{"name": "static-policy", "exit": audit_code}]
    if audit_code:
        blockers.append("STATIC_POLICY")
    if blockers:
        print(json.dumps({"status": "blocked", "blockers": sorted(set(blockers)), "commands": commands}, sort_keys=True))
        return 1 if audit_code else 0
    with tempfile.TemporaryDirectory(prefix="phase-b-tf-") as temporary:
        environment = scrubbed_environment(args.cli_config, Path(temporary) / "data", Path(temporary) / "home")
        Path(environment["HOME"]).mkdir()
        Path(environment["TF_DATA_DIR"]).mkdir()
        for terraform_args in TERRAFORM_COMMANDS:
            command = (args.sandbox_exec, "-p", SANDBOX_PROFILE, args.terraform_bin, *terraform_args)
            exit_code, output = command_result(command, repo_root / "infra/onnuri-seoul-staging-phase-b", environment)
            commands.append({"name": "terraform " + " ".join(terraform_args), "exit": exit_code})
            if terraform_args == ("version",):
                if output.count("Terraform v1.15.8") != 1 or output.count("on darwin_arm64") != 1:
                    print(json.dumps({"status": "blocked", "blockers": ["CLI_VERSION"], "commands": commands}, sort_keys=True))
                    return 0
            if exit_code:
                print(json.dumps({"status": "failed", "blockers": [], "commands": commands}, sort_keys=True))
                return 1
    print(json.dumps({"status": "passed", "blockers": [], "commands": commands}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
