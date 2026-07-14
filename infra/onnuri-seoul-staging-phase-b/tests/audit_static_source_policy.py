#!/usr/bin/env python3
"""Read-only static policy audit for the Phase B offline source inventory."""
import argparse
import hashlib
import json
from pathlib import Path

RULE_MANIFEST = "MANIFEST"
RULE_HASH = "PATH_HASH"
RULE_TERRAFORM = "TERRAFORM_SHAPE"
RULE_STATUS = "STATUS"


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def load_json(path):
    with path.open("rb") as handle:
        return json.load(handle)


def audit(repo_root, policy_path, expected_path, expected_sha):
    """Return deterministic rule-id/path findings without modifying or spawning."""
    repo_root = Path(repo_root).resolve()
    policy = load_json(Path(policy_path))
    expected_bytes = Path(expected_path).read_bytes()
    findings = []
    if sha256_bytes(expected_bytes) != expected_sha:
        return [(RULE_MANIFEST, "expected-manifest-sha")]
    expected = json.loads(expected_bytes)
    required = policy.get("required_paths")
    entries = expected.get("entries")
    if not isinstance(required, list) or len(required) != 39 or required != sorted(required):
        return [(RULE_MANIFEST, "policy-required-paths")]
    if expected.get("entry_count") != 39 or not isinstance(entries, list) or len(entries) != 39:
        return [(RULE_MANIFEST, "expected-entries")]
    paths = [entry.get("path") for entry in entries if isinstance(entry, dict)]
    if paths != required:
        return [(RULE_MANIFEST, "expected-paths")]
    for entry in entries:
        path = entry["path"]
        state = entry.get("state")
        if state not in {"present", "absent"}:
            findings.append((RULE_MANIFEST, path))
            continue
        if state == "absent":
            if "sha256" in entry:
                findings.append((RULE_MANIFEST, path))
            continue
        value = entry.get("sha256")
        candidate = repo_root / path
        if not isinstance(value, str) or len(value) != 64 or not candidate.is_file():
            findings.append((RULE_HASH, path))
            continue
        if sha256_bytes(candidate.read_bytes()) != value:
            findings.append((RULE_HASH, path))
    active_tf = [p for p in required if p.endswith(".tf") and "/tests/" not in p]
    forbidden = tuple(policy.get("forbidden_active_tokens", []))
    for path in active_tf:
        candidate = repo_root / path
        if not candidate.is_file():
            continue
        text = candidate.read_text(encoding="utf-8")
        lowered = text.lower()
        if any(token.lower() in lowered for token in forbidden):
            findings.append((RULE_TERRAFORM, path))
        if any(token in lowered for token in ("gcloud", "http://", "https://", "terraform apply", "terraform plan")):
            findings.append((RULE_TERRAFORM, path))
    for path in ("infra/onnuri-seoul-staging-phase-b/README.md", "context/006-onnuri-seoul-staging-phase-b-foundation-decision.md"):
        candidate = repo_root / path
        if candidate.is_file():
            text = candidate.read_text(encoding="utf-8").lower()
            if "open-confirmations-pending" not in text or "offline" not in text:
                findings.append((RULE_STATUS, path))
    return sorted(set(findings))


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--expected-manifest", required=True)
    parser.add_argument("--expected-manifest-sha", required=True)
    args = parser.parse_args(argv)
    findings = audit(args.repo_root, args.manifest, args.expected_manifest, args.expected_manifest_sha)
    print(json.dumps({"findings": [{"rule": rule, "path": path} for rule, path in findings]}, sort_keys=True))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
