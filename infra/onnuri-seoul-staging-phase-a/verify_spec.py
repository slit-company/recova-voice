#!/usr/bin/env python3
"""Provider-free verifier for the Onnuri Seoul staging Phase A contract."""

from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import NoReturn

EXIT_INTERFACE = 64
EXIT_SPEC = 65
EXIT_ENVIRONMENT = 66
EXIT_CAPABILITY = 69
EXIT_INFRASTRUCTURE = 70

PHASE_ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = PHASE_ROOT.parents[1]
SPEC_PATH = PHASE_ROOT / "control-spec.json"
SCHEMA_PATH = PHASE_ROOT / "control-spec.schema.json"
EXPECTED_SCHEMA_SHA256 = (
    "c7368d495e33e46e4df3453b393070edaab3fcfd11ea7e9f4765b54805f5e974"
)

CONTROL_IDS = ("sip_ingress", "sip_egress", "rtp_ingress", "rtp_egress")
STAGES = (
    "interface",
    "environment_guard",
    "evidence_path",
    "static_surface",
    "schema",
    "control_model",
    "network_deny",
    "unit_contract",
    "evidence_write",
)
REVIEW_IDENTITIES = [
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
SOURCE_PATHS = tuple(
    sorted(
        (
            "context/005-onnuri-seoul-staging-phase-a-operator-contract.md",
            "infra/onnuri-seoul-staging-phase-a/README.md",
            "infra/onnuri-seoul-staging-phase-a/control-spec.json",
            "infra/onnuri-seoul-staging-phase-a/control-spec.schema.json",
            "infra/onnuri-seoul-staging-phase-a/tests/test_validator_contract.py",
            "infra/onnuri-seoul-staging-phase-a/tests/test_verify_spec.py",
            "infra/onnuri-seoul-staging-phase-a/verify_spec.py",
            "scripts/validate_onnuri_seoul_no_traffic.ps1",
            "scripts/validate_onnuri_seoul_no_traffic.sh",
        ),
        key=lambda value: value.encode("utf-8"),
    )
)
PROHIBITED_ENV_PREFIXES = (
    "GOOGLE_",
    "GCLOUD_",
    "CLOUDSDK_",
    "GCP_",
    "TF_",
    "AWS_",
    "AZURE_",
)
PROHIBITED_ENV_PARTS = ("CREDENTIAL", "TOKEN", "SECRET", "PROXY", "NO_PROXY")
EVIDENCE_DIRECTORY = re.compile(r"^[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*$")
NETWORK_MODULES = {"socket", "urllib", "http", "ftplib", "requests", "aiohttp", "httpx"}
PROCESS_MODULES = {"subprocess", "multiprocessing", "pty"}


class VerificationError(Exception):
    def __init__(self, message: str, exit_code: int) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def fail(message: str, exit_code: int) -> NoReturn:
    raise VerificationError(message, exit_code)


def _expected_spec() -> dict[str, object]:
    disabled = {
        "disabled": True,
        "phase": "A",
        "deployment": "forbidden",
        "evidence_status": "waiting",
    }
    controls: dict[str, object] = {
        "sip_ingress": {
            **disabled,
            "fixture": {
                "source_cidr": "61.78.32.184/32",
                "fixture_only": True,
                "not_supplier_authoritative": True,
                "not_deployable": True,
            },
        },
        "sip_egress": {
            **disabled,
            "provenance": {
                "outbound_proxy": "61.78.32.184:5060/UDP",
                "fixture_only": True,
                "not_supplier_authoritative": True,
                "not_deployable": True,
            },
        },
        "rtp_ingress": {
            **disabled,
            "peer": None,
            "ports": None,
            "status": "unpopulated",
        },
        "rtp_egress": {
            **disabled,
            "peer": None,
            "ports": None,
            "status": "unpopulated",
        },
    }
    actions = {
        f"contain_{control_id}": {
            "control_id": control_id,
            "kind": "future_disable_or_delete",
            "execution": "not_implemented",
            "automatic_retry": False,
            "re_enable": False,
            "evidence_status": "waiting",
        }
        for control_id in CONTROL_IDS
    }
    return {
        "control_spec_version": "onnuri-seoul-staging-phase-a-control-spec-v1",
        "phase": "A",
        "status": "Waiting",
        "controls": controls,
        "actions": actions,
    }


def validate_environment(
    environment: dict[str, str] | os._Environ[str] = os.environ,
) -> None:
    for name in environment:
        upper = name.upper()
        if upper.startswith(PROHIBITED_ENV_PREFIXES) or any(
            part in upper for part in PROHIBITED_ENV_PARTS
        ):
            fail("prohibited environment name", EXIT_ENVIRONMENT)


def _open_evidence_directory(parts: tuple[str, ...], *, create: bool) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    current_fd = -1
    try:
        current_fd = os.open(PHASE_ROOT, flags)
        for part in parts:
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=current_fd)
                except FileExistsError:
                    pass
            next_fd = os.open(part, flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except (AttributeError, OSError) as exc:
        if current_fd >= 0:
            os.close(current_fd)
        fail(f"evidence path failure: {type(exc).__name__}", EXIT_INTERFACE)


def resolve_evidence_directory(relative: str) -> tuple[Path, tuple[int, int]]:
    if not EVIDENCE_DIRECTORY.fullmatch(relative):
        fail("invalid evidence directory", EXIT_INTERFACE)
    parts = tuple(relative.split("/"))
    directory_fd = _open_evidence_directory(parts, create=True)
    try:
        identity = os.fstat(directory_fd)
    finally:
        os.close(directory_fd)
    candidate = PHASE_ROOT.joinpath(*parts)
    return candidate, (identity.st_dev, identity.st_ino)


def _import_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def _qualified_name(node: ast.expr, aliases: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        parent = _qualified_name(node.value, aliases)
        return f"{parent}.{node.attr}" if parent else None
    return None


class _CallCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.function_stack: list[str] = []
        self.calls: list[tuple[str, ast.Call]] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.function_stack.append(node.name)
        self.generic_visit(node)
        self.function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.function_stack.append(node.name)
        self.generic_visit(node)
        self.function_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        function_name = self.function_stack[-1] if self.function_stack else "<module>"
        self.calls.append((function_name, node))
        self.generic_visit(node)


def _function_calls(tree: ast.AST) -> list[tuple[str, ast.Call]]:
    collector = _CallCollector()
    collector.visit(tree)
    return collector.calls


def _is_prohibited_call(qualified: str) -> bool:
    root = qualified.split(".", 1)[0]
    return (
        root in NETWORK_MODULES
        or root in PROCESS_MODULES
        or qualified in {"__import__", "builtins.__import__", "eval", "exec", "getattr"}
        or qualified.startswith("importlib.")
        or qualified
        in {"os.system", "os.popen", "os.fork", "os.forkpty", "os.startfile"}
        or qualified.startswith(("os.spawn", "os.exec", "os.posix_spawn"))
    )


def scan_python_surface(path: Path, surface: str) -> None:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError, UnicodeError) as exc:
        fail(f"unscannable Python source: {type(exc).__name__}", EXIT_CAPABILITY)
    aliases = _import_aliases(tree)
    imported_modules = set(aliases.values())
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        qualified = _qualified_name(node.value, aliases)
        if not qualified:
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                aliases[target.id] = qualified
    calls = _function_calls(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if (
                    alias.asname
                    and alias.name.split(".", 1)[0] in NETWORK_MODULES | PROCESS_MODULES
                ):
                    fail("capability import alias is prohibited", EXIT_CAPABILITY)
        elif isinstance(node, ast.ImportFrom) and node.module:
            if node.module.split(".", 1)[
                0
            ] in NETWORK_MODULES | PROCESS_MODULES and any(
                alias.asname for alias in node.names
            ):
                fail("capability import alias is prohibited", EXIT_CAPABILITY)
    if surface == "verifier":
        if any(
            module.split(".", 1)[0] in NETWORK_MODULES | PROCESS_MODULES
            for module in imported_modules
        ):
            fail("verifier imports prohibited capability", EXIT_CAPABILITY)
        for _, node in calls:
            qualified = _qualified_name(node.func, aliases)
            if qualified and _is_prohibited_call(qualified):
                fail("verifier calls prohibited capability", EXIT_CAPABILITY)
    elif surface == "network_test":
        allowed_imports = {"socket", "urllib.request"}
        network_imports = {
            module
            for module in imported_modules
            if module.split(".", 1)[0] in NETWORK_MODULES | PROCESS_MODULES
        }
        if network_imports - allowed_imports:
            fail("network test imports prohibited capability", EXIT_CAPABILITY)
        allowed_function = "test_socket_and_url_probes_pass_only_when_intercepted"
        allowed_calls = {"socket.create_connection", "urllib.request.urlopen"}
        for function_name, node in calls:
            qualified = _qualified_name(node.func, aliases)
            if qualified and _is_prohibited_call(qualified):
                if function_name != allowed_function or qualified not in allowed_calls:
                    fail(
                        "network probe escapes its patched test surface",
                        EXIT_CAPABILITY,
                    )
        probe_functions = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == allowed_function
        ]
        if len(probe_functions) != 1:
            fail("network deny probe is missing or duplicated", EXIT_CAPABILITY)
        probe_function = probe_functions[0]
        guarded_calls: set[int] = set()
        required_patches = {
            ("socket.socket", "connect"),
            ("socket", "create_connection"),
            ("urllib.request", "urlopen"),
        }
        for guard in (
            node for node in ast.walk(probe_function) if isinstance(node, ast.With)
        ):
            observed_patches: set[tuple[str, str]] = set()
            for item in guard.items:
                expression = item.context_expr
                if not isinstance(expression, ast.Call):
                    continue
                if (
                    _qualified_name(expression.func, aliases)
                    != "unittest.mock.patch.object"
                ):
                    continue
                if (
                    len(expression.args) >= 2
                    and isinstance(expression.args[1], ast.Constant)
                    and isinstance(expression.args[1].value, str)
                ):
                    target = _qualified_name(expression.args[0], aliases)
                    if target:
                        observed_patches.add((target, expression.args[1].value))
            if required_patches <= observed_patches:
                guarded_calls.update(
                    id(node) for node in ast.walk(guard) if isinstance(node, ast.Call)
                )
        if not guarded_calls:
            fail("network deny patch guard is incomplete", EXIT_CAPABILITY)
        for function_name, node in calls:
            qualified = _qualified_name(node.func, aliases)
            if (
                function_name == allowed_function
                and qualified in allowed_calls
                and id(node) not in guarded_calls
            ):
                fail(
                    "network probe is not dominated by its patch guard", EXIT_CAPABILITY
                )
    elif surface == "validator_test":
        process_imports = {
            module
            for module in imported_modules
            if module.split(".", 1)[0] in NETWORK_MODULES | PROCESS_MODULES
        }
        if process_imports - {"subprocess"}:
            fail("validator test imports prohibited capability", EXIT_CAPABILITY)
        for function_name, node in calls:
            qualified = _qualified_name(node.func, aliases)
            if not qualified or not _is_prohibited_call(qualified):
                continue
            if qualified != "subprocess.run" or function_name not in {
                "_run_bash",
                "_run_powershell",
            }:
                fail(
                    "validator test permits unscoped process execution", EXIT_CAPABILITY
                )
            if not node.args or not isinstance(node.args[0], ast.List):
                fail(
                    "validator test process arguments are not a fixed vector",
                    EXIT_CAPABILITY,
                )
            keywords = {keyword.arg: keyword.value for keyword in node.keywords}
            if not (
                isinstance(keywords.get("shell"), ast.Constant)
                and keywords["shell"].value is False
                and "env" in keywords
                and "cwd" in keywords
            ):
                fail("validator test process boundary is incomplete", EXIT_CAPABILITY)
    else:
        fail("unknown static-surface category", EXIT_CAPABILITY)


def validate_static_surfaces() -> None:
    scan_python_surface(PHASE_ROOT / "verify_spec.py", "verifier")
    scan_python_surface(PHASE_ROOT / "tests/test_verify_spec.py", "network_test")
    scan_python_surface(
        PHASE_ROOT / "tests/test_validator_contract.py", "validator_test"
    )


def validate_control_model(spec: object) -> None:
    if spec != _expected_spec():
        fail("control specification differs from the closed Phase A model", EXIT_SPEC)


def validate_schema_and_spec() -> dict[str, object]:
    try:
        schema_bytes = SCHEMA_PATH.read_bytes()
        if hashlib.sha256(schema_bytes).hexdigest() != EXPECTED_SCHEMA_SHA256:
            fail("schema differs from the reviewed canonical contract", EXIT_SPEC)
        schema = json.loads(schema_bytes)
        spec = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
    except VerificationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"malformed specification: {type(exc).__name__}", EXIT_SPEC)
    if not isinstance(schema, dict) or schema.get("additionalProperties") is not False:
        fail("schema is not closed", EXIT_SPEC)
    try:
        source_const = schema["$defs"]["sourceFixture"]["properties"]["source_cidr"][
            "const"
        ]
        proxy_const = schema["$defs"]["outboundProxyProvenance"]["properties"][
            "outbound_proxy"
        ]["const"]
    except (KeyError, TypeError):
        fail("schema whitelist is incomplete", EXIT_SPEC)
    if source_const != "61.78.32.184/32" or proxy_const != "61.78.32.184:5060/UDP":
        fail("schema whitelist mismatch", EXIT_SPEC)
    validate_control_model(spec)
    return spec


def _hash_file(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        fail(f"source evidence unavailable: {type(exc).__name__}", EXIT_INFRASTRUCTURE)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def build_evidence() -> dict[str, object]:
    source_files = [
        {"path": relative, "sha256": _hash_file(REPOSITORY_ROOT / relative)}
        for relative in SOURCE_PATHS
    ]
    evidence: dict[str, object] = {
        "artifact_id": "onnuri-seoul-staging-phase-a-no-traffic",
        "evidence_schema_version": "1",
        "phase": "A",
        "review_identities": REVIEW_IDENTITIES,
        "source_files": source_files,
        "spec_sha256": _hash_file(SPEC_PATH),
        "stage_results": [{"id": stage, "status": "pass"} for stage in STAGES],
        "validator_contract_version": "onnuri-seoul-staging-phase-a-validator-v1",
        "verifier_runtime_version": f"{sys.implementation.name}-{sys.version_info.major}.{sys.version_info.minor}",
    }
    evidence["evidence_sha256"] = hashlib.sha256(_canonical_json(evidence)).hexdigest()
    return evidence


def validate_source_snapshot(evidence: dict[str, object]) -> None:
    source_files = evidence.get("source_files")
    if not isinstance(source_files, list):
        fail("evidence source snapshot is missing", EXIT_INFRASTRUCTURE)
    expected = {
        relative: _hash_file(REPOSITORY_ROOT / relative) for relative in SOURCE_PATHS
    }
    observed: dict[str, str] = {}
    for entry in source_files:
        if not isinstance(entry, dict):
            fail("evidence source entry is malformed", EXIT_INFRASTRUCTURE)
        path = entry.get("path")
        digest = entry.get("sha256")
        if not isinstance(path, str) or not isinstance(digest, str):
            fail("evidence source entry is malformed", EXIT_INFRASTRUCTURE)
        observed[path] = digest
    if observed != expected:
        fail("source files changed during verification", EXIT_INFRASTRUCTURE)


def write_evidence(
    directory: Path,
    evidence: dict[str, object],
    expected_directory_identity: tuple[int, int] | None = None,
) -> Path:
    digest = evidence["evidence_sha256"]
    if not isinstance(digest, str):
        fail("invalid evidence digest", EXIT_INFRASTRUCTURE)
    destination_name = f"sha256-{digest}.json"
    temporary_name = f".evidence-{os.getpid()}-{digest}"
    payload = _canonical_json(evidence) + b"\n"
    directory_fd = -1
    temporary_exists = False
    destination_exists = False
    try:
        try:
            relative_directory = directory.relative_to(PHASE_ROOT)
        except ValueError:
            fail("evidence directory escaped Phase A root", EXIT_INFRASTRUCTURE)
        directory_parts = tuple(relative_directory.parts)
        directory_fd = _open_evidence_directory(directory_parts, create=False)
        descriptor_stat = os.fstat(directory_fd)
        if (
            expected_directory_identity is not None
            and (
                descriptor_stat.st_dev,
                descriptor_stat.st_ino,
            )
            != expected_directory_identity
        ):
            fail("evidence directory changed before write", EXIT_INFRASTRUCTURE)

        file_fd = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        temporary_exists = True
        with os.fdopen(file_fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(
            temporary_name,
            destination_name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        temporary_exists = False
        destination_exists = True

        persisted_fd = os.open(
            destination_name,
            os.O_RDONLY | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
        with os.fdopen(persisted_fd, "rb") as handle:
            persisted = json.loads(handle.read())
        persisted_digest_input = {
            key: value for key, value in persisted.items() if key != "evidence_sha256"
        }
        actual_digest = hashlib.sha256(
            _canonical_json(persisted_digest_input)
        ).hexdigest()
        if (
            persisted.get("evidence_sha256") != digest
            or actual_digest != digest
            or destination_name != f"sha256-{actual_digest}.json"
        ):
            fail("evidence revalidation failed", EXIT_INFRASTRUCTURE)
        validate_source_snapshot(persisted)

        final_directory_fd = _open_evidence_directory(directory_parts, create=False)
        try:
            final_path_stat = os.fstat(final_directory_fd)
        finally:
            os.close(final_directory_fd)
        if (
            descriptor_stat.st_dev != final_path_stat.st_dev
            or descriptor_stat.st_ino != final_path_stat.st_ino
        ):
            fail("evidence directory changed during write", EXIT_INFRASTRUCTURE)
    except VerificationError:
        if directory_fd >= 0 and destination_exists:
            os.unlink(destination_name, dir_fd=directory_fd)
        if directory_fd >= 0 and temporary_exists:
            os.unlink(temporary_name, dir_fd=directory_fd)
        raise
    except (AttributeError, OSError, TypeError, json.JSONDecodeError) as exc:
        if directory_fd >= 0 and destination_exists:
            os.unlink(destination_name, dir_fd=directory_fd)
        if directory_fd >= 0 and temporary_exists:
            os.unlink(temporary_name, dir_fd=directory_fd)
        fail(f"evidence write failure: {type(exc).__name__}", EXIT_INFRASTRUCTURE)
    finally:
        if directory_fd >= 0:
            os.close(directory_fd)
    return directory / destination_name


def parse_arguments(arguments: list[str]) -> str:
    if len(arguments) != 2 or arguments[0] != "--evidence-dir":
        fail("invalid verifier interface", EXIT_INTERFACE)
    return arguments[1]


def validate_wrapper_context(
    environment: dict[str, str] | os._Environ[str] = os.environ,
) -> None:
    expected_runtime = (
        f"{sys.implementation.name}-{sys.version_info.major}.{sys.version_info.minor}"
    )
    if environment.get("ONNURI_PHASE_A_WRAPPER_CONTRACT") != "validated-v1":
        fail("paired wrapper contract is required", EXIT_INFRASTRUCTURE)
    if environment.get("ONNURI_PHASE_A_RUNTIME_IDENTITY") != expected_runtime:
        fail("wrapper runtime identity mismatch", EXIT_INFRASTRUCTURE)


def run(arguments: list[str]) -> Path:
    relative = parse_arguments(arguments)
    validate_environment()
    validate_wrapper_context()
    directory, directory_identity = resolve_evidence_directory(relative)
    validate_static_surfaces()
    validate_schema_and_spec()
    evidence = build_evidence()
    validate_static_surfaces()
    validate_schema_and_spec()
    validate_source_snapshot(evidence)
    return write_evidence(directory, evidence, directory_identity)


def wrapper_main(arguments: list[str]) -> int:
    try:
        output = run(arguments)
        print(output.relative_to(PHASE_ROOT).as_posix())
        return 0
    except VerificationError as exc:
        print(str(exc), file=sys.stderr)
        return exc.exit_code
    except Exception as exc:  # fail closed without exposing values
        print(
            f"unexpected local verifier failure: {type(exc).__name__}", file=sys.stderr
        )
        return EXIT_INFRASTRUCTURE


def main() -> int:
    print("direct verifier invocation is not supported", file=sys.stderr)
    return EXIT_INFRASTRUCTURE


if __name__ == "__main__":
    raise SystemExit(main())
