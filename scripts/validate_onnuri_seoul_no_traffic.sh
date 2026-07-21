#!/usr/bin/env bash

set -u

usage() {
    printf '%s\n' 'Usage: validate_onnuri_seoul_no_traffic.sh (--help | --evidence-dir <relative-directory>)'
}

interface_failure() {
    printf '%s\n' 'validator interface or evidence path is invalid' >&2
    exit 64
}

environment_failure() {
    printf '%s\n' 'validator environment is prohibited' >&2
    exit 66
}
infrastructure_failure() {
    printf '%s\n' 'validator runtime infrastructure is unavailable' >&2
    exit 70
}

if [[ $# -eq 1 && $1 == '--help' ]]; then
    usage
    exit 0
fi

if [[ $# -ne 2 || $1 != '--evidence-dir' ]]; then
    interface_failure
fi

evidence_dir=$2
if [[ ! $evidence_dir =~ ^[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$ ]]; then
    interface_failure
fi

while IFS= read -r environment_name; do
    case $environment_name in
        [Gg][Oo][Oo][Gg][Ll][Ee]_*|[Gg][Cc][Ll][Oo][Uu][Dd]_*|[Cc][Ll][Oo][Uu][Dd][Ss][Dd][Kk]_*|[Gg][Cc][Pp]_*|[Tt][Ff]_*|[Aa][Ww][Ss]_*|[Aa][Zz][Uu][Rr][Ee]_*|*[Cc][Rr][Ee][Dd][Ee][Nn][Tt][Ii][Aa][Ll]*|*[Tt][Oo][Kk][Ee][Nn]*|*[Ss][Ee][Cc][Rr][Ee][Tt]*|*[Pp][Rr][Oo][Xx][Yy]*|*[Nn][Oo]_[Pp][Rr][Oo][Xx][Yy]*)
            environment_failure
            ;;
    esac
done < <(compgen -e)

python_candidate=${PYTHON:-python3}
if ! python_bin=$(command -v -- "$python_candidate"); then
    infrastructure_failure
fi

if ! runtime_identity=$("$python_bin" -c 'import sys; print(f"{sys.implementation.name}-{sys.version_info.major}.{sys.version_info.minor}")'); then
    infrastructure_failure
fi
if [[ ! $runtime_identity =~ ^[a-z0-9_]+-[0-9]+\.[0-9]+$ ]]; then
    infrastructure_failure
fi

if ! command -v bash >/dev/null || ! command -v pwsh >/dev/null; then
    infrastructure_failure
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P) || infrastructure_failure
phase_root=$(CDPATH= cd -- "$script_dir/../infra/onnuri-seoul-staging-phase-a" && pwd -P) || infrastructure_failure
if ! cd -- "$phase_root"; then
    infrastructure_failure
fi

if verifier_output=$(ONNURI_PHASE_A_WRAPPER_CONTRACT=validated-v1 ONNURI_PHASE_A_RUNTIME_IDENTITY="$runtime_identity" "$python_bin" -c 'import sys, verify_spec; raise SystemExit(verify_spec.wrapper_main(sys.argv[1:]))' --evidence-dir "$evidence_dir"); then
    status=0
else
    status=$?
fi
case $status in
    0)
        if [[ ! $verifier_output =~ ^[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*/sha256-[a-f0-9]{64}\.json$ ]]; then
            infrastructure_failure
        fi
        if [[ ! -f "$phase_root/$verifier_output" ]]; then
            infrastructure_failure
        fi
        printf '%s\n' "$verifier_output"
        exit 0
        ;;
    64|65|69|70)
        exit "$status"
        ;;
    *)
        infrastructure_failure
        ;;
esac
