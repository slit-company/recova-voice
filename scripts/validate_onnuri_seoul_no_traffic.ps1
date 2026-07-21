#!/usr/bin/env pwsh

$ErrorActionPreference = 'Stop'

function Write-Usage {
    [Console]::Out.WriteLine('Usage: validate_onnuri_seoul_no_traffic.ps1 (--help | --evidence-dir <relative-directory>)')
}

function Exit-InterfaceFailure {
    [Console]::Error.WriteLine('validator interface or evidence path is invalid')
    exit 64
}

function Exit-EnvironmentFailure {
    [Console]::Error.WriteLine('validator environment is prohibited')
    exit 66
}

function Exit-InfrastructureFailure {
    [Console]::Error.WriteLine('validator runtime infrastructure is unavailable')
    exit 70
}

if ($args.Count -eq 1 -and $args[0] -ceq '--help') {
    Write-Usage
    exit 0
}

if ($args.Count -ne 2 -or $args[0] -cne '--evidence-dir') {
    Exit-InterfaceFailure
}

$evidenceDir = $args[1]
if ($evidenceDir -notmatch '^[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*$') {
    Exit-InterfaceFailure
}

foreach ($environmentItem in Get-ChildItem Env:) {
    $environmentName = $environmentItem.Name
    if (
        $environmentName -imatch '^(GOOGLE_|GCLOUD_|CLOUDSDK_|GCP_|TF_|AWS_|AZURE_)' -or
        $environmentName -imatch '(CREDENTIAL|TOKEN|SECRET|PROXY|NO_PROXY)'
    ) {
        Exit-EnvironmentFailure
    }
}

$pythonCandidate = if ($env:PYTHON) { $env:PYTHON } else { 'python3' }
try {
    $pythonBin = (Get-Command -Name $pythonCandidate -CommandType Application -ErrorAction Stop).Source
    $runtimeIdentity = & $pythonBin -c 'import sys; print(f"{sys.implementation.name}-{sys.version_info.major}.{sys.version_info.minor}")'
    $runtimeStatus = $LASTEXITCODE
} catch {
    Exit-InfrastructureFailure
}
if ($runtimeStatus -ne 0 -or $runtimeIdentity -notmatch '^[a-z0-9_]+-[0-9]+\.[0-9]+$') {
    Exit-InfrastructureFailure
}

try {
    $null = Get-Command -Name bash -CommandType Application -ErrorAction Stop
    $null = Get-Command -Name pwsh -CommandType Application -ErrorAction Stop
} catch {
    Exit-InfrastructureFailure
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$phaseRoot = Join-Path (Split-Path -Parent $scriptDir) 'infra/onnuri-seoul-staging-phase-a'
try {
    Set-Location -LiteralPath $phaseRoot
} catch {
    Exit-InfrastructureFailure
}

$env:ONNURI_PHASE_A_WRAPPER_CONTRACT = 'validated-v1'
$env:ONNURI_PHASE_A_RUNTIME_IDENTITY = $runtimeIdentity
try {
    $verifierOutput = & $pythonBin -c 'import sys, verify_spec; raise SystemExit(verify_spec.wrapper_main(sys.argv[1:]))' --evidence-dir $evidenceDir
    $status = $LASTEXITCODE
} catch {
    Exit-InfrastructureFailure
} finally {
    Remove-Item Env:ONNURI_PHASE_A_WRAPPER_CONTRACT -ErrorAction SilentlyContinue
    Remove-Item Env:ONNURI_PHASE_A_RUNTIME_IDENTITY -ErrorAction SilentlyContinue
}
if ($status -eq 0) {
    if ($verifierOutput -is [array] -or [string]::IsNullOrWhiteSpace($verifierOutput)) {
        Exit-InfrastructureFailure
    }
    if (
        $verifierOutput -notmatch '^[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*/sha256-[a-f0-9]{64}\.json$' -or
        -not (Test-Path -LiteralPath (Join-Path $phaseRoot $verifierOutput) -PathType Leaf)
    ) {
        Exit-InfrastructureFailure
    }
    [Console]::Out.WriteLine($verifierOutput)
    exit 0
}
if ($status -in 64, 65, 69, 70) {
    exit $status
}
Exit-InfrastructureFailure
