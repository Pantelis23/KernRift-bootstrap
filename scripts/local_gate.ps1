$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..")
Set-Location $RepoRoot

$env:CARGO_HOME = Join-Path $RepoRoot ".tools\cargo"
$env:RUSTUP_HOME = Join-Path $RepoRoot ".tools\rustup"
$env:PATH = "$($env:CARGO_HOME)\bin;$($env:PATH)"

function Test-CargoCommand {
    param([string[]]$CmdArgs)
    try {
        & cargo @CmdArgs *> $null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

function Invoke-Cargo {
    param([string[]]$CmdArgs)
    & cargo @CmdArgs
    if ($LASTEXITCODE -ne 0) {
        throw "cargo command failed: cargo $($CmdArgs -join ' ')"
    }
}

if (
    -not (Get-Command cargo -ErrorAction SilentlyContinue) `
    -or -not (Test-CargoCommand -CmdArgs @("fmt", "--version")) `
    -or -not (Test-CargoCommand -CmdArgs @("clippy", "--version"))
) {
    & (Join-Path $RepoRoot "scripts\bootstrap_rust.ps1")
}

Invoke-Cargo -CmdArgs @("fmt", "--all", "--", "--check")
Invoke-Cargo -CmdArgs @("test", "--workspace", "--locked")

$testListPath = Join-Path $RepoRoot "test-list.txt"
cmd /c "cargo test -p kernriftc --tests --locked -- --list > `"$testListPath`" 2>&1"
if ($LASTEXITCODE -ne 0) {
    throw "cargo test discovery failed: cargo test -p kernriftc --tests -- --list"
}
$testDiscovery = Get-Content $testListPath -Raw
Write-Host $testDiscovery
Remove-Item -Force $testListPath

if (-not ($testDiscovery -match "kr0_contract\.rs")) {
    throw "missing test discovery entry for kr0_contract.rs"
}
if (-not ($testDiscovery -match "cli_contract\.rs")) {
    throw "missing test discovery entry for cli_contract.rs"
}

Invoke-Cargo -CmdArgs @("test", "-p", "kernriftc", "--tests", "--locked")
Invoke-Cargo -CmdArgs @("test", "-p", "kernriftc", "--test", "kr0_contract", "--locked")
Invoke-Cargo -CmdArgs @("test", "-p", "kernriftc", "--test", "cli_contract", "--locked")
Invoke-Cargo -CmdArgs @("clippy", "--workspace", "--all-targets", "--locked", "--", "-D", "warnings")
Invoke-Cargo -CmdArgs @("run", "-q", "-p", "kernriftc", "--locked", "--", "--emit", "lockgraph", "tests/must_pass/callee_acquires_lock.kr")

Write-Host "local gate: PASS"
