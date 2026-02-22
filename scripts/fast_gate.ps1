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
Invoke-Cargo -CmdArgs @("test", "-p", "kernriftc", "--test", "kr0_contract", "--locked")
Invoke-Cargo -CmdArgs @("test", "-p", "kernriftc", "--test", "cli_contract", "--locked")
Invoke-Cargo -CmdArgs @("clippy", "-p", "kernriftc", "-p", "passes", "-p", "emit", "--all-targets", "--locked", "--", "-D", "warnings")

Write-Host "fast gate: PASS"
