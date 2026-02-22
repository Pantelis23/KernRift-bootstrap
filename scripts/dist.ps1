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

Invoke-Cargo -CmdArgs @("build", "--release", "--locked", "-p", "kernriftc")

$binaryPath = Join-Path $RepoRoot "target\release\kernriftc.exe"
if (-not (Test-Path $binaryPath)) {
    throw "dist failed: missing release binary at $binaryPath"
}

& $binaryPath --selftest
if ($LASTEXITCODE -ne 0) {
    throw "dist failed: kernriftc --selftest failed"
}

$distDir = Join-Path $RepoRoot "dist"
New-Item -ItemType Directory -Force -Path $distDir | Out-Null

$arch = $env:PROCESSOR_ARCHITECTURE.ToLower()
$archiveName = "kernriftc-windows-$arch.zip"
$archivePath = Join-Path $distDir $archiveName
if (Test-Path $archivePath) {
    Remove-Item -Force $archivePath
}
Compress-Archive -Path $binaryPath -DestinationPath $archivePath -Force

$hash = Get-FileHash -Path $archivePath -Algorithm SHA256
$hashPath = "$archivePath.sha256"
"$($hash.Hash.ToLower())  $archiveName" | Set-Content -NoNewline $hashPath

Write-Host "dist artifact: $archivePath"
Write-Host "sha256 file: $hashPath"
