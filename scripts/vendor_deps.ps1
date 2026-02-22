$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..")
Set-Location $RepoRoot

$env:CARGO_HOME = Join-Path $RepoRoot ".tools\cargo"
$env:RUSTUP_HOME = Join-Path $RepoRoot ".tools\rustup"
$env:PATH = "$($env:CARGO_HOME)\bin;$($env:PATH)"

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    & (Join-Path $RepoRoot "scripts\bootstrap_rust.ps1")
}

New-Item -ItemType Directory -Force -Path (Join-Path $RepoRoot ".cargo") | Out-Null
$configPath = Join-Path $RepoRoot ".cargo\config.toml"
& cargo vendor vendor | Set-Content -NoNewline $configPath

Write-Host "vendored dependencies into $RepoRoot\vendor"
Write-Host "wrote $configPath"
