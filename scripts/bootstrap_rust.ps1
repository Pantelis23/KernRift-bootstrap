$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..")

$env:CARGO_HOME = Join-Path $RepoRoot ".tools\cargo"
$env:RUSTUP_HOME = Join-Path $RepoRoot ".tools\rustup"
$env:PATH = "$($env:CARGO_HOME)\bin;$($env:PATH)"

$toolchain = "stable"
$toolchainFile = Join-Path $RepoRoot "rust-toolchain.toml"
if (Test-Path $toolchainFile) {
    $content = Get-Content $toolchainFile -Raw
    $match = [regex]::Match($content, 'channel\s*=\s*"([^"]+)"')
    if ($match.Success) {
        $toolchain = $match.Groups[1].Value
    }
}

New-Item -ItemType Directory -Force -Path $env:CARGO_HOME | Out-Null
New-Item -ItemType Directory -Force -Path $env:RUSTUP_HOME | Out-Null

if (-not (Get-Command rustup -ErrorAction SilentlyContinue)) {
    $tmpExe = Join-Path $env:TEMP "rustup-init.exe"
    Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $tmpExe
    & $tmpExe -y --profile minimal --default-toolchain none --no-modify-path
}

try {
    & rustup run $toolchain rustc --version *> $null
    $toolchainInstalled = ($LASTEXITCODE -eq 0)
} catch {
    $toolchainInstalled = $false
}
if (-not $toolchainInstalled) {
    & rustup toolchain install $toolchain --profile minimal
}
& rustup default $toolchain

$installedComponents = (& rustup component list --toolchain $toolchain --installed) -join "`n"
$missing = @()
if ($installedComponents -notmatch '^rustfmt(-|$)') {
    $missing += "rustfmt"
}
if ($installedComponents -notmatch '^clippy(-|$)') {
    $missing += "clippy"
}
if ($missing.Count -gt 0) {
    & rustup component add @missing --toolchain $toolchain
}

Write-Host "bootstrap complete:"
Write-Host "  CARGO_HOME=$env:CARGO_HOME"
Write-Host "  RUSTUP_HOME=$env:RUSTUP_HOME"
& cargo --version
& rustc --version
