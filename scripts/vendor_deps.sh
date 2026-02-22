#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
cd "${repo_root}"

export CARGO_HOME="${repo_root}/.tools/cargo"
export RUSTUP_HOME="${repo_root}/.tools/rustup"
export PATH="${CARGO_HOME}/bin:${PATH}"

if ! command -v cargo >/dev/null 2>&1; then
  "${repo_root}/scripts/bootstrap_rust.sh"
fi

mkdir -p .cargo
cargo vendor vendor > .cargo/config.toml

echo "vendored dependencies into ${repo_root}/vendor"
echo "wrote ${repo_root}/.cargo/config.toml"
