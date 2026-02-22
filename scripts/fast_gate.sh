#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
cd "${repo_root}"

export CARGO_HOME="${repo_root}/.tools/cargo"
export RUSTUP_HOME="${repo_root}/.tools/rustup"
export PATH="${CARGO_HOME}/bin:${PATH}"

if ! command -v cargo >/dev/null 2>&1 \
  || ! cargo fmt --version >/dev/null 2>&1 \
  || ! cargo clippy --version >/dev/null 2>&1; then
  "${repo_root}/scripts/bootstrap_rust.sh"
fi

cargo fmt --all -- --check
cargo test -p kernriftc --test kr0_contract --locked
cargo test -p kernriftc --test cli_contract --locked
cargo clippy -p kernriftc -p passes -p emit --all-targets --locked -- -D warnings

echo "fast gate: PASS"
