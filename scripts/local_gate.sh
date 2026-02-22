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
cargo test --workspace --locked

test_discovery="$(
  cargo test -p kernriftc --tests --locked -- --list 2>&1 | tee /dev/stderr
)"
echo "$test_discovery" | grep -qE "kr0_contract\\.rs"
echo "$test_discovery" | grep -qE "cli_contract\\.rs"

cargo test -p kernriftc --tests --locked
cargo test -p kernriftc --test kr0_contract --locked
cargo test -p kernriftc --test cli_contract --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo run -q -p kernriftc --locked -- --emit lockgraph tests/must_pass/callee_acquires_lock.kr >/dev/null

echo "local gate: PASS"
