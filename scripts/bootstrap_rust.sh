#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

export CARGO_HOME="${repo_root}/.tools/cargo"
export RUSTUP_HOME="${repo_root}/.tools/rustup"
export PATH="${CARGO_HOME}/bin:${PATH}"

toolchain="stable"
toolchain_file="${repo_root}/rust-toolchain.toml"
if [[ -f "${toolchain_file}" ]]; then
  parsed_channel="$(sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*$/\1/p' "${toolchain_file}" | head -n 1)"
  if [[ -n "${parsed_channel}" ]]; then
    toolchain="${parsed_channel}"
  fi
fi

mkdir -p "${CARGO_HOME}" "${RUSTUP_HOME}"

if ! command -v rustup >/dev/null 2>&1; then
  if command -v curl >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --profile minimal --default-toolchain none --no-modify-path
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- https://sh.rustup.rs \
      | sh -s -- -y --profile minimal --default-toolchain none --no-modify-path
  else
    echo "bootstrap failed: require curl or wget to install rustup" >&2
    exit 1
  fi
fi

if ! rustup run "${toolchain}" rustc --version >/dev/null 2>&1; then
  rustup toolchain install "${toolchain}" --profile minimal
fi
rustup default "${toolchain}"

installed_components="$(rustup component list --toolchain "${toolchain}" --installed || true)"
missing_components=()
if ! grep -qE '^rustfmt(-|$)' <<<"${installed_components}"; then
  missing_components+=("rustfmt")
fi
if ! grep -qE '^clippy(-|$)' <<<"${installed_components}"; then
  missing_components+=("clippy")
fi
if ((${#missing_components[@]} > 0)); then
  rustup component add "${missing_components[@]}" --toolchain "${toolchain}"
fi

echo "bootstrap complete:"
echo "  CARGO_HOME=${CARGO_HOME}"
echo "  RUSTUP_HOME=${RUSTUP_HOME}"
cargo --version
rustc --version
