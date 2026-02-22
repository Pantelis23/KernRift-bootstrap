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

cargo build --release --locked -p kernriftc

bin_path="${repo_root}/target/release/kernriftc"
if [[ ! -x "${bin_path}" ]]; then
  echo "dist failed: missing release binary at ${bin_path}" >&2
  exit 1
fi

"${bin_path}" --selftest

if ! command -v zip >/dev/null 2>&1; then
  echo "dist failed: 'zip' command is required" >&2
  exit 1
fi

mkdir -p "${repo_root}/dist"
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
archive_name="kernriftc-${os}-${arch}.zip"
archive_path="${repo_root}/dist/${archive_name}"

tmp_dir="$(mktemp -d)"
cp "${bin_path}" "${tmp_dir}/kernriftc"
(cd "${tmp_dir}" && zip -q -r "${archive_path}" "kernriftc")
rm -rf "${tmp_dir}"

sha_path="${archive_path}.sha256"
if command -v sha256sum >/dev/null 2>&1; then
  (cd "${repo_root}/dist" && sha256sum "${archive_name}") > "${sha_path}"
elif command -v shasum >/dev/null 2>&1; then
  (cd "${repo_root}/dist" && shasum -a 256 "${archive_name}") > "${sha_path}"
else
  echo "dist failed: need sha256sum or shasum for checksum generation" >&2
  exit 1
fi

echo "dist artifact: ${archive_path}"
echo "sha256 file: ${sha_path}"
