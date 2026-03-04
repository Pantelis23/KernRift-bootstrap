#!/usr/bin/env bash
set -euo pipefail

acceptance_assert_nonempty_file() {
  local path="$1"
  if [[ ! -s "$path" ]]; then
    echo "expected non-empty file: $path" >&2
    exit 1
  fi
}

acceptance_optional_skip() {
  local label="$1"
  local reason="$2"
  echo "[optional] ${label} skipped: ${reason}"
}
