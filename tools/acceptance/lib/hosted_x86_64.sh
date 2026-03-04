#!/usr/bin/env bash
set -euo pipefail

acceptance_assemble_source() {
  local asm_compiler="$1"
  local src="$2"
  local out="$3"

  case "$asm_compiler" in
    as)
      "$asm_compiler" -o "$out" "$src"
      ;;
    *)
      "$asm_compiler" -c "$src" -o "$out"
      ;;
  esac
}

acceptance_write_hosted_runtime_stub() {
  local stub_path="$1"
  local entry_symbol="$2"
  local extern_symbol="$3"

  cat > "$stub_path" <<EOF
.text
.globl _start
.globl ${extern_symbol}
_start:
    call ${entry_symbol}
    mov \$60, %rax
    mov \$99, %rdi
    syscall
${extern_symbol}:
    mov \$60, %rax
    mov \$7, %rdi
    syscall
EOF
}

acceptance_assert_elf_rel_x86_64() {
  local readelf_tool="$1"
  local path="$2"
  local header
  header="$("$readelf_tool" -h "$path")"
  printf '%s\n' "$header" | grep -Eq 'Class:[[:space:]]+ELF64'
  printf '%s\n' "$header" | grep -Eq "Data:[[:space:]]+2's complement, little endian"
  printf '%s\n' "$header" | grep -Eq 'Type:[[:space:]]+REL'
  printf '%s\n' "$header" | grep -Eq 'Machine:[[:space:]]+(Advanced Micro Devices X86-64|x86-64)'
}

acceptance_assert_elf_exec_x86_64() {
  local readelf_tool="$1"
  local path="$2"
  local header
  header="$("$readelf_tool" -h "$path")"
  printf '%s\n' "$header" | grep -Eq 'Class:[[:space:]]+ELF64'
  printf '%s\n' "$header" | grep -Eq "Data:[[:space:]]+2's complement, little endian"
  printf '%s\n' "$header" | grep -Eq 'Type:[[:space:]]+EXEC'
  printf '%s\n' "$header" | grep -Eq 'Machine:[[:space:]]+(Advanced Micro Devices X86-64|x86-64)'
}

acceptance_assert_symbol_present() {
  local readelf_tool="$1"
  local path="$2"
  local symbol="$3"
  local symbols
  symbols="$("$readelf_tool" -sW "$path")"
  printf '%s\n' "$symbols" | grep -Eq "[[:space:]]${symbol}$"
}

acceptance_assert_symbol_undefined() {
  local readelf_tool="$1"
  local path="$2"
  local symbol="$3"
  local symbols
  symbols="$("$readelf_tool" -sW "$path")"
  printf '%s\n' "$symbols" | grep -Eq "[[:space:]]UND[[:space:]]+${symbol}$"
}

acceptance_assert_symbol_not_undefined() {
  local readelf_tool="$1"
  local path="$2"
  local symbol="$3"
  local symbols
  symbols="$("$readelf_tool" -sW "$path")"
  if printf '%s\n' "$symbols" | grep -Eq "[[:space:]]UND[[:space:]]+${symbol}$"; then
    echo "expected symbol '${symbol}' to be defined in $path" >&2
    exit 1
  fi
}

acceptance_assert_rela_text_present() {
  local readelf_tool="$1"
  local path="$2"
  local relocs
  relocs="$("$readelf_tool" -rW "$path")"
  printf '%s\n' "$relocs" | grep -Eq '\.rela\.text'
}

acceptance_assert_no_relocations() {
  local readelf_tool="$1"
  local path="$2"
  local relocs
  relocs="$("$readelf_tool" -rW "$path")"
  printf '%s\n' "$relocs" | grep -Eq 'There are no relocations in this file\.'
}

acceptance_assert_relocation_references_symbol() {
  local readelf_tool="$1"
  local path="$2"
  local symbol="$3"
  local relocs
  relocs="$("$readelf_tool" -rW "$path")"
  printf '%s\n' "$relocs" | grep -Eq "[[:space:]]${symbol}([[:space:]]|$)"
}

acceptance_assert_relocation_not_references_symbol() {
  local readelf_tool="$1"
  local path="$2"
  local symbol="$3"
  local relocs
  relocs="$("$readelf_tool" -rW "$path")"
  if printf '%s\n' "$relocs" | grep -Eq "[[:space:]]${symbol}([[:space:]]|$)"; then
    echo "expected no relocation reference to symbol '${symbol}' in $path" >&2
    exit 1
  fi
}

acceptance_run_binary_expect_exit_or_skip() {
  local path="$1"
  local label="$2"
  local expected_exit="$3"
  local stderr_path="$4"
  local status=0

  chmod +x "$path" || true
  set +e
  "$path" >/dev/null 2>"$stderr_path"
  status=$?
  set -e

  if [[ "$status" -eq "$expected_exit" ]]; then
    return 0
  fi

  if [[ "$status" -eq 126 ]] && grep -Eq 'Permission denied|Operation not permitted' "$stderr_path"; then
    acceptance_optional_skip "$label runtime smoke" "execution unavailable"
    return 0
  fi

  echo "expected ${label} runtime smoke to exit ${expected_exit}, got ${status}" >&2
  if [[ -s "$stderr_path" ]]; then
    cat "$stderr_path" >&2
  fi
  exit 1
}
