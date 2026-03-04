#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/kernrift-artifact-exports-XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

FIXTURE="tests/must_pass/basic.kr"
RELOC_FIXTURE="tests/must_pass/extern_call_object.kr"
KRBO_OUT="$TMP_DIR/basic.krbo"
KRBO_META="$TMP_DIR/basic.krbo.json"
ELF_OUT="$TMP_DIR/basic.o"
ELF_META="$TMP_DIR/basic.o.json"
RELOC_ELF_OUT="$TMP_DIR/extern_call_object.o"
RELOC_ELF_META="$TMP_DIR/extern_call_object.o.json"
ASM_OUT="$TMP_DIR/basic.s"
RELINKED_ELF_OUT="$TMP_DIR/basic.relinked.o"

find_readelf() {
  if command -v readelf >/dev/null 2>&1; then
    printf '%s\n' "readelf"
    return 0
  fi
  if command -v llvm-readelf >/dev/null 2>&1; then
    printf '%s\n' "llvm-readelf"
    return 0
  fi
  return 1
}

find_reloc_linker() {
  if command -v ld.lld >/dev/null 2>&1; then
    printf '%s\n' "ld.lld"
    return 0
  fi
  if command -v ld >/dev/null 2>&1; then
    printf '%s\n' "ld"
    return 0
  fi
  return 1
}

assert_nonempty_file() {
  local path="$1"
  if [[ ! -s "$path" ]]; then
    echo "expected non-empty file: $path" >&2
    exit 1
  fi
}

echo "[1/8] emit krbo + metadata"
cargo run -q -p kernriftc -- \
  --emit=krbo \
  -o "$KRBO_OUT" \
  --meta-out "$KRBO_META" \
  "$FIXTURE"
assert_nonempty_file "$KRBO_OUT"
assert_nonempty_file "$KRBO_META"

echo "[2/8] emit elfobj + metadata"
cargo run -q -p kernriftc -- \
  --emit=elfobj \
  -o "$ELF_OUT" \
  --meta-out "$ELF_META" \
  "$FIXTURE"
assert_nonempty_file "$ELF_OUT"
assert_nonempty_file "$ELF_META"

echo "[3/8] emit relocation-bearing elfobj + metadata"
cargo run -q -p kernriftc -- \
  --emit=elfobj \
  -o "$RELOC_ELF_OUT" \
  --meta-out "$RELOC_ELF_META" \
  "$RELOC_FIXTURE"
assert_nonempty_file "$RELOC_ELF_OUT"
assert_nonempty_file "$RELOC_ELF_META"

echo "[4/8] emit asm"
cargo run -q -p kernriftc -- \
  --emit=asm \
  -o "$ASM_OUT" \
  "$FIXTURE"
assert_nonempty_file "$ASM_OUT"

echo "[5/8] verify krbo metadata"
cargo run -q -p kernriftc -- \
  verify-artifact-meta \
  "$KRBO_OUT" \
  "$KRBO_META"

echo "[6/8] verify elfobj metadata"
cargo run -q -p kernriftc -- \
  verify-artifact-meta \
  "$ELF_OUT" \
  "$ELF_META"

echo "[7/8] verify relocation-bearing elfobj metadata"
cargo run -q -p kernriftc -- \
  verify-artifact-meta \
  "$RELOC_ELF_OUT" \
  "$RELOC_ELF_META"

echo "[8/8] smoke-check asm structure"
grep -q '^\.text$' "$ASM_OUT"
grep -q '^bar:$' "$ASM_OUT"
grep -q '^foo:$' "$ASM_OUT"
grep -q '^    call bar$' "$ASM_OUT"
grep -q '^    ret$' "$ASM_OUT"

if READELF_TOOL="$(find_readelf)"; then
  echo "[optional] inspect emitted elfobj with $READELF_TOOL"
  READELF_HEADER="$("$READELF_TOOL" -h "$ELF_OUT")"
  printf '%s\n' "$READELF_HEADER" | grep -Eq 'Class:[[:space:]]+ELF64'
  printf '%s\n' "$READELF_HEADER" | grep -Eq "Data:[[:space:]]+2's complement, little endian"
  printf '%s\n' "$READELF_HEADER" | grep -Eq 'Type:[[:space:]]+REL'
  printf '%s\n' "$READELF_HEADER" | grep -Eq 'Machine:[[:space:]]+(Advanced Micro Devices X86-64|x86-64)'

  READELF_SYMS="$("$READELF_TOOL" -sW "$ELF_OUT")"
  printf '%s\n' "$READELF_SYMS" | grep -Eq '[[:space:]]bar$'
  printf '%s\n' "$READELF_SYMS" | grep -Eq '[[:space:]]foo$'

  READELF_RELOCS="$("$READELF_TOOL" -rW "$ELF_OUT")"
  printf '%s\n' "$READELF_RELOCS" | grep -Eq 'There are no relocations in this file\.'

  RELOC_HEADER="$("$READELF_TOOL" -h "$RELOC_ELF_OUT")"
  printf '%s\n' "$RELOC_HEADER" | grep -Eq 'Type:[[:space:]]+REL'
  printf '%s\n' "$RELOC_HEADER" | grep -Eq 'Machine:[[:space:]]+(Advanced Micro Devices X86-64|x86-64)'

  RELOC_SYMS="$("$READELF_TOOL" -sW "$RELOC_ELF_OUT")"
  printf '%s\n' "$RELOC_SYMS" | grep -Eq '[[:space:]]entry$'
  printf '%s\n' "$RELOC_SYMS" | grep -Eq '[[:space:]]ext$'

  RELOC_RELOCS="$("$READELF_TOOL" -rW "$RELOC_ELF_OUT")"
  printf '%s\n' "$RELOC_RELOCS" | grep -Eq '\.rela\.text'
  printf '%s\n' "$RELOC_RELOCS" | grep -Eq 'R_X86_64_PLT32'
  printf '%s\n' "$RELOC_RELOCS" | grep -Eq '[[:space:]]ext([[:space:]]|$)'
fi

if RELOC_LINKER="$(find_reloc_linker)"; then
  echo "[optional] relocatable relink smoke with $RELOC_LINKER"
  "$RELOC_LINKER" -r "$ELF_OUT" -o "$RELINKED_ELF_OUT"
  assert_nonempty_file "$RELINKED_ELF_OUT"

  if READELF_TOOL="$(find_readelf)"; then
    RELINKED_HEADER="$("$READELF_TOOL" -h "$RELINKED_ELF_OUT")"
    printf '%s\n' "$RELINKED_HEADER" | grep -Eq 'Type:[[:space:]]+REL'
    printf '%s\n' "$RELINKED_HEADER" | grep -Eq 'Machine:[[:space:]]+(Advanced Micro Devices X86-64|x86-64)'
  fi
fi

echo "kernriftc artifact export acceptance: PASS"
