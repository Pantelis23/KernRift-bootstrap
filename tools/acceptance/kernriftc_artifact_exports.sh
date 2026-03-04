#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=tools/acceptance/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=tools/acceptance/lib/toolchain.sh
source "$SCRIPT_DIR/lib/toolchain.sh"
# shellcheck source=tools/acceptance/lib/hosted_x86_64.sh
source "$SCRIPT_DIR/lib/hosted_x86_64.sh"

cd "$ROOT_DIR"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/kernrift-artifact-exports-XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

BASIC_FIXTURE="tests/must_pass/basic.kr"
EXTERN_FIXTURE="tests/must_pass/extern_call_object.kr"
MIXED_FIXTURE="tests/must_pass/extern_internal_chain.kr"

BASIC_KRBO_OUT="$TMP_DIR/basic.krbo"
BASIC_KRBO_META="$TMP_DIR/basic.krbo.json"
BASIC_ELF_OUT="$TMP_DIR/basic.o"
BASIC_ELF_META="$TMP_DIR/basic.o.json"
BASIC_ASM_OUT="$TMP_DIR/basic.s"

EXTERN_ELF_OUT="$TMP_DIR/extern_call_object.o"
EXTERN_ELF_META="$TMP_DIR/extern_call_object.o.json"
EXTERN_ASM_OUT="$TMP_DIR/extern_call_object.s"
EXTERN_ASM_OBJ="$TMP_DIR/extern_call_object.from_asm.o"

MIXED_ELF_OUT="$TMP_DIR/extern_internal_chain.o"
MIXED_ELF_META="$TMP_DIR/extern_internal_chain.o.json"
MIXED_ASM_OUT="$TMP_DIR/extern_internal_chain.s"
MIXED_ASM_OBJ="$TMP_DIR/extern_internal_chain.from_asm.o"

RELINKED_BASIC_ELF_OUT="$TMP_DIR/basic.relinked.o"
FINAL_RUNTIME_STUB_SRC="$TMP_DIR/runtime_stub.s"
FINAL_RUNTIME_STUB_OBJ="$TMP_DIR/runtime_stub.o"
FINAL_EXTERN_ELF_OUT="$TMP_DIR/extern_call_object.elf.final"
FINAL_MIXED_ELF_OUT="$TMP_DIR/extern_internal_chain.elf.final"
FINAL_EXTERN_ASM_OUT="$TMP_DIR/extern_call_object.asm.final"
FINAL_MIXED_ASM_OUT="$TMP_DIR/extern_internal_chain.asm.final"

emit_artifact_with_meta() {
  local emit_kind="$1"
  local output_path="$2"
  local meta_path="$3"
  local fixture="$4"

  cargo run -q -p kernriftc -- \
    "--emit=${emit_kind}" \
    -o "$output_path" \
    --meta-out "$meta_path" \
    "$fixture"
  acceptance_assert_nonempty_file "$output_path"
  acceptance_assert_nonempty_file "$meta_path"
}

emit_artifact() {
  local emit_kind="$1"
  local output_path="$2"
  local fixture="$3"

  cargo run -q -p kernriftc -- \
    "--emit=${emit_kind}" \
    -o "$output_path" \
    "$fixture"
  acceptance_assert_nonempty_file "$output_path"
}

verify_artifact_meta() {
  local artifact_path="$1"
  local meta_path="$2"

  cargo run -q -p kernriftc -- \
    verify-artifact-meta \
    "$artifact_path" \
    "$meta_path"
}

assert_asm_line() {
  local line="$1"
  local file="$2"
  grep -q "^${line}$" "$file"
}

inspect_final_linked_artifact() {
  local readelf_tool="$1"
  local path="$2"

  acceptance_assert_elf_exec_x86_64 "$readelf_tool" "$path"
  acceptance_assert_symbol_present "$readelf_tool" "$path" "entry"
  acceptance_assert_symbol_present "$readelf_tool" "$path" "ext"
  acceptance_assert_symbol_not_undefined "$readelf_tool" "$path" "ext"
  acceptance_assert_relocation_not_references_symbol "$readelf_tool" "$path" "ext"
}

echo "[1/10] internal-only fixture: emit krbo/elfobj/asm"
emit_artifact_with_meta "krbo" "$BASIC_KRBO_OUT" "$BASIC_KRBO_META" "$BASIC_FIXTURE"
emit_artifact_with_meta "elfobj" "$BASIC_ELF_OUT" "$BASIC_ELF_META" "$BASIC_FIXTURE"
emit_artifact "asm" "$BASIC_ASM_OUT" "$BASIC_FIXTURE"

echo "[2/10] internal-only fixture: verify sidecars"
verify_artifact_meta "$BASIC_KRBO_OUT" "$BASIC_KRBO_META"
verify_artifact_meta "$BASIC_ELF_OUT" "$BASIC_ELF_META"

echo "[3/10] simple extern fixture: emit elfobj/asm"
emit_artifact_with_meta "elfobj" "$EXTERN_ELF_OUT" "$EXTERN_ELF_META" "$EXTERN_FIXTURE"
emit_artifact "asm" "$EXTERN_ASM_OUT" "$EXTERN_FIXTURE"

echo "[4/10] simple extern fixture: verify elfobj sidecar"
verify_artifact_meta "$EXTERN_ELF_OUT" "$EXTERN_ELF_META"

echo "[5/10] mixed internal+extern fixture: emit elfobj/asm"
emit_artifact_with_meta "elfobj" "$MIXED_ELF_OUT" "$MIXED_ELF_META" "$MIXED_FIXTURE"
emit_artifact "asm" "$MIXED_ASM_OUT" "$MIXED_FIXTURE"

echo "[6/10] mixed internal+extern fixture: verify elfobj sidecar"
verify_artifact_meta "$MIXED_ELF_OUT" "$MIXED_ELF_META"

echo "[7/10] asm text structure smoke"
assert_asm_line "\\.text" "$BASIC_ASM_OUT"
assert_asm_line "\\.globl bar" "$BASIC_ASM_OUT"
assert_asm_line "bar:" "$BASIC_ASM_OUT"
assert_asm_line "\\.globl foo" "$BASIC_ASM_OUT"
assert_asm_line "foo:" "$BASIC_ASM_OUT"
assert_asm_line "    call bar" "$BASIC_ASM_OUT"
assert_asm_line "    ret" "$BASIC_ASM_OUT"

assert_asm_line "\\.text" "$EXTERN_ASM_OUT"
assert_asm_line "\\.globl entry" "$EXTERN_ASM_OUT"
assert_asm_line "entry:" "$EXTERN_ASM_OUT"
assert_asm_line "    call ext" "$EXTERN_ASM_OUT"
assert_asm_line "    ret" "$EXTERN_ASM_OUT"

assert_asm_line "\\.text" "$MIXED_ASM_OUT"
assert_asm_line "\\.globl entry" "$MIXED_ASM_OUT"
assert_asm_line "entry:" "$MIXED_ASM_OUT"
assert_asm_line "    call helper" "$MIXED_ASM_OUT"
assert_asm_line "\\.globl helper" "$MIXED_ASM_OUT"
assert_asm_line "helper:" "$MIXED_ASM_OUT"
assert_asm_line "    call ext" "$MIXED_ASM_OUT"
assert_asm_line "    ret" "$MIXED_ASM_OUT"

echo "[8/10] optional emitted-ELF inspection matrix"
if READELF_TOOL="$(acceptance_find_readelf)"; then
  echo "[optional] inspect emitted elf objects with $READELF_TOOL"

  acceptance_assert_elf_rel_x86_64 "$READELF_TOOL" "$BASIC_ELF_OUT"
  acceptance_assert_symbol_present "$READELF_TOOL" "$BASIC_ELF_OUT" "bar"
  acceptance_assert_symbol_present "$READELF_TOOL" "$BASIC_ELF_OUT" "foo"
  acceptance_assert_no_relocations "$READELF_TOOL" "$BASIC_ELF_OUT"

  acceptance_assert_elf_rel_x86_64 "$READELF_TOOL" "$EXTERN_ELF_OUT"
  acceptance_assert_symbol_present "$READELF_TOOL" "$EXTERN_ELF_OUT" "entry"
  acceptance_assert_symbol_present "$READELF_TOOL" "$EXTERN_ELF_OUT" "ext"
  acceptance_assert_symbol_undefined "$READELF_TOOL" "$EXTERN_ELF_OUT" "ext"
  acceptance_assert_rela_text_present "$READELF_TOOL" "$EXTERN_ELF_OUT"
  acceptance_assert_relocation_references_symbol "$READELF_TOOL" "$EXTERN_ELF_OUT" "ext"

  acceptance_assert_elf_rel_x86_64 "$READELF_TOOL" "$MIXED_ELF_OUT"
  acceptance_assert_symbol_present "$READELF_TOOL" "$MIXED_ELF_OUT" "entry"
  acceptance_assert_symbol_present "$READELF_TOOL" "$MIXED_ELF_OUT" "helper"
  acceptance_assert_symbol_present "$READELF_TOOL" "$MIXED_ELF_OUT" "ext"
  acceptance_assert_symbol_undefined "$READELF_TOOL" "$MIXED_ELF_OUT" "ext"
  acceptance_assert_symbol_not_undefined "$READELF_TOOL" "$MIXED_ELF_OUT" "helper"
  acceptance_assert_rela_text_present "$READELF_TOOL" "$MIXED_ELF_OUT"
  acceptance_assert_relocation_references_symbol "$READELF_TOOL" "$MIXED_ELF_OUT" "ext"
  acceptance_assert_relocation_not_references_symbol "$READELF_TOOL" "$MIXED_ELF_OUT" "helper"
else
  acceptance_optional_skip "emitted-ELF inspection matrix" "readelf/llvm-readelf not found"
fi

echo "[9/10] optional downstream relink/final-link/runtime matrix"
if LINKER_TOOL="$(acceptance_find_linker)"; then
  echo "[optional] relocatable relink smoke with $LINKER_TOOL"
  "$LINKER_TOOL" -r "$BASIC_ELF_OUT" -o "$RELINKED_BASIC_ELF_OUT"
  acceptance_assert_nonempty_file "$RELINKED_BASIC_ELF_OUT"
  if READELF_TOOL="$(acceptance_find_readelf)"; then
    acceptance_assert_elf_rel_x86_64 "$READELF_TOOL" "$RELINKED_BASIC_ELF_OUT"
  fi
else
  acceptance_optional_skip "relocatable relink smoke" "ld.lld/ld not found"
fi

if LINKER_TOOL="$(acceptance_find_linker)" && ASM_COMPILER="$(acceptance_find_asm_compiler)"; then
  echo "[optional] final-link + hosted runtime for emitted elfobj with $LINKER_TOOL + $ASM_COMPILER"
  acceptance_write_hosted_runtime_stub "$FINAL_RUNTIME_STUB_SRC" "entry" "ext"
  acceptance_assemble_source "$ASM_COMPILER" "$FINAL_RUNTIME_STUB_SRC" "$FINAL_RUNTIME_STUB_OBJ"
  acceptance_assert_nonempty_file "$FINAL_RUNTIME_STUB_OBJ"

  "$LINKER_TOOL" -m elf_x86_64 -e _start -o "$FINAL_EXTERN_ELF_OUT" "$EXTERN_ELF_OUT" "$FINAL_RUNTIME_STUB_OBJ"
  acceptance_assert_nonempty_file "$FINAL_EXTERN_ELF_OUT"
  "$LINKER_TOOL" -m elf_x86_64 -e _start -o "$FINAL_MIXED_ELF_OUT" "$MIXED_ELF_OUT" "$FINAL_RUNTIME_STUB_OBJ"
  acceptance_assert_nonempty_file "$FINAL_MIXED_ELF_OUT"

  if READELF_TOOL="$(acceptance_find_readelf)"; then
    inspect_final_linked_artifact "$READELF_TOOL" "$FINAL_EXTERN_ELF_OUT"
    inspect_final_linked_artifact "$READELF_TOOL" "$FINAL_MIXED_ELF_OUT"
  fi

  acceptance_run_binary_expect_exit_or_skip "$FINAL_EXTERN_ELF_OUT" "emitted-elfobj-extern" 7 "$TMP_DIR/emitted-elfobj-extern.stderr"
  acceptance_run_binary_expect_exit_or_skip "$FINAL_MIXED_ELF_OUT" "emitted-elfobj-mixed" 7 "$TMP_DIR/emitted-elfobj-mixed.stderr"
else
  missing_tools=()
  if ! LINKER_TOOL="$(acceptance_find_linker)"; then
    missing_tools+=("ld.lld/ld")
  fi
  if ! ASM_COMPILER="$(acceptance_find_asm_compiler)"; then
    missing_tools+=("as/clang/gcc")
  fi
  acceptance_optional_skip "final-link + hosted runtime for emitted elfobj" "${missing_tools[*]}"
fi

if ASM_COMPILER="$(acceptance_find_asm_compiler)" && READELF_TOOL="$(acceptance_find_readelf)"; then
  echo "[optional] assemble emitted asm and inspect relocations with $ASM_COMPILER + $READELF_TOOL"
  acceptance_assemble_source "$ASM_COMPILER" "$EXTERN_ASM_OUT" "$EXTERN_ASM_OBJ"
  acceptance_assert_nonempty_file "$EXTERN_ASM_OBJ"
  acceptance_assemble_source "$ASM_COMPILER" "$MIXED_ASM_OUT" "$MIXED_ASM_OBJ"
  acceptance_assert_nonempty_file "$MIXED_ASM_OBJ"

  acceptance_assert_elf_rel_x86_64 "$READELF_TOOL" "$EXTERN_ASM_OBJ"
  acceptance_assert_rela_text_present "$READELF_TOOL" "$EXTERN_ASM_OBJ"
  acceptance_assert_relocation_references_symbol "$READELF_TOOL" "$EXTERN_ASM_OBJ" "ext"

  acceptance_assert_elf_rel_x86_64 "$READELF_TOOL" "$MIXED_ASM_OBJ"
  acceptance_assert_rela_text_present "$READELF_TOOL" "$MIXED_ASM_OBJ"
  acceptance_assert_relocation_references_symbol "$READELF_TOOL" "$MIXED_ASM_OBJ" "helper"
  acceptance_assert_relocation_references_symbol "$READELF_TOOL" "$MIXED_ASM_OBJ" "ext"
else
  missing_tools=()
  if ! ASM_COMPILER="$(acceptance_find_asm_compiler)"; then
    missing_tools+=("as/clang/gcc")
  fi
  if ! READELF_TOOL="$(acceptance_find_readelf)"; then
    missing_tools+=("readelf/llvm-readelf")
  fi
  acceptance_optional_skip "assemble emitted asm and inspect relocations" "${missing_tools[*]}"
fi

if LINKER_TOOL="$(acceptance_find_linker)" && ASM_COMPILER="$(acceptance_find_asm_compiler)"; then
  echo "[optional] final-link + hosted runtime for emitted asm with $LINKER_TOOL + $ASM_COMPILER"

  acceptance_assemble_source "$ASM_COMPILER" "$EXTERN_ASM_OUT" "$EXTERN_ASM_OBJ"
  acceptance_assert_nonempty_file "$EXTERN_ASM_OBJ"
  acceptance_assemble_source "$ASM_COMPILER" "$MIXED_ASM_OUT" "$MIXED_ASM_OBJ"
  acceptance_assert_nonempty_file "$MIXED_ASM_OBJ"

  if [[ ! -s "$FINAL_RUNTIME_STUB_OBJ" ]]; then
    acceptance_write_hosted_runtime_stub "$FINAL_RUNTIME_STUB_SRC" "entry" "ext"
    acceptance_assemble_source "$ASM_COMPILER" "$FINAL_RUNTIME_STUB_SRC" "$FINAL_RUNTIME_STUB_OBJ"
    acceptance_assert_nonempty_file "$FINAL_RUNTIME_STUB_OBJ"
  fi

  "$LINKER_TOOL" -m elf_x86_64 -e _start -o "$FINAL_EXTERN_ASM_OUT" "$EXTERN_ASM_OBJ" "$FINAL_RUNTIME_STUB_OBJ"
  acceptance_assert_nonempty_file "$FINAL_EXTERN_ASM_OUT"
  "$LINKER_TOOL" -m elf_x86_64 -e _start -o "$FINAL_MIXED_ASM_OUT" "$MIXED_ASM_OBJ" "$FINAL_RUNTIME_STUB_OBJ"
  acceptance_assert_nonempty_file "$FINAL_MIXED_ASM_OUT"

  if READELF_TOOL="$(acceptance_find_readelf)"; then
    inspect_final_linked_artifact "$READELF_TOOL" "$FINAL_EXTERN_ASM_OUT"
    inspect_final_linked_artifact "$READELF_TOOL" "$FINAL_MIXED_ASM_OUT"
  fi

  acceptance_run_binary_expect_exit_or_skip "$FINAL_EXTERN_ASM_OUT" "emitted-asm-extern" 7 "$TMP_DIR/emitted-asm-extern.stderr"
  acceptance_run_binary_expect_exit_or_skip "$FINAL_MIXED_ASM_OUT" "emitted-asm-mixed" 7 "$TMP_DIR/emitted-asm-mixed.stderr"
else
  missing_tools=()
  if ! LINKER_TOOL="$(acceptance_find_linker)"; then
    missing_tools+=("ld.lld/ld")
  fi
  if ! ASM_COMPILER="$(acceptance_find_asm_compiler)"; then
    missing_tools+=("as/clang/gcc")
  fi
  acceptance_optional_skip "final-link + hosted runtime for emitted asm" "${missing_tools[*]}"
fi

echo "[10/10] hosted artifact matrix complete"
echo "kernriftc artifact export acceptance: PASS"
