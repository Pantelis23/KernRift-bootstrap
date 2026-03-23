# AArch64 Object Linear Subset v0.1

## Purpose

This document defines the first AArch64 object compatibility/export paths emitted by KernRift:

- `emit_aarch64_elf_object_bytes` — ELF64 relocatable object for Linux/SysV AArch64
- `emit_aarch64_macho_object_bytes` — Mach-O 64-bit relocatable object for macOS AArch64
- `emit_aarch64_coff_object_bytes` — COFF relocatable object for Windows ARM64

These are intentionally downstream of the AArch64 assembly text emission layer defined in
`docs/spec/aarch64-asm-linear-subset-v0.1.md`. They remain intentionally tiny.

## Layer boundary

The intended pipeline for the supported subset is:

- surface KernRift
- canonical executable semantics
- executable KRIR
- backend target contract
- AArch64 assembly IR (`AArch64AsmModule`)
- AArch64 binary encoding
- object format wrapper (ELF / Mach-O / COFF)

The object is downstream of executable KRIR and is derived from the AArch64 asm IR.
It is not the semantic truth of the language.

## Supported lowering subset

Supported executable KRIR inputs:

- zero-parameter functions
- unit return
- exactly one explicit entry block per function
- ordered direct `Call`, `CallWithArgs`, `CallCapture` ops
- `TailCall` terminator (epilogue + `b <symbol>`)
- terminal `Return { value: Unit }` (epilogue + `ret`)
- direct calls to:
  - defined non-extern functions in the same module, or
  - unresolved external function targets (preserved as relocations)

Rejected at this lowering boundary:

- multiple blocks
- MMIO, stack, slot, arithmetic, compare, raw-pointer, and inline-asm instructions
  (these emit an error: "unsupported instruction ... in function '...'")

## Binary encoding

All AArch64 instructions are 32-bit little-endian words.

### Prologue (every function)

```
stp x29, x30, [sp, #-N]!   ; N = frame_bytes = ((n_stack_cells*8 + 15) & ~15) + 16
mov x29, sp                 ; 0x910003FD
```

Encoding of `stp x29, x30, [sp, #-N]!`:
- Opcode base: `0xA9800000`
- `imm7 = (-N/8) & 0x7F`
- Word: `0xA9800000 | (imm7 << 15) | (30 << 10) | (31 << 5) | 29`

### Epilogue (Ret / TailCall)

```
ldp x29, x30, [sp], #N
```

Encoding of `ldp x29, x30, [sp], #N`:
- Opcode base: `0xA8C00000`
- `imm7 = (N/8) & 0x7F`
- Word: `0xA8C00000 | (imm7 << 15) | (30 << 10) | (31 << 5) | 29`

### Ret

```
ret   ; 0xD65F03C0
```

### Call (internal)

```
bl <symbol>   ; 0x94000000 | (imm26 & 0x03FFFFFF)
```

The 26-bit PC-relative immediate is patched after all function offsets are known.
Displacement = `(target_offset - (patch_offset + 4)) / 4`.

### Call (external)

```
bl <symbol>   ; 0x94000000 (imm26 = 0, relocation emitted)
```

### TailCall

Epilogue (`ldp x29, x30, [sp], #N`) followed by:
```
b <symbol>    ; 0x14000000 | (imm26 & 0x03FFFFFF)
```

## ELF64 object layout (emit_aarch64_elf_object_bytes)

- `e_machine` = `0x00B7` (EM_AARCH64, little-endian at offset 18)
- `e_type` = `ET_REL` (1)
- Sections: `.text`, `.rela.text` (if external calls present), `.symtab`, `.strtab`, `.shstrtab`
- Relocation type used: R_AARCH64_CALL26 = 283 (0x11B)
- Addend = 0 for all relocations

## Mach-O 64-bit object layout (emit_aarch64_macho_object_bytes)

- Magic: `0xFEEDFACF` at offset 0 (MH_MAGIC_64)
- `cputype` = `0x0100000C` (CPU_TYPE_ARM64) at offset 4
- `cpusubtype` = `0x00000000` (CPU_SUBTYPE_ARM64_ALL) at offset 8
- `filetype` = `MH_OBJECT` (1)
- Segments: `__TEXT` with `__text` section
- Relocation type used: ARM64_RELOC_BRANCH26 = 2 (r_info lower byte = 0xD2)
- Symbol names are prefixed with `_` in the string table

## COFF object layout (emit_aarch64_coff_object_bytes)

- `Machine` = `0xAA64` (IMAGE_FILE_MACHINE_ARM64) at offset 0
- One `.text` section
- Relocation type used: IMAGE_REL_ARM64_BRANCH26 = 0x0003

## Frame size constraint

The STP/LDP immediate field is 7-bit signed (`imm7 ∈ [-64, 63]`).
For frame_bytes = N: `imm7 = -N/8` must be in `[-64, 63]`, so N ≤ 512.
With n_stack_cells ≤ 63 and alignment rounding, the maximum supported frame is 512 bytes.
Exceeding this returns an error.

## Non-goals

- No optimization passes
- No cross-function inlining
- No position-independent code (PIC/PIE) support
- MMIO, stack/slot, arithmetic, compare, raw-pointer instructions are not encoded in this subset
