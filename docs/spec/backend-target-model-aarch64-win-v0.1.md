# Backend Target Model AArch64 Windows v0.1

## Purpose

This document defines the AArch64 Windows (COFF/PE) backend target contract for KernRift.

## Target identity

- `target_id = aarch64-win`
- `arch = aarch64`
- `abi = aapcs64-win` (AAPCS64 Windows variant)
- `endian = little`
- `pointer_bits = 64`

## Stack contract

- `stack_alignment_bytes = 16`

## Symbol and section assumptions

Function symbol naming:

- no implicit function-name prefix (Windows ARM64 uses undecorated names for most C symbols)

Section naming assumptions:

- text: `.text`
- rodata: `.rdata`
- data: `.data`
- bss: `.bss`

## Differences from aarch64-sysv

- Target ID: `aarch64-win` instead of `aarch64-sysv`
- Section naming uses COFF/PE conventions (`.text`, `.rdata`)
- No symbol prefix
- Argument registers x4–x7 are volatile (same as SysV x4–x7)
- Callee-saved registers: x19–x28, x29, x30 (same as AAPCS64)

## ABI

AAPCS64 Windows variant (same as AAPCS64 with minor calling-convention differences):

- integer argument registers: x0–x7
- integer return register: x0
- callee-saved registers: x19–x28, x29 (frame pointer), x30 (link register)
- caller-saved registers: x0–x18
- stack pointer: x31 (sp)
- frame pointer: x29

Platform-reserved register: x18 (reserved by Windows ARM64 platform ABI; not used by KernRift).

## Object format

Emitted artifact: COFF relocatable object.

- `Machine` field: `0xAA64` (IMAGE_FILE_MACHINE_ARM64) at byte offset 0
- External call relocation type: `IMAGE_REL_ARM64_BRANCH26` = `0x0003`

See `docs/spec/aarch64-object-linear-subset-v0.1.md` for full encoding details.

## Non-goals

This target contract does not define instruction selection, prologue/epilogue rules,
register allocation, stack slot allocation, or linker scripts.
