# Backend Target Model AArch64 Mach-O v0.1

## Purpose

This document defines the AArch64 macOS (Mach-O) backend target contract for KernRift.

## Target identity

- `target_id = aarch64-macho`
- `arch = aarch64`
- `abi = aapcs64` (AAPCS64 with macOS/Darwin conventions)
- `endian = little`
- `pointer_bits = 64`

## Stack contract

- `stack_alignment_bytes = 16`

## Symbol and section assumptions

Function symbol naming:

- function-name prefix: `_` (underscore-prefixed, as is standard on Darwin/macOS)

Section naming assumptions:

- text: `__TEXT,__text` (Mach-O segment/section notation)
- rodata: `__TEXT,__const`
- data: `__DATA,__data`
- bss: `__DATA,__bss`

## Differences from aarch64-sysv

- Symbol prefix: `_` (macOS requires underscore-prefixed C symbols)
- Section naming uses Mach-O `__TEXT,__text` style instead of ELF `.text`
- Target ID: `aarch64-macho` instead of `aarch64-sysv`

## ABI

AAPCS64 (Procedure Call Standard for the Arm 64-bit Architecture) as used by macOS/Darwin:

- integer argument registers: x0–x7
- integer return register: x0
- callee-saved registers: x19–x28, x29 (frame pointer), x30 (link register)
- caller-saved registers: x0–x18, x29, x30 (within call)
- stack pointer: x31 (sp)
- frame pointer: x29

Platform-reserved register: x18 (reserved by macOS platform ABI; not used by KernRift).

## Object format

Emitted artifact: Mach-O 64-bit relocatable object (`MH_OBJECT`).

- Magic: `0xFEEDFACF` (MH_MAGIC_64)
- `cputype`: `0x0100000C` (CPU_TYPE_ARM64)
- `cpusubtype`: `0x00000000` (CPU_SUBTYPE_ARM64_ALL)

See `docs/spec/aarch64-object-linear-subset-v0.1.md` for full encoding details.

## Non-goals

This target contract does not define instruction selection, prologue/epilogue rules,
register allocation, stack slot allocation, or linker scripts.
