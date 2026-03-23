# Backend Target Model: AArch64 SysV (Linux) v0.1

## Overview

Target ID: `aarch64-sysv`
ABI: AAPCS64
Architecture: AArch64 (little-endian, 64-bit pointers)

## Register classification

| Register | Role | Class |
|----------|------|-------|
| x0–x7 | Arguments / return value (x0) | Caller-saved |
| x8 | Indirect result (syscall number) | Caller-saved |
| x9–x15 | Temporaries | Caller-saved |
| x16, x17 | Linker scratch (IP0/IP1) — excluded | — |
| x18 | Platform-reserved (shadow-call-stack) — excluded | — |
| x19–x28 | Saved registers | Callee-saved |
| x29 | Frame pointer | Callee-saved |
| x30 | Link register | Callee-saved |
| sp | Stack pointer | — |
| pc | Instruction pointer | — |

## Calling convention

- Arguments: x0–x7 (up to 8 integer/pointer arguments)
- Return value: x0
- Stack alignment: 16 bytes at call boundary
- Tail calls (direct): `b <target>`
- Tail calls (indirect): `br x9` (x9 is safe caller-saved scratch; x16/x17 must not be used)
