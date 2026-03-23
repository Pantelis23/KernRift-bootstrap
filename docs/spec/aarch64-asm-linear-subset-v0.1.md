# AArch64 Assembly Text Emission — Linear Subset v0.1

## Section and symbols

- `.section <name>` from `AArch64AsmModule.section`
- `.global <symbol>` before each function
- Label: `<symbol>:`

## Prologue / epilogue

- Prologue: `stp x29, x30, [sp, #-N]!` then `mov x29, sp`
  - N = frame_bytes = (stack_cells * 8 rounded up to 16) + 16 (for saved x29/x30)
- Epilogue: `ldp x29, x30, [sp], #N`

## Instruction mapping

| Instruction | Emitted assembly |
|-------------|-----------------|
| `Call { symbol }` | `bl <symbol>` |
| `CallWithArgs { symbol, .. }` | `bl <symbol>` |
| `TailCall { symbol, .. }` | epilogue + `b <symbol>` |
| `Ret` | epilogue + `ret` |
| `CallCapture { symbol, .. }` | `bl <symbol>` |
| `BranchIfZero { then_symbol, else_symbol, .. }` | `cbz x0, <then_symbol>` + `b <else_symbol>` |
| `BranchIfEqImm { compare_value, then_symbol, else_symbol, .. }` | `cmp x0, #<value>` + `b.eq <then_symbol>` + `b <else_symbol>` |
| `BranchIfMaskNonZeroImm { mask_value, then_symbol, else_symbol, .. }` | `tst x0, #<mask>` + `b.ne <then_symbol>` + `b <else_symbol>` |
| `MmioRead { addr, U8, .. }` | `ldr x1, =0x<addr>` + `ldrb w0, [x1]` |
| `MmioRead { addr, U16, .. }` | `ldr x1, =0x<addr>` + `ldrh w0, [x1]` |
| `MmioRead { addr, U32, .. }` | `ldr x1, =0x<addr>` + `ldr w0, [x1]` |
| `MmioRead { addr, U64, .. }` | `ldr x1, =0x<addr>` + `ldr x0, [x1]` |
| `MmioWriteImm { addr, value, U8 }` | `ldr x1, =0x<addr>` + `mov w2, #<value>` + `strb w2, [x1]` |
| `MmioWriteImm { addr, value, U16 }` | `ldr x1, =0x<addr>` + `mov w2, #<value>` + `strh w2, [x1]` |
| `MmioWriteImm { addr, value, U32 }` | `ldr x1, =0x<addr>` + `mov w2, #<value>` + `str w2, [x1]` |
| `MmioWriteImm { addr, value, U64 }` | `ldr x1, =0x<addr>` + `mov x2, #<value>` + `str x2, [x1]` |
| `MmioWriteValue { addr, U8 }` | `ldr x1, =0x<addr>` + `strb w2, [x1]` |
| `MmioWriteValue { addr, U32 }` | `ldr x1, =0x<addr>` + `str w2, [x1]` |
| `MmioWriteValue { addr, U64 }` | `ldr x1, =0x<addr>` + `str x2, [x1]` |
| `Label(name)` | `<name>:` |
| `JmpLabel(label)` | `b <label>` |
| `JmpIfZeroLabel(label)` | `cbz x0, <label>` |
| `JmpIfNonZeroLabel(label)` | `cbnz x0, <label>` |

## Register conventions (load/store)

| Width | Load reg | Store reg |
|-------|----------|-----------|
| U8 / F32 (32-bit) | `w0` | `w2` |
| U16 | `w0` | `w2` |
| U32 | `w0` | `w2` |
| U64 / F64 (64-bit) | `x0` | `x2` |

## Notes

- Address register: `x1` (scratch, holds MMIO address)
- Floating-point types (F32, F64) are mapped to their integer-width equivalents (w0/x0, w2/x2)
- Variants not listed above emit a `// TODO: unimplemented instruction` comment placeholder
