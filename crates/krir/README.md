# krir

Kernel Rust IR — the canonical data model for KernRift's semantic facts. All analysis passes and emitters operate on this representation.

## Inputs / Outputs

- **Input:** Populated by `hir`
- **Output:** Consumed by `passes` and `emit`

## Key Types

| Type | Description |
|------|-------------|
| `KrirModule` | Top-level IR: list of `KrirFn`, module capability set |
| `KrirFn` | One function: parameters, body ops, context set, effect set, capability set |
| `KrirOp` | IR instruction variants: slot ops, MMIO reads/writes, calls, control flow, loops |
| `MmioScalarType` | Scalar types: `U8`, `U16`, `U32`, `U64`, `I8` … `F32`, `F64`, `Bool` |
| `CtxSet` / `EffSet` / `CapSet` | Bitfield sets for contexts, effects, capabilities |
| `ExecutableOp` | Lowered instruction set for the x86_64 backend |

## Pipeline Position

```
hir → [krir] ← passes
              ← emit
              ← kernriftc (backend)
```
