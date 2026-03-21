# hir

High-level IR lowering. Validates types, resolves extern functions, expands device blocks, and lowers the AST to KRIR structures.

## Inputs / Outputs

- **Input:** `ModuleAst` from `parser`
- **Output:** `KrirModule` ready for `passes`

## Key Types

| Type | Description |
|------|-------------|
| `lower_module` | Top-level entry point — takes `ModuleAst`, returns `KrirModule` or errors |
| `lower_expr` | Lowers an `Expr` node to KRIR slot ops |
| `lower_stmt` | Lowers a `Stmt` node to KRIR ops |
| `DeviceRegMap` | Symbol table mapping device field names to MMIO base + offset |

## Pipeline Position

```
ModuleAst → [hir] → KrirModule → passes
```
