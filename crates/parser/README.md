# parser

Lexer and parser for `.kr` source files. Produces the `ModuleAst` consumed by `hir`.

## Inputs / Outputs

- **Input:** Raw `.kr` source text (`&str`)
- **Output:** `ModuleAst` — the complete AST for one source file

## Key Types

| Type | Description |
|------|-------------|
| `ModuleAst` | Top-level AST: list of functions, device declarations, lock declarations, constants |
| `FnAst` | A single function: name, params, return type, body statements, annotations |
| `Stmt` | Statement variants: `VarDecl`, `Assign`, `If`, `While`, `For`, `Return`, `ExprStmt` |
| `Expr` | Expression tree: literals, binary ops, field access, function calls |
| `DeviceDecl` | Named MMIO device block with register fields |
| `Lexer` / `TokParser` | Token-based parser (new syntax); falls back to character-level parser for old syntax |

## Pipeline Position

```
.kr source text → [parser] → ModuleAst → hir
```
