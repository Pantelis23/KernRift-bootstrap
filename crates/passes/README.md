# passes

Compiler analysis passes that verify semantic correctness. Each pass takes a `KrirModule` and returns a report or a list of errors.

## Inputs / Outputs

- **Input:** `KrirModule` from `hir`
- **Output:** `AnalysisReport` (lock graph, effect annotations, diagnostics) + `Vec<KernRiftError>`

## Key Types

| Type | Description |
|------|-------------|
| `analyze` | Entry point — runs all passes, returns `(AnalysisReport, Vec<KernRiftError>)` |
| `AnalysisReport` | Aggregated results: lock graph, yield spans, max lock depth per function |
| Context pass | Verifies call edges respect `@ctx` annotations |
| Effect pass | Verifies `@eff` constraints are not violated across call chains |
| Capability pass | Verifies `@module_caps` covers all privileged ops used |
| Lock graph pass | Builds lock acquisition graph, detects cycles (deadlocks), checks `@lock_budget` |

## Pipeline Position

```
KrirModule → [passes] → AnalysisReport + errors → emit
```
