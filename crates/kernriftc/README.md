# kernriftc

The `kernriftc` CLI binary. Orchestrates the full pipeline: parse → hir → krir → passes → emit. Also exposes the pipeline as a library API for integration tests.

## Inputs / Outputs

- **Input:** CLI arguments + `.kr` source files
- **Output:** Exit codes, stderr diagnostics, `.krbo` / `.elfobj` artifacts, JSON to stdout

## Key Entry Points

| Symbol | Description |
|--------|-------------|
| `main()` | CLI dispatcher — routes subcommands to handlers |
| `compile_file(path)` | Public API: parse + lower → `KrirModule` |
| `check_file(path)` | Public API: compile + analyze → `Ok(())` or errors |
| `emit_backend_artifact_file(path, kind)` | Compile + emit binary artifact bytes |
| `run_backend_emit(args)` | Execute backend emit pipeline from parsed CLI args |

## Subcommands

| Command | Description |
|---------|-------------|
| `kernriftc <file.kr>` | Compile to `<stem>.krbo` in CWD |
| `kernriftc check` | Analysis only |
| `kernriftc verify` | Verify artifact hash/signature |
| `kernriftc policy` | Evaluate policy against contracts |
| `kernriftc inspect-artifact` | Inspect artifact contents |
| `kernriftc fix` | Apply canonical source fixes |

## Pipeline Position

```
CLI args → [kernriftc] → parser → hir → krir → passes → emit → artifacts / JSON
```
