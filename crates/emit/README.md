# emit

Output emitters. Serialises `KrirModule` and `AnalysisReport` to JSON or canonical artifact formats.

## Inputs / Outputs

- **Input:** `KrirModule` + `AnalysisReport` from `passes`
- **Output:** JSON strings or `Vec<u8>` artifacts

## Key Functions

| Function | Output |
|----------|--------|
| `emit_krir_json(module)` | KRIR canonical IR as JSON string (stdout) |
| `emit_caps_manifest_json(module)` | Capabilities manifest JSON |
| `emit_lockgraph_json(report)` | Lock graph analysis JSON |
| `emit_contracts_json(module, report)` | Contracts bundle JSON (hashable, signable) |
| `emit_contracts_json_with_schema(...)` | Contracts with embedded schema version |

## Pipeline Position

```
KrirModule + AnalysisReport → [emit] → JSON / artifact bytes → kernriftc (CLI output)
```
