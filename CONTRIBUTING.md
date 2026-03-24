# Contributing to KernRift

## Prerequisites

- **Rust 1.93.1** — `rust-toolchain.toml` pins this automatically after cloning; no manual version management needed
- **Cargo** — bundled with Rust
- Run all commands from the **repo root**

## Build

```sh
cargo build --release -p kernrift -p kernriftc
```

Binaries land at `target/release/kernrift` and `target/release/kernriftc`.

## Test

```sh
# All tests
cargo test --workspace

# Quality gate (fmt + test + clippy with warnings-as-errors)
./scripts/local_gate.sh        # Linux / macOS
.\scripts\local_gate.ps1       # Windows PowerShell
```

All PRs must pass the gate before merge.

## Crate Map

The workspace contains 7 crates: a 6-crate compiler pipeline and a standalone runner.

| Crate | Role | Key Types |
|-------|------|-----------|
| [`parser`](crates/parser/) | Lexer + AST | `ModuleAst`, `FnAst`, `Stmt`, `Expr`, `DeviceDecl` |
| [`hir`](crates/hir/) | Type checking, lowering, extern resolution | `HirModule`, `HirFn`, `lower_module` |
| [`krir`](crates/krir/) | Canonical semantic IR + backend target model | `KrirModule`, `KrirFn`, `MmioScalarType`, `KrirOp`, `TargetArch`, `AArch64IntegerRegister`, `emit_krbofat_bytes`, `parse_krbofat_slice` |
| [`passes`](crates/passes/) | Context / effect / capability / lock analysis | `analyze`, `AnalysisReport` |
| [`emit`](crates/emit/) | JSON and artifact emission | `emit_krir_json`, `emit_contracts_json` |
| [`kernriftc`](crates/kernriftc/) | Compiler CLI — orchestrates the pipeline | `main`, `compile_file`, `check_file` |
| [`kernrift`](crates/kernrift/) | Runner CLI — executes `.krbo` files | `run_krbo_file` |

## Adding Tests

Tests live in `tests/` at the repo root:

| Directory | Purpose | When to add |
|-----------|---------|-------------|
| `tests/must_pass/` | Positive cases — compiler must accept | New valid syntax or feature |
| `tests/must_fail/` | Negative cases — compiler must reject | New error condition |
| `tests/golden/` | Snapshot tests — exact output must match | New CLI output format |

**Naming:** `tests/must_pass/descriptive_name.kr`, one `.kr` file per case.

Both `must_pass` and `must_fail` directories are auto-discovered by the suite tests in `crates/kernriftc/tests/kr0_contract.rs` — adding a file is enough; no test registration needed.

## Code Style

- `rustfmt` and `clippy` are enforced by the gate (warnings-as-errors)
- No `#[allow(warnings)]` in new code
- Run `cargo fmt --all` and `cargo clippy --workspace` before pushing

## PR Checklist

- [ ] Gate passes: `./scripts/local_gate.sh`
- [ ] New `.kr` test file in `tests/must_pass/` or `tests/must_fail/` for new behaviour
- [ ] `CHANGELOG.md` updated under `[Unreleased]`

## Dev Hooks

```sh
git config core.hooksPath tools/hooks
```
