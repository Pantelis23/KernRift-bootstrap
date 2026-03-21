# Repo Organization, Docs & CLI Redesign — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a clean onboarding layer (README, getting-started, CONTRIBUTING, per-crate docs) and make `kernriftc <file.kr>` the default compile command producing `<stem>.krbo`.

**Architecture:** CLI dispatcher (`main.rs`) gets a new branch before the wildcard arm. All new docs are standalone files — no changes to existing spec docs. Tests for the CLI change live in a new `cli_contract/default_compile.rs` file included from `cli_contract.rs`.

**Tech Stack:** Rust (existing codebase), `assert_cmd` (already in dev-deps), Markdown.

---

## File Map

| Status | Path | Change |
|--------|------|--------|
| Modify | `crates/kernriftc/src/main.rs` | Add default compile branch + replace wildcard with explicit errors |
| Create | `crates/kernriftc/tests/cli_contract/default_compile.rs` | Tests for new CLI behaviour |
| Modify | `crates/kernriftc/tests/cli_contract.rs` | Add `include!` for new test file |
| Modify | `README.md` | Full rewrite — lean landing page |
| Create | `docs/getting-started.md` | Full onboarding guide |
| Create | `CONTRIBUTING.md` | Build/test/crate map/PR checklist |
| Create | `crates/parser/README.md` | Per-crate doc |
| Create | `crates/hir/README.md` | Per-crate doc |
| Create | `crates/krir/README.md` | Per-crate doc |
| Create | `crates/passes/README.md` | Per-crate doc |
| Create | `crates/emit/README.md` | Per-crate doc |
| Create | `crates/kernriftc/README.md` | Per-crate doc |

---

## Task 1: CLI — default compile command

**Files:**
- Modify: `crates/kernriftc/src/main.rs` (lines 336–344, the wildcard arm)
- Create: `crates/kernriftc/tests/cli_contract/default_compile.rs`
- Modify: `crates/kernriftc/tests/cli_contract.rs` (add one `include!` line)

### Step 1: Write failing tests

Create `crates/kernriftc/tests/cli_contract/default_compile.rs`.

**Important:** this file is brought in via `include!` (not `mod`), so its content is pasted verbatim into `cli_contract.rs`. Do NOT add `use super::*;` — all imports from the top of `cli_contract.rs` (including `Command`, `predicates`, `repo_root()`, `fs`) are already in scope.

```rust
#[test]
fn default_compile_produces_krbo_in_cwd() {
    let tmp = std::env::temp_dir().join(format!(
        "kernriftc_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&tmp).unwrap();

    let hello_kr = repo_root().join("hello.kr");

    Command::cargo_bin("kernriftc")
        .unwrap()
        .current_dir(&tmp)
        .arg(hello_kr.to_str().unwrap())
        .assert()
        .success();

    assert!(
        tmp.join("hello.krbo").exists(),
        "expected hello.krbo in CWD after kernriftc hello.kr"
    );

    std::fs::remove_dir_all(&tmp).ok();
}

#[test]
fn default_compile_extra_args_gives_clear_error() {
    Command::cargo_bin("kernriftc")
        .unwrap()
        .arg(repo_root().join("hello.kr").to_str().unwrap())
        .arg("--extra")
        .assert()
        .failure()
        .stderr(predicates::str::contains("unexpected arguments after source file"));
}

#[test]
fn unknown_subcommand_gives_clear_error() {
    Command::cargo_bin("kernriftc")
        .unwrap()
        .arg("notacommand")
        .assert()
        .failure()
        .stderr(predicates::str::contains("unknown subcommand"));
}

#[test]
fn wrong_extension_gives_clear_error() {
    Command::cargo_bin("kernriftc")
        .unwrap()
        .arg("config.toml")
        .assert()
        .failure()
        .stderr(predicates::str::contains("expected a .kr source file"));
}

#[test]
fn unknown_flag_gives_clear_error() {
    Command::cargo_bin("kernriftc")
        .unwrap()
        .arg("--unknownflag")
        .assert()
        .failure()
        .stderr(predicates::str::contains("unknown flag"));
}
```

### Step 2: Add include to cli_contract.rs

At the end of `crates/kernriftc/tests/cli_contract.rs`, add:
```rust
include!("cli_contract/default_compile.rs");
```

### Step 3: Run tests — expect compile error then 5 failures

```bash
cargo test -p kernriftc --test cli_contract default_compile 2>&1 | tail -20
```
Expected first: compilation succeeds (the test file has no `use super::*;` so no import error).
Then: 5 FAILED — the binary doesn't yet behave as the tests expect.

If you see `error[E0433]: use super::*` or any import error, check that you did NOT add `use super::*;` to `default_compile.rs`.

### Step 3a: Verify parse_backend_emit_args accepts the synthetic args shape

Before implementing, confirm the existing `parse_backend_emit_args` function (in `crates/kernriftc/src/backend_emit/args.rs`) accepts `("-o", "<output>", "<file.kr>")` as positional args. It does: `-o <value>` sets `output_path`, and any non-flag token becomes a positional (exactly one required = `input_path`). No changes needed to that function.

### Step 4: Implement the CLI change in main.rs

In `crates/kernriftc/src/main.rs`, find the wildcard arm at approximately line 338:
```rust
        _ => match parse_backend_emit_args("elfobj", &args[1..], SurfaceProfile::Stable) {
            Ok(parsed) => run_backend_emit(&parsed),
            Err(_) => {
                print_usage();
                ExitCode::from(EXIT_INVALID_INPUT)
            }
        },
```

Replace it with:

```rust
        arg if args.len() == 2 && arg.ends_with(".kr") => {
            let stem = std::path::Path::new(arg)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("output");
            let output = format!("{}.krbo", stem);
            let synthetic: Vec<String> =
                vec!["-o".to_string(), output, arg.to_string()];
            match parse_backend_emit_args("krbo", &synthetic, SurfaceProfile::Stable) {
                Ok(parsed) => run_backend_emit(&parsed),
                Err(err) => {
                    eprintln!("{}", err);
                    ExitCode::from(EXIT_INVALID_INPUT)
                }
            }
        }
        arg if args.len() > 2 && args[1].ends_with(".kr") => {
            eprintln!(
                "error: unexpected arguments after source file. \
                 Use 'kernriftc check' or '--emit=krbo -o <out> <file.kr>' for explicit control."
            );
            ExitCode::from(EXIT_INVALID_INPUT)
        }
        arg if arg.starts_with("--") => {
            eprintln!(
                "error: unknown flag '{}'. Run 'kernriftc check --help' for usage.",
                arg
            );
            ExitCode::from(EXIT_INVALID_INPUT)
        }
        arg if arg.contains('.') => {
            eprintln!(
                "error: expected a .kr source file, got '{}'",
                arg
            );
            ExitCode::from(EXIT_INVALID_INPUT)
        }
        arg => {
            eprintln!(
                "error: unknown subcommand '{}'. Did you mean 'kernriftc check'?",
                arg
            );
            ExitCode::from(EXIT_INVALID_INPUT)
        }
```

**Note on guard ordering:** The `args.len() > 2 && args[1].ends_with(".kr")` arm must use `args[1]` not `arg` for the `.kr` check, because `arg` is bound to `args[1]` in the outer match. The Rust match guards evaluate left-to-right.

### Step 5: Run tests — expect PASS

```bash
cargo test -p kernriftc --test cli_contract default_compile 2>&1 | tail -10
```
Expected: 5 passed

### Step 6: Run full suite

```bash
cargo test --workspace 2>&1 | grep -E "FAILED|error\[" | head -20
```
Expected: no failures

### Step 7: Commit

```bash
git add crates/kernriftc/src/main.rs \
        crates/kernriftc/tests/cli_contract/default_compile.rs \
        crates/kernriftc/tests/cli_contract.rs
git commit -m "feat(cli): add default compile command — kernriftc <file.kr> produces <stem>.krbo"
```

---

## Task 2: Rewrite README.md

**Files:**
- Modify: `README.md` (full rewrite)

### Step 1: Replace README.md with the new landing page

Overwrite the file entirely:

```markdown
# KernRift

A kernel-first systems language that turns OS invariants into compile-time errors — not boot-time crashes.

Generic systems languages don't model kernel reality. KernRift bakes interrupt contexts, lock ordering, MMIO semantics, and capability requirements directly into the type system. Invalid kernel behaviour fails at compile time.

## Features

- **Context safety** — functions are annotated with allowed execution contexts (`boot`, `thread`, `irq`, `nmi`); invalid call edges are rejected
- **Lock ordering** — deadlock cycles are detected and rejected at compile time
- **MMIO correctness** — hardware register access is typed and volatile-safe
- **Capability gating** — privileged operations require explicit module capability declarations
- **Effect tracking** — allocation, blocking, and yield in disallowed paths are compile errors
- **Signed artifacts** — contracts can be hashed and signed with Ed25519 for supply-chain verification

## Install

| Platform | Command |
|----------|---------|
| Linux / macOS | `cargo install --git https://github.com/Pantelis23/KernRift --bin kernriftc` |
| Windows | See [Getting Started](docs/getting-started.md#windows) |
| All (prebuilt) | See [Releases](../../releases) |

## Quickstart

```sh
# Write a kernel function
cat > entry.kr << 'EOF'
@module_caps(MmioRaw);

@ctx(thread, boot)
fn entry() {
    raw_write<u8>(0x10000000, 0x48);
}
EOF

# Compile it
kernriftc entry.kr
# → entry.krbo

# Or run the analysis pass only
kernriftc check entry.kr
```

## Documentation

| Doc | Description |
|-----|-------------|
| [Getting Started](docs/getting-started.md) | Install, first program, full command reference |
| [Language Reference](docs/LANGUAGE.md) | Complete syntax and type system |
| [Architecture](docs/ARCHITECTURE.md) | Compiler pipeline and design decisions |
| [Contributing](CONTRIBUTING.md) | Build, test, crate map, PR checklist |
| [Changelog](CHANGELOG.md) | Release history |

## Status

KR0 (facts-only pipeline + artifact emission) is complete. KR1–KR3 (driver subset, kernel module, real OS integration) are in progress. See [KR0_KR3_PLAN.md](docs/KR0_KR3_PLAN.md) for the roadmap.

## License

MIT
```

### Step 2: Verify it renders

```bash
cat README.md | head -5
```
Expected: first line is `# KernRift`

### Step 3: Commit

```bash
git add README.md
git commit -m "docs: rewrite README.md as lean landing page"
```

---

## Task 3: Write docs/getting-started.md

**Files:**
- Create: `docs/getting-started.md`

### Step 1: Create the file

```markdown
# Getting Started with KernRift

## Prerequisites

- **Rust 1.93.1** — install via [rustup](https://rustup.rs). Once you clone this repo, `rust-toolchain.toml` auto-selects the correct version; no manual pinning needed.
- **Cargo** — bundled with Rust

## Install

### From source (all platforms)

Clone the repo and run from the repo root:

```sh
git clone https://github.com/Pantelis23/KernRift
cd KernRift
cargo install --path crates/kernriftc
```

This builds and installs the `kernriftc` binary to `~/.cargo/bin/` (Linux/macOS) or `%USERPROFILE%\.cargo\bin\` (Windows), which Cargo adds to your PATH automatically.

### Prebuilt binary — Linux / macOS

Download from the [Releases page](../../releases) and verify:

```sh
# Download
curl -L -o kernriftc https://github.com/Pantelis23/KernRift/releases/latest/download/kernriftc-linux-x86_64
curl -L -o kernriftc.sha256 https://github.com/Pantelis23/KernRift/releases/latest/download/kernriftc-linux-x86_64.sha256

# Verify
sha256sum --check kernriftc.sha256

# Install
chmod +x kernriftc
sudo mv kernriftc /usr/local/bin/
```

### Prebuilt binary — Windows

```powershell
# Download
Invoke-WebRequest -Uri "https://github.com/Pantelis23/KernRift/releases/latest/download/kernriftc-windows-x86_64.exe" -OutFile kernriftc.exe
Invoke-WebRequest -Uri "https://github.com/Pantelis23/KernRift/releases/latest/download/kernriftc-windows-x86_64.sha256" -OutFile kernriftc.sha256

# Verify
$expected = (Get-Content kernriftc.sha256).Split(" ")[0]
$actual   = (Get-FileHash kernriftc.exe -Algorithm SHA256).Hash.ToLower()
if ($expected -ne $actual) { Write-Error "SHA256 mismatch!" } else { Write-Host "OK" }

# Add to PATH — move to a directory already on your PATH, e.g.:
Move-Item kernriftc.exe "$env:USERPROFILE\bin\kernriftc.exe"
```

---

## Your First Program

The repo includes `hello.kr`:

```kr
@module_caps(MmioRaw);         // this module uses raw MMIO

@ctx(thread, boot)             // callable from thread and boot contexts
fn entry() {
    raw_write<u8>(0x10000000, 0x48);  // write 'H' to UART base address
}
```

- `@module_caps(MmioRaw)` — declares that this module performs raw memory-mapped I/O. Without it, `raw_write` is a compile error.
- `@ctx(thread, boot)` — this function may only be called from thread or boot contexts. Calling it from `@ctx(irq)` is a compile error.
- `raw_write<u8>(addr, value)` — a typed volatile write. The type parameter enforces width.

Compile it:

```sh
kernriftc hello.kr
```

On success, `kernriftc` exits 0 and produces `hello.krbo` in the current directory. No output to stdout.

A context violation looks like this:

```kr
@ctx(irq)
fn bad_call() {
    entry();   // error: entry() requires ctx(thread|boot), caller is ctx(irq)
}
```

```
error[E0002]: context mismatch: `entry` requires {thread, boot}, called from {irq}
  --> bad.kr:3:5
```

---

## Command Reference

| Command | Output | Description |
|---------|--------|-------------|
| `kernriftc <file.kr>` | `<stem>.krbo` in CWD | **Default compile** |
| `kernriftc check <file.kr>` | stderr diagnostics | Analysis only, no binary |
| `kernriftc check --emit=krir <file.kr>` | JSON to **stdout** | KRIR canonical IR |
| `kernriftc check --emit=lockgraph <file.kr>` | JSON to **stdout** | Lock graph analysis |
| `kernriftc check --emit=caps <file.kr>` | JSON to **stdout** | Capabilities manifest |
| `kernriftc check --emit=contracts <file.kr>` | JSON to **stdout** | Signed contracts artifact |
| `kernriftc check --report <metrics> <file.kr>` | JSON to **stdout** | Analysis report |
| `kernriftc verify --contracts <f> --hash <h>` | JSON to **stdout** | Verify artifact hash |
| `kernriftc policy --policy <p> --contracts <c>` | JSON to **stdout** | Policy evaluation |
| `kernriftc inspect-artifact <path>` | JSON/text to **stdout** | Artifact inspection |
| `kernriftc fix ...` | Source edits | Apply canonical fixes |

---

## Next Steps

- [Language Reference](LANGUAGE.md) — types, control flow, annotations, device blocks
- [Architecture](ARCHITECTURE.md) — compiler pipeline, KRIR facts model, pass design
- [examples/](../examples/) — more example programs
- [Contributing](../CONTRIBUTING.md) — build from source, run tests, add features
```

### Step 2: Verify it exists

```bash
head -3 docs/getting-started.md
```
Expected: `# Getting Started with KernRift`

### Step 3: Commit

```bash
git add docs/getting-started.md
git commit -m "docs: add getting-started guide with Linux/macOS/Windows install instructions"
```

---

## Task 4: Write CONTRIBUTING.md

**Files:**
- Create: `CONTRIBUTING.md`

### Step 1: Create the file

```markdown
# Contributing to KernRift

## Prerequisites

- **Rust 1.93.1** — `rust-toolchain.toml` pins this automatically after cloning; no manual version management needed
- **Cargo** — bundled with Rust
- Run all commands from the **repo root**

## Build

```sh
cargo build --release -p kernriftc
```

The `kernriftc` binary lands at `target/release/kernriftc`.

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

The compiler is a 6-crate pipeline. Each crate has a `README.md` with full details.

| Crate | Role | Key Types |
|-------|------|-----------|
| [`parser`](crates/parser/) | Lexer + AST | `ModuleAst`, `FnAst`, `Stmt`, `Expr`, `DeviceDecl` |
| [`hir`](crates/hir/) | Type checking, lowering, extern resolution | `HirModule`, `HirFn`, `lower_module` |
| [`krir`](crates/krir/) | Canonical semantic IR | `KrirModule`, `KrirFn`, `MmioScalarType`, `KrirOp` |
| [`passes`](crates/passes/) | Context / effect / capability / lock analysis | `analyze`, `AnalysisReport` |
| [`emit`](crates/emit/) | JSON and artifact emission | `emit_krir_json`, `emit_contracts_json` |
| [`kernriftc`](crates/kernriftc/) | CLI binary, orchestrates the pipeline | `main`, `compile_file`, `check_file` |

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
```

### Step 2: Commit

```bash
git add CONTRIBUTING.md
git commit -m "docs: add CONTRIBUTING.md with build/test/crate map/PR checklist"
```

---

## Task 5: Per-crate README.md files

**Files:**
- Create: `crates/parser/README.md`
- Create: `crates/hir/README.md`
- Create: `crates/krir/README.md`
- Create: `crates/passes/README.md`
- Create: `crates/emit/README.md`
- Create: `crates/kernriftc/README.md`

### Step 1: Create crates/parser/README.md

```markdown
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
```

### Step 2: Create crates/hir/README.md

```markdown
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
```

### Step 3: Create crates/krir/README.md

```markdown
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
```

### Step 4: Create crates/passes/README.md

```markdown
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
```

### Step 5: Create crates/emit/README.md

```markdown
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
```

### Step 6: Create crates/kernriftc/README.md

```markdown
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
```

### Step 7: Commit all per-crate READMEs

```bash
git add crates/parser/README.md \
        crates/hir/README.md \
        crates/krir/README.md \
        crates/passes/README.md \
        crates/emit/README.md \
        crates/kernriftc/README.md
git commit -m "docs: add per-crate README.md for all 6 pipeline crates"
```

---

## Final Verification

```bash
cargo test --workspace 2>&1 | grep -E "test result|FAILED" | tail -20
```
Expected: all suites pass, 0 failures.
