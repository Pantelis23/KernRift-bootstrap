# Repo Organization, Docs & CLI Redesign

**Date:** 2026-03-21
**Status:** Approved
**Scope:** Onboarding layer, per-crate docs, installation instructions, CLI default command

---

## Goal

Make KernRift approachable for external kernel/systems developers. Add a complete onboarding path covering Linux, macOS, and Windows. Clean up the primary CLI interface.

---

## Deliverables

### 1. Rewritten `README.md`

Replace the current ~200-line CLI-heavy README with a lean landing page:

- **Header**: 1-paragraph pitch — what KernRift is, why it exists
- **Feature bullets**: 5–6 one-liners (context safety, lock ordering, MMIO correctness, capability gating, signed artifacts)
- **Install table**: Three-platform quick commands — `cargo install` and prebuilt binary download paths
- **Quickstart**: 5 lines — install, write a `.kr` file, run `kernriftc hello.kr`, see `.krbo` output
- **Links section**: Getting Started → Language Reference → Architecture → Contributing → Changelog

The entire existing CLI reference table is removed from `README.md`. All command documentation lives in `docs/getting-started.md`.

---

### 2. `docs/getting-started.md`

Full guided onboarding document:

**Prerequisites**
- Rust 1.93.1 via rustup. `rust-toolchain.toml` (present in the repo, pinned to `channel = "1.93.1"` with `rustfmt` and `clippy` components) auto-selects this version once cloned — no manual version management needed.
- Cargo (bundled with Rust)

**Install from source**
Run from the repo root:
```
cargo install --path crates/kernriftc
```

**Install prebuilt binary**
- Linux/macOS: `gh release download` or `curl`, SHA256 verification via `sha256sum`, `chmod +x`, move to a directory on `$PATH`
- Windows: PowerShell `Invoke-WebRequest`, `Get-FileHash` SHA256 check, move to a directory in `$env:PATH`

**Your first program**
Annotated walkthrough of `hello.kr` — each annotation explained in plain English (`@ctx`, `@module_caps`, `raw_write`).

**Running the compiler**
`kernriftc hello.kr` → produces `hello.krbo` in the current working directory. What success looks like. What a context violation error looks like.

**Stable command reference**

The following commands are stable and user-facing:

| Command | Output | Notes |
|---|---|---|
| `kernriftc <file.kr>` | `<stem>.krbo` in CWD | Default compile |
| `kernriftc check <file.kr>` | Exit code + diagnostics to stderr | Analysis only, no binary |
| `kernriftc check --emit=krir <file.kr>` | KRIR JSON to **stdout** | |
| `kernriftc check --emit=lockgraph <file.kr>` | Lock graph JSON to **stdout** | |
| `kernriftc check --emit=caps <file.kr>` | Capabilities manifest JSON to **stdout** | |
| `kernriftc check --emit=contracts <file.kr>` | Contracts artifact JSON to **stdout** | |
| `kernriftc check --report <metrics> <file.kr>` | Analysis report JSON to **stdout** | |
| `kernriftc verify ...` | Verify report to stdout | Hash/sig check |
| `kernriftc policy ...` | Policy report to stdout | Evaluate policy against contracts |
| `kernriftc inspect-artifact <path>` | Artifact inspection report | `--format text\|json` |
| `kernriftc fix ...` | Source edits | Canonical fix application |

The following subcommands exist but are **internal/unstable** and intentionally omitted from user docs: `verify-artifact-meta`, `inspect`, `inspect-report`, `features`, `living-compiler`, `proposals`, `migrate-preview`, `--selftest`.

**Next steps**: links to `docs/LANGUAGE.md`, `docs/ARCHITECTURE.md`, `examples/`

---

### 3. `CONTRIBUTING.md`

- **Prerequisites**: Rust 1.93.1 (auto-pinned by `rust-toolchain.toml`); run all commands from repo root
- **Build**: `cargo build --release -p kernriftc`
- **Test**: `cargo test --workspace`, `./scripts/local_gate.sh` (fmt + test + clippy, warnings-as-errors)
- **Crate map**: summary table with 6 rows — crate name, one-line role, key types. The per-crate `README.md` files (Section 4) are the authoritative source; this table is a quick-reference copy
- **Adding tests**: when to use `tests/must_pass/` vs `tests/must_fail/` vs `tests/golden/`; file naming convention
- **Code style**: rustfmt + clippy enforced by gate; no `#[allow(warnings)]` in new code
- **PR checklist**: gate passes, new `.kr` test for new behaviour, `CHANGELOG.md` updated

---

### 4. Per-Crate `README.md` Files

One `README.md` per crate under `crates/*/README.md`, ~30 lines each. These are the authoritative descriptions of each crate; the `CONTRIBUTING.md` crate map summarizes them.

Template:
```
# <crate-name>
One-line role in the pipeline.

## Inputs / Outputs
## Key Types
## Pipeline Position
  upstream → [this crate] → downstream
```

Crates: `parser`, `hir`, `krir`, `passes`, `emit`, `kernriftc`.

---

### 5. CLI Change: Default Compile Command

**New behaviour:**
```
kernriftc <file.kr>               # compiles → <stem>.krbo in CWD  (NEW)
kernriftc check <file.kr>         # analysis only (unchanged)
kernriftc verify ...              # unchanged
kernriftc policy ...              # unchanged
kernriftc inspect-artifact ...    # unchanged
```

**Implementation rules (all changes in `crates/kernriftc/src/main.rs`):**

1. Add a new branch **before the wildcard arm** (line ~339) that matches when **`args.len() == 2`** and `args[1]` ends with `.kr`. The default compile path takes **exactly one argument** (the source file) and no flags. This branch:
   - Computes the output path: strip directory prefix and `.kr` extension from the input filename, append `.krbo`, place in the current working directory. E.g. `src/foo.kr` → `./foo.krbo`.
   - Calls `parse_backend_emit_args("krbo", ...)` with the equivalent of `-o <stem>.krbo <file.kr>`, then calls `run_backend_emit(&parsed)`. Identical to the existing `--emit=krbo -o ...` path — no new emit logic.
   - If `args.len() > 2` and `args[1]` ends with `.kr` (extra arguments present), emit a clear error **before** reaching the wildcard: `"error: unexpected arguments after source file. Use 'kernriftc check' or 'kernriftc --emit=krbo -o <out> <file.kr>' for explicit control."` and exit non-zero.

2. Replace the existing wildcard arm (`_ => parse_backend_emit_args("elfobj", ...)`) with explicit error dispatch. **This is an intentional breaking change**: the previous wildcard silently attempted an `elfobj` emit for any unrecognised input; that undocumented fallback is removed. New dispatch:
   - If `arg` starts with `--`: `"error: unknown flag '{arg}'. Run 'kernriftc --help' for usage."`
   - If `arg` contains a `.` but does not end with `.kr`: `"error: expected a .kr source file, got '{arg}'"`
   - Otherwise (bare word, no extension): `"error: unknown subcommand '{arg}'. Did you mean 'kernriftc check'?"`
   - All three cases exit with a non-zero exit code.

3. The `--selftest`, `features`, `living-compiler`, `proposals`, `migrate-preview`, `fix`, `verify-artifact-meta`, `inspect`, `inspect-report` arms are **unchanged** — they remain in the dispatcher but are not documented publicly.

---

## Out of Scope

- Package manager distribution (apt, winget, Homebrew) — deferred; requires stable versioning and per-ecosystem registry work
- Reorganizing `docs/` subdirectory structure
- Modifying existing spec docs (`KRIR_SPEC.md`, `ARCHITECTURE.md`, `LANGUAGE.md`)
