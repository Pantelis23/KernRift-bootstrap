# KernRift Architecture

## Scope

Freestanding, ahead-of-time language + compiler targeting kernel and driver development with strict interop and code-shape control.

## Compiler Pipeline

1. Front-end
- Lexer/parser
- AST + symbol resolution
- Type checker with effect and capability rules

2. Mid-end (KRIR)
- Control-flow graph in SSA-like form
- Effect facts attached to functions/basic blocks
- Lock-order metadata and callgraph summaries

3. OS-aware optimization passes
- Fast-path shaping for designated syscall/interrupt hot paths
- Stack-budget verification on exception/IRQ paths
- MMIO ordering validation and fence-requirement checks
- Callgraph pinning and section placement constraints

4. Backend
- Custom compiler-owned backend; no LLVM or host-compiler dependency
- Default artifact: `KRBOFAT` fat binary (`.krbo`), containing both x86_64 and ARM64 slices (LZ4-compressed); 8-byte magic `KRBOFAT\0` detected before single-arch `KRBO` magic in both compiler and runner
- Single-arch `krbo` (KernRift Binary Object): deterministic compiler-owned binary format with explicit symbols and fixups; emitted via `--emit=krboexe`
- Explicit fat binary emit: `--emit=krbofat`
- ELF64 relocatable object export (`elfobj`) derived from `krbo` for linker compatibility
- Textual assembly export (`asm`) for debug/reference only: x86-64 SysV and AArch64 variants
- Native object emission (ELF, Mach-O, COFF), section control, symbol visibility
- Linker script integration for kernel builds
- x86_64 target: `x86_64-sysv` (Linux/macOS), `x86_64-win` (Windows)
- ARM64 (AArch64) targets: `aarch64-sysv` (Linux), `aarch64-macho` (macOS), `aarch64-win` (Windows)
- ARM64 I-cache flush: runner flushes instruction cache after writing AArch64 code to executable memory

## Core Language Features (MVP)

- `unsafe` blocks for explicit escape hatches
- Structured MMIO declarations plus typed MMIO operations:
  - `mmio NAME = INT_LITERAL;`
  - `mmio_reg BASE.REG = INT_LITERAL : TYPE ACCESS;`
  - `mmio_read<T>(addr)` / `mmio_write<T>(addr, value)`
- Canonical surface facts: `@ctx(...)`, `@eff(...)`, `@caps(...)`, `@module_caps(...)`
- Canonical surface facts lower into KRIR facts (`ctx_ok`, `eff_used`, `caps_req`)
- Capabilities for privileged operations (I/O ports, page-table writes, IRQ routing)
- Lock-order declarations with compile-time cycle detection (or proof artifact emission)
- Execution-shaping primitives: `yieldpoint()`, `@noyield`, `lock_budget(N)`, `critical { ... }`

## Formal Semantics (KRIR Facts)

### Closed vocabularies (MVP)

- `ctx in {boot, thread, irq, nmi}`
- `effects in {alloc, block, preempt_off, ioport, mmio, dma_map, yield}`
- `capabilities in {Cap::PhysMap, Cap::PageTableWrite, Cap::IrqRoute, Cap::IoPort(range), Cap::Mmio(base,len), Cap::DmaMap(dev_id)}`

### Function fact model

Each function carries:

- `ctx_ok: CtxSet` (contexts where function may execute)
- `eff_used: EffSet` (effects function may perform)
- `caps_req: CapSet` (capabilities required to call/execute)
- region attrs: `@noyield`, `lock_budget(N)`, `@hotpath`, optional `@leaf`

Kernel-critical resources (frames, DMA buffers, transient mappings) are modeled with linear capabilities so ownership and revocation are explicit.

### Context policy model

Compiler builtins define per-context allowed effects:

- `eff_allowed(boot)`
- `eff_allowed(thread)`
- `eff_allowed(irq)`
- `eff_allowed(nmi)`

MVP baseline includes:

- `eff_allowed(irq)` excludes `alloc`, `block`, and `yield`
- `eff_allowed(nmi)` is at least as strict as IRQ

### Call-edge enforcement rule

For any call edge `caller -> callee`, compilation requires:

- `ctx_ok(caller) subset_of ctx_ok(callee)`
- for all `c in ctx_ok(caller)`: `eff_used(callee) subset_of eff_allowed(c)`
- `caps_avail(caller) superset_of caps_req(callee)`

Violation is compile error, not lint.

### MMIO op model (in KRIR/OSIR)

MMIO is represented as explicit IR ops:

- `MmioRead(addr, width, order)` where `order in {Relaxed, Acquire}`
- `MmioWrite(addr, value, width, order)` where `order in {Release, SeqCst}`
- `Fence(domain, kind)` where `domain in {mmio, cpu}`

Verification policy for MVP:

- Illegal width or access mode is compile error
- Missing required fence is compile error (no auto-insert in MVP)

### Lock graph model

- Every lock instance must declare a lock class
- Lock edges are emitted per object (`lockgraph.json`)
- Final link step merges all lock graphs and rejects cycles

### Yield/preemption semantics

- `@noyield` regions forbid any yield op
- `yieldpoint()` is legal only when not in IRQ context and not under a spinlock
- `lock_budget(N)` uses call-count metric:
- budget unit is 1 per call to a non-`@leaf` function
- for every path from `Acquire` to matching `Release`, call-count must be `<= N`
- build report includes `max_lock_depth` and `no_yield_spans`

### Lowering invariants

The following must survive lowering unchanged in meaning:

- section placement attributes
- calling convention attributes
- visibility and symbol linkage attributes
- `@hotpath` / layout pinning hints
- MMIO ordering semantics
- lock-class metadata references

## Non-Negotiable Interop

- C ABI import/export
- Inline assembly with explicit clobbers/constraints
- Custom calling conventions where required
- Exact section placement for boot, ISR tables, per-cpu segments, and linker-defined symbols

## Living Compiler

`kernriftc lc` (alias: `living-compiler`) is an advisory static analysis layer. It compiles the input, collects a `TelemetryReport`, and then matches patterns to produce ranked suggestions. It does not modify or reject the source — all output is advisory.

### Command forms

```
kernriftc lc <file.kr>
kernriftc lc --format json <file.kr>
kernriftc lc --surface experimental <file.kr>
kernriftc lc --ci <file.kr>
kernriftc lc --ci --min-fitness 70 <file.kr>
kernriftc lc --diff <file.kr>
kernriftc lc --diff <before.kr> <after.kr>
kernriftc lc --fix --dry-run <file.kr>
kernriftc lc --fix --write <file.kr>
kernriftc living-compiler <file.kr>   # backwards-compatible alias
```

### TelemetryReport fields

`collect_telemetry` populates these fields from the compiled `KrirModule`:

| Field | Meaning |
|-------|---------|
| `op_counts` | Per-op-kind counts across all functions |
| `mmio_register_count` | Number of declared device registers |
| `lock_class_count` | Number of declared lock classes |
| `ctx_distribution` | Function count per execution context |
| `irq_fn_count` | Functions whose `ctx_ok` includes `Irq` |
| `max_lock_depth` | Deepest lock nesting depth (from `passes::AnalysisReport`) |

### Patterns

Each pattern has an `id`, a `fitness` (0–100), a human-readable `signal`, and a `suggestion`. Higher fitness means the pattern applies more strongly.

| Pattern | Condition | Fitness | Surface |
|---------|-----------|---------|---------|
| `try_tail_call` | plain calls present, no `tail_call` op | `min(call_count × 15, 100)` | stable |
| `high_extern_ratio` | high ratio of extern calls | varies | stable |
| `irq_raw_mmio` | IRQ functions + raw MMIO ops | `min(30 + irq_fn_count × 10, 80)` | stable |
| `high_lock_depth` | `max_lock_depth ≥ 3` | `min(20 + (depth − 2) × 15, 75)` | stable |
| `mmio_without_lock` | MMIO registers declared, no lock class | 40 (fixed) | stable |

`irq_raw_mmio` distinguishes `KrirOp::RawMmioRead`/`RawMmioWrite` (unguarded hardware access) from the abstracted `KrirOp::MmioRead`/`MmioWrite` (device-block accesses). Only raw ops trigger the pattern.

### CI mode

`--ci` exits 1 if any suggestion has fitness ≥ 50. Override with `--min-fitness N`. Using `--min-fitness` without `--ci` is valid but only affects display filtering (suggestions below the threshold are hidden).

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No suggestions at or above threshold, or no suggestions at all |
| 1 | At least one suggestion at or above threshold (CI mode) |
| 2 | Compile error, bad arguments, or I/O error |

### Diff mode

Shows only suggestions that are new or worsened (fitness increased by ≥ 10) between two states:

- **`--diff <file.kr>`** — compares the current file against `git show HEAD:<file>`. Requires `git` on PATH.
- **`--diff <before.kr> <after.kr>`** — two-file form, no git dependency.

`--diff` and `--fix` cannot be combined.

### Auto-fix (`try_tail_call`)

`--fix` rewrites the last bare call statement in each function body to include the `tail` keyword, enabling zero-stack-growth loop-back patterns. Only `try_tail_call` is fixable in this version.

- `--fix --dry-run` — emits a unified diff to stdout; no files changed. With `--ci`, CI gate evaluates the pre-fix state.
- `--fix --write` — writes the patched source atomically (temp file + rename). With `--ci`, re-runs analysis on the patched file.
- `--fix` alone (without `--dry-run` or `--write`) is an error (exit 2).

---

## Self-Contained Toolchain

KernRift is fully self-contained: `kernriftc` produces native executables for
all three major desktop platforms without requiring any external compiler,
assembler, linker, or archiver.

### Native executable writers

The compiler includes built-in writers for every major executable format:

| Format   | Platform           | Emit flag           | Previously required |
|----------|--------------------|---------------------|---------------------|
| ELF      | Linux x86_64/AArch64 | `--emit=elfexe`   | `ld`                |
| PE32+    | Windows x86_64/AArch64 | `--emit=peexe`  | `link.exe`          |
| Mach-O   | macOS x86_64/AArch64 | `--emit=machoexe` | `ld`/`cc`           |
| `.a`     | All Unix           | `--emit=staticlib`  | `ar`                |

The ELF writer emits a fully-formed ET_EXEC binary with program headers,
section headers, and symbol tables.  The PE32+ writer includes import
directories for Windows API access.  The Mach-O writer includes load commands
for dyld and libSystem linkage.

### Host runtime blobs (Phase 3a)

`--emit=hostexe` produces a native executable that runs on the host OS.
The compiler links user code with a platform-specific runtime blob — hand-
assembled machine code that provides the process entry point and OS interface.

Six runtime variants exist:

| Variant             | Architecture | OS      |
|---------------------|-------------|---------|
| `rt_linux_x86_64`   | x86_64      | Linux   |
| `rt_linux_aarch64`  | AArch64     | Linux   |
| `rt_macos_x86_64`   | x86_64      | macOS   |
| `rt_macos_aarch64`  | AArch64     | macOS   |
| `rt_windows_x86_64` | x86_64      | Windows |
| `rt_windows_aarch64`| AArch64     | Windows |

Each runtime blob implements:

- `_start` — process entry point (calls user `main`, then exits)
- `__kr_exit(code)` — terminate the process
- `__kr_write(fd, buf, len)` — write to a file descriptor
- `__kr_mmap_alloc(size)` — allocate memory via mmap/VirtualAlloc
- `__kr_alloc(size)` / `__kr_dealloc(ptr, size)` — memory management
- `__kr_getenv(name)` — environment variable lookup
- `__kr_exec(cmd)` — execute a shell command
- `__kr_str_copy(dst, src)` / `__kr_str_cat(dst, src)` / `__kr_str_len(s)` — string utilities

### How hostexe works

1. The compiler compiles user `.kr` code to native machine code for the target
   architecture.
2. It selects the matching runtime blob for the target OS + architecture.
3. The native executable writer (ELF, PE32+, or Mach-O) combines the user code
   and runtime blob into a single self-contained executable.
4. The result runs directly — no external runtime, no interpreter, no linking
   step.

### KrboFat v2

The KrboFat container format was bumped to v2 to support the self-contained
runtime.  Each architecture entry now includes `runtime_offset` and
`runtime_len` fields, allowing the fat binary to carry per-architecture
runtime blobs alongside user code.

---

## Near-Term Risk Controls

- Keep language surface small until KR2
- Prefer explicit effects over inferred magic in safety-critical paths
- Treat backend output shape as a compatibility contract for kernel entry/interrupt code
