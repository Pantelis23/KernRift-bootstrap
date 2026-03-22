# `.krbo` Portable Loader Design

**Goal:** Make `kernriftc hello.kr` produce a portable `.krbo` file that `kernrift` can execute on Linux, macOS, and Windows without any external tools (no linker, no C compiler, no assembler).

**Architecture:** Replace the platform-specific linker-based emission paths with a self-contained binary container format. `kernriftc` emits raw x86-64 bytes wrapped in a 16-byte header. `kernrift` becomes a native loader that maps the code as executable memory and calls `entry()` directly.

**Tech Stack:** Rust, `libc` crate (Linux/macOS mmap), `windows-sys` crate (Windows VirtualAlloc), hand-written `.krbo` header emission in `krir`.

---

## The `.krbo` File Format

A 16-byte fixed header followed by raw machine code bytes.

```
Offset | Field        | Size | Description
-------|--------------|------|------------
0      | magic        | 4    | "KRBO" = [0x4B, 0x52, 0x42, 0x4F]
4      | version      | 1    | Format version. Currently 1.
5      | arch         | 1    | Target ISA. 0x01 = x86-64. Reserved for future ISAs.
6      | reserved     | 2    | Must be 0x0000.
8      | entry_offset | 4    | Byte offset of the `entry` function within the code blob.
12     | code_length  | 4    | Number of code bytes following the header.
16     | <code>       | N    | Raw machine code.
```

### Properties

- **Self-contained:** All internal `call rel32` fixups are resolved at compile time by the existing `lower_executable_krir_to_x86_64_object` path. No relocation is needed at load time.
- **Position-independent (for internal calls):** `call rel32` is relative to the next instruction pointer, so the code blob can be loaded at any address.
- **UART convention:** KernRift programs write output to a fixed buffer at `0x10000000` (4 KB). `kernrift` maps this buffer before calling `entry()`. The address is a constant embedded in the instruction stream.
- **Extensible:** The `arch` byte allows future ISAs to be added without breaking the format. `kernrift` rejects files whose `arch` tag does not match the host.

---

## `krir` crate changes

Add to `crates/krir/src/lib.rs`:

- `KrboHeader` struct (matches the 16-byte layout above).
- `emit_krbo_bytes(object: &X86_64RelocatableObject, entry_offset: u32) -> Vec<u8>` — writes the header then the code bytes.
- `parse_krbo_header(bytes: &[u8]) -> Result<KrboHeader, String>` — validates magic, version, arch, bounds.

Both `kernriftc` and `kernrift` depend on `krir`, so the format is defined in one place.

---

## `kernriftc` changes

### `emit_x86_64_executable_bytes` — full replacement

The function body becomes:

1. Validate: no extern declarations, has an `entry` function (same checks as today).
2. Lower to object: `lower_executable_krir_to_x86_64_object(executable, &BackendTargetContract::x86_64_sysv())`.
3. Find entry offset: look up `"entry"` in `object.function_symbols` to get its byte offset.
4. Emit: `krir::emit_krbo_bytes(&object, entry_offset)`.
5. Return the bytes — done. No subprocess, no temp files, no linker.

### Removed

- `link_x86_64_linux_executable` and `hosted_startup_stub_asm` (Linux linker path).
- `link_x86_64_macos_executable` and `hosted_startup_stub_asm_macos` (macOS linker path).
- `link_x86_64_windows_executable` and `hosted_startup_stub_c_windows` (Windows linker path).
- The `emit_native_executable` dispatch functions (Linux/macOS/Windows/fallback).
- All `#[cfg(target_os = ...)]` guards in the emission path.

The `kernriftc/Cargo.toml` loses no dependencies (the linker paths used only `std`).

---

## `kernrift` changes

`crates/kernriftc/src/runner.rs` is rewritten. The new logic, on all platforms:

### Step 1 — Parse

Read the file. Validate with `krir::parse_krbo_header`. Fail fast with a clear error on:

- Wrong magic → `"not a .krbo file"`
- Wrong version → `"unsupported .krbo version N (expected 1)"`
- Wrong arch tag → `"this .krbo targets <arch> but this host is x86-64"`
- `entry_offset >= code_length` → `"malformed .krbo: entry_offset out of range"`
- `code_length == 0` → `"malformed .krbo: empty code section"`

### Step 2 — Map UART buffer

Map 4 KB of read/write anonymous memory at `0x10000000`. Zero-initialise it.

- Linux/macOS: `libc::mmap(0x10000000, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANON, -1, 0)`
- Windows: `VirtualAlloc(0x10000000 as *mut _, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)`

On failure: `"failed to map UART buffer at 0x10000000: <os error>"`.

### Step 3 — Map and load code

Allocate executable memory large enough for the code bytes. Copy code in.

- Linux/macOS: `mmap(NULL, code_len, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, -1, 0)`, then `memcpy`.
- Windows: `VirtualAlloc(NULL, code_len, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)`, then `copy_nonoverlapping`.

On failure: `"failed to map executable memory: <os error>"`.

### Step 4 — Execute

Cast `code_ptr + entry_offset` to `unsafe extern "C" fn()` and call it. After it returns, execution continues in `kernrift`.

### Step 5 — Flush output and exit

Scan `0x10000000..0x10001000` for the first `0x00` byte. Write the bytes before it to stdout. Exit 0.

- Linux/macOS: `write(1, buf, len)` syscall via `libc`, then `libc::exit(0)`.
- Windows: `GetStdHandle(STD_OUTPUT_HANDLE)` + `WriteFile`, then `ExitProcess(0)` via `windows-sys`.

### Dependencies added to `kernriftc/Cargo.toml`

```toml
[target.'cfg(unix)'.dependencies]
libc = "0.2"

[target.'cfg(windows)'.dependencies]
windows-sys = { version = "0.59", features = ["Win32_System_Memory", "Win32_Foundation", "Win32_Storage_FileSystem", "Win32_System_Console"] }
```

---

## Error Handling Summary

| Situation | Error message |
|-----------|---------------|
| Wrong magic | `"not a .krbo file"` |
| Wrong version | `"unsupported .krbo version N (expected 1)"` |
| Wrong arch | `"this .krbo targets <arch> but this host is x86-64"` |
| Empty code | `"malformed .krbo: empty code section"` |
| Bad entry offset | `"malformed .krbo: entry_offset out of range"` |
| UART map fails | `"failed to map UART buffer at 0x10000000: <os error>"` |
| Code map fails | `"failed to map executable memory: <os error>"` |

---

## Testing

- **Unit:** `krir` — `emit_krbo_bytes` produces correct magic, arch tag, entry offset, code bytes. `parse_krbo_header` rejects each invalid case.
- **Unit:** `kernriftc` — `emit_x86_64_executable_bytes` returns bytes starting with `"KRBO"` magic for a valid module.
- **Integration (Linux):** `kernrift hello.krbo` prints `"Hello, World!\n"`.
- **Existing suite:** `bash tools/validation/local_safe.sh` passes unchanged.

---

## What Does Not Change

- The KernRift language, type system, and compiler passes — untouched.
- The `kernriftc check`, `kernriftc policy`, `kernriftc object`, `kernriftc asm` commands — untouched.
- The `krir` object format structs (`X86_64RelocatableObject`, etc.) — untouched.
- The `BackendTargetContract::x86_64_sysv()` target used for code lowering — still used (x86-64 SysV is the right calling convention for the user code; `kernrift` calls `entry()` using that convention).
