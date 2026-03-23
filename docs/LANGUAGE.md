# KernRift Language Reference

KernRift is a freestanding, ahead-of-time compiled systems language for kernel
and driver development.  It targets bare-metal x86-64 with no runtime, no libc,
and no implicit heap.  Safety properties — execution context, MMIO capabilities,
lock order, and yield restrictions — are checked at compile time, not at
runtime.  Every construct maps directly to machine instructions; there are no
hidden costs.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Quick Start](#2-quick-start)
3. [Types](#3-types)
4. [Variables and Assignment](#4-variables-and-assignment)
5. [Operators](#5-operators)
6. [Functions](#6-functions)
7. [Control Flow](#7-control-flow)
8. [Constants](#8-constants)
9. [Structs and Enums](#9-structs-and-enums)
10. [Hardware Access (Device Blocks)](#10-hardware-access-device-blocks)
11. [Kernel Safety Annotations](#11-kernel-safety-annotations)
12. [Locks](#12-locks)
13. [Per-CPU Variables](#13-per-cpu-variables)
14. [Extern Functions](#14-extern-functions)
15. [Tail Calls](#15-tail-calls)

---

## 1. Introduction

KernRift source files use the `.kr` extension.  One file is one module.
Comments are `//` (line) or `/* ... */` (block).  Statements do not require a
trailing semicolon in the new surface syntax, though one is accepted and
ignored.

---

## 2. Quick Start

A minimal driver that sends a byte over UART:

```kr
@module_caps(Mmio)

device UART0 at 0x3F000000 {
    Data   at 0x00 : uint8  rw
    Status at 0x04 : uint32 ro
}

@ctx(thread, boot)
fn send_byte(uint8 b) {
    UART0.Data = b
}
```

`@module_caps(Mmio)` declares that this module uses the safe MMIO capability.
`device` declares the hardware block at a base address with named registers.
`@ctx(thread, boot)` restricts callers to thread and boot contexts.
The assignment `UART0.Data = b` is a volatile MMIO write enforced by the
compiler.

---

## 3. Types

### Scalar types

| Type      | Width | Notes                                      |
|-----------|-------|--------------------------------------------|
| `uint8`   | 1 B   | Unsigned byte. Aliases: `u8`, `byte`       |
| `uint16`  | 2 B   | Unsigned 16-bit. Alias: `u16`              |
| `uint32`  | 4 B   | Unsigned 32-bit. Alias: `u32`              |
| `uint64`  | 8 B   | Unsigned 64-bit, pointer-sized. Aliases: `u64`, `addr` |
| `int8`    | 1 B   | Signed byte. Alias: `i8`                   |
| `int16`   | 2 B   | Signed 16-bit. Alias: `i16`                |
| `int32`   | 4 B   | Signed 32-bit. Alias: `i32`                |
| `int64`   | 8 B   | Signed 64-bit. Alias: `i64`                |
| `float32` | 4 B   | IEEE-754 single. Alias: `f32`. *(V2 codegen)* |
| `float64` | 8 B   | IEEE-754 double. Alias: `f64`. *(V2 codegen)* |
| `float16` | 2 B   | IEEE-754 half, stored as raw 16-bit. *(V2)* |
| `bool`    | 1 B   | Boolean; `true` / `false` literals         |
| `char`    | 1 B   | ASCII character; `'x'` literals            |

### Slice type

`[T]` is a fat pointer — a `(ptr: uint64, len: uint64)` pair under SysV ABI.
Slices are views over caller-owned memory; no allocation occurs.

```kr
fn write_buf(uint8 first, [uint8] data) { ... }
```

---

## 4. Variables and Assignment

### Declaration

```kr
TYPE name = expr
TYPE name           // uninitialized
```

The type precedes the name (C style, not `name: TYPE`).

```kr
uint32 status = UART0.Status
uint8  byte   = 0xFF
bool   ready  = false
float32 scale = 1.0
```

### Simple assignment

```kr
name = expr
DEVICE.FIELD = expr
```

```kr
status = 0
UART0.Data = byte
```

### Compound assignment

```kr
name op= expr
```

All supported compound operators:

| Operator | Meaning            |
|----------|--------------------|
| `+=`     | add                |
| `-=`     | subtract           |
| `&=`     | bitwise AND        |
| `\|=`    | bitwise OR         |
| `^=`     | bitwise XOR        |
| `<<=`    | left shift         |
| `>>=`    | right shift        |
| `*=`     | multiply *(V2)*    |
| `/=`     | divide *(V2)*      |
| `%=`     | remainder *(V2)*   |

```kr
count += 1
flags &= 0xF0
mask |= 0x01
shift <<= 2
```

---

## 5. Operators

Expressions use a Pratt parser.  Precedence from highest (tightest) to lowest:

| Precedence | Operators            | Notes                     |
|------------|----------------------|---------------------------|
| 110 (prefix) | `!`, `~`, `-`      | Logical not, bitwise not, negation |
| 100        | `*`, `/`, `%`        | Multiply, divide, remainder *(V2)* |
| 90         | `+`, `-`             | Add, subtract             |
| 80         | `<<`, `>>`           | Shift left, shift right   |
| 50         | `&`                  | Bitwise AND               |
| 40         | `^`                  | Bitwise XOR               |
| 30         | `\|`                  | Bitwise OR                |
| 60         | `==`, `!=`           | Equality                  |
| 70         | `<`, `>`, `<=`, `>=` | Comparison                |
| 20         | `&&`                 | Logical AND               |
| 10         | `\|\|`               | Logical OR                |

All binary operators are left-associative.  Use parentheses to override:

```kr
uint32 x = (a + b) & 0xFF
bool   ok = (flags & 0x01) != 0
```

Literals: decimal `42`, hexadecimal `0x1000`, binary `0b1010`, float `3.14`,
char `'A'`, bool `true` / `false`.

---

## 6. Functions

### Syntax

```kr
fn name(TYPE param, TYPE param, ...) -> TYPE {
    body
}
```

The return type after `->` is optional; omitting it means the function returns
void.  Parameters are written as `TYPE name` (type before name).

```kr
fn get_status() -> uint32 {
    uint32 s = UART0.Status
    return s
}

fn send(uint8 b) {
    UART0.Data = b
}
```

There is no implicit return.  Every code path that returns a value must end
with an explicit `return expr`.

### Parameters

Scalar and slice parameters:

```kr
fn compute(uint32 a, uint32 b) -> uint32 { ... }
fn dma_setup([uint8] buf) { ... }    // slice: (ptr, len) pair
```

### Slice length access

Inside a function, `slice.len` reads the element count of a slice parameter:

```kr
fn write_buf([uint8] data) {
    uint64 n = data.len
}
```

---

## 7. Control Flow

### if / else

```kr
if condition {
    // then
} else {
    // else (optional)
}
```

```kr
if status == 0 {
    uint32 x = 1
} else {
    uint32 x = 2
}
```

Conditions are full expressions.  There are no parentheses around the
condition (they are accepted but not required).

### while

```kr
while condition {
    body
}
```

```kr
uint32 i = 0
while i < n {
    i += 1
}
```

### for (range loop)

Exclusive range `..`:

```kr
for i in 0..n {
    total += 1
}
```

Inclusive range `..=`:

```kr
for i in 0..=255 {
    sum += i
}
```

The loop variable `i` is an implicit `uint64` induction variable.  It is
read-only inside the body.

### break and continue

```kr
while true {
    if done { break }
    if skip { continue }
    total += 1
}
```

### return

```kr
return expr    // return a value
return         // void return
```

```kr
fn get_val() -> uint32 {
    uint32 x = 42
    return x
}
```

---

## 8. Constants

```kr
const TYPE NAME = VALUE
```

Integer constants only.  Constants are inlined at every use site; no runtime
storage.

```kr
const uint32 UART_ENABLE = 0x0001
const uint16 BAUD_115200 = 0x001A
const uint64 BASE_ADDR   = 0xFEB00000
```

---

## 9. Structs and Enums

### Structs

```kr
struct NAME {
    field: TYPE,
    ...
}
```

Layout is C-style packed: no alignment padding, fields in declaration order.
Field offsets are compile-time constants available as `NAME::field`.

```kr
struct UartRegs {
    Control: uint32,   // offset 0
    Status:  uint32,   // offset 4
    Data:    uint8,    // offset 8
}
```

### Enums

```kr
enum NAME: TYPE {
    VARIANT = INTEGER,
    ...
}
```

Each variant is a named integer constant.  Referenced as `NAME::VARIANT`.

```kr
enum UartBase: uint64 {
    Uart0 = 0x40000000,
    Uart1 = 0x40001000,
}
```

Enums and structs are compile-time tools for address arithmetic.  No runtime
objects are created.

---

## 10. Hardware Access (Device Blocks)

### Device declaration

```kr
device NAME at BASE_ADDR {
    FIELD at OFFSET : TYPE ACCESS
    ...
}
```

`ACCESS` is one of `rw` (read-write), `ro` (read-only), `wo` (write-only).
Requires `@module_caps(Mmio)` at the top of the file.

```kr
@module_caps(Mmio)

device UART0 at 0x3F000000 {
    Data   at 0x00 : uint8  rw
    Status at 0x04 : uint32 ro
    CR     at 0x08 : uint16 rw
}
```

### Reading a device register

Assign the field to a variable; the compiler emits a volatile load:

```kr
uint32 s = UART0.Status
uint16 c = UART0.CR
```

### Writing a device register

```kr
UART0.Data = byte
UART0.CR   = 0xFF
```

### Raw MMIO access

For hardware not described by a device block.  Requires `@module_caps(MmioRaw)`.

```kr
@module_caps(MmioRaw)

fn entry() {
    raw_write<uint32>(0x1014, x)
    raw_read<uint32>(0x1014, result)
}
```

`raw_write<T>(addr, value)` performs a volatile store to an arbitrary address.
`raw_read<T>(addr, slot)` performs a volatile load.

---

## 11. Kernel Safety Annotations

Annotations appear on the line(s) immediately before `fn`.  Multiple
annotations can share a line or occupy separate lines; order does not matter.

### `@ctx(context, ...)`

Declares which execution contexts the function may run in.

| Context  | Meaning                                       |
|----------|-----------------------------------------------|
| `thread` | Normal thread / task context                  |
| `boot`   | Early boot, before scheduling is active       |
| `irq`    | Hardware interrupt handler                    |
| `nmi`    | Non-maskable interrupt (strictest)            |

```kr
@ctx(thread, boot)
fn init() { ... }

@ctx(irq)
fn irq_handler() { ... }
```

For any call edge `caller → callee`, the compiler requires
`ctx(caller) ⊆ ctx(callee)`.

### `@eff(effect, ...)`

Declares side effects.  An empty `@eff()` declares no effects.

| Effect    | Meaning                                |
|-----------|----------------------------------------|
| `Mmio`    | MMIO reads / writes                    |
| `alloc`   | Memory allocation (forbidden in `irq`) |
| `block`   | Blocking / sleeping                    |
| `yield`   | Voluntary CPU yield                    |

### `@module_caps(cap, ...)`

Top-level module declaration listing which capability classes the module may
use.  The compiler rejects any operation that requires an unlisted capability.

| Capability | Meaning                                      |
|------------|----------------------------------------------|
| `Mmio`     | MMIO via declared device blocks              |
| `MmioRaw`  | Raw MMIO at arbitrary addresses              |
| `Ioport`   | x86 I/O port instructions                   |

```kr
@module_caps(Mmio)
@module_caps(MmioRaw)
@module_caps(Mmio, MmioRaw)
```

### `@leaf`

Marks a function as a leaf: it does not call any other KernRift functions.
Used by the lock-budget checker.

```kr
@leaf
fn tiny() { }
```

### `@lock_budget(N)`

The number of non-`@leaf` function calls on any path between an `acquire` and
its matching `release` must not exceed `N`.

```kr
@lock_budget(3)
@ctx(thread)
fn do_work() {
    acquire(DevLock)
    step_a()
    step_b()
    step_c()
    release(DevLock)
}
```

### `@noyield`

The function must not call any function that may yield.  Required on IRQ
handlers and scheduler hooks.

```kr
@noyield
@ctx(irq)
fn irq_handler() { ... }
```

---

## 12. Locks

### Declaration

```kr
lock NAME
```

Declared at module level, no semicolon required (accepted and ignored).

```kr
lock ConsoleLock
lock DevLock
```

### Acquire and release

```kr
acquire(NAME)
release(NAME)
```

```kr
lock ConsoleLock

fn write_char(uint8 b) {
    acquire(ConsoleLock)
    UART0.Data = b
    release(ConsoleLock)
}
```

Acquire and release must be balanced on all paths.  The compiler builds a
lock graph across the module and fails the build if a deadlock cycle is
detected.  Always acquire locks in a consistent global order.

---

## 13. Per-CPU Variables

Declared at module level:

```kr
percpu NAME: TYPE
```

Accessed with the low-level intrinsics `percpu_read<T>` and `percpu_write<T>`
(old surface syntax, still supported):

```kr
percpu cpu_active: uint32

fn mark_active() {
    percpu_write<uint32>(cpu_active, 0x01)
}
```

Per-cpu variables have no address in the conventional sense; the compiler
generates `%gs`-relative accesses on x86-64.

---

## 14. Extern Functions

```kr
extern fn name(TYPE param, ...);
```

Declares a function implemented in another compilation unit (C, assembly).
Annotations must describe the function's context and capabilities so the
compiler can enforce call-edge rules.

```kr
extern @ctx(thread, boot) fn platform_barrier();
extern @ctx(irq) fn uart_irq_ack();
extern @ctx(thread, boot) fn memcpy([uint8] dst, [uint8] src, uint64 n);
```

---

## 15. Tail Calls

A tail call discards the current function's stack frame and jumps directly to the callee.  The result is zero stack growth per iteration, which is the correct way to implement unbounded poll loops and state machines in kernel code — especially in `@ctx(irq)` functions where stack space is fixed and never reclaimed.

### Intrinsic form

```kr
tail_call(callee[, arg, ...])
```

`tail_call` is an explicit intrinsic statement.  It transfers control to `callee` with zero stack growth.  Arguments are passed positionally.

```kr
@ctx(irq)
fn uart_poll(uint64 head) {
    uint64 next = (head + 1) & 7
    tail_call(uart_poll, next)   // jmp uart_poll — no frame growth
}
```

`tail_call` requires `--surface experimental`.  On stable surface, the living compiler emits the `try_tail_call` suggestion when plain calls are present but no tail calls are.

### Auto-fix

`kernriftc lc --fix --dry-run <file.kr>` previews what a tail-call rewrite would look like as a unified diff.  `--fix --write` applies it atomically.  The rewrite prepends `tail ` to the last bare call statement in each function body.

### Constraints

- `tail_call` must be the last statement executed in the function.
- The callee's `@ctx` must be compatible with the caller's (same rules as any other call edge).
- Arguments are limited to six by the SysV ABI on x86-64.

---

## Full example

A complete UART send driver using the new surface syntax:

```kr
@module_caps(Mmio)

device UART0 at 0x3F000000 {
    Data   at 0x00 : uint8  rw
    Status at 0x04 : uint32 ro
}

lock UartLock

const uint32 TX_READY = 0x20

@ctx(thread, boot)
fn uart_ready() -> bool {
    uint32 s = UART0.Status
    return (s & TX_READY) != 0
}

@ctx(thread, boot)
fn uart_send(uint8 b) {
    acquire(UartLock)
    uint32 i = 0
    while i < 1000 {
        if uart_ready() {
            UART0.Data = b
            release(UartLock)
            return
        }
        i += 1
    }
    release(UartLock)
}
```

---

*See `docs/ARCHITECTURE.md` for compiler internals and `docs/KRIR_SPEC.md`
for the intermediate representation specification.*
