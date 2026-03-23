// KR2 contract tests — spinlock declarations, lock-order inversion, per-cpu
// variables, and scheduler hooks.
//
// Exit criteria (KR2):
//   - Intentional lock-order inversion is compile-time failure
//   - Per-cpu access rules validated (undeclared var rejected)
//   - Scheduler hook without @noyield is rejected
//   - @hook(sched_in|sched_out) with @noyield compiles
//   - KR2 sample module compiles to x86_64 ELF object

use std::path::{Path, PathBuf};

use kernriftc::{check_module, compile_file, compile_source};
use krir::{
    BackendTargetContract, lower_current_krir_to_executable_krir,
    lower_executable_krir_to_x86_64_object,
};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("repo root")
}

fn check_src(src: &str) -> Result<(), Vec<String>> {
    compile_source(src).and_then(|module| check_module(&module))
}

// ── Spinlock declaration validation ─────────────────────────────────────────

#[test]
fn undeclared_lock_class_is_rejected() {
    let src = r#"
        fn bad() { acquire(MissingLock); release(MissingLock); }
    "#;
    let errs = compile_source(src).expect_err("undeclared lock must fail HIR");
    assert!(
        errs.iter().any(|e| e.contains("undeclared lock class")),
        "expected undeclared lock class error; got: {errs:?}"
    );
}

#[test]
fn declared_lock_class_compiles() {
    let src = r#"
        spinlock MyLock;
        fn ok() { acquire(MyLock); release(MyLock); }
    "#;
    check_src(src).expect("declared lock must pass");
}

// ── Lock order inversion (cycle) detection ───────────────────────────────────

#[test]
fn lock_order_inversion_is_rejected() {
    let src = r#"
        spinlock LockA;
        spinlock LockB;
        fn thread_a() {
            acquire(LockA);
            acquire(LockB);
            release(LockB);
            release(LockA);
        }
        fn thread_b() {
            acquire(LockB);
            acquire(LockA);
            release(LockA);
            release(LockB);
        }
    "#;
    let errs = check_src(src).expect_err("lock inversion must fail");
    assert!(
        errs.iter().any(|e| e.contains("LOCK_ORDER_INVERSION")),
        "expected LOCK_ORDER_INVERSION error; got: {errs:?}"
    );
}

#[test]
fn consistent_lock_order_compiles() {
    let src = r#"
        spinlock LockA;
        spinlock LockB;
        fn thread_a() {
            acquire(LockA);
            acquire(LockB);
            release(LockB);
            release(LockA);
        }
        fn thread_b() {
            acquire(LockA);
            acquire(LockB);
            release(LockB);
            release(LockA);
        }
    "#;
    check_src(src).expect("consistent lock order must pass");
}

// ── Per-cpu variable validation ───────────────────────────────────────────────

#[test]
fn undeclared_percpu_var_is_rejected() {
    let src = r#"
        @ctx(thread, boot)
        fn bad() { percpu_read<u32>(cpu_state, val); }
    "#;
    let errs = compile_source(src).expect_err("undeclared percpu must fail HIR");
    assert!(
        errs.iter()
            .any(|e| e.contains("undeclared per-cpu variable")),
        "expected undeclared per-cpu variable error; got: {errs:?}"
    );
}

#[test]
fn declared_percpu_var_compiles() {
    let src = r#"
        percpu cpu_state: u32;
        @ctx(thread, boot) @eff(yield) @caps()
        fn read_cpu_state() { percpu_read<u32>(cpu_state, val); }
    "#;
    check_src(src).expect("declared percpu must pass");
}

// ── Scheduler hook validation ─────────────────────────────────────────────────

#[test]
fn sched_hook_without_noyield_is_rejected() {
    let src = r#"
        @hook(sched_in)
        @ctx(thread, boot)
        fn bad_hook() { }
    "#;
    let errs = check_src(src).expect_err("hook without noyield must fail");
    assert!(
        errs.iter().any(|e| e.contains("HOOK_MISSING_NOYIELD")),
        "expected HOOK_MISSING_NOYIELD error; got: {errs:?}"
    );
}

#[test]
fn sched_hook_with_noyield_compiles() {
    let src = r#"
        @hook(sched_in) @noyield @ctx(thread, boot)
        fn good_sched_in() { }
        @hook(sched_out) @noyield @ctx(thread, boot)
        fn good_sched_out() { }
    "#;
    check_src(src).expect("hook with noyield must pass");
}

#[test]
fn invalid_hook_kind_is_rejected() {
    let src = r#"
        @hook(bad_event) @noyield @ctx(thread, boot)
        fn h() { }
    "#;
    let errs = compile_source(src).expect_err("invalid hook kind must fail HIR");
    assert!(
        errs.iter().any(|e| e.contains("@hook")),
        "expected @hook parse error; got: {errs:?}"
    );
}

// ── KR2 sample module — semantic analysis ────────────────────────────────────

#[test]
fn kr2_sample_module_passes_all_semantic_checks() {
    // kr2_sample.kr uses spinlocks, percpu vars, and sched hooks.
    // acquire/release/percpu are analysis-only ops (no x86 lowering).
    // The full semantic pass (lock cycle check, hook noyield check, etc.)
    // must accept it.
    let fixture = repo_root()
        .join("examples")
        .join("kernel")
        .join("kr2_sample.kr");
    let module = compile_file(&fixture).expect("kr2_sample.kr must parse and lower to KRIR");
    check_module(&module).expect("kr2_sample.kr must pass all semantic checks");

    // Verify the lock graph has the expected edges (DevLock→StatLock).
    let (report, _) = passes::analyze_module(&module);
    assert!(
        report
            .lock_edges
            .iter()
            .any(|e| e.from == "DevLock" && e.to == "StatLock"),
        "expected DevLock->StatLock edge in lock graph; got: {:?}",
        report.lock_edges
    );
}

#[test]
fn kr2_mmio_only_module_compiles_to_x86_64_elf_object() {
    // Pure MMIO module (no lock/percpu) verifying the full ELF pipeline still
    // works alongside the KR2 analysis features.
    let src = r#"
        @module_caps(Mmio);
        mmio DEV = 0xFEB00000;
        mmio_reg DEV.Control = 0x04 : u32 rw;
        spinlock DevLock;
        @ctx(thread, boot)
        fn get_status() {
            mmio_read<u32>(DEV + 0x04, val);
        }
    "#;
    let module = compile_source(src).expect("must compile");
    check_module(&module).expect("must pass checks");
    let exec =
        lower_current_krir_to_executable_krir(&module).expect("must lower to executable KRIR");
    let target = BackendTargetContract::x86_64_sysv();
    let object = lower_executable_krir_to_x86_64_object(&exec, &target)
        .expect("must lower to x86_64 ELF object");
    assert!(
        !object.text_bytes.is_empty(),
        "must emit non-empty text section"
    );
}

// ── lock_edge_cycle_check unit tests ─────────────────────────────────────────

use passes::{LockEdge, lock_edge_cycle_check};

#[test]
fn lock_edge_cycle_check_detects_two_module_inversion() {
    let edges = vec![
        LockEdge { from: "AcquireLock".to_string(), to: "BcquireLock".to_string() },
        LockEdge { from: "BcquireLock".to_string(), to: "AcquireLock".to_string() },
    ];
    let errs = lock_edge_cycle_check(&edges);
    assert!(!errs.is_empty(), "should detect cross-module lock cycle: {edges:?}");
    assert!(
        errs.iter().any(|e| e.message.contains("AcquireLock") || e.message.contains("BcquireLock")),
        "cycle error should name the locks: {errs:?}"
    );
}

#[test]
fn lock_edge_cycle_check_passes_for_valid_ordering() {
    let edges = vec![
        LockEdge { from: "A".to_string(), to: "B".to_string() },
        LockEdge { from: "B".to_string(), to: "C".to_string() },
    ];
    let errs = lock_edge_cycle_check(&edges);
    assert!(errs.is_empty(), "linear ordering A→B→C should not be a cycle: {errs:?}");
}

// ── kernriftc link CLI integration tests ─────────────────────────────────────

fn kernriftc_bin() -> std::path::PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.push("kernriftc");
    p
}

#[test]
fn link_detects_cross_module_lock_inversion() {
    let pid = std::process::id();
    let tmp1 = std::env::temp_dir().join(format!("link_inversion_{pid}_a.kr"));
    let tmp2 = std::env::temp_dir().join(format!("link_inversion_{pid}_b.kr"));

    // File A: only acquires Lock1 → Lock2 (no inversion in this file alone)
    std::fs::write(&tmp1, r#"
spinlock Lock1;
spinlock Lock2;
@ctx(thread)
fn a() { acquire(Lock1); acquire(Lock2); release(Lock2); release(Lock1); }
"#).unwrap();

    // File B: only acquires Lock2 → Lock1 (no inversion in this file alone)
    // Together with A the merged graph has Lock1→Lock2 and Lock2→Lock1 → cycle
    std::fs::write(&tmp2, r#"
spinlock Lock2;
spinlock Lock1;
@ctx(thread)
fn b() { acquire(Lock2); acquire(Lock1); release(Lock1); release(Lock2); }
"#).unwrap();

    let out = std::process::Command::new(kernriftc_bin())
        .arg("link")
        .arg(tmp1.to_str().unwrap())
        .arg(tmp2.to_str().unwrap())
        .output()
        .expect("link command must run");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "link with cross-module inversion should fail; stderr: {stderr}"
    );
    assert!(
        stderr.contains("cycle") || stderr.contains("Lock1") || stderr.contains("Lock2"),
        "error should mention the cycle or lock names: {stderr}"
    );
}

#[test]
fn link_passes_for_consistent_ordering() {
    let pid = std::process::id();
    let tmp1 = std::env::temp_dir().join(format!("link_ok_{pid}_a.kr"));
    let tmp2 = std::env::temp_dir().join(format!("link_ok_{pid}_b.kr"));

    std::fs::write(&tmp1, r#"
spinlock Lock1;
spinlock Lock2;
@ctx(thread)
fn a() { acquire(Lock1); acquire(Lock2); release(Lock2); release(Lock1); }
"#).unwrap();
    std::fs::write(&tmp2, r#"
spinlock Lock1;
spinlock Lock2;
@ctx(thread)
fn b() { acquire(Lock1); acquire(Lock2); release(Lock2); release(Lock1); }
"#).unwrap();

    let out = std::process::Command::new(kernriftc_bin())
        .arg("link")
        .arg(tmp1.to_str().unwrap())
        .arg(tmp2.to_str().unwrap())
        .output()
        .expect("link command must run");

    assert!(
        out.status.success(),
        "link with consistent ordering should succeed; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
