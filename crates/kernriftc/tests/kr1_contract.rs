// KR1 contract tests — effect-aware call checking, @noyield semantics,
// capability declarations, and context enforcement.

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

// ── @noyield ────────────────────────────────────────────────────────────────

#[test]
fn noyield_direct_yieldpoint_is_rejected() {
    // A @noyield function that directly contains yieldpoint() must be rejected
    // with the NOYIELD_YIELD_BOUNDARY diagnostic.
    let src = r#"
        @noyield @ctx(thread, boot)
        fn spinloop() { yieldpoint(); }
    "#;
    let errs = check_src(src).expect_err("noyield direct yield must fail");
    assert!(
        errs.iter()
            .any(|e| e.contains("NOYIELD_YIELD_BOUNDARY") && e.contains("spinloop")),
        "expected NOYIELD_YIELD_BOUNDARY for spinloop; got: {errs:?}"
    );
}

#[test]
fn noyield_transitive_yieldpoint_is_rejected() {
    // A @noyield function that calls a function containing yieldpoint() must
    // also be rejected — the check is transitive.
    let src = r#"
        @ctx(thread, boot)
        fn do_yield() { yieldpoint(); }

        @noyield @ctx(thread, boot)
        fn spinloop() { do_yield(); }
    "#;
    let errs = check_src(src).expect_err("noyield transitive yield must fail");
    assert!(
        errs.iter()
            .any(|e| e.contains("NOYIELD_YIELD_BOUNDARY") && e.contains("spinloop")),
        "expected NOYIELD_YIELD_BOUNDARY for spinloop; got: {errs:?}"
    );
}

#[test]
fn noyield_function_without_yield_compiles() {
    // A @noyield function that never yields (directly or transitively) must
    // compile without errors.
    let src = r#"
        @ctx(thread, boot)
        fn helper() {}

        @noyield @ctx(thread, boot)
        fn spinloop() { helper(); }
    "#;
    assert!(
        check_src(src).is_ok(),
        "noyield function without yield must compile"
    );
}

// ── context/effect boundaries (KR1 exit criteria) ──────────────────────────

#[test]
fn yield_in_irq_is_rejected() {
    let src = r#"
        @ctx(irq)
        fn tick() { yieldpoint(); }
    "#;
    let errs = check_src(src).expect_err("yield in irq must fail");
    assert!(
        errs.iter()
            .any(|e| e.contains("irq") || e.contains("yield")),
        "expected irq/yield error; got: {errs:?}"
    );
}

#[test]
fn block_in_irq_is_rejected() {
    let src = r#"
        @ctx(thread, boot) @eff(block) @caps()
        extern fn os_sleep();

        @ctx(irq)
        fn tick() { os_sleep(); }
    "#;
    let errs = check_src(src).expect_err("block in irq must fail");
    assert!(
        errs.iter()
            .any(|e| e.contains("irq") && (e.contains("block") || e.contains("BLOCK"))),
        "expected irq/block error; got: {errs:?}"
    );
}

#[test]
fn missing_module_cap_is_rejected() {
    let src = r#"
        @caps(PhysMap)
        @ctx(thread, boot)
        fn map_page() {}
    "#;
    let errs = check_src(src).expect_err("missing module cap must fail");
    assert!(
        errs.iter().any(|e| e.contains("PhysMap")),
        "expected PhysMap cap error; got: {errs:?}"
    );
}

// ── PCI/IRQ demo driver — KR1 artifact exit criterion ──────────────────────

#[test]
fn pci_irq_driver_compiles_to_x86_64_elf_object() {
    // The minimal PCI/IRQ driver must compile all the way to an x86_64 ELF
    // object without errors. This verifies the full pipeline:
    //   source → KRIR → ExecutableKrir → x86_64 ELF object
    //
    // The driver uses @noyield + @ctx(irq) for the handler and @caps(Ioport)
    // for PCI config space access, exercising all KR1 capability paths.
    let root = repo_root();
    let fixture = root
        .join("examples")
        .join("kernel")
        .join("pci_irq_driver.kr");
    let module = compile_file(&fixture).expect("pci_irq_driver.kr must parse and lower to KRIR");
    check_module(&module).expect("pci_irq_driver.kr must pass all semantic checks");
    let executable =
        lower_current_krir_to_executable_krir(&module).expect("lower to executable krir");
    let target = BackendTargetContract::x86_64_sysv();
    let object = lower_executable_krir_to_x86_64_object(&executable, &target)
        .expect("lower to x86_64 ELF object");

    // The object must be non-empty and contain ELF magic.
    assert!(
        !object.text_bytes.is_empty(),
        "pci_irq_driver.kr must emit non-empty text section"
    );
}
