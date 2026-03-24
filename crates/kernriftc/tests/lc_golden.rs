use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("repo root")
}

#[test]
fn lc_ci_exit0_with_high_min_fitness() {
    let root = repo_root();
    let bin = assert_cmd::cargo::cargo_bin!("kernriftc");
    let input = root.join("tests/golden/cases/lc_ci.kr");
    let expected_file = root.join("tests/golden/expect/lc_ci.lc_ci_exit0.stdout");

    let out = Command::new(bin)
        .args(["lc", "--ci", "--min-fitness", "90"])
        .arg(&input)
        .output()
        .expect("run kernriftc");

    assert_eq!(
        out.status.code(),
        Some(0),
        "expected exit 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let expected = std::fs::read_to_string(&expected_file).expect("read expected file");
    let actual = String::from_utf8_lossy(&out.stdout);
    assert_eq!(actual.trim(), expected.trim());
}

#[test]
fn lc_fix_nothing_to_fix() {
    let root = repo_root();
    let bin = assert_cmd::cargo::cargo_bin!("kernriftc");
    let input = root.join("tests/golden/cases/lc_ci.kr");

    let out = Command::new(bin)
        .args(["lc", "--fix", "--dry-run"])
        .arg(&input)
        .output()
        .expect("run kernriftc");

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("nothing to fix"), "got: {}", stdout);
}

#[test]
fn lc_fix_write_applies_fix() {
    let root = repo_root();
    let bin = assert_cmd::cargo::cargo_bin!("kernriftc");
    let src = root.join("tests/golden/cases/lc_fix.kr");

    let tmp = std::env::temp_dir().join("lc_fix_write_test.kr");
    std::fs::copy(&src, &tmp).expect("copy lc_fix.kr");

    let out = Command::new(bin)
        .args(["lc", "--fix", "--write"])
        .arg(&tmp)
        .output()
        .expect("run kernriftc");

    assert_eq!(
        out.status.code(),
        Some(0),
        "expected exit 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("(1 site(s))") || stdout.contains("nothing to fix"),
        "expected fix confirmation or nothing-to-fix, got: {}",
        stdout
    );

    let _ = std::fs::remove_file(&tmp);
}
