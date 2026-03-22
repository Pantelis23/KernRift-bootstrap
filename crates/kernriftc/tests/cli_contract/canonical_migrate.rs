
#[test]
fn migrate_canonical_source_noops_cleanly() {
    let src = must_pass_fixture("basic.kr");
    let tmp = unique_temp_output_path("migrate-noop", "kr");
    fs::copy(&src, &tmp).unwrap();

    let mut cmd: Command = cargo_bin_cmd!("kernriftc");
    cmd.arg("migrate").arg(tmp.to_str().unwrap());
    let assert = cmd.assert().success();
    let stdout = stdout_string(&assert);
    assert!(
        stdout.contains("No migration needed"),
        "expected 'No migration needed', got: {stdout}"
    );
    assert_eq!(
        fixture_text(&tmp),
        fixture_text(&src),
        "file should be unchanged for canonical source"
    );
}

#[test]
fn migrate_dry_run_does_not_write() {
    let tmp = unique_temp_output_path("migrate-dry-run", "kr");
    // @thread_entry is a stable alias with migration_safe=true.
    fs::write(&tmp, "@thread_entry\nfn f() {}\n").unwrap();
    let original = fixture_text(&tmp);

    let mut cmd: Command = cargo_bin_cmd!("kernriftc");
    cmd.arg("migrate").arg(tmp.to_str().unwrap()).arg("--dry-run");
    let assert = cmd.assert().success();
    let stdout = stdout_string(&assert);
    assert!(
        stdout.contains("dry-run") || stdout.contains("Would migrate"),
        "expected dry-run notice, got: {stdout}"
    );
    assert!(
        stdout.contains("thread_entry") || stdout.contains("fn f"),
        "output should name the function or alias: {stdout}"
    );
    assert_eq!(
        fixture_text(&tmp),
        original,
        "--dry-run must not write the file"
    );
}
