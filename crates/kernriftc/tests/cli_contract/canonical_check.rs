
#[test]
fn check_canonical_reports_legacy_unary_shorthands_exactly() {
    let root = repo_root();
    let fixture = living_compiler_fixture("migration_preview_legacy_unary.kr");
    let assert = run_check_canonical_file(&root, &fixture, None, None)
        .failure()
        .code(1);
    let stdout = stdout_string(&assert);
    let stderr = stderr_string(&assert);
    assert!(
        stderr.is_empty(),
        "canonical check must report via stdout only"
    );
    assert_eq!(
        stdout.lines().collect::<Vec<_>>(),
        vec![
            "surface: stable",
            "canonical_findings: 5",
            "function: alloc_worker",
            "classification: compatibility_alias",
            "surface_form: @alloc",
            "canonical_replacement: @eff(alloc)",
            "migration_safe: true",
            "function: block_worker",
            "classification: compatibility_alias",
            "surface_form: @block",
            "canonical_replacement: @eff(block)",
            "migration_safe: true",
            "function: irq_entry",
            "classification: compatibility_alias",
            "surface_form: @irq",
            "canonical_replacement: @ctx(irq)",
            "migration_safe: true",
            "function: noirq_worker",
            "classification: compatibility_alias",
            "surface_form: @noirq",
            "canonical_replacement: @ctx(thread, boot)",
            "migration_safe: true",
            "function: preempt_guarded",
            "classification: compatibility_alias",
            "surface_form: @preempt_off",
            "canonical_replacement: @eff(preempt_off)",
            "migration_safe: true",
        ]
    );
}

#[test]
fn check_canonical_json_reports_legacy_unary_shorthands_exactly() {
    let root = repo_root();
    let fixture = living_compiler_fixture("migration_preview_legacy_unary.kr");
    let assert = run_check_canonical_file(&root, &fixture, None, Some("json"))
        .failure()
        .code(1);
    let stdout = stdout_string(&assert);
    let stderr = stderr_string(&assert);
    assert_json_transport(&stdout, &stderr, "kernrift_canonical_findings_v1");
    let json: Value = serde_json::from_str(&stdout).expect("json stdout");
    validate_canonical_findings_schema(&json);
    assert_eq!(
        stdout,
        "{\n  \"schema_version\": \"kernrift_canonical_findings_v1\",\n  \"surface\": \"stable\",\n  \"canonical_findings\": 5,\n  \"findings\": [\n    {\n      \"function\": \"alloc_worker\",\n      \"classification\": \"compatibility_alias\",\n      \"surface_form\": \"@alloc\",\n      \"canonical_replacement\": \"@eff(alloc)\",\n      \"migration_safe\": true\n    },\n    {\n      \"function\": \"block_worker\",\n      \"classification\": \"compatibility_alias\",\n      \"surface_form\": \"@block\",\n      \"canonical_replacement\": \"@eff(block)\",\n      \"migration_safe\": true\n    },\n    {\n      \"function\": \"irq_entry\",\n      \"classification\": \"compatibility_alias\",\n      \"surface_form\": \"@irq\",\n      \"canonical_replacement\": \"@ctx(irq)\",\n      \"migration_safe\": true\n    },\n    {\n      \"function\": \"noirq_worker\",\n      \"classification\": \"compatibility_alias\",\n      \"surface_form\": \"@noirq\",\n      \"canonical_replacement\": \"@ctx(thread, boot)\",\n      \"migration_safe\": true\n    },\n    {\n      \"function\": \"preempt_guarded\",\n      \"classification\": \"compatibility_alias\",\n      \"surface_form\": \"@preempt_off\",\n      \"canonical_replacement\": \"@eff(preempt_off)\",\n      \"migration_safe\": true\n    }\n  ]\n}\n"
    );
}

#[test]
fn check_canonical_reports_accepted_aliases_under_experimental_surface() {
    let root = repo_root();
    let fixture = living_compiler_fixture("canonical_check_aliases.kr");
    let assert = run_check_canonical_file(&root, &fixture, Some("experimental"), None)
        .failure()
        .code(1);
    let stdout = stdout_string(&assert);
    let stderr = stderr_string(&assert);
    assert!(
        stderr.is_empty(),
        "canonical check must report via stdout only"
    );
    assert_eq!(
        stdout.lines().collect::<Vec<_>>(),
        vec![
            "surface: experimental",
            "canonical_findings: 3",
            "function: blocker",
            "classification: compatibility_alias",
            "surface_form: @may_block",
            "canonical_replacement: @eff(block)",
            "migration_safe: true",
            "function: isr",
            "classification: compatibility_alias",
            "surface_form: @irq_handler",
            "canonical_replacement: @ctx(irq)",
            "migration_safe: true",
            "function: worker",
            "classification: compatibility_alias",
            "surface_form: @thread_entry",
            "canonical_replacement: @ctx(thread)",
            "migration_safe: true",
        ]
    );
}

#[test]
fn check_canonical_json_reports_accepted_aliases_under_experimental_surface() {
    let root = repo_root();
    let fixture = living_compiler_fixture("canonical_check_aliases.kr");
    let assert = run_check_canonical_file(&root, &fixture, Some("experimental"), Some("json"))
        .failure()
        .code(1);
    let stdout = stdout_string(&assert);
    let stderr = stderr_string(&assert);
    assert_json_transport(&stdout, &stderr, "kernrift_canonical_findings_v1");
    let json: Value = serde_json::from_str(&stdout).expect("json stdout");
    validate_canonical_findings_schema(&json);
    assert_eq!(
        stdout,
        "{\n  \"schema_version\": \"kernrift_canonical_findings_v1\",\n  \"surface\": \"experimental\",\n  \"canonical_findings\": 3,\n  \"findings\": [\n    {\n      \"function\": \"blocker\",\n      \"classification\": \"compatibility_alias\",\n      \"surface_form\": \"@may_block\",\n      \"canonical_replacement\": \"@eff(block)\",\n      \"migration_safe\": true\n    },\n    {\n      \"function\": \"isr\",\n      \"classification\": \"compatibility_alias\",\n      \"surface_form\": \"@irq_handler\",\n      \"canonical_replacement\": \"@ctx(irq)\",\n      \"migration_safe\": true\n    },\n    {\n      \"function\": \"worker\",\n      \"classification\": \"compatibility_alias\",\n      \"surface_form\": \"@thread_entry\",\n      \"canonical_replacement\": \"@ctx(thread)\",\n      \"migration_safe\": true\n    }\n  ]\n}\n"
    );
}

#[test]
fn check_canonical_from_stdin_reports_legacy_unary_shorthands_exactly() {
    let root = repo_root();
    let input = fixture_text(&living_compiler_fixture(
        "migration_preview_legacy_unary.kr",
    ));
    let assert = run_check_canonical_stdin(&root, &input, None, None)
        .failure()
        .code(1);
    let stdout = stdout_string(&assert);
    let stderr = stderr_string(&assert);
    assert!(
        stderr.is_empty(),
        "canonical check stdin mode must report via stdout only"
    );
    assert_eq!(
        stdout.lines().collect::<Vec<_>>(),
        vec![
            "surface: stable",
            "canonical_findings: 5",
            "function: alloc_worker",
            "classification: compatibility_alias",
            "surface_form: @alloc",
            "canonical_replacement: @eff(alloc)",
            "migration_safe: true",
            "function: block_worker",
            "classification: compatibility_alias",
            "surface_form: @block",
            "canonical_replacement: @eff(block)",
            "migration_safe: true",
            "function: irq_entry",
            "classification: compatibility_alias",
            "surface_form: @irq",
            "canonical_replacement: @ctx(irq)",
            "migration_safe: true",
            "function: noirq_worker",
            "classification: compatibility_alias",
            "surface_form: @noirq",
            "canonical_replacement: @ctx(thread, boot)",
            "migration_safe: true",
            "function: preempt_guarded",
            "classification: compatibility_alias",
            "surface_form: @preempt_off",
            "canonical_replacement: @eff(preempt_off)",
            "migration_safe: true",
        ]
    );
}

#[test]
fn check_canonical_json_from_stdin_reports_legacy_unary_shorthands_exactly() {
    let root = repo_root();
    let input = fixture_text(&living_compiler_fixture(
        "migration_preview_legacy_unary.kr",
    ));
    let assert = run_check_canonical_stdin(&root, &input, None, Some("json"))
        .failure()
        .code(1);
    let stdout = stdout_string(&assert);
    let stderr = stderr_string(&assert);
    assert_json_transport(&stdout, &stderr, "kernrift_canonical_findings_v1");
    let json: Value = serde_json::from_str(&stdout).expect("json stdout");
    validate_canonical_findings_schema(&json);
    assert_eq!(
        stdout,
        "{\n  \"schema_version\": \"kernrift_canonical_findings_v1\",\n  \"surface\": \"stable\",\n  \"canonical_findings\": 5,\n  \"findings\": [\n    {\n      \"function\": \"alloc_worker\",\n      \"classification\": \"compatibility_alias\",\n      \"surface_form\": \"@alloc\",\n      \"canonical_replacement\": \"@eff(alloc)\",\n      \"migration_safe\": true\n    },\n    {\n      \"function\": \"block_worker\",\n      \"classification\": \"compatibility_alias\",\n      \"surface_form\": \"@block\",\n      \"canonical_replacement\": \"@eff(block)\",\n      \"migration_safe\": true\n    },\n    {\n      \"function\": \"irq_entry\",\n      \"classification\": \"compatibility_alias\",\n      \"surface_form\": \"@irq\",\n      \"canonical_replacement\": \"@ctx(irq)\",\n      \"migration_safe\": true\n    },\n    {\n      \"function\": \"noirq_worker\",\n      \"classification\": \"compatibility_alias\",\n      \"surface_form\": \"@noirq\",\n      \"canonical_replacement\": \"@ctx(thread, boot)\",\n      \"migration_safe\": true\n    },\n    {\n      \"function\": \"preempt_guarded\",\n      \"classification\": \"compatibility_alias\",\n      \"surface_form\": \"@preempt_off\",\n      \"canonical_replacement\": \"@eff(preempt_off)\",\n      \"migration_safe\": true\n    }\n  ]\n}\n"
    );
}

#[test]
fn check_canonical_from_stdin_reports_accepted_aliases_under_experimental_surface_exactly() {
    let root = repo_root();
    let input = fixture_text(&living_compiler_fixture("canonical_check_aliases.kr"));
    let assert = run_check_canonical_stdin(&root, &input, Some("experimental"), None)
        .failure()
        .code(1);
    let stdout = stdout_string(&assert);
    let stderr = stderr_string(&assert);
    assert!(
        stderr.is_empty(),
        "canonical check stdin mode must report via stdout only"
    );
    assert_eq!(
        stdout.lines().collect::<Vec<_>>(),
        vec![
            "surface: experimental",
            "canonical_findings: 3",
            "function: blocker",
            "classification: compatibility_alias",
            "surface_form: @may_block",
            "canonical_replacement: @eff(block)",
            "migration_safe: true",
            "function: isr",
            "classification: compatibility_alias",
            "surface_form: @irq_handler",
            "canonical_replacement: @ctx(irq)",
            "migration_safe: true",
            "function: worker",
            "classification: compatibility_alias",
            "surface_form: @thread_entry",
            "canonical_replacement: @ctx(thread)",
            "migration_safe: true",
        ]
    );
}

#[test]
fn check_canonical_succeeds_cleanly_for_canonical_source() {
    let root = repo_root();
    let fixture = must_pass_fixture("basic.kr");
    let assert = run_check_canonical_file(&root, &fixture, None, None).success();
    let stdout = stdout_string(&assert);
    let stderr = stderr_string(&assert);
    assert!(
        stderr.is_empty(),
        "canonical check success must keep stderr empty"
    );
    assert_eq!(
        stdout.lines().collect::<Vec<_>>(),
        vec!["surface: stable", "canonical_findings: 0"]
    );
}

#[test]
fn check_canonical_from_stdin_succeeds_cleanly_for_canonical_source() {
    let root = repo_root();
    let input = fixture_text(&must_pass_fixture("basic.kr"));
    let assert = run_check_canonical_stdin(&root, &input, None, None).success();
    let stdout = stdout_string(&assert);
    let stderr = stderr_string(&assert);
    assert!(
        stderr.is_empty(),
        "canonical check stdin success must keep stderr empty"
    );
    assert_eq!(
        stdout.lines().collect::<Vec<_>>(),
        vec!["surface: stable", "canonical_findings: 0"]
    );
}

#[test]
fn check_canonical_json_succeeds_cleanly_for_canonical_source() {
    let root = repo_root();
    let fixture = must_pass_fixture("basic.kr");
    let assert = run_check_canonical_file(&root, &fixture, None, Some("json")).success();
    let stdout = stdout_string(&assert);
    let stderr = stderr_string(&assert);
    assert_json_transport(&stdout, &stderr, "kernrift_canonical_findings_v1");
    let json: Value = serde_json::from_str(&stdout).expect("json stdout");
    validate_canonical_findings_schema(&json);
    assert_eq!(
        stdout,
        "{\n  \"schema_version\": \"kernrift_canonical_findings_v1\",\n  \"surface\": \"stable\",\n  \"canonical_findings\": 0,\n  \"findings\": []\n}\n"
    );
}

#[test]
fn check_canonical_json_from_stdin_succeeds_cleanly_for_canonical_source() {
    let root = repo_root();
    let input = fixture_text(&must_pass_fixture("basic.kr"));
    let assert = run_check_canonical_stdin(&root, &input, None, Some("json")).success();
    let stdout = stdout_string(&assert);
    let stderr = stderr_string(&assert);
    assert_json_transport(&stdout, &stderr, "kernrift_canonical_findings_v1");
    let json: Value = serde_json::from_str(&stdout).expect("json stdout");
    validate_canonical_findings_schema(&json);
    assert_eq!(
        stdout,
        "{\n  \"schema_version\": \"kernrift_canonical_findings_v1\",\n  \"surface\": \"stable\",\n  \"canonical_findings\": 0,\n  \"findings\": []\n}\n"
    );
}

#[test]
fn check_canonical_text_file_and_stdin_are_parity_locked_for_legacy_unary() {
    let root = repo_root();
    let fixture = living_compiler_fixture("migration_preview_legacy_unary.kr");
    let input = fixture_text(&fixture);

    let file_assert = run_check_canonical_file(&root, &fixture, None, None)
        .failure()
        .code(1);
    let file_stdout = stdout_string(&file_assert);
    let file_stderr = stderr_string(&file_assert);

    let stdin_assert = run_check_canonical_stdin(&root, &input, None, None)
        .failure()
        .code(1);
    let stdin_stdout = stdout_string(&stdin_assert);
    let stdin_stderr = stderr_string(&stdin_assert);

    assert!(file_stderr.is_empty());
    assert!(stdin_stderr.is_empty());
    assert_eq!(file_stdout, stdin_stdout);
}

#[test]
fn check_canonical_json_file_and_stdin_are_parity_locked_for_legacy_unary() {
    let root = repo_root();
    let fixture = living_compiler_fixture("migration_preview_legacy_unary.kr");
    let input = fixture_text(&fixture);

    let file_assert = run_check_canonical_file(&root, &fixture, None, Some("json"))
        .failure()
        .code(1);
    let stdin_assert = run_check_canonical_stdin(&root, &input, None, Some("json"))
        .failure()
        .code(1);

    let file_json = stdout_json(&file_assert);
    let stdin_json = stdout_json(&stdin_assert);
    assert_eq!(file_json, stdin_json);
}

#[test]
fn check_canonical_text_count_matches_json_count_for_legacy_unary() {
    let root = repo_root();
    let fixture = living_compiler_fixture("migration_preview_legacy_unary.kr");

    let text_assert = run_check_canonical_file(&root, &fixture, None, None)
        .failure()
        .code(1);
    let text_stdout = stdout_string(&text_assert);

    let json_assert = run_check_canonical_file(&root, &fixture, None, Some("json"))
        .failure()
        .code(1);
    let json = stdout_json(&json_assert);

    assert_eq!(
        text_count_value(&text_stdout, "canonical_findings"),
        json.get("canonical_findings")
            .and_then(Value::as_u64)
            .expect("canonical_findings field") as usize
    );
}

#[test]
fn check_canonical_noop_file_and_stdin_text_and_json_are_parity_locked() {
    let root = repo_root();
    let fixture = must_pass_fixture("basic.kr");
    let input = fixture_text(&fixture);

    let file_text = stdout_string(&run_check_canonical_file(&root, &fixture, None, None).success());
    let stdin_text = stdout_string(&run_check_canonical_stdin(&root, &input, None, None).success());

    let file_json =
        stdout_json(&run_check_canonical_file(&root, &fixture, None, Some("json")).success());
    let stdin_json =
        stdout_json(&run_check_canonical_stdin(&root, &input, None, Some("json")).success());

    assert_eq!(file_text, stdin_text);
    assert_eq!(file_json, stdin_json);
    assert_eq!(text_count_value(&file_text, "canonical_findings"), 0);
    assert_eq!(
        file_json.get("canonical_findings").and_then(Value::as_u64),
        Some(0)
    );
}

#[test]
fn check_canonical_rejects_duplicate_stdin_flag() {
    let root = repo_root();
    let mut cmd: Command = cargo_bin_cmd!("kernriftc");
    cmd.current_dir(&root)
        .arg("check")
        .arg("--canonical")
        .arg("--stdin")
        .arg("--stdin")
        .write_stdin("@irq\nfn entry() { }\n");
    let assert = cmd.assert().failure().code(2);
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).expect("stderr utf8");
    assert_eq!(
        stderr.lines().next(),
        Some("invalid check mode: duplicate --stdin")
    );
}

#[test]
fn check_canonical_rejects_stdin_and_file_together() {
    let root = repo_root();
    let fixture = root.join("tests").join("must_pass").join("basic.kr");
    let mut cmd: Command = cargo_bin_cmd!("kernriftc");
    cmd.current_dir(&root)
        .arg("check")
        .arg("--canonical")
        .arg("--stdin")
        .arg(fixture.as_os_str())
        .write_stdin("@irq\nfn entry() { }\n");
    let assert = cmd.assert().failure().code(2);
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).expect("stderr utf8");
    assert_eq!(
        stderr.lines().next(),
        Some("invalid check mode: --stdin cannot be combined with an input file")
    );
}

#[test]
fn check_canonical_rejects_policy_and_output_flags() {
    let root = repo_root();
    let fixture = root.join("tests").join("must_pass").join("basic.kr");
    let mut cmd: Command = cargo_bin_cmd!("kernriftc");
    cmd.current_dir(&root)
        .arg("check")
        .arg("--canonical")
        .arg("--policy")
        .arg("policies/kernel.toml")
        .arg(fixture.as_os_str());
    let assert = cmd.assert().failure().code(2);
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).expect("stderr utf8");
    assert_eq!(
        stderr.lines().next(),
        Some(
            "invalid check mode: --canonical cannot be combined with --profile, --contracts-schema, --contracts-out, --policy, --hash-out, --sign-ed25519, or --sig-out"
        )
    );
}
