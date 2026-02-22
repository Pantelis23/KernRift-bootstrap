use std::path::Path;

use hir::lower_to_krir;
use krir::KrirModule;
use parser::parse_module;
pub use passes::{AnalysisReport, NoYieldSpan};
use passes::{CheckError, analyze_module, run_checks};

pub fn compile_source(src: &str) -> Result<KrirModule, Vec<String>> {
    let ast = parse_module(src)?;
    lower_to_krir(&ast)
}

pub fn compile_file(path: &Path) -> Result<KrirModule, Vec<String>> {
    let src = std::fs::read_to_string(path)
        .map_err(|e| vec![format!("failed to read '{}': {}", path.display(), e)])?;
    compile_source(&src)
}

pub fn check_module(module: &KrirModule) -> Result<(), Vec<String>> {
    run_checks(module).map_err(format_check_errors)
}

pub fn check_file(path: &Path) -> Result<(), Vec<String>> {
    let module = compile_file(path)?;
    check_module(&module)
}

pub fn analyze(module: &KrirModule) -> (AnalysisReport, Vec<String>) {
    let (report, errs) = analyze_module(module);
    let formatted = format_check_errors(errs);
    (report, formatted)
}

pub fn analyze_file(path: &Path) -> Result<(AnalysisReport, Vec<String>), Vec<String>> {
    let module = compile_file(path)?;
    Ok(analyze(&module))
}

fn format_check_errors(mut errs: Vec<CheckError>) -> Vec<String> {
    errs.sort_by(|a, b| (a.pass, a.message.as_str()).cmp(&(b.pass, b.message.as_str())));
    errs.iter().map(format_check_error).collect()
}

fn format_check_error(err: &CheckError) -> String {
    format!("{}: {}", err.pass, err.message)
}
