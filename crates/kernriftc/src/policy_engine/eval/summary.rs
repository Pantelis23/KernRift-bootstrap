use super::super::{ContractsBundle, ContractsFactSymbol};
use super::common::{canonicalize_provenance_fields, format_bracketed_list};

pub(crate) fn contracts_bundle_schema_version(contracts: &ContractsBundle) -> &str {
    &contracts.schema_version
}

pub(crate) fn format_contracts_inspect_summary(contracts: &ContractsBundle) -> String {
    let irq_reachable = collect_sorted_symbol_names_by(&contracts.facts.symbols, |symbol| {
        symbol.has_ctx_reachable("irq")
    });
    let critical_functions =
        collect_sorted_symbol_names_by(&contracts.facts.symbols, |symbol| symbol.attrs.critical);
    let alloc_symbols = collect_sorted_symbol_names_by(&contracts.facts.symbols, |symbol| {
        symbol.has_eff_transitive("alloc")
    });
    let block_symbols = collect_sorted_symbol_names_by(&contracts.facts.symbols, |symbol| {
        symbol.has_eff_transitive("block")
    });
    let yield_symbols = collect_sorted_symbol_names_by(&contracts.facts.symbols, |symbol| {
        symbol.has_eff_transitive("yield")
    });
    let cap_symbols = collect_sorted_symbol_names_by(&contracts.facts.symbols, |symbol| {
        !symbol.caps_transitive.is_empty()
    });

    let mut critical_violations = contracts.report.critical.violations.clone();
    critical_violations.sort();
    critical_violations.dedup();

    let mut lines = vec![
        format!("schema: {}", contracts.schema_version),
        format!("symbols: total={}", contracts.facts.symbols.len()),
        "contexts:".to_string(),
        format!(
            "irq_reachable: {} {}",
            irq_reachable.len(),
            format_bracketed_list(&irq_reachable)
        ),
        format!(
            "critical_functions: {} {}",
            critical_functions.len(),
            format_bracketed_list(&critical_functions)
        ),
        "effects:".to_string(),
        format!(
            "alloc: {} {}",
            alloc_symbols.len(),
            format_bracketed_list(&alloc_symbols)
        ),
        format!(
            "block: {} {}",
            block_symbols.len(),
            format_bracketed_list(&block_symbols)
        ),
        format!(
            "yield: {} {}",
            yield_symbols.len(),
            format_bracketed_list(&yield_symbols)
        ),
        "capabilities:".to_string(),
        format!(
            "symbols_with_caps: {} {}",
            cap_symbols.len(),
            format_bracketed_list(&cap_symbols)
        ),
        "critical_report:".to_string(),
        format!("violations: {}", critical_violations.len()),
    ];

    for violation in critical_violations {
        let (direct, via_callee, via_extern) =
            canonicalize_provenance_fields(Some(&violation.provenance));
        lines.push(format!(
            "violation: function={} effect={} direct={} via_callee={} via_extern={}",
            violation.function,
            violation.effect,
            direct,
            format_bracketed_list(&via_callee),
            format_bracketed_list(&via_extern)
        ));
    }

    lines.join("\n")
}

fn collect_sorted_symbol_names_by<F>(symbols: &[ContractsFactSymbol], predicate: F) -> Vec<String>
where
    F: Fn(&ContractsFactSymbol) -> bool,
{
    let mut out = symbols
        .iter()
        .filter(|symbol| predicate(symbol))
        .map(|symbol| symbol.name.clone())
        .collect::<Vec<_>>();
    out.sort();
    out.dedup();
    out
}
