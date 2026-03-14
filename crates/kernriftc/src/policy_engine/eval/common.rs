use super::super::ContractsProvenance;

pub(super) fn format_provenance(provenance: &ContractsProvenance) -> String {
    let mut via_callee = provenance.via_callee.clone();
    via_callee.sort();
    via_callee.dedup();
    let mut via_extern = provenance.via_extern.clone();
    via_extern.sort();
    via_extern.dedup();
    format!(
        "direct={}, via_callee=[{}], via_extern=[{}]",
        provenance.direct,
        via_callee.join(","),
        via_extern.join(",")
    )
}

pub(super) fn format_optional_provenance(provenance: Option<&ContractsProvenance>) -> String {
    provenance
        .map(format_provenance)
        .unwrap_or_else(|| "direct=false, via_callee=[], via_extern=[]".to_string())
}

pub(super) fn canonicalize_provenance_fields(
    provenance: Option<&ContractsProvenance>,
) -> (bool, Vec<String>, Vec<String>) {
    let mut via_callee = provenance.map(|p| p.via_callee.clone()).unwrap_or_default();
    via_callee.sort();
    via_callee.dedup();

    let mut via_extern = provenance.map(|p| p.via_extern.clone()).unwrap_or_default();
    via_extern.sort();
    via_extern.dedup();

    (
        provenance.map(|p| p.direct).unwrap_or(false),
        via_callee,
        via_extern,
    )
}

pub(super) fn format_bracketed_list(items: &[String]) -> String {
    format!("[{}]", items.join(","))
}
