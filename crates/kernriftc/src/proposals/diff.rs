use kernriftc::AdaptiveFeaturePromotionPlan;

use super::model::{PromotionFieldDiff, PromotionFileUpdate};
use super::state::{
    extract_hir_entry, extract_rust_status_field, extract_rust_string_field,
    parse_proposal_json_fields,
};

pub(super) fn render_promotion_diff_preview(
    plan: &AdaptiveFeaturePromotionPlan,
    updates: &[PromotionFileUpdate],
) -> Result<Vec<String>, String> {
    let diffs = build_promotion_field_diffs(plan, updates)?;
    let mut lines = Vec::with_capacity(3 + diffs.len() * 4);
    lines.push(format!("promotion-diff: {}", diffs.len()));
    lines.push(format!("feature: {}", plan.feature_id));
    lines.push(format!("proposal_id: {}", plan.proposal_id));
    for diff in diffs {
        lines.push(format!("file: {}", diff.file));
        lines.push(format!("field: {}", diff.field));
        lines.push(format!("before: {}", diff.before));
        lines.push(format!("after: {}", diff.after));
    }
    Ok(lines)
}

pub(super) fn build_promotion_field_diffs(
    plan: &AdaptiveFeaturePromotionPlan,
    updates: &[PromotionFileUpdate],
) -> Result<Vec<PromotionFieldDiff>, String> {
    let hir_update = updates
        .iter()
        .find(|update| update.path.ends_with("crates/hir/src/lib.rs"))
        .ok_or_else(|| "proposal-promotion: missing HIR update target".to_string())?;
    let proposal_update = updates
        .iter()
        .find(|update| {
            update
                .path
                .ends_with(format!("{}.proposal.json", plan.proposal_id))
        })
        .ok_or_else(|| "proposal-promotion: missing proposal update target".to_string())?;

    let original_feature_entry = extract_hir_entry(
        &hir_update.original,
        "const ADAPTIVE_SURFACE_FEATURES:",
        plan.feature_id,
    )?;
    let updated_feature_entry = extract_hir_entry(
        &hir_update.updated,
        "const ADAPTIVE_SURFACE_FEATURES:",
        plan.feature_id,
    )?;
    let original_proposal_entry = extract_hir_entry(
        &hir_update.original,
        "const ADAPTIVE_FEATURE_PROPOSALS:",
        plan.proposal_id,
    )?;
    let updated_proposal_entry = extract_hir_entry(
        &hir_update.updated,
        "const ADAPTIVE_FEATURE_PROPOSALS:",
        plan.proposal_id,
    )?;

    let mut diffs = vec![
        PromotionFieldDiff {
            file: "crates/hir/src/lib.rs".to_string(),
            field: "feature.status",
            before: extract_rust_status_field(&original_feature_entry)?,
            after: extract_rust_status_field(&updated_feature_entry)?,
        },
        PromotionFieldDiff {
            file: "crates/hir/src/lib.rs".to_string(),
            field: "proposal.status",
            before: extract_rust_status_field(&original_proposal_entry)?,
            after: extract_rust_status_field(&updated_proposal_entry)?,
        },
        PromotionFieldDiff {
            file: "crates/hir/src/lib.rs".to_string(),
            field: "proposal.title",
            before: extract_rust_string_field(&original_proposal_entry, "title")?,
            after: extract_rust_string_field(&updated_proposal_entry, "title")?,
        },
        PromotionFieldDiff {
            file: "crates/hir/src/lib.rs".to_string(),
            field: "proposal.compatibility_risk",
            before: extract_rust_string_field(&original_proposal_entry, "compatibility_risk")?,
            after: extract_rust_string_field(&updated_proposal_entry, "compatibility_risk")?,
        },
        PromotionFieldDiff {
            file: "crates/hir/src/lib.rs".to_string(),
            field: "proposal.migration_plan",
            before: extract_rust_string_field(&original_proposal_entry, "migration_plan")?,
            after: extract_rust_string_field(&updated_proposal_entry, "migration_plan")?,
        },
    ];

    let original_json = parse_proposal_json_fields(&proposal_update.original)?;
    let updated_json = parse_proposal_json_fields(&proposal_update.updated)?;
    let proposal_path = format!("docs/design/examples/{}.proposal.json", plan.proposal_id);
    diffs.extend([
        PromotionFieldDiff {
            file: proposal_path.clone(),
            field: "proposal.status",
            before: original_json.status,
            after: updated_json.status,
        },
        PromotionFieldDiff {
            file: proposal_path.clone(),
            field: "proposal.title",
            before: original_json.title,
            after: updated_json.title,
        },
        PromotionFieldDiff {
            file: proposal_path.clone(),
            field: "proposal.compatibility_risk",
            before: original_json.compatibility_risk,
            after: updated_json.compatibility_risk,
        },
        PromotionFieldDiff {
            file: proposal_path,
            field: "proposal.migration_plan",
            before: original_json.migration_plan,
            after: updated_json.migration_plan,
        },
    ]);

    diffs.sort_by(|a, b| a.file.cmp(&b.file).then(a.field.cmp(b.field)));
    Ok(diffs)
}
