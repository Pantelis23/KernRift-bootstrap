use std::fs;

use kernriftc::AdaptiveFeaturePromotionPlan;
use serde_json::Value;

use super::model::{PromotionFileUpdate, PromotionTargetFiles};
use super::state::{escape_rust_string_literal, rust_string_literal_end};

pub(super) fn build_promotion_target_updates(
    paths: &PromotionTargetFiles,
    plan: &AdaptiveFeaturePromotionPlan,
) -> Result<Vec<PromotionFileUpdate>, String> {
    let hir_original = fs::read_to_string(&paths.hir_path).map_err(|err| {
        format!(
            "proposal-promotion: failed to read '{}': {}",
            paths.hir_path.display(),
            err
        )
    })?;
    let proposal_original = fs::read_to_string(&paths.proposal_path).map_err(|err| {
        format!(
            "proposal-promotion: failed to read '{}': {}",
            paths.proposal_path.display(),
            err
        )
    })?;

    let hir_updated = promote_status_in_hir_source(&hir_original, plan)?;
    let proposal_updated = promote_proposal_example_json(&proposal_original, plan)?;

    Ok(vec![
        PromotionFileUpdate {
            path: paths.hir_path.clone(),
            original: hir_original,
            updated: hir_updated,
        },
        PromotionFileUpdate {
            path: paths.proposal_path.clone(),
            original: proposal_original,
            updated: proposal_updated,
        },
    ])
}

pub(super) fn promote_status_in_hir_source(
    src: &str,
    plan: &AdaptiveFeaturePromotionPlan,
) -> Result<String, String> {
    let src = promote_status_in_rust_entry(
        src,
        "const ADAPTIVE_SURFACE_FEATURES:",
        plan.feature_id,
        plan.feature_id,
    )?;
    let src = promote_status_in_rust_entry(
        &src,
        "const ADAPTIVE_FEATURE_PROPOSALS:",
        plan.proposal_id,
        plan.feature_id,
    )?;
    normalize_proposal_text_in_hir_source(&src, plan)
}

fn promote_status_in_rust_entry(
    src: &str,
    section_marker: &str,
    entry_id: &str,
    feature_id: &str,
) -> Result<String, String> {
    let section_start = src.find(section_marker).ok_or_else(|| {
        format!(
            "proposal-promotion: failed to locate '{}' in crates/hir/src/lib.rs",
            section_marker
        )
    })?;
    let id_marker = format!("        id: \"{}\",", entry_id);
    let relative_entry_start = src[section_start..]
        .find(&id_marker)
        .ok_or_else(|| format!("proposal-promotion: failed to locate entry '{}'", entry_id))?;
    let entry_start = section_start + relative_entry_start;
    let relative_entry_end = src[entry_start..].find("    },").ok_or_else(|| {
        format!(
            "proposal-promotion: failed to locate end of entry '{}'",
            entry_id
        )
    })?;
    let entry_end = entry_start + relative_entry_end;
    let entry = &src[entry_start..entry_end];
    let experimental = "status: AdaptiveFeatureStatus::Experimental,";
    let stable = "status: AdaptiveFeatureStatus::Stable,";
    if !entry.contains(experimental) {
        return Err(format!(
            "proposal-promotion: feature '{}' is not promotable: expected experimental status in '{}'",
            feature_id, entry_id
        ));
    }
    let replaced = entry.replacen(experimental, stable, 1);
    let mut out = String::with_capacity(src.len() - entry.len() + replaced.len());
    out.push_str(&src[..entry_start]);
    out.push_str(&replaced);
    out.push_str(&src[entry_end..]);
    Ok(out)
}

fn normalize_proposal_text_in_hir_source(
    src: &str,
    plan: &AdaptiveFeaturePromotionPlan,
) -> Result<String, String> {
    let section_marker = "const ADAPTIVE_FEATURE_PROPOSALS:";
    let section_start = src.find(section_marker).ok_or_else(|| {
        format!(
            "proposal-promotion: failed to locate '{}' in crates/hir/src/lib.rs",
            section_marker
        )
    })?;
    let id_marker = format!("        id: \"{}\",", plan.proposal_id);
    let relative_entry_start = src[section_start..].find(&id_marker).ok_or_else(|| {
        format!(
            "proposal-promotion: failed to locate entry '{}'",
            plan.proposal_id
        )
    })?;
    let entry_start = section_start + relative_entry_start;
    let relative_entry_end = src[entry_start..].find("    },").ok_or_else(|| {
        format!(
            "proposal-promotion: failed to locate end of entry '{}'",
            plan.proposal_id
        )
    })?;
    let entry_end = entry_start + relative_entry_end;
    let entry = &src[entry_start..entry_end];

    let normalized = replace_rust_string_field(entry, "title", &plan.normalized_proposal_title)?;
    let normalized = replace_rust_string_field(
        &normalized,
        "compatibility_risk",
        &plan.normalized_compatibility_risk,
    )?;
    let normalized = replace_rust_string_field(
        &normalized,
        "migration_plan",
        &plan.normalized_migration_plan,
    )?;

    let mut out = String::with_capacity(src.len() - entry.len() + normalized.len());
    out.push_str(&src[..entry_start]);
    out.push_str(&normalized);
    out.push_str(&src[entry_end..]);
    Ok(out)
}

fn replace_rust_string_field(
    src: &str,
    field_name: &str,
    new_value: &str,
) -> Result<String, String> {
    let field_marker = format!("        {}: \"", field_name);
    let field_start = src.find(&field_marker).ok_or_else(|| {
        format!(
            "proposal-promotion: failed to locate field '{}' in proposal entry",
            field_name
        )
    })?;
    let value_start = field_start + field_marker.len();
    let value_end = rust_string_literal_end(src, value_start).ok_or_else(|| {
        format!(
            "proposal-promotion: failed to locate end of field '{}' in proposal entry",
            field_name
        )
    })?;
    let escaped_value = escape_rust_string_literal(new_value);
    let mut out =
        String::with_capacity(src.len() - (value_end - value_start) + escaped_value.len());
    out.push_str(&src[..value_start]);
    out.push_str(&escaped_value);
    out.push_str(&src[value_end..]);
    Ok(out)
}

pub(super) fn promote_proposal_example_json(
    src: &str,
    plan: &AdaptiveFeaturePromotionPlan,
) -> Result<String, String> {
    let mut value: Value = serde_json::from_str(src)
        .map_err(|err| format!("proposal-promotion: failed to parse proposal JSON: {}", err))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "proposal-promotion: proposal JSON must be an object".to_string())?;
    object.insert("status".to_string(), Value::String("stable".to_string()));
    object.insert(
        "title".to_string(),
        Value::String(plan.normalized_proposal_title.clone()),
    );
    object.insert(
        "compatibility_risk".to_string(),
        Value::String(plan.normalized_compatibility_risk.clone()),
    );
    object.insert(
        "migration_plan".to_string(),
        Value::String(plan.normalized_migration_plan.clone()),
    );
    let mut text = serde_json::to_string_pretty(&value).map_err(|err| {
        format!(
            "proposal-promotion: failed to serialize proposal JSON: {}",
            err
        )
    })?;
    text.push('\n');
    Ok(text)
}
