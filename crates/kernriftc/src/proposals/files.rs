use std::fs;
use std::path::PathBuf;

use kernriftc::AdaptiveFeaturePromotionPlan;
use serde_json::Value;

use super::model::PromotionFileUpdate;
use super::state::extract_hir_entry;

pub(super) fn write_files_atomically(updates: &[PromotionFileUpdate]) -> Result<(), String> {
    let mut temp_paths = Vec::<PathBuf>::new();
    for (idx, update) in updates.iter().enumerate() {
        let tmp = update.path.with_extension(format!(
            "{}.kernriftc-promote-{}.tmp",
            update
                .path
                .extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("file"),
            idx
        ));
        fs::write(&tmp, &update.updated).map_err(|err| {
            let _ = remove_temp_files(&temp_paths);
            format!(
                "proposal-promotion: failed to stage '{}': {}",
                update.path.display(),
                err
            )
        })?;
        temp_paths.push(tmp);
    }

    let mut renamed = Vec::<(PathBuf, String)>::new();
    for (update, tmp) in updates.iter().zip(temp_paths.iter()) {
        if let Err(err) = fs::rename(tmp, &update.path) {
            let _ = rollback_renamed_files(&renamed);
            let _ = remove_temp_files(&temp_paths);
            return Err(format!(
                "proposal-promotion: failed to commit '{}': {}",
                update.path.display(),
                err
            ));
        }
        renamed.push((update.path.clone(), update.original.clone()));
    }

    Ok(())
}

pub(super) fn validate_written_promotion_files(
    updates: &[PromotionFileUpdate],
    plan: &AdaptiveFeaturePromotionPlan,
) -> Result<(), String> {
    for update in updates {
        let current = fs::read_to_string(&update.path).map_err(|err| {
            format!(
                "proposal-promotion: failed to read '{}' after write: {}",
                update.path.display(),
                err
            )
        })?;
        if current != update.updated {
            return Err(format!(
                "proposal-promotion: validation failed for '{}'",
                update.path.display()
            ));
        }
    }

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

    let feature_entry = extract_hir_entry(
        &hir_update.updated,
        "const ADAPTIVE_SURFACE_FEATURES:",
        plan.feature_id,
    )?;
    if !feature_entry.contains("status: AdaptiveFeatureStatus::Stable,") {
        return Err(format!(
            "proposal-promotion: validation failed for feature '{}'",
            plan.feature_id
        ));
    }

    let proposal_entry = extract_hir_entry(
        &hir_update.updated,
        "const ADAPTIVE_FEATURE_PROPOSALS:",
        plan.proposal_id,
    )?;
    if !proposal_entry.contains("status: AdaptiveFeatureStatus::Stable,")
        || !proposal_entry.contains(&format!("title: \"{}\",", plan.normalized_proposal_title))
        || !proposal_entry.contains(&format!(
            "compatibility_risk: \"{}\",",
            plan.normalized_compatibility_risk
        ))
        || !proposal_entry.contains(&format!(
            "migration_plan: \"{}\",",
            plan.normalized_migration_plan
        ))
    {
        return Err(format!(
            "proposal-promotion: validation failed for proposal '{}'",
            plan.proposal_id
        ));
    }

    let proposal_json: Value = serde_json::from_str(&proposal_update.updated).map_err(|err| {
        format!(
            "proposal-promotion: validation failed for proposal '{}': {}",
            plan.proposal_id, err
        )
    })?;
    let obj = proposal_json.as_object().ok_or_else(|| {
        "proposal-promotion: validation failed for proposal JSON object".to_string()
    })?;
    let status = obj
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(|| "proposal-promotion: validation failed for proposal status".to_string())?;
    let title = obj
        .get("title")
        .and_then(Value::as_str)
        .ok_or_else(|| "proposal-promotion: validation failed for proposal title".to_string())?;
    let compatibility = obj
        .get("compatibility_risk")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            "proposal-promotion: validation failed for proposal compatibility text".to_string()
        })?;
    let migration = obj
        .get("migration_plan")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            "proposal-promotion: validation failed for proposal migration text".to_string()
        })?;
    if status != "stable"
        || title != plan.normalized_proposal_title
        || compatibility != plan.normalized_compatibility_risk
        || migration != plan.normalized_migration_plan
    {
        return Err(format!(
            "proposal-promotion: validation failed for proposal '{}'",
            plan.proposal_id
        ));
    }

    Ok(())
}

pub(super) fn rollback_written_promotion_files(
    updates: &[PromotionFileUpdate],
) -> Result<(), String> {
    let mut errs = Vec::<String>::new();
    for update in updates {
        if let Err(err) = fs::write(&update.path, &update.original) {
            errs.push(format!("{}: {}", update.path.display(), err));
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "proposal-promotion: rollback failed for {}",
            errs.join(", ")
        ))
    }
}

fn rollback_renamed_files(renamed: &[(PathBuf, String)]) -> Result<(), String> {
    let mut errs = Vec::<String>::new();
    for (path, original) in renamed.iter().rev() {
        if let Err(err) = fs::write(path, original) {
            errs.push(format!("{}: {}", path.display(), err));
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "proposal-promotion: rollback failed for {}",
            errs.join(", ")
        ))
    }
}

fn remove_temp_files(temp_paths: &[PathBuf]) -> Result<(), String> {
    let mut errs = Vec::<String>::new();
    for path in temp_paths {
        if let Err(err) = fs::remove_file(path)
            && path.exists()
        {
            errs.push(format!("{}: {}", path.display(), err));
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "proposal-promotion: temp cleanup failed for {}",
            errs.join(", ")
        ))
    }
}
