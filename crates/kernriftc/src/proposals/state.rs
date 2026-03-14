use std::fs;
use std::path::Path;
use std::process::Command as ProcessCommand;

use kernriftc::{AdaptiveFeaturePromotionPlan, adaptive_feature_proposal_summaries};
use serde_json::Value;

use super::model::{
    CompiledPromotionState, PromotionTargetFiles, RepoFeatureState, RepoPromotionState,
    RepoProposalState,
};

pub(super) fn compiled_promotion_state(feature_id: &str) -> Result<CompiledPromotionState, String> {
    let summary = adaptive_feature_proposal_summaries()
        .into_iter()
        .find(|summary| summary.feature.id == feature_id)
        .ok_or_else(|| format!("proposal-promotion: unknown feature '{}'", feature_id))?;
    Ok(CompiledPromotionState {
        feature_id: summary.feature.id,
        proposal_id: summary.feature.proposal_id,
        feature_status: summary.feature.status.as_str(),
        proposal_status: summary.proposal.status.as_str(),
        canonical_replacement: summary.feature.canonical_replacement,
    })
}

pub(super) fn validate_governance_repo_root(repo_root: &Path) -> Result<(), String> {
    let required = [
        repo_root.join(".git"),
        repo_root
            .join("crates")
            .join("hir")
            .join("src")
            .join("lib.rs"),
        repo_root.join("docs").join("design").join("examples"),
    ];
    if required.iter().all(|path| path.exists()) {
        Ok(())
    } else {
        Err("proposal-promotion: current directory is not a KernRift repo root".to_string())
    }
}

pub(super) fn ensure_clean_governance_worktree(repo_root: &Path) -> Result<(), String> {
    let output = ProcessCommand::new("git")
        .arg("status")
        .arg("--porcelain=v1")
        .current_dir(repo_root)
        .output()
        .map_err(|err| format!("proposal-promotion: failed to run git status: {}", err))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "proposal-promotion: failed to run git status: {}",
            stderr.trim()
        ));
    }
    if !output.stdout.is_empty() {
        return Err("proposal-promotion: repository worktree is not clean".to_string());
    }
    Ok(())
}

pub(super) fn promotion_target_files(
    repo_root: &Path,
    plan: &AdaptiveFeaturePromotionPlan,
) -> PromotionTargetFiles {
    PromotionTargetFiles {
        hir_path: repo_root
            .join("crates")
            .join("hir")
            .join("src")
            .join("lib.rs"),
        proposal_path: repo_root
            .join("docs")
            .join("design")
            .join("examples")
            .join(format!("{}.proposal.json", plan.proposal_id)),
    }
}

pub(super) fn load_repo_promotion_state(
    repo_root: &Path,
    feature_id: &str,
) -> Result<RepoPromotionState, String> {
    let hir_path = repo_root
        .join("crates")
        .join("hir")
        .join("src")
        .join("lib.rs");
    let hir_src = fs::read_to_string(&hir_path).map_err(|err| {
        format!(
            "proposal-promotion: failed to read '{}': {}",
            hir_path.display(),
            err
        )
    })?;

    let feature_entry = extract_hir_entry(&hir_src, "const ADAPTIVE_SURFACE_FEATURES:", feature_id)
        .map_err(|_| {
            format!(
                "proposal-promotion: target repo missing feature '{}'",
                feature_id
            )
        })?;
    let feature = RepoFeatureState {
        feature_id: extract_rust_string_field(&feature_entry, "id").map_err(|_| {
            format!(
                "proposal-promotion: target repo missing feature '{}'",
                feature_id
            )
        })?,
        proposal_id: extract_rust_string_field(&feature_entry, "proposal_id").map_err(|_| {
            format!(
                "proposal-promotion: target repo missing feature '{}'",
                feature_id
            )
        })?,
        status: extract_rust_status_field(&feature_entry).map_err(|_| {
            format!(
                "proposal-promotion: target repo missing feature '{}'",
                feature_id
            )
        })?,
        canonical_replacement: extract_rust_string_field(&feature_entry, "canonical_replacement")
            .map_err(|_| {
            format!(
                "proposal-promotion: target repo missing feature '{}'",
                feature_id
            )
        })?,
    };

    let proposal_entry = extract_hir_entry(
        &hir_src,
        "const ADAPTIVE_FEATURE_PROPOSALS:",
        &feature.proposal_id,
    )
    .map_err(|_| {
        format!(
            "proposal-promotion: target repo missing proposal '{}'",
            feature.proposal_id
        )
    })?;
    let proposal_hir = RepoProposalState {
        id: extract_rust_string_field(&proposal_entry, "id").map_err(|_| {
            format!(
                "proposal-promotion: target repo missing proposal '{}'",
                feature.proposal_id
            )
        })?,
        status: extract_rust_status_field(&proposal_entry).map_err(|_| {
            format!(
                "proposal-promotion: target repo missing proposal '{}'",
                feature.proposal_id
            )
        })?,
        title: extract_rust_string_field(&proposal_entry, "title").map_err(|_| {
            format!(
                "proposal-promotion: target repo missing proposal '{}'",
                feature.proposal_id
            )
        })?,
        compatibility_risk: extract_rust_string_field(&proposal_entry, "compatibility_risk")
            .map_err(|_| {
                format!(
                    "proposal-promotion: target repo missing proposal '{}'",
                    feature.proposal_id
                )
            })?,
        migration_plan: extract_rust_string_field(&proposal_entry, "migration_plan").map_err(
            |_| {
                format!(
                    "proposal-promotion: target repo missing proposal '{}'",
                    feature.proposal_id
                )
            },
        )?,
    };

    let proposal_json_path = repo_root
        .join("docs")
        .join("design")
        .join("examples")
        .join(format!("{}.proposal.json", feature.proposal_id));
    let proposal_json_text = fs::read_to_string(&proposal_json_path).map_err(|_| {
        format!(
            "proposal-promotion: target repo missing proposal '{}'",
            feature.proposal_id
        )
    })?;
    let proposal_json_value: Value = serde_json::from_str(&proposal_json_text).map_err(|err| {
        format!(
            "proposal-promotion: failed to parse proposal JSON '{}': {}",
            proposal_json_path.display(),
            err
        )
    })?;
    let proposal_json_obj = proposal_json_value.as_object().ok_or_else(|| {
        format!(
            "proposal-promotion: failed to parse proposal JSON '{}': expected object",
            proposal_json_path.display()
        )
    })?;
    let proposal_json = RepoProposalState {
        id: proposal_json_obj
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!(
                    "proposal-promotion: target repo missing proposal '{}'",
                    feature.proposal_id
                )
            })?
            .to_string(),
        status: proposal_json_obj
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!(
                    "proposal-promotion: target repo missing proposal '{}'",
                    feature.proposal_id
                )
            })?
            .to_string(),
        title: proposal_json_obj
            .get("title")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!(
                    "proposal-promotion: target repo missing proposal '{}'",
                    feature.proposal_id
                )
            })?
            .to_string(),
        compatibility_risk: proposal_json_obj
            .get("compatibility_risk")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!(
                    "proposal-promotion: target repo missing proposal '{}'",
                    feature.proposal_id
                )
            })?
            .to_string(),
        migration_plan: proposal_json_obj
            .get("migration_plan")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!(
                    "proposal-promotion: target repo missing proposal '{}'",
                    feature.proposal_id
                )
            })?
            .to_string(),
    };

    Ok(RepoPromotionState {
        feature,
        proposal_hir,
        proposal_json,
    })
}

pub(super) fn validate_repo_promotion_state(
    compiled: &CompiledPromotionState,
    repo: &RepoPromotionState,
) -> Result<(), String> {
    if repo.feature.feature_id != compiled.feature_id {
        return Err(format!(
            "proposal-promotion: target repo missing feature '{}'",
            compiled.feature_id
        ));
    }
    if repo.feature.proposal_id != compiled.proposal_id {
        return Err(format!(
            "proposal-promotion: target repo feature '{}' proposal linkage mismatch",
            compiled.feature_id
        ));
    }
    if repo.feature.canonical_replacement != compiled.canonical_replacement {
        return Err(format!(
            "proposal-promotion: target repo feature '{}' canonical replacement mismatch",
            compiled.feature_id
        ));
    }
    if repo.proposal_hir.id != repo.proposal_json.id {
        return Err(format!(
            "proposal-promotion: target repo proposal '{}' id mismatch between HIR and JSON",
            compiled.proposal_id
        ));
    }
    if repo.proposal_hir.title != repo.proposal_json.title {
        return Err(format!(
            "proposal-promotion: target repo proposal '{}' title mismatch between HIR and JSON",
            compiled.proposal_id
        ));
    }
    if repo.proposal_hir.compatibility_risk != repo.proposal_json.compatibility_risk {
        return Err(format!(
            "proposal-promotion: target repo proposal '{}' compatibility text mismatch between HIR and JSON",
            compiled.proposal_id
        ));
    }
    if repo.proposal_hir.migration_plan != repo.proposal_json.migration_plan {
        return Err(format!(
            "proposal-promotion: target repo proposal '{}' migration text mismatch between HIR and JSON",
            compiled.proposal_id
        ));
    }
    if repo.proposal_hir.status != repo.proposal_json.status {
        return Err(format!(
            "proposal-promotion: target repo proposal '{}' status mismatch between HIR and JSON",
            compiled.proposal_id
        ));
    }
    if repo.feature.status != compiled.feature_status {
        return Err(format!(
            "proposal-promotion: binary/repo disagreement for feature '{}' current status",
            compiled.feature_id
        ));
    }
    if repo.proposal_hir.status != compiled.proposal_status {
        return Err(format!(
            "proposal-promotion: binary/repo disagreement for proposal '{}' current status",
            compiled.proposal_id
        ));
    }
    if repo.feature.status != "experimental" {
        return Err(format!(
            "proposal-promotion: target repo feature '{}' is not experimental",
            compiled.feature_id
        ));
    }
    if repo.proposal_hir.status != "experimental" {
        return Err(format!(
            "proposal-promotion: target repo proposal '{}' is not experimental",
            compiled.proposal_id
        ));
    }
    Ok(())
}

pub(super) fn parse_proposal_json_fields(src: &str) -> Result<RepoProposalState, String> {
    let proposal_json_value: Value = serde_json::from_str(src)
        .map_err(|err| format!("proposal-promotion: failed to parse proposal JSON: {}", err))?;
    let proposal_json_obj = proposal_json_value
        .as_object()
        .ok_or_else(|| "proposal-promotion: proposal JSON must be an object".to_string())?;
    Ok(RepoProposalState {
        id: proposal_json_obj
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| "proposal-promotion: missing proposal JSON field 'id'".to_string())?
            .to_string(),
        status: proposal_json_obj
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(|| "proposal-promotion: missing proposal JSON field 'status'".to_string())?
            .to_string(),
        title: proposal_json_obj
            .get("title")
            .and_then(Value::as_str)
            .ok_or_else(|| "proposal-promotion: missing proposal JSON field 'title'".to_string())?
            .to_string(),
        compatibility_risk: proposal_json_obj
            .get("compatibility_risk")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                "proposal-promotion: missing proposal JSON field 'compatibility_risk'".to_string()
            })?
            .to_string(),
        migration_plan: proposal_json_obj
            .get("migration_plan")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                "proposal-promotion: missing proposal JSON field 'migration_plan'".to_string()
            })?
            .to_string(),
    })
}

pub(super) fn extract_hir_entry(
    src: &str,
    section_marker: &str,
    entry_id: &str,
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
    Ok(src[entry_start..entry_end].to_string())
}

pub(super) fn extract_rust_string_field(src: &str, field_name: &str) -> Result<String, String> {
    let field_marker = format!("        {}: \"", field_name);
    let field_start = src
        .find(&field_marker)
        .ok_or_else(|| format!("missing rust string field '{}'", field_name))?;
    let value_start = field_start + field_marker.len();
    let value_end = rust_string_literal_end(src, value_start)
        .ok_or_else(|| format!("missing rust string field end '{}'", field_name))?;
    unescape_rust_string_literal(&src[value_start..value_end])
}

pub(super) fn rust_string_literal_end(src: &str, value_start: usize) -> Option<usize> {
    let bytes = src.as_bytes();
    let mut idx = value_start;
    let mut escaped = false;
    while idx < bytes.len() {
        let byte = bytes[idx];
        if escaped {
            escaped = false;
            idx += 1;
            continue;
        }
        match byte {
            b'\\' => {
                escaped = true;
                idx += 1;
            }
            b'"' => return Some(idx),
            _ => idx += 1,
        }
    }
    None
}

pub(super) fn escape_rust_string_literal(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\0' => escaped.push_str("\\0"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

pub(super) fn unescape_rust_string_literal(value: &str) -> Result<String, String> {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        let Some(next) = chars.next() else {
            return Err("unterminated rust string escape".to_string());
        };
        match next {
            '\\' => out.push('\\'),
            '"' => out.push('"'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            '0' => out.push('\0'),
            'x' => {
                let hi = chars
                    .next()
                    .ok_or_else(|| "invalid rust hex escape".to_string())?;
                let lo = chars
                    .next()
                    .ok_or_else(|| "invalid rust hex escape".to_string())?;
                let hex = [hi, lo].iter().collect::<String>();
                let byte = u8::from_str_radix(&hex, 16)
                    .map_err(|_| "invalid rust hex escape".to_string())?;
                out.push(byte as char);
            }
            'u' => {
                if chars.next() != Some('{') {
                    return Err("invalid rust unicode escape".to_string());
                }
                let mut hex = String::new();
                loop {
                    let ch = chars
                        .next()
                        .ok_or_else(|| "invalid rust unicode escape".to_string())?;
                    if ch == '}' {
                        break;
                    }
                    hex.push(ch);
                }
                let code = u32::from_str_radix(&hex, 16)
                    .map_err(|_| "invalid rust unicode escape".to_string())?;
                let scalar = char::from_u32(code)
                    .ok_or_else(|| "invalid rust unicode scalar".to_string())?;
                out.push(scalar);
            }
            other => {
                return Err(format!("unsupported rust string escape '{}'", other));
            }
        }
    }
    Ok(out)
}

pub(super) fn extract_rust_status_field(src: &str) -> Result<String, String> {
    let marker = "status: AdaptiveFeatureStatus::";
    let start = src
        .find(marker)
        .ok_or_else(|| "missing rust status field".to_string())?
        + marker.len();
    let end = src[start..]
        .find(',')
        .map(|idx| start + idx)
        .ok_or_else(|| "missing rust status field end".to_string())?;
    match &src[start..end] {
        "Experimental" => Ok("experimental".to_string()),
        "Stable" => Ok("stable".to_string()),
        "Deprecated" => Ok("deprecated".to_string()),
        other => Err(format!("unknown rust status '{}'", other)),
    }
}
