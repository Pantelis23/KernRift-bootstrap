use std::path::Path;
use std::process::ExitCode;

use kernriftc::{
    adaptive_feature_promotion_plan, adaptive_feature_promotion_readiness,
    adaptive_feature_proposal_summaries, validate_adaptive_feature_governance,
};

use super::args::ProposalsArgs;
use super::diff::render_promotion_diff_preview;
use super::files::{
    rollback_written_promotion_files, validate_written_promotion_files, write_files_atomically,
};
use super::promote::build_promotion_target_updates;
use super::state::{
    compiled_promotion_state, ensure_clean_governance_worktree, load_repo_promotion_state,
    promotion_target_files, validate_governance_repo_root, validate_repo_promotion_state,
};
use crate::EXIT_INVALID_INPUT;

pub(crate) fn run_proposals(args: &ProposalsArgs) -> ExitCode {
    if args.validate {
        let errors = validate_adaptive_feature_governance();
        if errors.is_empty() {
            println!("proposal-validation: OK");
            return ExitCode::SUCCESS;
        }
        for err in errors {
            println!("{}", err);
        }
        return ExitCode::from(1);
    }

    if let Some(feature_id) = args.promote_feature.as_deref() {
        match apply_adaptive_feature_promotion(Path::new("."), feature_id, args.dry_run, args.diff)
        {
            Ok(lines) => {
                for line in lines {
                    println!("{}", line);
                }
                return ExitCode::SUCCESS;
            }
            Err(err) => {
                eprintln!("{}", err);
                return ExitCode::from(EXIT_INVALID_INPUT);
            }
        }
    }

    if args.promotion_readiness {
        let readiness = adaptive_feature_promotion_readiness();
        println!("promotion-readiness: {}", readiness.len());
        for entry in readiness {
            println!("feature: {}", entry.feature_id);
            println!("current_status: {}", entry.current_status.as_str());
            println!("promotable_to_stable: {}", entry.promotable_to_stable);
            println!("reason: {}", entry.reason);
        }
        return ExitCode::SUCCESS;
    }

    let proposals = adaptive_feature_proposal_summaries();
    println!("proposals: {}", proposals.len());
    println!("features: {}", proposals.len());
    for summary in proposals {
        println!("feature: {}", summary.feature.id);
        println!("proposal_id: {}", summary.proposal.id);
        println!("status: {}", summary.feature.status.as_str());
        println!("surface_form: @{}", summary.feature.surface_form);
        println!("lowering_target: {}", summary.feature.lowering_target);
        println!(
            "canonical_replacement: {}",
            summary.feature.canonical_replacement
        );
    }
    ExitCode::SUCCESS
}

fn apply_adaptive_feature_promotion(
    repo_root: &Path,
    feature_id: &str,
    dry_run: bool,
    diff: bool,
) -> Result<Vec<String>, String> {
    validate_governance_repo_root(repo_root)?;
    ensure_clean_governance_worktree(repo_root)?;

    let plan = adaptive_feature_promotion_plan(feature_id)?;
    let compiled_state = compiled_promotion_state(feature_id)?;
    let repo_state = load_repo_promotion_state(repo_root, feature_id)?;
    validate_repo_promotion_state(&compiled_state, &repo_state)?;
    let paths = promotion_target_files(repo_root, &plan);
    let updates = build_promotion_target_updates(&paths, &plan)?;
    let mut lines = Vec::<String>::new();

    if diff {
        lines.extend(render_promotion_diff_preview(&plan, &updates)?);
    }

    if dry_run {
        lines.push(format!(
            "proposal-promotion: dry-run promotion for feature '{}' is valid",
            feature_id
        ));
        return Ok(lines);
    }

    write_files_atomically(&updates)?;
    if let Err(err) = validate_written_promotion_files(&updates, &plan) {
        rollback_written_promotion_files(&updates)?;
        return Err(err);
    }

    lines.push(format!(
        "proposal-promotion: promoted feature '{}' to stable",
        feature_id
    ));
    Ok(lines)
}
