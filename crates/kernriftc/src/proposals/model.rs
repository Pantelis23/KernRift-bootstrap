use std::path::PathBuf;

#[derive(Debug)]
pub(super) struct PromotionTargetFiles {
    pub(super) hir_path: PathBuf,
    pub(super) proposal_path: PathBuf,
}

#[derive(Debug)]
pub(super) struct PromotionFileUpdate {
    pub(super) path: PathBuf,
    pub(super) original: String,
    pub(super) updated: String,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct PromotionFieldDiff {
    pub(super) file: String,
    pub(super) field: &'static str,
    pub(super) before: String,
    pub(super) after: String,
}

#[derive(Debug)]
pub(super) struct CompiledPromotionState {
    pub(super) feature_id: &'static str,
    pub(super) proposal_id: &'static str,
    pub(super) feature_status: &'static str,
    pub(super) proposal_status: &'static str,
    pub(super) canonical_replacement: &'static str,
}

#[derive(Debug)]
pub(super) struct RepoFeatureState {
    pub(super) feature_id: String,
    pub(super) proposal_id: String,
    pub(super) status: String,
    pub(super) canonical_replacement: String,
}

#[derive(Debug)]
pub(super) struct RepoProposalState {
    pub(super) id: String,
    pub(super) status: String,
    pub(super) title: String,
    pub(super) compatibility_risk: String,
    pub(super) migration_plan: String,
}

#[derive(Debug)]
pub(super) struct RepoPromotionState {
    pub(super) feature: RepoFeatureState,
    pub(super) proposal_hir: RepoProposalState,
    pub(super) proposal_json: RepoProposalState,
}
