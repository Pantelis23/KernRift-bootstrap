//! Diff mode for `kernriftc lc --diff`.
//!
//! Compares two sets of [`PatternMatch`] results and returns only suggestions
//! that are new or worsened (fitness increased by >= 10).

use kernriftc::PatternMatch;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DiffStatus {
    New,
    Worsened { fitness_before: u8 },
}

#[derive(Debug, Clone)]
pub(crate) struct DiffEntry {
    pub(crate) status: DiffStatus,
    pub(crate) suggestion: PatternMatch,
}

/// Compare `before` and `after` suggestion lists.
/// Returns entries that are new or worsened (fitness delta >= 10).
pub(crate) fn compute_diff(before: &[PatternMatch], after: &[PatternMatch]) -> Vec<DiffEntry> {
    let mut entries = Vec::new();

    for a in after {
        match before.iter().find(|b| b.id == a.id) {
            None => {
                entries.push(DiffEntry {
                    status: DiffStatus::New,
                    suggestion: a.clone(),
                });
            }
            Some(b) if a.fitness >= b.fitness + 10 => {
                entries.push(DiffEntry {
                    status: DiffStatus::Worsened {
                        fitness_before: b.fitness,
                    },
                    suggestion: a.clone(),
                });
            }
            _ => {}
        }
    }

    entries
}

/// Fetch the "before" source for git-aware diff mode.
/// Runs `git show HEAD:<file_path>` and returns the content as a String.
pub(crate) fn git_show_head(file_path: &str) -> Result<String, String> {
    use std::process::Command;

    let output = Command::new("git")
        .args(["show", &format!("HEAD:{}", file_path)])
        .output()
        .map_err(|e| format!("lc diff: failed to run git: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "lc diff: git show HEAD:{} failed: {}",
            file_path,
            stderr.trim()
        ));
    }

    String::from_utf8(output.stdout)
        .map_err(|_| format!("lc diff: git HEAD:{} is not valid UTF-8", file_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pm(id: &'static str, fitness: u8) -> PatternMatch {
        PatternMatch {
            id,
            title: "t",
            signal: "s".to_string(),
            suggestion: "sugg",
            fitness,
            requires_experimental: false,
        }
    }

    #[test]
    fn new_suggestion_is_returned() {
        let before = vec![pm("a", 50)];
        let after = vec![pm("a", 50), pm("b", 40)];
        let diff = compute_diff(&before, &after);
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].suggestion.id, "b");
        assert!(matches!(diff[0].status, DiffStatus::New));
    }

    #[test]
    fn worsened_suggestion_is_returned() {
        let before = vec![pm("a", 30)];
        let after = vec![pm("a", 40)];
        let diff = compute_diff(&before, &after);
        assert_eq!(diff.len(), 1);
        assert!(matches!(
            diff[0].status,
            DiffStatus::Worsened { fitness_before: 30 }
        ));
    }

    #[test]
    fn below_threshold_delta_is_dropped() {
        let before = vec![pm("a", 30)];
        let after = vec![pm("a", 39)];
        let diff = compute_diff(&before, &after);
        assert!(diff.is_empty());
    }

    #[test]
    fn improved_suggestion_is_dropped() {
        let before = vec![pm("a", 60)];
        let after = vec![pm("a", 30)];
        let diff = compute_diff(&before, &after);
        assert!(diff.is_empty());
    }

    #[test]
    fn disappeared_suggestion_is_dropped() {
        let before = vec![pm("a", 60)];
        let after = vec![];
        let diff = compute_diff(&before, &after);
        assert!(diff.is_empty());
    }
}
