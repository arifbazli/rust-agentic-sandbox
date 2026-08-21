use std::path::{Path, PathBuf};

use crate::broker::CapabilityDecision;

/// Resolves `path` to its canonical, symlink-free form. If `path` doesn't
/// exist yet (e.g. a proposed new file), canonicalizes its parent directory
/// instead and rejoins the file name — so a not-yet-created file still gets
/// a real, traversal-resistant path to check containment against. This only
/// tolerates one level of non-existence (the file itself); if the parent is
/// missing too, resolution fails and the caller denies by default.
fn canonicalize_best_effort(path: &Path) -> std::io::Result<PathBuf> {
    if let Ok(canonical) = std::fs::canonicalize(path) {
        return Ok(canonical);
    }
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "path has no parent directory to resolve")
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name component")
    })?;
    let canonical_parent = std::fs::canonicalize(parent)?;
    Ok(canonical_parent.join(file_name))
}

/// Deterministic capability check for a proposed file write: grants only if
/// the proposed path, once fully resolved (symlinks and `..` included),
/// stays within `workspace_root`. See CONTEXT.md sections 2 and 3 — nothing
/// outside the declared boundary is reachable, regardless of how the path
/// tries to get there.
pub fn evaluate_file_write(workspace_root: &Path, proposed_path: &Path) -> CapabilityDecision {
    let canonical_root = match std::fs::canonicalize(workspace_root) {
        Ok(root) => root,
        Err(e) => {
            return CapabilityDecision::Denied {
                reason: format!("workspace root {} could not be resolved: {e}", workspace_root.display()),
            }
        }
    };

    let canonical_proposed = match canonicalize_best_effort(proposed_path) {
        Ok(p) => p,
        Err(e) => {
            return CapabilityDecision::Denied {
                reason: format!("proposed path {} could not be resolved: {e}", proposed_path.display()),
            }
        }
    };

    if canonical_proposed.starts_with(&canonical_root) {
        CapabilityDecision::Granted
    } else {
        CapabilityDecision::Denied {
            reason: format!(
                "proposed path resolves to {} which is outside the workspace root {} (path traversal, symlink escape, or an absolute path outside the workspace)",
                canonical_proposed.display(),
                canonical_root.display()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_path_inside_workspace_is_allowed() {
        let workspace = tempfile::tempdir().unwrap();
        let proposed = workspace.path().join("file.txt");
        std::fs::write(&proposed, "hello").unwrap();

        assert_eq!(evaluate_file_write(workspace.path(), &proposed), CapabilityDecision::Granted);
    }

    #[test]
    fn parent_traversal_outside_workspace_is_denied() {
        let workspace = tempfile::tempdir().unwrap();
        let proposed = workspace.path().join("..").join("escaped.txt");

        assert!(matches!(evaluate_file_write(workspace.path(), &proposed), CapabilityDecision::Denied { .. }));
    }

    #[test]
    #[cfg(unix)]
    fn symlink_inside_workspace_pointing_outside_is_denied() {
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_file = outside.path().join("secret.txt");
        std::fs::write(&outside_file, "secret").unwrap();

        let link_path = workspace.path().join("link");
        std::os::unix::fs::symlink(outside.path(), &link_path).unwrap();
        let proposed = link_path.join("secret.txt");

        assert!(matches!(evaluate_file_write(workspace.path(), &proposed), CapabilityDecision::Denied { .. }));
    }

    #[test]
    fn absolute_path_outside_workspace_is_denied() {
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let proposed = outside.path().join("file.txt");
        std::fs::write(&proposed, "x").unwrap();

        assert!(matches!(evaluate_file_write(workspace.path(), &proposed), CapabilityDecision::Denied { .. }));
    }

    #[test]
    fn nonexistent_file_with_parent_inside_workspace_is_allowed() {
        let workspace = tempfile::tempdir().unwrap();
        let proposed = workspace.path().join("new_file.txt");

        assert_eq!(evaluate_file_write(workspace.path(), &proposed), CapabilityDecision::Granted);
    }

    #[test]
    fn nonexistent_file_with_parent_outside_workspace_is_denied() {
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let proposed = outside.path().join("new_file.txt");

        assert!(matches!(evaluate_file_write(workspace.path(), &proposed), CapabilityDecision::Denied { .. }));
    }

    /// `canonicalize_best_effort` only tolerates one level of non-existence
    /// (the file itself). A missing intermediate directory must not be
    /// silently treated as "inside the workspace, trust it" — resolution
    /// fails and the caller denies by default.
    #[test]
    fn nonexistent_file_under_nonexistent_parent_directory_is_denied() {
        let workspace = tempfile::tempdir().unwrap();
        let proposed = workspace.path().join("newdir").join("newfile.txt");

        assert!(matches!(evaluate_file_write(workspace.path(), &proposed), CapabilityDecision::Denied { .. }));
    }
}
