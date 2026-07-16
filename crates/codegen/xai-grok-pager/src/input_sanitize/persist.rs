//! Load / write `[input_sanitize]` without round-tripping the whole Config struct.
//!
//! Uses `toml_edit` so sibling tables in config.toml are preserved (same pattern
//! as [`crate::config_toml_edit`]).

use std::path::{Path, PathBuf};

use xai_grok_input_sanitize::{
    CategoryAction, InputSanitizeConfig, RiskCategory, SanitizePolicy,
};

use crate::config_toml_edit::read_config_document_for_edit;

/// User-level config path (`~/.grok/config.toml`).
pub fn user_config_path() -> PathBuf {
    xai_grok_tools::util::grok_home::grok_home().join("config.toml")
}

/// Project config path for `cwd` (`.grok/config.toml`).
pub fn project_config_path(cwd: &Path) -> PathBuf {
    cwd.join(".grok").join("config.toml")
}

/// Load merged policy: defaults ← user config ← nearest project config.
pub fn load_policy(cwd: Option<&Path>) -> SanitizePolicy {
    let mut cfg = InputSanitizeConfig::default();

    if let Some(user) = load_section_from_path(&user_config_path()) {
        cfg.merge_over(&user);
    }

    if let Some(cwd) = cwd {
        // Prefer cwd project file; walk is left for a later iteration if needed.
        if let Some(proj) = load_section_from_path(&project_config_path(cwd)) {
            cfg.merge_over(&proj);
        }
    }

    cfg.to_policy()
}

fn load_section_from_path(path: &Path) -> Option<InputSanitizeConfig> {
    let raw = std::fs::read_to_string(path).ok()?;
    let value: toml::Value = toml::from_str(&raw).ok()?;
    let table = value.get("input_sanitize")?.clone();
    table.try_into().ok()
}

/// Persist a single category action under `[input_sanitize]` in `path`.
pub fn write_category_action(
    path: &Path,
    cat: RiskCategory,
    action: CategoryAction,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let Some(mut doc) = read_config_document_for_edit(path) else {
        return Ok(());
    };
    doc["input_sanitize"][cat.as_str()] = toml_edit::value(action.as_str());
    std::fs::write(path, doc.to_string())
}

/// Persist keep for a capability category at user or project scope.
pub fn persist_allow(
    cat: RiskCategory,
    user: bool,
    project: bool,
    cwd: Option<&Path>,
) -> std::io::Result<()> {
    if user {
        write_category_action(&user_config_path(), cat, CategoryAction::Keep)?;
    }
    if project {
        let path = match cwd {
            Some(c) => project_config_path(c),
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "project scope requires a cwd",
                ));
            }
        };
        write_category_action(&path, cat, CategoryAction::Keep)?;
    }
    Ok(())
}

/// Persist strip (deny keep) for user/project.
pub fn persist_deny(
    cat: RiskCategory,
    user: bool,
    project: bool,
    cwd: Option<&Path>,
) -> std::io::Result<()> {
    if user {
        write_category_action(&user_config_path(), cat, CategoryAction::Strip)?;
    }
    if project {
        let path = match cwd {
            Some(c) => project_config_path(c),
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "project scope requires a cwd",
                ));
            }
        };
        write_category_action(&path, cat, CategoryAction::Strip)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn write_and_load_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[ui]\ncompact_mode = true\n").unwrap();
        write_category_action(&path, RiskCategory::LatinExtended, CategoryAction::Keep).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("compact_mode"));
        assert!(body.contains("latin_extended"));
        assert!(body.contains("keep"));

        let cfg = load_section_from_path(&path).unwrap();
        let p = cfg.to_policy();
        assert_eq!(p.action(RiskCategory::LatinExtended), CategoryAction::Keep);
    }
}
