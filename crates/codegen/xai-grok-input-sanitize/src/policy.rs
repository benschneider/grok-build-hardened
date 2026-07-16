//! Sanitize policy and per-category actions.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::category::RiskCategory;

/// Per-category handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CategoryAction {
    /// Remove matching characters (default).
    #[default]
    Strip,
    /// Leave matching characters in the output.
    Keep,
    /// Fail the whole sanitize if any matching character appears.
    Reject,
}

impl CategoryAction {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "strip" => Some(Self::Strip),
            "keep" => Some(Self::Keep),
            "reject" => Some(Self::Reject),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Strip => "strip",
            Self::Keep => "keep",
            Self::Reject => "reject",
        }
    }
}

/// Full sanitize policy (runtime).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizePolicy {
    /// When false, return input unchanged with an empty report.
    pub enabled: bool,
    /// Whether emoji keep also preserves ZWJ / VS-16 used in sequences.
    pub allow_emoji_joiners: bool,
    /// Toast / notify when security categories fire (UI layer reads this).
    pub notify_when_stripped: bool,
    actions: BTreeMap<RiskCategory, CategoryAction>,
}

impl Default for SanitizePolicy {
    fn default() -> Self {
        let mut actions = BTreeMap::new();
        for &cat in RiskCategory::ALL {
            actions.insert(cat, CategoryAction::Strip);
        }
        Self {
            enabled: true,
            allow_emoji_joiners: true,
            notify_when_stripped: true,
            actions,
        }
    }
}

impl SanitizePolicy {
    pub fn action(&self, cat: RiskCategory) -> CategoryAction {
        self.actions
            .get(&cat)
            .copied()
            .unwrap_or(CategoryAction::Strip)
    }

    pub fn set_action(&mut self, cat: RiskCategory, action: CategoryAction) {
        self.actions.insert(cat, action);
    }

    /// Set a capability category to keep (rejects security categories).
    pub fn allow_keep(&mut self, cat: RiskCategory) -> Result<(), PolicyError> {
        if !cat.allow_user_keep() {
            return Err(PolicyError::SecurityKeepForbidden(cat));
        }
        self.set_action(cat, CategoryAction::Keep);
        Ok(())
    }

    /// Set category back to strip.
    pub fn deny_keep(&mut self, cat: RiskCategory) {
        self.set_action(cat, CategoryAction::Strip);
    }

    pub fn actions_iter(&self) -> impl Iterator<Item = (RiskCategory, CategoryAction)> + '_ {
        RiskCategory::ALL
            .iter()
            .copied()
            .map(|c| (c, self.action(c)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("category `{0}` is security-sensitive and cannot be set to keep")]
    SecurityKeepForbidden(RiskCategory),
}
