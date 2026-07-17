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
///
/// Prefer named constructors rather than ad-hoc category toggles:
/// - [`SanitizePolicy::default`] / [`SanitizePolicy::terminal`] — user TUI input
/// - [`SanitizePolicy::untrusted_external`] — mid-stack shared/tool content
/// - [`SanitizePolicy::model_bound`] — sampling egress (use via [`crate::hard_filter_model_text`])
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizePolicy {
    /// When false, return input unchanged with an empty report.
    pub enabled: bool,
    /// Toast / notify when security categories fire (UI layer reads this).
    pub notify_when_stripped: bool,
    /// Run statistical / steganographic analysis on raw + cleaned text.
    pub analyze_enabled: bool,
    actions: BTreeMap<RiskCategory, CategoryAction>,
}

impl Default for SanitizePolicy {
    fn default() -> Self {
        // Balanced terminal profile — see [`SanitizeProfile::Balanced`].
        SanitizeProfile::Balanced.to_policy()
    }
}

/// Named terminal input-sanitize profiles (capability keep sets).
///
/// Security classes always strip under every profile. Exotic emoji chrome is
/// still removed at model-bound egress regardless of the terminal profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SanitizeProfile {
    /// Printable ASCII + newline only (capability categories strip).
    Strict,
    /// Everyday coding: emoji, Latin accents, math ops, tabs. Default.
    Balanced,
    /// All capability languages / punctuation (docs, CJK, Cyrillic, …).
    Multilingual,
}

impl SanitizeProfile {
    pub const ALL: &'static [SanitizeProfile] =
        &[Self::Strict, Self::Balanced, Self::Multilingual];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Balanced => "balanced",
            Self::Multilingual => "multilingual",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "strict" | "ascii" => Some(Self::Strict),
            "balanced" | "default" | "everyday" => Some(Self::Balanced),
            "multilingual" | "i18n" | "international" | "permissive" => {
                Some(Self::Multilingual)
            }
            _ => None,
        }
    }

    /// Capability categories kept under this profile (security always strip).
    pub fn keep_categories(self) -> &'static [RiskCategory] {
        match self {
            Self::Strict => &[],
            Self::Balanced => &[
                RiskCategory::Emoji,
                RiskCategory::LatinExtended,
                RiskCategory::MathSymbols,
                RiskCategory::Tab,
            ],
            Self::Multilingual => &[
                RiskCategory::Tab,
                RiskCategory::Emoji,
                RiskCategory::MathSymbols,
                RiskCategory::LatinExtended,
                RiskCategory::UnicodeLetters,
                RiskCategory::UnicodePunctuation,
            ],
        }
    }

    pub fn to_policy(self) -> SanitizePolicy {
        let mut actions = BTreeMap::new();
        for &cat in RiskCategory::ALL {
            actions.insert(cat, CategoryAction::Strip);
        }
        for &cat in self.keep_categories() {
            actions.insert(cat, CategoryAction::Keep);
        }
        SanitizePolicy {
            enabled: true,
            notify_when_stripped: true,
            analyze_enabled: true,
            actions,
        }
    }

    /// Best-effort match of a live policy's capability keeps to a named profile.
    /// Returns `None` when the keep set is a custom mix.
    pub fn detect(policy: &SanitizePolicy) -> Option<Self> {
        let keeps: std::collections::BTreeSet<RiskCategory> = RiskCategory::ALL
            .iter()
            .copied()
            .filter(|c| c.allow_user_keep() && policy.action(*c) == CategoryAction::Keep)
            .collect();
        for &prof in Self::ALL {
            let expected: std::collections::BTreeSet<RiskCategory> =
                prof.keep_categories().iter().copied().collect();
            if keeps == expected {
                return Some(prof);
            }
        }
        None
    }
}

impl SanitizePolicy {
    /// Alias for [`Default`]: terminal / headless user input ([`SanitizeProfile::Balanced`]).
    pub fn terminal() -> Self {
        Self::default()
    }

    /// Apply a named profile's capability keep set (preserves enabled / notify / analyze).
    pub fn apply_profile(&mut self, profile: SanitizeProfile) {
        for &cat in RiskCategory::ALL {
            if cat.allow_user_keep() {
                let action = if profile.keep_categories().contains(&cat) {
                    CategoryAction::Keep
                } else {
                    CategoryAction::Strip
                };
                let _ = self.set_action(cat, action);
            }
        }
    }

    /// Policy for **external / tool** content (MCP results, file reads, web
    /// fetch, shell stdout, etc.).
    ///
    /// Mid-stack only: analysis notes + security Unicode strip for shared
    /// content. **Not** the sampling hard strip — that is [`Self::model_bound`]
    /// / [`crate::hard_filter_model_text`] on the conversation request clone.
    ///
    /// Keeps capability Unicode (languages, punctuation, emoji, tabs) so real
    /// docs and code survive. Still **strips all security categories** and runs
    /// residual-risk analysis.
    pub fn untrusted_external() -> Self {
        let mut p = Self::default();
        for cat in [
            RiskCategory::Tab,
            RiskCategory::Emoji,
            RiskCategory::MathSymbols,
            RiskCategory::LatinExtended,
            RiskCategory::UnicodeLetters,
            RiskCategory::UnicodePunctuation,
        ] {
            let _ = p.allow_keep(cat);
        }
        p
    }

    /// **Model-bound hard filter** applied to the sampling payload (last hop).
    ///
    /// - Strips all **security** Unicode (invisibles, bidi, lookalikes, …)
    /// - Keeps languages / punctuation / tabs / basic emoji (😀 👍 …)
    /// - Exotic emoji chrome is stripped in [`crate::hard_filter_model_text`]
    ///   (flags, skin tones, supplemental blocks, VS-16, …) — token stuffing
    /// - **No** residual analysis notes (silent — notes would burn tokens too)
    pub fn model_bound() -> Self {
        let mut p = Self::untrusted_external();
        // Keep the Emoji *category* so basic smileys survive; exotic codepoints
        // are removed by `hard_filter_model_text` / `is_exotic_emoji`.
        p.analyze_enabled = false;
        p.notify_when_stripped = false;
        p
    }

    pub fn action(&self, cat: RiskCategory) -> CategoryAction {
        self.actions
            .get(&cat)
            .copied()
            .unwrap_or(CategoryAction::Strip)
    }

    /// Set a category action. Security categories cannot be set to [`CategoryAction::Keep`].
    pub fn set_action(
        &mut self,
        cat: RiskCategory,
        action: CategoryAction,
    ) -> Result<(), PolicyError> {
        if action == CategoryAction::Keep && !cat.allow_user_keep() {
            return Err(PolicyError::SecurityKeepForbidden(cat));
        }
        self.actions.insert(cat, action);
        Ok(())
    }

    /// Set a capability category to keep (rejects security categories).
    pub fn allow_keep(&mut self, cat: RiskCategory) -> Result<(), PolicyError> {
        self.set_action(cat, CategoryAction::Keep)
    }

    /// Set category back to strip.
    pub fn deny_keep(&mut self, cat: RiskCategory) {
        let _ = self.set_action(cat, CategoryAction::Strip);
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
