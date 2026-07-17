//! Pager adapter for `xai-grok-input-sanitize`.
//!
//! Keeps AgentView / dispatch free of classification logic:
//! - [`session`] — per-agent policy overlay + last raw/result
//! - [`apply`] — sanitize helpers for paste vs send
//! - [`persist`] — load/write `[input_sanitize]` in config.toml

mod apply;
mod persist;
mod session;

pub use apply::{ApplyKind, AppliedInput};
pub use persist::{
    load_policy, persist_allow, persist_bool_user, persist_category_user, persist_deny,
};
pub use session::InputSanitizeSession;

/// Compact live snapshot of terminal input-sanitize policy for the settings modal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputSanitizeSnapshot {
    pub enabled: bool,
    pub notify_when_stripped: bool,
    pub analyze: bool,
    pub tab_keep: bool,
    pub emoji_keep: bool,
    pub math_symbols_keep: bool,
    pub latin_extended_keep: bool,
    pub unicode_letters_keep: bool,
    pub unicode_punctuation_keep: bool,
}

impl Default for InputSanitizeSnapshot {
    fn default() -> Self {
        // Matches `SanitizePolicy::terminal()` defaults (emoji keep; other
        // capability categories strip until allowed).
        Self {
            enabled: true,
            notify_when_stripped: true,
            analyze: true,
            tab_keep: false,
            emoji_keep: true,
            math_symbols_keep: false,
            latin_extended_keep: false,
            unicode_letters_keep: false,
            unicode_punctuation_keep: false,
        }
    }
}

impl InputSanitizeSnapshot {
    pub fn from_policy(p: &xai_grok_input_sanitize::SanitizePolicy) -> Self {
        use xai_grok_input_sanitize::{CategoryAction, RiskCategory};
        let keep = |c: RiskCategory| p.action(c) == CategoryAction::Keep;
        Self {
            enabled: p.enabled,
            notify_when_stripped: p.notify_when_stripped,
            analyze: p.analyze_enabled,
            tab_keep: keep(RiskCategory::Tab),
            emoji_keep: keep(RiskCategory::Emoji),
            math_symbols_keep: keep(RiskCategory::MathSymbols),
            latin_extended_keep: keep(RiskCategory::LatinExtended),
            unicode_letters_keep: keep(RiskCategory::UnicodeLetters),
            unicode_punctuation_keep: keep(RiskCategory::UnicodePunctuation),
        }
    }

    pub fn category_keep(&self, cat: xai_grok_input_sanitize::RiskCategory) -> bool {
        use xai_grok_input_sanitize::RiskCategory;
        match cat {
            RiskCategory::Tab => self.tab_keep,
            RiskCategory::Emoji => self.emoji_keep,
            RiskCategory::MathSymbols => self.math_symbols_keep,
            RiskCategory::LatinExtended => self.latin_extended_keep,
            RiskCategory::UnicodeLetters => self.unicode_letters_keep,
            RiskCategory::UnicodePunctuation => self.unicode_punctuation_keep,
            _ => false,
        }
    }
}
