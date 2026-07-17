//! Serde config surface for `[input_sanitize]` TOML / JSON.

use serde::{Deserialize, Serialize};

use crate::category::RiskCategory;
use crate::policy::{CategoryAction, SanitizePolicy};

/// User-facing config table. All fields optional; missing ⇒ balanced defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct InputSanitizeConfig {
    pub enabled: Option<bool>,
    pub notify_when_stripped: Option<bool>,
    /// Statistical / steganographic residual-risk analysis (default true).
    pub analyze: Option<bool>,
    /// Named profile: `strict` | `balanced` | `multilingual` (optional).
    pub profile: Option<String>,
    pub tab: Option<CategoryAction>,
    pub control_c0_c1: Option<CategoryAction>,
    pub bidi_controls: Option<CategoryAction>,
    pub zero_width_format: Option<CategoryAction>,
    pub emoji: Option<CategoryAction>,
    pub math_alphanumeric: Option<CategoryAction>,
    pub math_symbols: Option<CategoryAction>,
    pub latin_extended: Option<CategoryAction>,
    pub unicode_letters: Option<CategoryAction>,
    pub unicode_punctuation: Option<CategoryAction>,
    pub private_use: Option<CategoryAction>,
    pub noncharacters: Option<CategoryAction>,
}

impl InputSanitizeConfig {
    /// Build a runtime policy from this config (defaults + overrides).
    pub fn to_policy(&self) -> SanitizePolicy {
        use crate::policy::SanitizeProfile;
        let mut p = match self.profile.as_deref() {
            // Custom = hand-tuned mix; start from balanced then apply per-key
            // overrides below (disk writes both profile=custom and category keys).
            Some(name) if name.eq_ignore_ascii_case("custom") => SanitizePolicy::default(),
            Some(name) => SanitizeProfile::parse(name)
                .unwrap_or(SanitizeProfile::Balanced)
                .to_policy(),
            None => SanitizePolicy::default(),
        };
        if let Some(v) = self.enabled {
            p.enabled = v;
        }
        if let Some(v) = self.notify_when_stripped {
            p.notify_when_stripped = v;
        }
        if let Some(v) = self.analyze {
            p.analyze_enabled = v;
        }
        let pairs: &[(RiskCategory, Option<CategoryAction>)] = &[
            (RiskCategory::Tab, self.tab),
            (RiskCategory::ControlC0C1, self.control_c0_c1),
            (RiskCategory::BidiControls, self.bidi_controls),
            (RiskCategory::ZeroWidthFormat, self.zero_width_format),
            (RiskCategory::Emoji, self.emoji),
            (RiskCategory::MathAlphanumeric, self.math_alphanumeric),
            (RiskCategory::MathSymbols, self.math_symbols),
            (RiskCategory::LatinExtended, self.latin_extended),
            (RiskCategory::UnicodeLetters, self.unicode_letters),
            (RiskCategory::UnicodePunctuation, self.unicode_punctuation),
            (RiskCategory::PrivateUse, self.private_use),
            (RiskCategory::Noncharacters, self.noncharacters),
        ];
        for &(cat, action) in pairs {
            if let Some(a) = action {
                // Security keep is ignored at config load (fail closed).
                let _ = p.set_action(cat, a);
            }
        }
        p
    }

    /// Overlay another config (e.g. project over user). `other` wins when set.
    pub fn merge_over(&mut self, other: &InputSanitizeConfig) {
        if other.enabled.is_some() {
            self.enabled = other.enabled;
        }
        if other.notify_when_stripped.is_some() {
            self.notify_when_stripped = other.notify_when_stripped;
        }
        if other.analyze.is_some() {
            self.analyze = other.analyze;
        }
        if other.profile.is_some() {
            self.profile = other.profile.clone();
        }
        merge_opt(&mut self.tab, other.tab);
        merge_opt(&mut self.control_c0_c1, other.control_c0_c1);
        merge_opt(&mut self.bidi_controls, other.bidi_controls);
        merge_opt(&mut self.zero_width_format, other.zero_width_format);
        merge_opt(&mut self.emoji, other.emoji);
        merge_opt(&mut self.math_alphanumeric, other.math_alphanumeric);
        merge_opt(&mut self.math_symbols, other.math_symbols);
        merge_opt(&mut self.latin_extended, other.latin_extended);
        merge_opt(&mut self.unicode_letters, other.unicode_letters);
        merge_opt(&mut self.unicode_punctuation, other.unicode_punctuation);
        merge_opt(&mut self.private_use, other.private_use);
        merge_opt(&mut self.noncharacters, other.noncharacters);
    }
}

fn merge_opt<T: Copy>(slot: &mut Option<T>, other: Option<T>) {
    if other.is_some() {
        *slot = other;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_roundtrip_defaults() {
        let raw = r#"
            enabled = true
            latin_extended = "keep"
            emoji = "strip"
        "#;
        let cfg: InputSanitizeConfig = toml::from_str(raw).unwrap();
        let p = cfg.to_policy();
        assert!(p.enabled);
        assert_eq!(p.action(RiskCategory::LatinExtended), CategoryAction::Keep);
        assert_eq!(p.action(RiskCategory::Emoji), CategoryAction::Strip);
    }

    #[test]
    fn security_keep_in_config_ignored() {
        let raw = r#"bidi_controls = "keep""#;
        let cfg: InputSanitizeConfig = toml::from_str(raw).unwrap();
        let p = cfg.to_policy();
        assert_eq!(p.action(RiskCategory::BidiControls), CategoryAction::Strip);
    }
}
