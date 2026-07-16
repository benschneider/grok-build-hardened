//! Risk categories and severity for the switch table.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Severity of a category for model notes and UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Invisible / deceptive / terminal-abuse — warn the user; do not offer keep.
    Security,
    /// Language / emoji / tab — may suggest `/input-allow`.
    Capability,
}

/// Character class that can be toggled in config / slash commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskCategory {
    Tab,
    ControlC0C1,
    BidiControls,
    ZeroWidthFormat,
    Emoji,
    MathAlphanumeric,
    MathSymbols,
    LatinExtended,
    UnicodeLetters,
    UnicodePunctuation,
    PrivateUse,
    Noncharacters,
}

impl RiskCategory {
    pub const ALL: &'static [RiskCategory] = &[
        RiskCategory::Tab,
        RiskCategory::ControlC0C1,
        RiskCategory::BidiControls,
        RiskCategory::ZeroWidthFormat,
        RiskCategory::Emoji,
        RiskCategory::MathAlphanumeric,
        RiskCategory::MathSymbols,
        RiskCategory::LatinExtended,
        RiskCategory::UnicodeLetters,
        RiskCategory::UnicodePunctuation,
        RiskCategory::PrivateUse,
        RiskCategory::Noncharacters,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            RiskCategory::Tab => "tab",
            RiskCategory::ControlC0C1 => "control_c0_c1",
            RiskCategory::BidiControls => "bidi_controls",
            RiskCategory::ZeroWidthFormat => "zero_width_format",
            RiskCategory::Emoji => "emoji",
            RiskCategory::MathAlphanumeric => "math_alphanumeric",
            RiskCategory::MathSymbols => "math_symbols",
            RiskCategory::LatinExtended => "latin_extended",
            RiskCategory::UnicodeLetters => "unicode_letters",
            RiskCategory::UnicodePunctuation => "unicode_punctuation",
            RiskCategory::PrivateUse => "private_use",
            RiskCategory::Noncharacters => "noncharacters",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "tab" => Some(Self::Tab),
            "control_c0_c1" | "control" => Some(Self::ControlC0C1),
            "bidi_controls" | "bidi" => Some(Self::BidiControls),
            "zero_width_format" | "zero_width" | "zwsp" => Some(Self::ZeroWidthFormat),
            "emoji" => Some(Self::Emoji),
            "math_alphanumeric" | "math_alnum" => Some(Self::MathAlphanumeric),
            "math_symbols" | "math" => Some(Self::MathSymbols),
            "latin_extended" | "latin" => Some(Self::LatinExtended),
            "unicode_letters" | "letters" => Some(Self::UnicodeLetters),
            "unicode_punctuation" | "punctuation" | "punct" => Some(Self::UnicodePunctuation),
            "private_use" | "pua" => Some(Self::PrivateUse),
            "noncharacters" | "noncharacter" => Some(Self::Noncharacters),
            _ => None,
        }
    }

    pub fn severity(self) -> Severity {
        match self {
            RiskCategory::Tab
            | RiskCategory::Emoji
            | RiskCategory::MathSymbols
            | RiskCategory::LatinExtended
            | RiskCategory::UnicodeLetters
            | RiskCategory::UnicodePunctuation => Severity::Capability,
            RiskCategory::ControlC0C1
            | RiskCategory::BidiControls
            | RiskCategory::ZeroWidthFormat
            | RiskCategory::MathAlphanumeric
            | RiskCategory::PrivateUse
            | RiskCategory::Noncharacters => Severity::Security,
        }
    }

    /// Whether `/input-allow` may set this category to keep.
    pub fn allow_user_keep(self) -> bool {
        matches!(self.severity(), Severity::Capability)
    }
}

impl fmt::Display for RiskCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
