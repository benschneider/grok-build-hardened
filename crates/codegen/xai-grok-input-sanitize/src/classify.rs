//! Character classification into risk categories.

use crate::category::RiskCategory;
use crate::policy::{CategoryAction, SanitizePolicy};

/// Base allowlist: printable ASCII + LF (CR normalized before classify).
#[inline]
pub fn is_base_allowed(c: char) -> bool {
    matches!(c, '\n' | '\u{20}'..='\u{7E}')
}

/// Classify a non-base character. Order: specific buckets before generic letter/punct.
pub fn classify(c: char, policy: &SanitizePolicy) -> RiskCategory {
    let cp = c as u32;

    if c == '\t' {
        return RiskCategory::Tab;
    }

    if cp <= 0x1F || cp == 0x7F || (0x80..=0x9F).contains(&cp) {
        return RiskCategory::ControlC0C1;
    }

    if is_noncharacter(cp) {
        return RiskCategory::Noncharacters;
    }

    if is_private_use(cp) {
        return RiskCategory::PrivateUse;
    }

    if is_bidi_control(cp) {
        return RiskCategory::BidiControls;
    }

    if is_math_alphanumeric(cp) || is_fullwidth_latin(cp) {
        return RiskCategory::MathAlphanumeric;
    }

    if is_emoji_codepoint(cp)
        || cp == 0xFE0F
        || (cp == 0x200D && policy.action(RiskCategory::Emoji) == CategoryAction::Keep)
    {
        return RiskCategory::Emoji;
    }

    if is_zero_width_format(cp) {
        return RiskCategory::ZeroWidthFormat;
    }

    if is_math_symbol(cp) {
        return RiskCategory::MathSymbols;
    }

    if is_latin_extended(cp) || is_combining_mark_for_latin(cp) {
        return RiskCategory::LatinExtended;
    }

    if c.is_alphabetic() {
        return RiskCategory::UnicodeLetters;
    }

    RiskCategory::UnicodePunctuation
}

fn is_noncharacter(cp: u32) -> bool {
    (0xFDD0..=0xFDEF).contains(&cp) || (cp & 0xFFFE) == 0xFFFE
}

fn is_private_use(cp: u32) -> bool {
    (0xE000..=0xF8FF).contains(&cp)
        || (0xF0000..=0xFFFFD).contains(&cp)
        || (0x100000..=0x10FFFD).contains(&cp)
}

fn is_bidi_control(cp: u32) -> bool {
    matches!(
        cp,
        0x061C | 0x200E | 0x200F | 0x202A..=0x202E | 0x2066..=0x2069
    )
}

fn is_zero_width_format(cp: u32) -> bool {
    matches!(
        cp,
        0x00AD
            | 0x034F
            | 0x180E
            | 0x200B..=0x200D
            | 0x2028..=0x2029
            | 0x2060..=0x2064
            | 0x206A..=0x206F
            | 0xFEFF
            | 0xFFF9..=0xFFFB
            | 0xE0001
            | 0xE0020..=0xE007F
    )
}

fn is_math_alphanumeric(cp: u32) -> bool {
    (0x1D400..=0x1D7FF).contains(&cp)
}

fn is_fullwidth_latin(cp: u32) -> bool {
    (0xFF01..=0xFF5E).contains(&cp)
}

fn is_emoji_codepoint(cp: u32) -> bool {
    (0x1F300..=0x1FAFF).contains(&cp)
        || (0x1F1E6..=0x1F1FF).contains(&cp)
        || (0x2600..=0x27BF).contains(&cp)
        || (0x2300..=0x23FF).contains(&cp)
}

fn is_math_symbol(cp: u32) -> bool {
    (0x2200..=0x22FF).contains(&cp)
        || (0x27C0..=0x27EF).contains(&cp)
        || (0x2980..=0x29FF).contains(&cp)
        || (0x2A00..=0x2AFF).contains(&cp)
        || (0x2100..=0x214F).contains(&cp)
        || (0x2190..=0x21FF).contains(&cp)
}

fn is_latin_extended(cp: u32) -> bool {
    (0x00C0..=0x00D6).contains(&cp)
        || (0x00D8..=0x00F6).contains(&cp)
        || (0x00F8..=0x00FF).contains(&cp)
        || (0x0100..=0x017F).contains(&cp)
        || (0x0180..=0x024F).contains(&cp)
        || (0x1E00..=0x1EFF).contains(&cp)
        || (0x2C60..=0x2C7F).contains(&cp)
        || (0xA720..=0xA7FF).contains(&cp)
        || (0xAB30..=0xAB6F).contains(&cp)
}

fn is_combining_mark_for_latin(cp: u32) -> bool {
    (0x0300..=0x036F).contains(&cp)
}
