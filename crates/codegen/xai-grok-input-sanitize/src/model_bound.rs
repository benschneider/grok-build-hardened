//! Last-hop hard filter for **model-bound** payloads.
//!
//! Applied when assembling the request that goes to the sampling API.
//! Silent strip — no analysis notes (notes cost tokens).
//!
//! # What is hard-stripped
//!
//! - **Security Unicode** — invisibles, bidi, lookalikes, controls, fillers
//! - **Exotic emoji / token-stuffing chrome** — not every smiley:
//!   flags (regional indicators), skin-tone modifiers, VS-16, keycap marks,
//!   supplemental pictographs (U+1F900–1FAFF), mahjong/cards, etc.
//!
//! Basic faces/symbols (e.g. 😀 👍 ✅) are kept so normal conversation still works.

use crate::policy::SanitizePolicy;
use crate::sanitize::sanitize;

/// Hard-filter text for the model API: strip security Unicode + exotic emoji.
///
/// Always returns a string; never fails open to the original when sanitize
/// errors (reject is not used by [`SanitizePolicy::model_bound`]).
pub fn hard_filter_model_text(input: &str) -> String {
    let base = match sanitize(input, &SanitizePolicy::model_bound()) {
        Ok(r) => r.text,
        Err(_) => input
            .chars()
            .filter(|&c| {
                matches!(c, '\n' | '\t' | '\u{20}'..='\u{7E}')
                    || (c.is_alphabetic() && !is_exotic_emoji(c))
            })
            .collect(),
    };
    // Second pass: drop exotic emoji that the capability keep would otherwise preserve.
    base.chars().filter(|&c| !is_exotic_emoji(c)).collect()
}

/// Token-heavy / sequence / stuffing-prone emoji and emoji chrome.
///
/// Intentionally **does not** include basic faces (U+1F600–1F64F), common
/// pictographs (U+1F300–1F5FF), transport (U+1F680–1F6FF), or BMP dingbats.
pub fn is_exotic_emoji(c: char) -> bool {
    let cp = c as u32;
    matches!(
        cp,
        // ZWJ — joins multi-person/profession sequences (token-heavy); when
        // emoji is kept, classify treats ZWJ as Emoji so we must strip here.
        0x200D
            // Emoji presentation selector (multi-unit glyphs)
            | 0xFE0F
            // Skin-tone modifiers
            | 0x1F3FB..=0x1F3FF
            // Regional indicators (flag pairs — classic stuffing)
            | 0x1F1E6..=0x1F1FF
            // Combining enclosing keycap
            | 0x20E3
            // Mahjong / domino / playing cards
            | 0x1F000..=0x1F02F
            | 0x1F030..=0x1F09F
            | 0x1F0A0..=0x1F0FF
            // Supplemental Symbols and Pictographs + extended-A
            // (newer emoji; frequent in stuffing dumps)
            | 0x1F900..=0x1FAFF
            // Alchemical symbols
            | 0x1F700..=0x1F77F
            // Geometric shapes extended / ornamental dingbats (often spam)
            | 0x1F780..=0x1F7FF
            | 0x1F650..=0x1F67F
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_zwsp_and_bidi() {
        let s = "hello\u{200B} world\u{202E}";
        let out = hard_filter_model_text(s);
        assert_eq!(out, "hello world");
    }

    #[test]
    fn keeps_basic_emoji() {
        // Faces + common pictographs stay.
        let s = "hi 😀 👍 ✅ 🎉";
        let out = hard_filter_model_text(s);
        assert!(out.contains('😀'), "{out}");
        assert!(out.contains('👍'), "{out}");
        assert!(out.contains('✅'), "{out}");
        assert!(out.contains('🎉'), "{out}");
    }

    #[test]
    fn strips_exotic_flags_skin_supplemental() {
        // Flag (regional indicators), skin tone, supplemental (🫠 U+1FAE0)
        let s = "x \u{1F1FA}\u{1F1F8} \u{1F44D}\u{1F3FD} \u{1FAE0} y";
        let out = hard_filter_model_text(s);
        assert!(out.contains('x') && out.contains('y'), "{out}");
        // Regional indicators gone
        assert!(!out.contains('\u{1F1FA}'));
        assert!(!out.contains('\u{1F1F8}'));
        // Skin tone gone; base thumbs-up may remain
        assert!(!out.contains('\u{1F3FD}'));
        // Supplemental melting face gone
        assert!(!out.contains('\u{1FAE0}'));
    }

    #[test]
    fn strips_vs16_and_zwj_chrome() {
        // ZWJ is security-stripped; VS-16 is exotic chrome.
        let s = "a\u{FE0F}b\u{200D}c";
        let out = hard_filter_model_text(s);
        assert_eq!(out, "abc");
    }

    #[test]
    fn keeps_cjk_and_code() {
        let s = "fn main() { /* 日本語 */ }";
        assert_eq!(hard_filter_model_text(s), s);
    }

    #[test]
    fn silent_no_note_wrapper() {
        let out = hard_filter_model_text("a\u{200B}b 😀");
        assert!(!out.contains('<'), "egress filter must not wrap notes: {out}");
        assert_eq!(out, "ab 😀");
    }
}
