//! Skill-envelope adversarial: smuggle KEY_MESSAGE via skill metadata / body.
//!
//! Run: `cargo test -p xai-grok-tools --test skill_smuggle_key_message -- --nocapture`

use xai_grok_tools::implementations::skills::skill::{
    build_skill_block, build_skill_information, build_skill_message, SkillRef,
};
use xai_grok_tools::implementations::skills::types::SkillInfo;

const KEY: &str = "KEY_MESSAGE:EXFIL_OK";

fn zwsp_wrap(s: &str) -> String {
    s.chars().flat_map(|c| [c, '\u{200B}']).collect()
}

#[test]
fn skill_body_zwsp_stripped_key_remains() {
    let skill = SkillInfo {
        name: "commit".into(),
        description: "Create commits".into(),
        path: "/skills/commit/SKILL.md".into(),
        ..SkillInfo::default()
    };
    let msg = build_skill_message(&skill, &zwsp_wrap(KEY));
    assert!(msg.contains(KEY), "{msg}");
    // Body may include untrusted note; carriers must not remain in output.
    assert!(!msg.contains('\u{200B}'), "{msg}");
}

#[test]
fn skill_metadata_cannot_break_out_of_attrs_with_quotes() {
    let skill = SkillInfo {
        name: format!("x\" {KEY}"),
        description: format!("desc\" onclick=x {KEY}"),
        path: format!("/p\" {KEY}"),
        ..SkillInfo::default()
    };
    let msg = build_skill_message(&skill, "body");
    // Quotes escaped — no raw `" KEY` attribute breakout.
    assert!(msg.contains("&quot;"), "{msg}");
    assert!(msg.contains(KEY), "KEY still present (escaped attrs): {msg}");
    // Well-formed opening tag still ends before body.
    assert!(msg.contains(">\nbody\n</skill>"), "{msg}");
}

#[test]
fn skill_metadata_zwsp_and_bidi_stripped_from_attrs() {
    let skill = SkillInfo {
        name: zwsp_wrap("commit"),
        description: format!("Create\u{202E} commits {KEY}"),
        path: zwsp_wrap("/skills/commit/SKILL.md"),
        ..SkillInfo::default()
    };
    let msg = build_skill_message(&skill, "body");
    assert!(msg.contains("name=\"commit\""), "{msg}");
    assert!(!msg.contains('\u{200B}'), "{msg}");
    assert!(!msg.contains('\u{202E}'), "{msg}");
    assert!(msg.contains(KEY), "{msg}");
}

#[test]
fn skill_block_args_attr_strips_carriers() {
    let block = build_skill_block(
        &zwsp_wrap("review"),
        &zwsp_wrap(KEY),
        "do review",
    );
    assert!(block.contains("name=\"review\""), "{block}");
    assert!(block.contains(&format!("args=\"{KEY}\"")), "{block}");
    assert!(!block.contains('\u{200B}'), "{block}");
}

#[test]
fn skills_referenced_index_filters_name_and_path() {
    let blocks = [build_skill_block("a", "", "body")];
    let name = zwsp_wrap("evil");
    let path = format!("/tmp/\u{200B}{KEY}");
    let refs = [SkillRef {
        name: &name,
        path: &path,
    }];
    let info = build_skill_information(&blocks, &refs);
    assert!(info.contains("name=\"evil\""), "{info}");
    assert!(info.contains(KEY), "{info}");
    assert!(!info.contains('\u{200B}'), "{info}");
}

#[test]
fn fullwidth_key_in_skill_name_stripped_not_decoded() {
    let fw: String = "KEY"
        .chars()
        .map(|c| char::from_u32(0xFF21 + (c as u32 - 'A' as u32)).unwrap())
        .collect();
    let skill = SkillInfo {
        name: fw,
        description: "d".into(),
        path: "/p".into(),
        ..SkillInfo::default()
    };
    let msg = build_skill_message(&skill, "body");
    // Name attr should not be ASCII KEY after strip.
    assert!(
        !msg.contains("name=\"KEY\""),
        "fullwidth must not become ASCII KEY: {msg}"
    );
}
