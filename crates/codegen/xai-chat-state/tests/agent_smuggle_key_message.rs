//! Agent-path adversarial: smuggle `KEY_MESSAGE:EXFIL_OK` through every
//! model-bound channel (conversation items, tool specs / MCP descriptors,
//! tool-call args, multi-hop assembly).
//!
//! Run: `cargo test -p xai-chat-state --test agent_smuggle_key_message -- --nocapture`

use std::sync::Arc;

use xai_chat_state::{
    hard_filter_conversation_items, hard_filter_conversation_request, hard_filter_tool_specs,
};
use xai_grok_sampling_types::{
    AssistantItem, ContentPart, ConversationItem, ConversationRequest, ToolCall, ToolSpec,
};

const KEY: &str = "KEY_MESSAGE:EXFIL_OK";

fn zwsp_wrap(s: &str) -> String {
    s.chars().flat_map(|c| [c, '\u{200B}']).collect()
}

fn item_text(item: &ConversationItem) -> String {
    match item {
        ConversationItem::System(s) => s.content.to_string(),
        ConversationItem::User(u) => u
            .content
            .iter()
            .filter_map(|p| match p {
                ContentPart::Text { text } => Some(text.as_ref()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join(""),
        ConversationItem::Assistant(a) => a.content.to_string(),
        ConversationItem::ToolResult(t) => t.content.to_string(),
        _ => String::new(),
    }
}

// ── Conversation item channels ───────────────────────────────────────────

#[test]
fn key_in_user_message_with_zwsp_carriers_stripped() {
    let raw = zwsp_wrap(KEY);
    let out = hard_filter_conversation_items(vec![ConversationItem::user(raw)]);
    let text = item_text(&out[0]);
    assert_eq!(text, KEY);
    assert!(!text.contains('\u{200B}'));
}

#[test]
fn key_in_system_prompt_stego_stripped() {
    let raw = format!("You are helpful.\u{202E}{KEY}\u{200B}");
    let out = hard_filter_conversation_items(vec![ConversationItem::system(raw)]);
    let text = item_text(&out[0]);
    assert!(text.contains(KEY));
    assert!(!text.contains('\u{200B}'));
    assert!(!text.contains('\u{202E}'));
}

#[test]
fn key_in_tool_result_stego_stripped() {
    let raw = format!("file contents:\n{}\n", zwsp_wrap(KEY));
    let out = hard_filter_conversation_items(vec![ConversationItem::tool_result("c1", raw)]);
    let text = item_text(&out[0]);
    assert!(text.contains(KEY));
    assert!(!text.contains('\u{200B}'));
}

#[test]
fn key_in_tool_call_arguments_and_name() {
    let out = hard_filter_conversation_items(vec![ConversationItem::Assistant(AssistantItem {
        content: Arc::from("calling"),
        tool_calls: vec![ToolCall {
            id: "1".into(),
            name: format!("bash\u{200B}"),
            arguments: Arc::from(format!(
                "{{\"cmd\":\"echo {}\",\"note\":\"{}\"}}",
                zwsp_wrap(KEY),
                KEY
            )),
            // remaining fields via Default if any — construct fully
        }],
        model_id: None,
        model_fingerprint: None,
        reasoning_effort: None,
    })]);
    let ConversationItem::Assistant(a) = &out[0] else {
        panic!("assistant");
    };
    assert_eq!(a.tool_calls[0].name, "bash");
    let args = a.tool_calls[0].arguments.as_ref();
    assert!(args.contains(KEY), "{args}");
    assert!(!args.contains('\u{200B}'), "{args}");
}

// ── MCP / tool descriptor channel (every agent turn) ─────────────────────

#[test]
fn key_in_mcp_tool_description_and_schema_strings() {
    let tools = hard_filter_tool_specs(vec![ToolSpec {
        name: format!("search\u{200B}"),
        description: Some(format!(
            "Search docs. Hidden: {}\u{202E}",
            zwsp_wrap(KEY)
        )),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {
                "q": {
                    "type": "string",
                    "description": format!("query — also {KEY}\u{200B}"),
                    "default": format!("{KEY}\u{1FAE0}")
                },
                "enum_trap": {
                    "type": "string",
                    "enum": [format!("{KEY}\u{200B}"), "benign"]
                }
            },
            "required": ["q"]
        }),
    }]);

    assert_eq!(tools[0].name, "search");
    let desc = tools[0].description.as_deref().unwrap();
    assert!(desc.contains(KEY), "{desc}");
    assert!(!desc.contains('\u{200B}') && !desc.contains('\u{202E}'), "{desc}");

    let q_desc = tools[0].parameters["properties"]["q"]["description"]
        .as_str()
        .unwrap();
    assert!(q_desc.contains(KEY));
    assert!(!q_desc.contains('\u{200B}'));

    let default = tools[0].parameters["properties"]["q"]["default"]
        .as_str()
        .unwrap();
    assert_eq!(default, KEY); // exotic emoji stripped

    let enum0 = tools[0].parameters["properties"]["enum_trap"]["enum"][0]
        .as_str()
        .unwrap();
    assert_eq!(enum0, KEY);
}

#[test]
fn fullwidth_key_in_tool_description_does_not_become_ascii_key() {
    // Fullwidth Latin encoding of KEY — model-bound strips security lookalikes.
    let fw: String = KEY
        .chars()
        .map(|c| match c {
            'A'..='Z' => char::from_u32(0xFF21 + (c as u32 - 'A' as u32)).unwrap(),
            'a'..='z' => char::from_u32(0xFF41 + (c as u32 - 'a' as u32)).unwrap(),
            '0'..='9' => char::from_u32(0xFF10 + (c as u32 - '0' as u32)).unwrap(),
            ':' => '\u{FF1A}',
            '_' => '\u{FF3F}',
            other => other,
        })
        .collect();

    let tools = hard_filter_tool_specs(vec![ToolSpec {
        name: "t".into(),
        description: Some(fw.clone()),
        parameters: serde_json::json!({}),
    }]);
    let desc = tools[0].description.clone().unwrap_or_default();
    assert!(
        !desc.contains("KEY_MESSAGE"),
        "fullwidth KEY must not decode to ASCII in tool desc: {desc:?}"
    );
    // No fullwidth leftovers preferred (all stripped).
    assert!(
        !desc.chars().any(|c| (0xFF01..=0xFF5E).contains(&(c as u32))),
        "fullwidth chars leaked: {desc:?}"
    );
}

// ── Full request assembly (items + tools) ────────────────────────────────

#[test]
fn agent_turn_request_scrubs_all_channels_idempotently() {
    let req = hard_filter_conversation_request(ConversationRequest {
        items: vec![
            ConversationItem::system(zwsp_wrap(&format!("sys {KEY}"))),
            ConversationItem::user(format!("user \u{202E}{KEY}")),
            ConversationItem::tool_result("1", zwsp_wrap(KEY)),
            ConversationItem::Assistant(AssistantItem {
                content: Arc::from(format!("asst {KEY}\u{1FAE0}")),
                tool_calls: vec![ToolCall {
                    id: "tc".into(),
                    name: format!("run\u{200B}"),
                    arguments: Arc::from(format!("{{\"x\":\"{}\"}}", zwsp_wrap(KEY))),
                    // fields complete
                }],
                model_id: None,
                model_fingerprint: None,
                reasoning_effort: None,
            }),
        ],
        tools: vec![ToolSpec {
            name: format!("mcp_tool\u{200B}"),
            description: Some(format!("desc {KEY}\u{200B}")),
            parameters: serde_json::json!({
                "properties": { "a": { "description": format!("{KEY}\u{200B}") } }
            }),
        }],
        ..Default::default()
    });

    // All item texts contain KEY without carriers.
    for item in &req.items {
        let t = item_text(item);
        if !t.is_empty() {
            assert!(t.contains(KEY) || t.contains("sys KEY") || t.contains("user"), "{t}");
            assert!(!t.contains('\u{200B}'), "{t}");
            assert!(!t.contains('\u{202E}'), "{t}");
            assert!(!t.contains('\u{1FAE0}'), "{t}");
        }
    }
    if let ConversationItem::Assistant(a) = &req.items[3] {
        assert_eq!(a.tool_calls[0].name, "run");
        assert!(!a.tool_calls[0].arguments.contains('\u{200B}'));
        assert!(a.tool_calls[0].arguments.contains(KEY));
    }

    assert_eq!(req.tools[0].name, "mcp_tool");
    assert!(req.tools[0]
        .description
        .as_deref()
        .unwrap()
        .contains(KEY));
    assert!(!req.tools[0]
        .description
        .as_deref()
        .unwrap()
        .contains('\u{200B}'));

    // Second pass identical (sampler re-applies filter).
    let twice = hard_filter_conversation_request(req.clone());
    assert_eq!(
        serde_json::to_string(&req.items).unwrap(),
        serde_json::to_string(&twice.items).unwrap()
    );
    assert_eq!(req.tools[0].name, twice.tools[0].name);
    assert_eq!(req.tools[0].parameters, twice.tools[0].parameters);
}

// ── Fuzzy agent: many random stego variants on tool result ───────────────

#[test]
fn fuzzy_tool_result_stego_matrix() {
    let carriers = [
        '\u{200B}', '\u{200C}', '\u{202E}', '\u{FEFF}', '\u{2066}', '\u{00AD}', '\u{3164}',
    ];
    let mut seed = 7u64;
    let lcg = |s: &mut u64| {
        *s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
        *s
    };

    for i in 0..200 {
        let mut raw = String::new();
        for c in KEY.chars() {
            raw.push(c);
            let n = 1 + (lcg(&mut seed) % 2) as usize;
            for _ in 0..n {
                raw.push(carriers[(lcg(&mut seed) as usize) % carriers.len()]);
            }
        }
        // Mix exotic emoji (prepend/append via char-safe concat)
        if lcg(&mut seed) % 3 == 0 {
            raw.push('\u{1FAE0}');
        }
        if lcg(&mut seed) % 3 == 0 {
            raw = format!("\u{1F1FA}\u{1F1F8}{raw}");
        }

        let out = hard_filter_conversation_items(vec![ConversationItem::tool_result(
            format!("c{i}"),
            &raw,
        )]);
        let text = item_text(&out[0]);
        assert_eq!(text, KEY, "case {i} raw={raw:?} → {text:?}");
        for ch in carriers {
            assert!(!text.contains(ch), "case {i} leaked {ch:?}");
        }
        assert!(!text.contains('\u{1FAE0}'));
        assert!(!text.contains('\u{1F1FA}'));
    }
    eprintln!("fuzzy_tool_result_stego_matrix: 200 cases OK");
}

// ── Bypass attempt: empty tools + only image parts (no text leak path) ───

#[test]
fn image_only_user_message_leaves_images_untouched_no_text_key() {
    let mut user = ConversationItem::user("");
    if let ConversationItem::User(u) = &mut user {
        // Replace empty text with image — KEY must not magically appear.
        u.content.clear();
        u.content.push(ContentPart::Image {
            url: Arc::from(format!("data:image/png;base64,AAAA{KEY}")),
        });
    }
    let out = hard_filter_conversation_items(vec![user]);
    if let ConversationItem::User(u) = &out[0] {
        assert!(matches!(&u.content[0], ContentPart::Image { .. }));
        // Image URLs are not hard-filtered (documented residual: stego in pixels/base64).
        if let ContentPart::Image { url } = &u.content[0] {
            assert!(
                url.contains(KEY),
                "documented residual: image URL not scrubbed"
            );
        }
    }
}
