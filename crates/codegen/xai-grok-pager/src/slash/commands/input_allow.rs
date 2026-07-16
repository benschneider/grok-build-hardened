//! `/input-allow`, `/input-deny`, `/input-sanitize` — category switch table for
//! the hardened ASCII-keyboard input filter.

use xai_grok_input_sanitize::RiskCategory;

use crate::app::actions::Action;
use crate::slash::command::{CommandExecCtx, CommandResult, SlashCommand};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    Session,
    User,
    Project,
}

impl Scope {
    fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "--session" | "session" => Some(Self::Session),
            "--user" | "user" => Some(Self::User),
            "--project" | "project" => Some(Self::Project),
            _ => None,
        }
    }
}

/// `/input-allow <category>[,category...] [--session|--user|--project]`
pub struct InputAllowCommand;

impl SlashCommand for InputAllowCommand {
    fn name(&self) -> &str {
        "input-allow"
    }

    fn description(&self) -> &str {
        "Allow extra input character categories (latin, emoji, …) for this session or config"
    }

    fn usage(&self) -> &str {
        "/input-allow <category>[,…] [--session|--user|--project] | /input-allow status"
    }

    fn takes_args(&self) -> bool {
        true
    }

    fn aliases(&self) -> &[&str] {
        &["input-sanitize"]
    }

    fn run(&self, _ctx: &mut CommandExecCtx, args: &str) -> CommandResult {
        let args = args.trim();
        if args.is_empty() || args.eq_ignore_ascii_case("status") {
            return CommandResult::Action(Action::InputSanitizeStatus);
        }
        match parse_allow_args(args) {
            Ok((cats, scope)) => CommandResult::Action(Action::InputSanitizeAllow {
                categories: cats.iter().map(|c| c.as_str().to_string()).collect(),
                session_only: matches!(scope, Scope::Session),
                user_config: matches!(scope, Scope::User),
                project_config: matches!(scope, Scope::Project),
            }),
            Err(msg) => CommandResult::Error(msg),
        }
    }
}

/// `/input-deny <category>[,…] [--session]`
pub struct InputDenyCommand;

impl SlashCommand for InputDenyCommand {
    fn name(&self) -> &str {
        "input-deny"
    }

    fn description(&self) -> &str {
        "Revoke allowed input categories (back to strip)"
    }

    fn usage(&self) -> &str {
        "/input-deny <category>[,…] [--session]"
    }

    fn takes_args(&self) -> bool {
        true
    }

    fn run(&self, _ctx: &mut CommandExecCtx, args: &str) -> CommandResult {
        let args = args.trim();
        if args.is_empty() {
            return CommandResult::Error(
                "Usage: /input-deny <category>[,…] [--session]".into(),
            );
        }
        match parse_allow_args(args) {
            Ok((cats, _scope)) => CommandResult::Action(Action::InputSanitizeDeny {
                categories: cats.iter().map(|c| c.as_str().to_string()).collect(),
            }),
            Err(msg) => CommandResult::Error(msg),
        }
    }
}

fn parse_allow_args(args: &str) -> Result<(Vec<RiskCategory>, Scope), String> {
    let mut scope = Scope::Session;
    let mut cats = Vec::new();
    for tok in args.split_whitespace() {
        if let Some(s) = Scope::parse(tok) {
            scope = s;
            continue;
        }
        for part in tok.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let Some(cat) = RiskCategory::parse(part) else {
                return Err(format!(
                    "Unknown category `{part}`. Try: latin_extended, unicode_letters, emoji, tab, math_symbols, …"
                ));
            };
            if !cat.allow_user_keep() {
                return Err(format!(
                    "Category `{}` is security-sensitive and cannot be enabled.",
                    cat.as_str()
                ));
            }
            cats.push(cat);
        }
    }
    if cats.is_empty() {
        return Err("Specify at least one category (e.g. latin_extended).".into());
    }
    Ok((cats, scope))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_session_latin() {
        let (cats, scope) = parse_allow_args("latin_extended --session").unwrap();
        assert_eq!(cats, vec![RiskCategory::LatinExtended]);
        assert_eq!(scope, Scope::Session);
    }

    #[test]
    fn rejects_bidi() {
        assert!(parse_allow_args("bidi_controls").is_err());
    }
}
