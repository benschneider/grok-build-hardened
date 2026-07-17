//! `/input-filter` — open the Input filter menu (settings UI, pre-filtered).
//!
//! Same controls live under `/settings` → Editor & Input.
//!
//! Optional args:
//! - profile name (`strict` / `balanced` / `multilingual`) — apply without opening UI
//! - `status` — print the current policy summary
//!
//! Aliases: `/input-allow`, `/input-sanitize`, `/sanitize`, `/input-deny`.

use crate::app::actions::Action;
use crate::slash::command::{AppCtx, ArgItem, CommandExecCtx, CommandResult, SlashCommand};

/// Filter query for the settings modal — matches the Input filter profile
/// and Input sanitizer rows under Editor & Input.
const SETTINGS_FILTER: &str = "input filter";

fn open_menu() -> CommandResult {
    CommandResult::Action(Action::OpenSettingsFiltered {
        query: SETTINGS_FILTER.into(),
    })
}

/// `/input-filter` [profile|status]
pub struct InputAllowCommand;

impl SlashCommand for InputAllowCommand {
    fn name(&self) -> &str {
        "input-filter"
    }

    fn description(&self) -> &str {
        "Open the input filter menu (profiles and character allows)"
    }

    fn usage(&self) -> &str {
        "/input-filter [strict|balanced|multilingual|status]"
    }

    fn takes_args(&self) -> bool {
        true
    }

    fn args_required(&self) -> bool {
        false
    }

    fn arg_placeholder(&self) -> Option<&str> {
        Some("[profile]")
    }

    fn aliases(&self) -> &[&str] {
        &["input-allow", "input-sanitize", "sanitize"]
    }

    fn suggest_args(&self, _ctx: &AppCtx, _args_query: &str) -> Option<Vec<ArgItem>> {
        Some(vec![
            ArgItem {
                display: "Open menu…".into(),
                match_text: "open menu ui settings".into(),
                insert_text: "".into(),
                description: "Open the input filter menu (same as /settings → Input filter)"
                    .into(),
            },
            ArgItem {
                display: "strict".into(),
                match_text: "strict ascii".into(),
                insert_text: "strict".into(),
                description: "ASCII only (max filter)".into(),
            },
            ArgItem {
                display: "balanced".into(),
                match_text: "balanced recommended".into(),
                insert_text: "balanced".into(),
                description: "Accents, emoji, math, tabs (default)".into(),
            },
            ArgItem {
                display: "multilingual".into(),
                match_text: "multilingual i18n languages".into(),
                insert_text: "multilingual".into(),
                description: "Balanced + non-English scripts".into(),
            },
            ArgItem {
                display: "status".into(),
                match_text: "status show policy".into(),
                insert_text: "status".into(),
                description: "Print current policy summary".into(),
            },
        ])
    }

    fn run(&self, _ctx: &mut CommandExecCtx, args: &str) -> CommandResult {
        let args = args.trim();
        if args.is_empty() {
            return open_menu();
        }
        if args.eq_ignore_ascii_case("status") || args.eq_ignore_ascii_case("show") {
            return CommandResult::Action(Action::InputSanitizeStatus);
        }
        if args.eq_ignore_ascii_case("ui")
            || args.eq_ignore_ascii_case("settings")
            || args.eq_ignore_ascii_case("open")
            || args.eq_ignore_ascii_case("menu")
        {
            return open_menu();
        }
        // Named profile shortcut (apply immediately, no modal).
        if let Some(profile) = xai_grok_input_sanitize::SanitizeProfile::parse(args) {
            return CommandResult::Action(Action::SetInputSanitizeProfile(
                profile.as_str().to_string(),
            ));
        }
        // Unknown / legacy CLI flags → open the menu (no cryptic errors).
        open_menu()
    }
}

/// `/input-deny` — same menu (turn allows off with the toggles there).
pub struct InputDenyCommand;

impl SlashCommand for InputDenyCommand {
    fn name(&self) -> &str {
        "input-deny"
    }

    fn description(&self) -> &str {
        "Open the input filter menu (turn off allows there)"
    }

    fn usage(&self) -> &str {
        "/input-deny"
    }

    fn run(&self, _ctx: &mut CommandExecCtx, _args: &str) -> CommandResult {
        open_menu()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acp::model_state::ModelState;

    static DEFAULT_BUNDLE_STATE: crate::app::bundle::BundleState =
        crate::app::bundle::BundleState {
            has_cache: false,
            version: String::new(),
            personas: Vec::new(),
            roles: Vec::new(),
            agents: Vec::new(),
            skills: Vec::new(),
            persona_details: Vec::new(),
            role_details: Vec::new(),
        };

    fn make_ctx<'a>(models: &'a ModelState) -> CommandExecCtx<'a> {
        CommandExecCtx {
            models,
            session_id: None,
            bundle_state: &DEFAULT_BUNDLE_STATE,
            screen_mode: crate::app::ScreenMode::Inline,
            pager_state: crate::settings::PagerLocalSnapshot::default(),
        }
    }

    #[test]
    fn empty_opens_settings_filtered() {
        let models = ModelState::default();
        let mut ctx = make_ctx(&models);
        let r = InputAllowCommand.run(&mut ctx, "");
        match r {
            CommandResult::Action(Action::OpenSettingsFiltered { query }) => {
                assert_eq!(query, SETTINGS_FILTER);
            }
            other => panic!("expected OpenSettingsFiltered, got {other:?}"),
        }
    }

    #[test]
    fn command_name_is_input_filter() {
        assert_eq!(InputAllowCommand.name(), "input-filter");
        assert!(InputAllowCommand.aliases().contains(&"input-allow"));
    }

    #[test]
    fn balanced_sets_profile() {
        let models = ModelState::default();
        let mut ctx = make_ctx(&models);
        let r = InputAllowCommand.run(&mut ctx, "balanced");
        match r {
            CommandResult::Action(Action::SetInputSanitizeProfile(p)) => {
                assert_eq!(p, "balanced");
            }
            other => panic!("expected SetInputSanitizeProfile, got {other:?}"),
        }
    }

    #[test]
    fn status_shows_policy() {
        let models = ModelState::default();
        let mut ctx = make_ctx(&models);
        assert!(matches!(
            InputAllowCommand.run(&mut ctx, "status"),
            CommandResult::Action(Action::InputSanitizeStatus)
        ));
    }

    #[test]
    fn deny_opens_menu() {
        let models = ModelState::default();
        let mut ctx = make_ctx(&models);
        assert!(matches!(
            InputDenyCommand.run(&mut ctx, "emoji"),
            CommandResult::Action(Action::OpenSettingsFiltered { .. })
        ));
    }

    #[test]
    fn legacy_flags_open_menu_not_error() {
        let models = ModelState::default();
        let mut ctx = make_ctx(&models);
        assert!(matches!(
            InputAllowCommand.run(&mut ctx, "latin_extended --user"),
            CommandResult::Action(Action::OpenSettingsFiltered { .. })
        ));
    }
}
