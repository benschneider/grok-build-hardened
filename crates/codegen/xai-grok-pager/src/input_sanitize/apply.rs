//! Apply sanitize policy to inbound text (paste vs send).

use xai_grok_input_sanitize::{model_payload, sanitize, security_toast, SanitizeError, SanitizeResult};

use super::session::InputSanitizeSession;

/// Whether this apply is for the composer UI or the model-facing payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyKind {
    /// Clean text for the prompt buffer (user sees this).
    Ui,
    /// Clean text + optional model note for the agent.
    Send,
}

/// Result of applying input sanitize at an ingress point.
#[derive(Debug, Clone)]
pub struct AppliedInput {
    /// Text for UI / scrollback (always cleaned, no model note).
    pub display_text: String,
    /// Text to send to the model (may include `<input_sanitize>` note).
    pub model_text: String,
    pub result: SanitizeResult,
    pub toast: Option<String>,
}

impl AppliedInput {
    /// Apply session policy to `raw`. Records last raw/result on success.
    pub fn apply(
        session: &mut InputSanitizeSession,
        raw: &str,
        kind: ApplyKind,
    ) -> Result<Self, SanitizeError> {
        let policy = session.policy();
        let result = sanitize(raw, &policy)?;
        let toast = if policy.notify_when_stripped {
            security_toast(&result)
        } else {
            None
        };
        let display_text = result.text.clone();
        let model_text = match kind {
            ApplyKind::Ui => display_text.clone(),
            ApplyKind::Send => model_payload(&result),
        };
        session.record(raw.to_owned(), result.clone());
        Ok(Self {
            display_text,
            model_text,
            result,
            toast,
        })
    }
}
