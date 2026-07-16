//! Apply sanitize policy to inbound text (paste vs send).

use xai_grok_input_sanitize::{
    model_payload, model_payload_with_body, sanitize, security_toast, SanitizeError, SanitizeResult,
};

use super::session::InputSanitizeSession;

/// Whether this apply is for the composer UI or the model-facing payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyKind {
    /// Clean text for the prompt buffer (user sees this).
    ///
    /// Records a pending strip report so a later [`ApplyKind::Send`] can still
    /// attach a model note after the composer is already clean.
    Ui,
    /// Clean text only (no model note, no pending mutation). For bash / shell.
    Strip,
    /// Clean text + optional model note for the agent.
    ///
    /// Does **not** clear pending strip reports — call
    /// [`InputSanitizeSession::clear_pending_strip_report`] after the send
    /// actually enqueues so deferred paths (project picker) keep the note.
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
    /// True when model_text used a pending paste note or a fresh strip note.
    pub attached_model_note: bool,
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
        let (model_text, attached_model_note) = match kind {
            ApplyKind::Ui => {
                session.note_ui_strip(&result);
                (display_text.clone(), false)
            }
            ApplyKind::Strip => (display_text.clone(), false),
            ApplyKind::Send => {
                if result.needs_model_note() {
                    (model_payload(&result), true)
                } else if let Some(pending) = session.pending_strip_report() {
                    // Paste-time strip/analysis note on already-clean composer text.
                    (model_payload_with_body(pending, &result.text), true)
                } else {
                    (result.text.clone(), false)
                }
            }
        };
        session.record(raw.to_owned(), result.clone());
        Ok(Self {
            display_text,
            model_text,
            result,
            toast,
            attached_model_note,
        })
    }
}
