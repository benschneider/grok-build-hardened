//! Session-scoped input sanitize state (policy overlay + last report).

use xai_grok_input_sanitize::{
    CategoryAction, PolicyError, RiskCategory, SanitizePolicy, SanitizeResult,
};

/// Per-agent state: base policy, session keeps, last raw submit, last result.
#[derive(Debug, Clone)]
pub struct InputSanitizeSession {
    base: SanitizePolicy,
    /// Categories kept for this session only (capability).
    session_keeps: Vec<RiskCategory>,
    pub last_raw: Option<String>,
    pub last_result: Option<SanitizeResult>,
    /// Strip report from paste/Ui that still needs a model note on the next
    /// Send (composer is already clean, so re-sanitize alone would drop it).
    /// Cleared only after a successful model-facing send via
    /// [`Self::clear_pending_strip_report`].
    pending_strip_report: Option<SanitizeResult>,
}

impl Default for InputSanitizeSession {
    fn default() -> Self {
        Self::new(SanitizePolicy::default())
    }
}

impl InputSanitizeSession {
    pub fn new(base: SanitizePolicy) -> Self {
        Self {
            base,
            session_keeps: Vec::new(),
            last_raw: None,
            last_result: None,
            pending_strip_report: None,
        }
    }

    /// Effective policy = base + session keeps.
    pub fn policy(&self) -> SanitizePolicy {
        let mut p = self.base.clone();
        for &cat in &self.session_keeps {
            let _ = p.allow_keep(cat);
        }
        p
    }

    pub fn set_base(&mut self, base: SanitizePolicy) {
        self.base = base;
    }

    pub fn allow_session(&mut self, cat: RiskCategory) -> Result<(), PolicyError> {
        if !cat.allow_user_keep() {
            return Err(PolicyError::SecurityKeepForbidden(cat));
        }
        if !self.session_keeps.contains(&cat) {
            self.session_keeps.push(cat);
        }
        Ok(())
    }

    pub fn deny_session(&mut self, cat: RiskCategory) {
        self.session_keeps.retain(|&c| c != cat);
        self.base.deny_keep(cat);
    }

    pub fn record(&mut self, raw: String, result: SanitizeResult) {
        self.last_raw = Some(raw);
        self.last_result = Some(result);
    }

    /// Remember a Ui report so the next Send can still attach a model note
    /// (strip hits and/or elevated residual-risk analysis).
    pub fn note_ui_strip(&mut self, result: &SanitizeResult) {
        if result.needs_model_note() {
            self.pending_strip_report = Some(result.clone());
        }
    }

    /// Borrow pending paste/Ui strip report (does not clear).
    pub fn pending_strip_report(&self) -> Option<&SanitizeResult> {
        self.pending_strip_report.as_ref()
    }

    /// Clear pending after a successful model-facing send.
    pub fn clear_pending_strip_report(&mut self) {
        self.pending_strip_report = None;
    }

    pub fn status_text(&self) -> String {
        let p = self.policy();
        let mut lines = vec![
            format!("input_sanitize enabled={}", p.enabled),
            format!("notify_when_stripped={}", p.notify_when_stripped),
            "categories:".into(),
        ];
        for (cat, action) in p.actions_iter() {
            let scope = if self.session_keeps.contains(&cat) && action == CategoryAction::Keep {
                " (session)"
            } else {
                ""
            };
            lines.push(format!("  {} = {}{scope}", cat.as_str(), action.as_str()));
        }
        if self.pending_strip_report.is_some() {
            lines.push("pending_model_note: yes (from paste/Ui strip or analysis)".into());
        }
        if let Some(ref r) = self.last_result {
            lines.push(format!(
                "last: {} → {} chars, {} categories flagged, analysis={}({})",
                r.original_len,
                r.cleaned_len,
                r.hits.len(),
                r.analysis.level.as_str(),
                r.analysis.score
            ));
        }
        lines.join("\n")
    }
}
