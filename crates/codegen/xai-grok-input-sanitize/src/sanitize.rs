//! Core sanitize pass + analysis attachment.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::analyze::{analyze, AnalysisReport};
use crate::category::{RiskCategory, Severity};
use crate::classify::{classify, is_base_allowed};
use crate::policy::{CategoryAction, SanitizePolicy};

/// One category that contributed stripped/rejected characters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CategoryHit {
    pub category: RiskCategory,
    pub severity: Severity,
    pub count: usize,
    pub action: CategoryAction,
}

/// Outcome of a successful sanitize.
#[derive(Debug, Clone, PartialEq)]
pub struct SanitizeResult {
    pub text: String,
    pub hits: Vec<CategoryHit>,
    pub original_len: usize,
    pub cleaned_len: usize,
    /// Statistical / steganographic residual-risk report (on raw + cleaned).
    pub analysis: AnalysisReport,
}

impl SanitizeResult {
    pub fn was_modified(&self) -> bool {
        !self.hits.is_empty() || self.original_len != self.cleaned_len
    }

    pub fn has_security_hits(&self) -> bool {
        self.hits
            .iter()
            .any(|h| h.severity == Severity::Security && h.count > 0)
    }

    pub fn has_capability_hits(&self) -> bool {
        self.hits
            .iter()
            .any(|h| h.severity == Severity::Capability && h.count > 0)
    }

    /// Categories that were stripped (not kept).
    pub fn stripped_hits(&self) -> impl Iterator<Item = &CategoryHit> {
        self.hits
            .iter()
            .filter(|h| h.action != CategoryAction::Keep && h.count > 0)
    }

    /// Whether the model should receive an `<input_sanitize>` note.
    pub fn needs_model_note(&self) -> bool {
        self.stripped_hits().next().is_some() || self.analysis.should_warn()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SanitizeError {
    #[error(
        "input rejected: category `{category}` ({count} character(s)) is set to reject"
    )]
    Rejected {
        category: RiskCategory,
        count: usize,
    },
}

/// Sanitize `input` under `policy`, then analyze residual injection risk.
pub fn sanitize(input: &str, policy: &SanitizePolicy) -> Result<SanitizeResult, SanitizeError> {
    let original_len = input.chars().count();

    if !policy.enabled {
        return Ok(SanitizeResult {
            text: input.to_owned(),
            hits: Vec::new(),
            original_len,
            cleaned_len: original_len,
            analysis: AnalysisReport::empty(),
        });
    }

    let mut out = String::with_capacity(input.len());
    let mut counts: BTreeMap<RiskCategory, usize> = BTreeMap::new();
    let mut reject: Option<(RiskCategory, usize)> = None;

    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            out.push('\n');
            continue;
        }

        if is_base_allowed(c) {
            out.push(c);
            continue;
        }

        let cat = classify(c, policy);
        let action = policy.action(cat);
        *counts.entry(cat).or_insert(0) += 1;

        match action {
            CategoryAction::Keep => out.push(c),
            CategoryAction::Strip => {}
            CategoryAction::Reject => {
                let n = counts.get(&cat).copied().unwrap_or(1);
                reject = Some(match reject {
                    Some((r, n0)) if r == cat => (r, n0.max(n)),
                    Some(other) => other,
                    None => (cat, n),
                });
            }
        }
    }

    if let Some((category, count)) = reject {
        let count = counts.get(&category).copied().unwrap_or(count);
        return Err(SanitizeError::Rejected { category, count });
    }

    let hits: Vec<CategoryHit> = counts
        .into_iter()
        .filter(|(_, n)| *n > 0)
        .map(|(category, count)| CategoryHit {
            severity: category.severity(),
            action: policy.action(category),
            category,
            count,
        })
        .collect();

    let cleaned_len = out.chars().count();
    let analysis = analyze(input, &out, &hits, policy);

    Ok(SanitizeResult {
        text: out,
        hits,
        original_len,
        cleaned_len,
        analysis,
    })
}

/// Clean text for the model: cleaned body + structured note when warranted.
pub fn model_payload(result: &SanitizeResult) -> String {
    model_payload_with_body(result, &result.text)
}

/// Model payload using `report` for the note and `body` as authoritative text.
///
/// Used when paste already stripped characters (Ui) and submit re-sanitizes
/// clean composer text — the note must still warn about the original hits /
/// analysis.
pub fn model_payload_with_body(report: &SanitizeResult, body: &str) -> String {
    if !report.needs_model_note() {
        return body.to_owned();
    }
    format!("{}\n\n{}", crate::note::format_model_note(report), body)
}

/// Short TUI toast for security strip hits and/or elevated analysis.
pub fn security_toast(result: &SanitizeResult) -> Option<String> {
    let mut parts = Vec::new();

    if result.has_security_hits() {
        let n: usize = result
            .hits
            .iter()
            .filter(|h| h.severity == Severity::Security)
            .map(|h| h.count)
            .sum();
        parts.push(format!(
            "Removed {n} invisible/deceptive character(s)"
        ));
    }

    if result.analysis.should_warn() {
        parts.push(format!(
            "injection-risk analysis {} (score {})",
            result.analysis.level.as_str(),
            result.analysis.score
        ));
    }

    if parts.is_empty() {
        return None;
    }
    Some(format!("{} — review cleaned prompt carefully.", parts.join("; ")))
}
