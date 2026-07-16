//! Pager adapter for `xai-grok-input-sanitize`.
//!
//! Keeps AgentView / dispatch free of classification logic:
//! - [`session`] — per-agent policy overlay + last raw/result
//! - [`apply`] — sanitize helpers for paste vs send

mod apply;
mod session;

pub use apply::{ApplyKind, AppliedInput};
pub use session::InputSanitizeSession;
