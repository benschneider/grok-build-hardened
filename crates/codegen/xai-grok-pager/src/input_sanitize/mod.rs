//! Pager adapter for `xai-grok-input-sanitize`.
//!
//! Keeps AgentView / dispatch free of classification logic:
//! - [`session`] — per-agent policy overlay + last raw/result
//! - [`apply`] — sanitize helpers for paste vs send
//! - [`persist`] — load/write `[input_sanitize]` in config.toml

mod apply;
mod persist;
mod session;

pub use apply::{ApplyKind, AppliedInput};
pub use persist::{load_policy, persist_allow, persist_deny};
pub use session::InputSanitizeSession;
