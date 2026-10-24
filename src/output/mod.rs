//! Output sinks: plain-text, JSON, learned-bundle export, webhook.
//! Prometheus arrives in v0.10.

pub mod json;
pub mod learn;
pub mod text;

#[cfg(feature = "webhook")]
pub mod webhook;
