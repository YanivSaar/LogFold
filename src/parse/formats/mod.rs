//! Base parsers (syslog RFC 3164/5424, CLF, JSON, KV, CEF, LEEF, W3C).
//!
//! Bundles can opt in via `[parse] format = "..."`. Supported values:
//!
//! * `"raw"` (default) — tokenise the whole line.
//! * `"syslog"` — strip the RFC 3164 / 5424 envelope and tokenise only
//!   the free-form `msg` body. Added in v0.2.
//!
//! Each parser lives in its own submodule and returns a borrowed view
//! of the input, so the fold hot path stays allocation-free.

pub mod syslog;
