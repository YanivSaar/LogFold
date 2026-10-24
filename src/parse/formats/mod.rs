//! Base parsers (syslog RFC 3164/5424, JSON, KV, CEF, LEEF).
//!
//! Bundles can opt in via `[parse] format = "..."`. Supported values:
//!
//! * `"raw"` (default) - tokenise the whole line.
//! * `"syslog"` - strip the RFC 3164 / 5424 envelope and tokenise only
//!   the free-form `msg` body. v0.2.
//! * `"json"` - parse the line as a JSON object and tokenise the
//!   `msg` / `message` / `event` field. v0.4.
//! * `"kv"` - parse `key=value` pairs (logfmt / syslog-ng) and
//!   tokenise the recognised message key. v0.4.
//! * `"cef"` - ArcSight CEF; use the `Name` field as the fold key. v0.4.
//! * `"leef"` - IBM LEEF; use the EventID as the fold key. v0.4.
//!
//! Each parser lives in its own submodule and returns a borrowed view
//! of the input, so the fold hot path stays allocation-free.

pub mod cef;
pub mod json;
pub mod kv;
pub mod leef;
pub mod modsec_v3;
pub mod syslog;
