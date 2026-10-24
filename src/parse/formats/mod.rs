//! Base parsers (syslog RFC 3164/5424, CLF, JSON, KV, CEF, LEEF, W3C).
//!
//! P1 is format-agnostic: the tokenizer runs over the raw line. Format-aware
//! parsing arrives in P2 together with the bundle loader so each bundle can
//! name its `format = "..."` and skip the generic path.
