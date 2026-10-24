//! Multiline event assembler.
//!
//! Two modes:
//!
//! * **Heuristic** (default) — a line is treated as a *continuation* of
//!   the previous event if it starts with whitespace or matches a known
//!   stack-trace prefix (`at `, `Caused by:`, `...`). A fresh first-line
//!   flushes the pending event.
//!
//! * **Section-delimited** — one event spans from a `start` marker line
//!   to an `end` marker line (both inclusive). Used for formats whose
//!   "event" is a multi-section document delimited by boundary strings,
//!   notably ModSecurity audit logs where each entry runs from an
//!   `-- <uniqueid>-A --` marker to a `-- <uniqueid>-Z --` marker.
//!
//! A 500 ms idle timeout flushes a pending event in either mode so a
//! live tail doesn't wedge the last entry.

use std::time::{Duration, Instant};

use regex::Regex;

/// Timeout after which the pending event is flushed even without a
/// terminating first-line.
pub const FLUSH_AFTER: Duration = Duration::from_millis(500);

/// How the assembler decides event boundaries.
#[derive(Default)]
pub enum Mode {
    /// Heuristic continuation rules (whitespace / `at ` / `Caused by:`).
    #[default]
    Heuristic,
    /// Boundary lines mark event start / end.
    SectionDelimited {
        start_marker: Regex,
        end_marker: Regex,
    },
}

#[derive(Default)]
pub struct Assembler {
    pending: String,
    started_at: Option<Instant>,
    mode: Mode,
    in_section: bool,
}

impl Assembler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_mode(mode: Mode) -> Self {
        Assembler {
            mode,
            ..Self::default()
        }
    }

    /// Build a section-delimited assembler for ModSecurity-style audit
    /// logs. `start_pattern` opens a new event, `end_pattern` closes
    /// (and flushes) it; both lines are included in the emitted event.
    pub fn modsec_sections() -> Self {
        // `-- <uniqueid>-A --` opens, `-- <uniqueid>-Z --` closes.
        // The id is 8-32 chars of alphanumeric; be permissive on padding
        // whitespace around the dashes.
        let start = Regex::new(r"^-{2,}\s*[A-Za-z0-9@._-]+-A-{2,}\s*$").expect("valid regex");
        let end = Regex::new(r"^-{2,}\s*[A-Za-z0-9@._-]+-Z-{2,}\s*$").expect("valid regex");
        Assembler::with_mode(Mode::SectionDelimited {
            start_marker: start,
            end_marker: end,
        })
    }

    /// Feed one raw line. Returns `Some(event)` when a prior event has
    /// been fully assembled; `None` while still collecting.
    pub fn push(&mut self, line: &str) -> Option<String> {
        match &self.mode {
            Mode::Heuristic => self.push_heuristic(line),
            Mode::SectionDelimited { .. } => self.push_section(line),
        }
    }

    fn push_heuristic(&mut self, line: &str) -> Option<String> {
        if is_continuation(line) && self.started_at.is_some() {
            self.pending.push('\n');
            self.pending.push_str(line);
            None
        } else {
            let flushed = self.take();
            self.pending.push_str(line);
            self.started_at = Some(Instant::now());
            flushed
        }
    }

    fn push_section(&mut self, line: &str) -> Option<String> {
        // We can't borrow self.mode and self.pending mutably at the same
        // time, so extract match outcomes first.
        let (is_start, is_end) = if let Mode::SectionDelimited {
            start_marker,
            end_marker,
        } = &self.mode
        {
            (start_marker.is_match(line), end_marker.is_match(line))
        } else {
            unreachable!()
        };

        if is_start {
            // Flush anything we had — recovers from a dropped Z marker.
            let flushed = self.take();
            self.pending.push_str(line);
            self.started_at = Some(Instant::now());
            self.in_section = true;
            return flushed;
        }
        if is_end && self.in_section {
            if !self.pending.is_empty() {
                self.pending.push('\n');
            }
            self.pending.push_str(line);
            self.in_section = false;
            return self.take();
        }
        if self.in_section {
            if !self.pending.is_empty() {
                self.pending.push('\n');
            }
            self.pending.push_str(line);
        }
        // Lines between entries (outside A..Z) are dropped — a well-formed
        // ModSec serial log has no inter-entry noise, and dropping is
        // safer than tokenising half-formed events.
        None
    }

    /// Flush if idle longer than [`FLUSH_AFTER`]. Call from a periodic tick.
    pub fn tick(&mut self, now: Instant) -> Option<String> {
        match self.started_at {
            Some(t) if now.saturating_duration_since(t) >= FLUSH_AFTER => self.take(),
            _ => None,
        }
    }

    /// Drain any pending event (end-of-stream).
    pub fn drain(&mut self) -> Option<String> {
        self.take()
    }

    fn take(&mut self) -> Option<String> {
        if self.pending.is_empty() {
            self.started_at = None;
            self.in_section = false;
            return None;
        }
        let ev = std::mem::take(&mut self.pending);
        self.started_at = None;
        self.in_section = false;
        Some(ev)
    }
}

fn is_continuation(line: &str) -> bool {
    let bytes = line.as_bytes();
    if bytes
        .first()
        .map(|b| b.is_ascii_whitespace())
        .unwrap_or(false)
    {
        return true;
    }
    line.starts_with("at ") || line.starts_with("Caused by:") || line.starts_with("...")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_line_flushes_on_next_first_line() {
        let mut a = Assembler::new();
        assert_eq!(a.push("ERROR something"), None);
        assert_eq!(
            a.push("INFO next event").as_deref(),
            Some("ERROR something")
        );
    }

    #[test]
    fn indented_continuation_folds_in() {
        let mut a = Assembler::new();
        a.push("ERROR failed with trace:");
        a.push("    at Foo.bar(Foo.java:42)");
        a.push("    at Baz.qux(Baz.java:17)");
        let out = a.push("INFO next");
        assert_eq!(
            out.as_deref(),
            Some("ERROR failed with trace:\n    at Foo.bar(Foo.java:42)\n    at Baz.qux(Baz.java:17)")
        );
    }

    #[test]
    fn java_at_prefix_is_continuation() {
        let mut a = Assembler::new();
        a.push("ERROR x");
        a.push("at Foo.bar(Foo.java:42)");
        let out = a.push("INFO next");
        assert_eq!(out.as_deref(), Some("ERROR x\nat Foo.bar(Foo.java:42)"));
    }

    #[test]
    fn drain_flushes_last_pending() {
        let mut a = Assembler::new();
        a.push("ERROR x");
        assert_eq!(a.drain().as_deref(), Some("ERROR x"));
    }

    #[test]
    fn tick_flushes_after_timeout() {
        let mut a = Assembler::new();
        a.push("ERROR x");
        let past = Instant::now() + Duration::from_secs(1);
        assert_eq!(a.tick(past).as_deref(), Some("ERROR x"));
    }

    #[test]
    fn modsec_section_boundaries() {
        let mut a = Assembler::modsec_sections();
        // Nothing emitted while inside a section …
        assert_eq!(a.push("--abc123-A--"), None);
        assert_eq!(
            a.push("[01/Jan/2026:12:34:56 +0000] abc123 1.2.3.4 51234 10.0.0.1 443"),
            None
        );
        assert_eq!(a.push("--abc123-B--"), None);
        assert_eq!(a.push("GET / HTTP/1.1"), None);
        assert_eq!(a.push("Host: example.com"), None);
        assert_eq!(a.push("--abc123-H--"), None);
        assert_eq!(
            a.push("Message: Access denied with code 403 (phase 2). [id \"942100\"]"),
            None
        );
        // … and emits exactly on Z.
        let out = a.push("--abc123-Z--");
        let s = out.expect("Z marker should flush");
        assert!(s.contains("--abc123-A--"));
        assert!(s.contains("Access denied"));
        assert!(s.contains("--abc123-Z--"));
    }

    #[test]
    fn modsec_drops_inter_entry_noise() {
        let mut a = Assembler::modsec_sections();
        // Random garbage before the first A marker is discarded.
        assert_eq!(a.push("some junk"), None);
        assert_eq!(a.push(""), None);
        assert_eq!(a.push("--def456-A--"), None);
        assert_eq!(a.push("header line"), None);
        let out = a.push("--def456-Z--");
        let s = out.expect("Z flushes");
        assert!(!s.contains("junk"));
    }

    #[test]
    fn modsec_recovers_from_missing_z() {
        // Two entries where the first never saw its Z marker — the next A
        // marker still flushes the stuck one so we don't lose data.
        let mut a = Assembler::modsec_sections();
        a.push("--one-A--");
        a.push("partial entry");
        let flushed = a.push("--two-A--");
        assert!(flushed.unwrap().contains("--one-A--"));
    }
}
