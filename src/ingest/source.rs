//! Source ingestion.
//!
//! One-shot mode (default) reads a source to EOF through the engine.
//! `--follow` (file sources only) uses the `watcher` module to tail
//! appended lines until the caller signals shutdown.

use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
#[cfg(feature = "watcher")]
use std::sync::Arc;
use std::time::Instant;

use color_eyre::eyre::{Context, Result};
use compact_str::CompactString;

use crate::detect::probe::{Detector, Verdict};
use crate::detect::registry::{BundleRegistry, DetectConfig, MultilineMode, ParseFormat};
use crate::engine::registry::PatternRegistry;
use crate::ingest::multiline::Assembler;
use crate::parse::formats::{cef, json, kv, leef, syslog};
use crate::parse::skeleton::ContextRule;
use crate::parse::{skeleton, tokenizer, Token};

/// Hard cap on a single logical line we accept from any source.
/// A line longer than this is truncated at the boundary — this prevents
/// a single pathological file (or a crafted binary blob) from exhausting
/// memory via `read_until`.
pub const MAX_LINE_BYTES: usize = 1 << 20; // 1 MiB

/// A source descriptor passed in from the CLI.
#[derive(Debug, Clone)]
pub enum SourceKind {
    Stdin,
    File(PathBuf),
}

impl SourceKind {
    pub fn label(&self) -> String {
        match self {
            SourceKind::Stdin => "stdin".to_string(),
            SourceKind::File(p) => p.display().to_string(),
        }
    }

    pub fn path(&self) -> Option<&Path> {
        match self {
            SourceKind::Stdin => None,
            SourceKind::File(p) => Some(p.as_path()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SourceReport {
    pub source: SourceKind,
    pub lines: u64,
    pub verdict: Verdict,
}

/// Parsing configuration derived from the chosen bundle.
///
/// Carried through the fold path so `drive_source_follow` doesn't need
/// to re-reach into the `BundleRegistry` on every tailed line.
#[derive(Debug, Clone)]
pub struct ParseSpec {
    pub bundle_id: String,
    pub format: ParseFormat,
    pub multiline: MultilineMode,
    pub context_types: Vec<ContextRule>,
}

impl ParseSpec {
    pub fn from_bundle(bundles: &BundleRegistry, bundle_id: &str) -> Self {
        match bundles.by_id(bundle_id) {
            Some(b) => ParseSpec {
                bundle_id: bundle_id.to_string(),
                format: b.format,
                multiline: b.multiline,
                context_types: b.context_types.clone(),
            },
            None => ParseSpec {
                bundle_id: bundle_id.to_string(),
                format: ParseFormat::default(),
                multiline: MultilineMode::default(),
                context_types: Vec::new(),
            },
        }
    }
}

/// Drive one source to EOF.
pub fn drive_source(
    source: &SourceKind,
    engine: &PatternRegistry,
    bundles: &BundleRegistry,
    detect_cfg: DetectConfig,
    forced_bundle: Option<&str>,
) -> Result<SourceReport> {
    let reader: Box<dyn BufRead> = match source {
        SourceKind::Stdin => Box::new(io::stdin().lock()),
        SourceKind::File(p) => Box::new(BufReader::new(open_file_checked(p)?)),
    };
    drive(reader, source, engine, bundles, detect_cfg, forced_bundle)
}

/// Open a file source, warning about symlinks and non-regular files.
/// We still open symlinks (common for logrotate'd /var/log/*.log) — this
/// is advisory, not a block, because a locked-down ACL on the parent dir
/// is the real defence.
fn open_file_checked(p: &Path) -> Result<std::fs::File> {
    match std::fs::symlink_metadata(p) {
        Ok(md) => {
            if md.file_type().is_symlink() {
                let target = std::fs::read_link(p).ok();
                tracing::warn!(
                    path = %p.display(),
                    ?target,
                    "source is a symlink; following (be sure of its target when running as root)"
                );
            } else if !md.file_type().is_file() {
                tracing::warn!(
                    path = %p.display(),
                    kind = ?md.file_type(),
                    "source is not a regular file; proceeding anyway"
                );
            }
        }
        Err(e) => tracing::warn!(path = %p.display(), ?e, "symlink_metadata failed; proceeding"),
    }
    std::fs::File::open(p).with_context(|| format!("opening {}", p.display()))
}

/// Drive one source in follow (tail -f) mode. Blocks until `shutdown` returns true.
#[cfg(feature = "watcher")]
pub fn drive_source_follow(
    source: &SourceKind,
    engine: Arc<PatternRegistry>,
    spec: ParseSpec,
    shutdown: &dyn Fn() -> bool,
) -> Result<()> {
    let path = match source {
        SourceKind::File(p) => p.clone(),
        _ => color_eyre::eyre::bail!("follow mode only supports file sources"),
    };

    let mut assembler = match spec.multiline {
        MultilineMode::ModsecSections => Assembler::modsec_sections(),
        MultilineMode::Heuristic => Assembler::new(),
    };
    crate::ingest::watcher::tail(
        &path,
        |line| {
            if let Some(ev) = assembler.push(line) {
                fold_one(&ev, &engine, &spec);
            }
        },
        shutdown,
    )?;
    if let Some(final_ev) = assembler.drain() {
        fold_one(&final_ev, &engine, &spec);
    }
    Ok(())
}

fn drive(
    reader: Box<dyn BufRead>,
    source: &SourceKind,
    engine: &PatternRegistry,
    bundles: &BundleRegistry,
    detect_cfg: DetectConfig,
    forced_bundle: Option<&str>,
) -> Result<SourceReport> {
    let mut detector = Detector::attach(
        bundles,
        detect_cfg,
        source.path().map(|p| p.to_path_buf()),
        None,
    );

    if let Some(id) = forced_bundle {
        let verdict = Verdict {
            bundle_id: id.to_string(),
            score: f32::INFINITY,
            candidates: vec![],
        };
        let spec = ParseSpec::from_bundle(bundles, &verdict.bundle_id);
        let mut assembler = assembler_for(bundles, &verdict.bundle_id);
        let lines = fold_to_eof(reader, engine, &spec, &mut assembler)?;
        return Ok(SourceReport {
            source: source.clone(),
            lines,
            verdict,
        });
    }

    if let Some(id) = detector.early_win() {
        let verdict = Verdict {
            bundle_id: id,
            score: 1.5,
            candidates: vec![],
        };
        let spec = ParseSpec::from_bundle(bundles, &verdict.bundle_id);
        let mut assembler = assembler_for(bundles, &verdict.bundle_id);
        let lines = fold_to_eof(reader, engine, &spec, &mut assembler)?;
        return Ok(SourceReport {
            source: source.clone(),
            lines,
            verdict,
        });
    }

    let mut assembler;

    // Line-probe path: buffer up to probe_lines, decide, replay, continue.
    let mut reader = reader;
    let mut buf = Vec::<u8>::with_capacity(1024);
    loop {
        buf.clear();
        let line = match read_bounded_line(&mut reader, &mut buf)? {
            Some(s) => s,
            None => break, // EOF
        };
        if line.is_empty() {
            continue;
        }
        if detector.observe(&line) {
            break;
        }
    }

    let verdict = detector.decide();
    // Rebuild the assembler now that we know which bundle won — ModSec
    // bundles need section-delimited grouping, not the heuristic default.
    assembler = assembler_for(bundles, &verdict.bundle_id);
    let spec = ParseSpec::from_bundle(bundles, &verdict.bundle_id);
    let pending = detector.drain_pending();
    for line in &pending {
        if let Some(ev) = assembler.push(line) {
            fold_one(&ev, engine, &spec);
        }
    }
    let post = fold_to_eof(reader, engine, &spec, &mut assembler)?;

    Ok(SourceReport {
        source: source.clone(),
        lines: pending.len() as u64 + post,
        verdict,
    })
}

fn fold_to_eof<R: BufRead>(
    mut reader: R,
    engine: &PatternRegistry,
    spec: &ParseSpec,
    assembler: &mut Assembler,
) -> Result<u64> {
    let mut buf = Vec::<u8>::with_capacity(1024);
    let mut lines = 0u64;
    loop {
        buf.clear();
        let line = match read_bounded_line(&mut reader, &mut buf)? {
            Some(s) => s,
            None => break,
        };
        if line.is_empty() {
            continue;
        }
        if let Some(ev) = assembler.push(&line) {
            fold_one(&ev, engine, spec);
        }
        lines += 1;
    }
    if let Some(final_ev) = assembler.drain() {
        fold_one(&final_ev, engine, spec);
    }
    Ok(lines)
}

/// Read one line (up to a `\n`) into `buf`, returning the UTF-8-lossy
/// text with trailing newline/CR stripped.
///
/// Guarantees:
/// - At most [`MAX_LINE_BYTES`] bytes consumed. If the newline is
///   farther out we return what we have and skip to the next `\n` on
///   the next call, so a single pathological super-line can't exhaust
///   memory.
/// - Returns `None` only at true EOF, never on partial reads.
/// - Invalid UTF-8 is replaced with U+FFFD; the parser never aborts
///   because of a stray non-UTF-8 byte in an otherwise good log.
fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    buf: &mut Vec<u8>,
) -> std::io::Result<Option<String>> {
    buf.clear();
    // We can't use `Read::take(&mut r, n)` here because it consumes the
    // reader, so loop manually with a BufRead::fill_buf-style read.
    let mut truncated = false;
    while buf.len() < MAX_LINE_BYTES {
        let remaining = MAX_LINE_BYTES - buf.len();
        let before = buf.len();
        let n = reader.read_until(b'\n', buf)?;
        if n == 0 {
            break;
        }
        if buf.last().copied() == Some(b'\n') {
            break;
        }
        if buf.len() - before >= remaining {
            // read_until gave us data without a newline, and we've hit the cap.
            buf.truncate(MAX_LINE_BYTES);
            truncated = true;
            break;
        }
    }
    if buf.is_empty() {
        return Ok(None);
    }
    // If we hit the cap without a newline, discard the rest of this line.
    if truncated {
        let mut sink = Vec::<u8>::with_capacity(1024);
        loop {
            sink.clear();
            let n = reader.read_until(b'\n', &mut sink)?;
            if n == 0 || sink.last().copied() == Some(b'\n') {
                break;
            }
            if sink.len() > MAX_LINE_BYTES * 4 {
                // Give up — pathological input.
                tracing::warn!("abandoning oversize line");
                break;
            }
        }
    }
    // Trim trailing \n and \r.
    while matches!(buf.last().copied(), Some(b'\n') | Some(b'\r')) {
        buf.pop();
    }
    let s = String::from_utf8_lossy(buf).into_owned();
    Ok(Some(s))
}

/// Pick an [`Assembler`] mode based on the chosen bundle's `multiline`
/// field. Unknown bundles get the heuristic default.
fn assembler_for(bundles: &BundleRegistry, bundle_id: &str) -> Assembler {
    match bundles.by_id(bundle_id).map(|b| b.multiline) {
        Some(MultilineMode::ModsecSections) => Assembler::modsec_sections(),
        _ => Assembler::new(),
    }
}

fn fold_one(line: &str, engine: &PatternRegistry, spec: &ParseSpec) {
    // Format-aware preprocessing: strip the envelope if the bundle
    // asked for it. Falls through to raw tokenisation on parse miss
    // so a non-matching line in a format-tagged file still gets folded.
    //
    // JSON's msg is a Cow because stringified primitives (`"msg": 200`)
    // need an owned backing string. We stash that owner in `_owned_msg`
    // so the borrow below outlives the match arm.
    let owned_json: Option<String> = match spec.format {
        ParseFormat::Json => json::parse(line).map(|p| p.msg),
        _ => None,
    };
    let effective: &str = match spec.format {
        ParseFormat::Raw => line,
        ParseFormat::Syslog => match syslog::parse(line) {
            Some(p) => p.msg,
            None => line,
        },
        ParseFormat::Json => owned_json.as_deref().unwrap_or(line),
        ParseFormat::Kv => kv::parse(line).map(|p| p.msg).unwrap_or(line),
        ParseFormat::Cef => cef::parse(line).map(|p| p.name).unwrap_or(line),
        ParseFormat::Leef => leef::parse(line).map(|p| p.event_id).unwrap_or(line),
    };

    let mut tokens: Vec<Token<'_>> = Vec::with_capacity(64);
    tokenizer::classify(effective, &mut tokens);
    if tokens.is_empty() {
        return;
    }
    let mut skel = CompactString::default();
    let mut slots = Vec::with_capacity(8);
    skeleton::build_with_context(&tokens, &spec.context_types, &mut skel, &mut slots);
    engine.upsert(&skel, &slots, &tokens, &spec.bundle_id, Instant::now());
}
