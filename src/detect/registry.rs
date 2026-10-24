//! Bundle registry — loads `.toml` pattern bundles from a compiled-in
//! default set plus any user-supplied directory.
//!
//! The runtime surface is a `BundleRegistry` the detector queries. Each
//! `Bundle` carries pre-compiled [globset]/[regex] matchers so the hot
//! path never re-parses them.

use std::path::Path;

use color_eyre::eyre::{Context, Result};
use compact_str::CompactString;
use globset::{Glob, GlobSet, GlobSetBuilder};
use include_dir::{include_dir, Dir};
use regex::{RegexSet, RegexSetBuilder};
use serde::Deserialize;

/// Trust level for a bundle source. Compiled-in bundles ship with the
/// binary and are trusted. User-supplied bundles via `--patterns-dir` are
/// compiled with tight size limits to bound ReDoS/compile-time blowup.
#[derive(Debug, Clone, Copy)]
pub enum Trust {
    Builtin,
    UserSupplied,
}

impl Trust {
    const USER_REGEX_SIZE_LIMIT: usize = 100_000;
    const USER_REGEX_DFA_LIMIT: usize = 100_000;
}

use crate::parse::skeleton::ContextRule;
use crate::types::{Severity, TokenType};

/// Bundles baked into the binary at compile time. These ship as a
/// default library; `--patterns-dir` adds more at runtime.
static DEFAULT_BUNDLES: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/patterns");

/// Opaque bundle identifier (e.g. `"sshd"`, `"nginx-access"`).
pub type BundleId = CompactString;

/// A loaded pattern bundle with compiled matchers.
pub struct Bundle {
    pub id: BundleId,
    pub name: CompactString,
    pub category: CompactString,
    pub description: CompactString,

    pub path_globs: Option<GlobSet>,
    pub process_hints: Vec<CompactString>,
    pub line_probes: Option<RegexSet>,
    pub probe_threshold: f32,

    /// How the multiline assembler should group lines into events.
    pub multiline: MultilineMode,

    /// How to normalise a line before tokenisation.
    pub format: ParseFormat,

    /// WORD-after-WORD promotion rules consulted by the skeleton
    /// builder. Empty vec means no promotion (hot path stays zero-cost).
    pub context_types: Vec<ContextRule>,

    pub seeded: Vec<SeededPattern>,
}

/// Multiline grouping mode declared in `[parse]` section of a bundle.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MultilineMode {
    /// Default heuristic: whitespace-indent / "at " continuation.
    #[default]
    Heuristic,
    /// ModSec serial-format: one event per `A..Z` section group.
    ModsecSections,
}

/// Line format declared in `[parse]` section of a bundle.
///
/// Governs envelope stripping before tokenisation. New in v0.2.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ParseFormat {
    /// Tokenise the whole line (default).
    #[default]
    Raw,
    /// Treat the line as RFC 3164 / 5424 syslog; strip the envelope
    /// and tokenise only the free-form message body.
    Syslog,
}

/// A `[[pattern]]` entry — a named canonical skeleton the engine
/// pre-populates so the display shows the user-friendly label.
#[derive(Debug, Clone)]
pub struct SeededPattern {
    pub skeleton: CompactString,
    pub label: CompactString,
    pub severity: Severity,
}

/// Runtime config knobs for the detector.
#[derive(Debug, Clone)]
pub struct DetectConfig {
    pub probe_lines: usize,
    pub decision_timeout_ms: u64,
}

impl Default for DetectConfig {
    fn default() -> Self {
        DetectConfig {
            probe_lines: 64,
            decision_timeout_ms: 500,
        }
    }
}

pub struct BundleRegistry {
    bundles: Vec<Bundle>,
}

impl BundleRegistry {
    /// Load the compiled-in default bundles plus any `.toml` files found
    /// under `extra_dir` (recursively).
    pub fn load(extra_dir: Option<&Path>) -> Result<Self> {
        let mut out = Vec::new();

        // 1. compiled-in defaults.
        collect_from_dir(&DEFAULT_BUNDLES, &mut out)?;

        // 2. user override / extra dir.
        if let Some(dir) = extra_dir {
            if dir.is_dir() {
                collect_from_fs(dir, &mut out)?;
            } else {
                tracing::warn!(?dir, "patterns-dir does not exist or is not a directory");
            }
        }

        tracing::info!(count = out.len(), "pattern bundles loaded");
        Ok(BundleRegistry { bundles: out })
    }

    pub fn bundles(&self) -> &[Bundle] {
        &self.bundles
    }

    pub fn by_id(&self, id: &str) -> Option<&Bundle> {
        self.bundles.iter().find(|b| b.id == id)
    }
}

fn collect_from_dir(dir: &Dir<'_>, out: &mut Vec<Bundle>) -> Result<()> {
    for file in dir.files() {
        if file.path().extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        let body = file.contents_utf8().unwrap_or("");
        let raw: RawBundle = toml::from_str(body)
            .with_context(|| format!("parsing bundled {}", file.path().display()))?;
        out.push(raw.compile(Trust::Builtin)?);
    }
    for sub in dir.dirs() {
        collect_from_dir(sub, out)?;
    }
    Ok(())
}

fn collect_from_fs(dir: &Path, out: &mut Vec<Bundle>) -> Result<()> {
    // Cap total user TOML bytes we'll load. A hostile --patterns-dir with
    // 10 GB of .toml files shouldn't be allowed to swallow memory before
    // we even hit the regex compiler.
    const MAX_USER_TOML_BYTES: u64 = 8 * 1024 * 1024; // 8 MiB per file
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_from_fs(&path, out)?;
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        if let Ok(md) = std::fs::metadata(&path) {
            if md.len() > MAX_USER_TOML_BYTES {
                tracing::warn!(
                    path = %path.display(),
                    bytes = md.len(),
                    "skipping oversized user bundle (> 8 MiB)"
                );
                continue;
            }
        }
        let body = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let raw: RawBundle =
            toml::from_str(&body).with_context(|| format!("parsing {}", path.display()))?;
        out.push(raw.compile(Trust::UserSupplied)?);
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// On-disk schema
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct RawBundle {
    meta: RawMeta,
    #[serde(default)]
    detect: RawDetect,
    #[serde(default)]
    parse: RawParse,
    #[serde(default)]
    pattern: Vec<RawPattern>,
    #[serde(default, rename = "context_types")]
    context_types: Vec<RawContextRule>,
}

/// On-disk schema for a single `[[context_types]]` entry.
#[derive(Debug, Deserialize)]
struct RawContextRule {
    after: String,
    #[serde(rename = "type")]
    ty: TokenType,
}

#[derive(Debug, Deserialize, Default)]
struct RawParse {
    /// Multiline grouping policy. Accepts `"heuristic"` (default) or
    /// `"modsec-sections"`.
    #[serde(default)]
    multiline: Option<String>,
    /// Line format for envelope stripping. Accepts `"raw"` (default)
    /// or `"syslog"`.
    #[serde(default)]
    format: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawMeta {
    id: String,
    name: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    description: String,
}

#[derive(Debug, Deserialize, Default)]
struct RawDetect {
    #[serde(default)]
    path_hints: Vec<String>,
    #[serde(default)]
    process_hints: Vec<String>,
    #[serde(default)]
    line_probes: Vec<String>,
    #[serde(default = "default_threshold")]
    probe_threshold: f32,
}

fn default_threshold() -> f32 {
    0.15
}

#[derive(Debug, Deserialize)]
struct RawPattern {
    skeleton: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    severity: Severity,
}

impl RawBundle {
    fn compile(self, trust: Trust) -> Result<Bundle> {
        // Reject bundle IDs that could escape a learn-output directory or
        // contain path-sensitive characters. We don't need rich filenames
        // here — kebab/snake case is fine.
        if matches!(trust, Trust::UserSupplied) && !is_safe_bundle_id(&self.meta.id) {
            color_eyre::eyre::bail!(
                "bundle id {:?} contains unsafe characters (allowed: a-z, 0-9, _, -, /)",
                self.meta.id
            );
        }
        let path_globs = if self.detect.path_hints.is_empty() {
            None
        } else {
            let mut builder = GlobSetBuilder::new();
            for hint in &self.detect.path_hints {
                // "journald:" prefixes aren't filesystem globs — they're
                // matched separately via `process_hints`. Skip them here.
                if hint.starts_with("journald:") {
                    continue;
                }
                let glob = Glob::new(hint)
                    .with_context(|| format!("bad glob `{hint}` in bundle {}", self.meta.id))?;
                builder.add(glob);
            }
            Some(
                builder
                    .build()
                    .with_context(|| format!("compiling globs for bundle {}", self.meta.id))?,
            )
        };

        // journald unit names (from the "journald:unit" prefix) merge into
        // the process_hints list; both are matched case-insensitively.
        let mut process_hints: Vec<CompactString> = self
            .detect
            .process_hints
            .iter()
            .map(|s| CompactString::new(s.to_ascii_lowercase()))
            .collect();
        for hint in &self.detect.path_hints {
            if let Some(unit) = hint.strip_prefix("journald:") {
                process_hints.push(CompactString::new(unit.to_ascii_lowercase()));
            }
        }

        let line_probes =
            if self.detect.line_probes.is_empty() {
                None
            } else {
                let mut builder = RegexSetBuilder::new(&self.detect.line_probes);
                if matches!(trust, Trust::UserSupplied) {
                    builder
                        .size_limit(Trust::USER_REGEX_SIZE_LIMIT)
                        .dfa_size_limit(Trust::USER_REGEX_DFA_LIMIT);
                }
                Some(builder.build().with_context(|| {
                    format!("compiling line_probes for bundle {}", self.meta.id)
                })?)
            };

        let seeded = self
            .pattern
            .into_iter()
            .map(|p| SeededPattern {
                skeleton: p.skeleton.into(),
                label: p.label.into(),
                severity: p.severity,
            })
            .collect();

        let multiline = match self.parse.multiline.as_deref() {
            None | Some("heuristic") => MultilineMode::Heuristic,
            Some("modsec-sections") => MultilineMode::ModsecSections,
            Some(other) => {
                tracing::warn!(
                    bundle = %self.meta.id,
                    unknown = %other,
                    "unknown multiline mode; falling back to heuristic"
                );
                MultilineMode::Heuristic
            }
        };

        let format = match self.parse.format.as_deref() {
            None | Some("raw") => ParseFormat::Raw,
            Some("syslog") => ParseFormat::Syslog,
            Some(other) => {
                tracing::warn!(
                    bundle = %self.meta.id,
                    unknown = %other,
                    "unknown parse format; falling back to raw"
                );
                ParseFormat::Raw
            }
        };

        let context_types = self
            .context_types
            .into_iter()
            .map(|r| ContextRule {
                after: r.after.into(),
                ty: r.ty,
            })
            .collect();

        Ok(Bundle {
            id: self.meta.id.into(),
            name: self.meta.name.into(),
            category: self.meta.category.into(),
            description: self.meta.description.into(),
            path_globs,
            process_hints,
            line_probes,
            probe_threshold: self.detect.probe_threshold,
            multiline,
            format,
            context_types,
            seeded,
        })
    }
}

fn is_safe_bundle_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '/'))
        && !id.contains("..")
        && !id.starts_with('/')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_bundle() {
        let toml_src = r#"
            [meta]
            id   = "demo"
            name = "Demo"

            [detect]
            path_hints  = ["**/demo.log"]
            line_probes = ["demo\\["]
        "#;
        let raw: RawBundle = toml::from_str(toml_src).unwrap();
        let bundle = raw.compile(Trust::Builtin).unwrap();
        assert_eq!(bundle.id, "demo");
        assert!(bundle.path_globs.is_some());
        assert!(bundle.line_probes.is_some());
    }

    #[test]
    fn rejects_unsafe_user_bundle_id() {
        let toml_src = r#"
            [meta]
            id   = "../../etc/evil"
            name = "evil"
        "#;
        let raw: RawBundle = toml::from_str(toml_src).unwrap();
        assert!(raw.compile(Trust::UserSupplied).is_err());
    }

    #[test]
    fn allows_slash_in_builtin_bundle_id() {
        // "generic/syslog" is a legitimate compiled-in id.
        let toml_src = r#"
            [meta]
            id = "generic/syslog"
            name = "Generic syslog"
        "#;
        let raw: RawBundle = toml::from_str(toml_src).unwrap();
        assert!(raw.compile(Trust::Builtin).is_ok());
    }

    #[test]
    fn loads_default_bundles() {
        let reg = BundleRegistry::load(None).unwrap();
        assert!(!reg.bundles().is_empty(), "no default bundles loaded");
    }
}
