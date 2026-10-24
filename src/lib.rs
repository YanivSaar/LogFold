//! `logfold` library crate.

#![forbid(unsafe_code)]

pub mod detect;
pub mod engine;
pub mod ingest;
pub mod output;
pub mod parse;
pub mod tui;
pub mod types;

use std::path::PathBuf;
#[cfg(any(feature = "tui", feature = "watcher"))]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use color_eyre::eyre::{bail, Result};
use parking_lot::Mutex;

use crate::detect::registry::{BundleRegistry, DetectConfig};
use crate::engine::registry::PatternRegistry;
use crate::ingest::source::{self, SourceKind, SourceReport};
use crate::output::text::TextConfig;

pub struct Config {
    pub sources: Vec<SourceKind>,
    pub no_tui: bool,
    pub json: bool,
    pub ndjson: bool,
    pub follow: bool,
    pub top: usize,
    pub min_fold: u64,
    pub anomaly_threshold: u32,
    pub max_patterns: usize,
    pub quiet: bool,
    pub forced_bundle: Option<String>,
    pub patterns_dir: Option<PathBuf>,
    pub detect: DetectConfig,
    pub learn: Option<LearnOptions>,
}

#[derive(Debug, Clone)]
pub struct LearnOptions {
    pub out_dir: PathBuf,
    pub min_count: u64,
    pub top: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            sources: vec![SourceKind::Stdin],
            no_tui: false,
            json: false,
            ndjson: false,
            follow: false,
            top: 20,
            min_fold: 3,
            anomaly_threshold: 40,
            max_patterns: 100_000,
            quiet: false,
            forced_bundle: None,
            patterns_dir: None,
            detect: DetectConfig::default(),
            learn: None,
        }
    }
}

pub fn run(cfg: Config) -> Result<()> {
    if cfg.follow && cfg.sources.iter().any(|s| matches!(s, SourceKind::Stdin)) {
        bail!("--follow is only supported on file sources, not stdin");
    }
    if (cfg.json || cfg.ndjson) && !cfg.no_tui {
        bail!("--json / --ndjson require --no-tui");
    }

    let bundles = Arc::new(BundleRegistry::load(cfg.patterns_dir.as_deref())?);
    let engine = Arc::new(PatternRegistry::new(cfg.max_patterns));
    let reports: Arc<Mutex<Vec<SourceReport>>> = Arc::new(Mutex::new(Vec::new()));

    if cfg.no_tui {
        return run_no_tui(cfg, engine, bundles, reports);
    }

    #[cfg(feature = "tui")]
    {
        run_with_tui(cfg, engine, bundles, reports)
    }
    #[cfg(not(feature = "tui"))]
    {
        bail!("logfold was built without the `tui` feature; re-run with --no-tui")
    }
}

fn run_no_tui(
    cfg: Config,
    engine: Arc<PatternRegistry>,
    bundles: Arc<BundleRegistry>,
    reports: Arc<Mutex<Vec<SourceReport>>>,
) -> Result<()> {
    if !cfg.quiet {
        eprintln!("logfold v{}", env!("CARGO_PKG_VERSION"));
    }

    // --no-tui, --follow: run follow forever (user Ctrl-Cs out).
    for src in &cfg.sources {
        let r = source::drive_source(
            src,
            &engine,
            &bundles,
            cfg.detect.clone(),
            cfg.forced_bundle.as_deref(),
        )?;
        reports.lock().push(r);
    }

    #[cfg(feature = "watcher")]
    if cfg.follow {
        let shutdown = Arc::new(AtomicBool::new(false));
        let s = shutdown.clone();
        ctrlc_once(move || s.store(true, Ordering::Relaxed));
        // Thread each follow source so a slow one doesn't starve others.
        let mut handles = Vec::new();
        for src in cfg.sources.clone() {
            let bundle_id = reports
                .lock()
                .iter()
                .find(|r| r.source.label() == src.label())
                .map(|r| r.verdict.bundle_id.clone());
            let Some(bundle_id) = bundle_id else {
                continue;
            };
            let engine = engine.clone();
            let shutdown = shutdown.clone();
            handles.push(std::thread::spawn(move || -> Result<()> {
                source::drive_source_follow(&src, engine, bundle_id, &|| {
                    shutdown.load(Ordering::Relaxed)
                })
            }));
        }
        for h in handles {
            if let Err(payload) = h.join() {
                tracing::error!(?payload, "follow thread panicked");
            }
        }
    }

    render_text(&cfg, &engine, &reports.lock())?;
    maybe_learn(&cfg, &engine)?;
    Ok(())
}

#[cfg(feature = "tui")]
fn run_with_tui(
    cfg: Config,
    engine: Arc<PatternRegistry>,
    bundles: Arc<BundleRegistry>,
    reports: Arc<Mutex<Vec<SourceReport>>>,
) -> Result<()> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();

    // One ingest thread per source. Each runs drive_source (one-shot) and —
    // if --follow is set — follows afterwards.
    for src in cfg.sources.clone() {
        let engine = engine.clone();
        let bundles = bundles.clone();
        let reports = reports.clone();
        let shutdown = shutdown.clone();
        let detect = cfg.detect.clone();
        let forced = cfg.forced_bundle.clone();
        let follow = cfg.follow;

        let h = std::thread::spawn(move || -> Result<()> {
            let r = source::drive_source(&src, &engine, &bundles, detect, forced.as_deref())?;
            let bundle_id = r.verdict.bundle_id.clone();
            reports.lock().push(r);
            if follow {
                #[cfg(feature = "watcher")]
                {
                    let sd = shutdown.clone();
                    source::drive_source_follow(&src, engine.clone(), bundle_id, &move || {
                        sd.load(Ordering::Relaxed)
                    })?;
                }
                #[cfg(not(feature = "watcher"))]
                {
                    let _ = (bundle_id, &shutdown);
                    tracing::warn!("--follow set but the `watcher` feature is disabled");
                }
            }
            Ok(())
        });
        handles.push(h);
    }

    tui::run(
        engine.clone(),
        reports,
        shutdown.clone(),
        cfg.anomaly_threshold,
        cfg.min_fold,
    )?;

    shutdown.store(true, Ordering::Relaxed);
    for h in handles {
        match h.join() {
            Ok(Err(e)) => tracing::error!(?e, "ingest thread returned an error"),
            Err(payload) => tracing::error!(?payload, "ingest thread panicked"),
            _ => {}
        }
    }
    maybe_learn(&cfg, &engine)?;
    Ok(())
}

fn render_text(cfg: &Config, engine: &PatternRegistry, reports: &[SourceReport]) -> Result<()> {
    let snaps = engine.snapshot();
    let mut out = std::io::stdout().lock();

    if cfg.json || cfg.ndjson {
        let json_cfg = output::json::Settings {
            ndjson: cfg.ndjson,
            min_fold: cfg.min_fold,
            top_values_per_var: 10,
        };
        output::json::render(&mut out, &snaps, reports, &json_cfg)?;
        return Ok(());
    }

    if !cfg.quiet {
        eprintln!("\nSources:");
        for r in reports {
            eprintln!(
                "  {label:<32} → {bundle} [score {score:.2}, {lines} lines]",
                label = r.source.label(),
                bundle = r.verdict.bundle_id,
                score = r.verdict.score,
                lines = r.lines
            );
        }
    }

    let text_cfg = TextConfig {
        top: cfg.top,
        min_fold: cfg.min_fold,
        anomaly_threshold: cfg.anomaly_threshold,
    };
    output::text::render(&mut out, &snaps, &text_cfg)?;

    if !cfg.quiet {
        let total: u64 = reports.iter().map(|r| r.lines).sum();
        eprintln!("\nFolded {total} line(s) into {} pattern(s).", engine.len());
    }
    Ok(())
}

fn maybe_learn(cfg: &Config, engine: &PatternRegistry) -> Result<()> {
    let Some(opts) = cfg.learn.as_ref() else {
        return Ok(());
    };
    let snaps = engine.snapshot();
    let n = output::learn::write(
        &snaps,
        &output::learn::LearnConfig {
            out_dir: &opts.out_dir,
            min_count: opts.min_count,
            top: opts.top,
        },
    )?;
    if !cfg.quiet {
        eprintln!(
            "Learned {n} bundle file(s) under {}",
            opts.out_dir.display()
        );
    }
    Ok(())
}

/// Register a minimal Ctrl-C handler that calls `f` once. Idempotent on
/// re-entry so tests that call `run` multiple times don't panic.
#[cfg(feature = "watcher")]
fn ctrlc_once<F: FnOnce() + Send + 'static>(f: F) {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(move || {
        let mut slot = Some(f);
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                if let Some(cb) = slot.take() {
                    cb();
                }
            }
        });
    });
}
