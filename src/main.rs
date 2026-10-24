//! `logfold` CLI entry point.

use std::path::PathBuf;

use clap::Parser;
use color_eyre::eyre::Result;
use tracing_subscriber::EnvFilter;

use logfold::ingest::source::SourceKind;
use logfold::{detect::registry::DetectConfig, Config, LearnOptions};

#[derive(Debug, Parser)]
#[command(
    name = "logfold",
    version,
    about = "Zero-config log pattern folder and anomaly detector"
)]
struct Cli {
    /// Files or "-" for stdin. Omit to read stdin.
    #[arg(value_name = "SOURCE")]
    sources: Vec<String>,

    /// Show top N anomalies.
    #[arg(short = 't', long, default_value_t = 20)]
    top: usize,

    /// Min occurrences before folding a pattern.
    #[arg(short = 'm', long, default_value_t = 3)]
    min_fold: u64,

    /// Min score to show in anomaly section.
    #[arg(short = 'T', long, default_value_t = 40)]
    threshold: u32,

    /// Force a specific pattern bundle (skip detection).
    #[arg(short = 'b', long)]
    bundle: Option<String>,

    /// Load additional pattern .toml files from DIR.
    #[arg(short = 'P', long)]
    patterns_dir: Option<PathBuf>,

    /// Max lines sampled before deciding a bundle.
    #[arg(long, default_value_t = 64)]
    probe_lines: usize,

    /// Disable TUI; print to stdout.
    #[arg(long)]
    no_tui: bool,

    /// Follow (tail -f) each file source after reading to EOF.
    #[arg(short = 'f', long)]
    follow: bool,

    /// After reading, export observed patterns as .toml files.
    #[arg(long)]
    learn: bool,

    /// Directory to write learned bundles into.
    #[arg(long, default_value = "./learned")]
    learn_out: PathBuf,

    /// Minimum count required to export a learned pattern.
    #[arg(long, default_value_t = 5)]
    learn_min: u64,

    /// Output one JSON object per pattern on exit (P5).
    #[arg(long, conflicts_with = "ndjson")]
    json: bool,

    /// Stream NDJSON (P5).
    #[arg(long)]
    ndjson: bool,

    /// Soft cap on total patterns held in memory.
    #[arg(long, default_value_t = 100_000)]
    max_patterns: usize,

    /// Suppress detection banner.
    #[arg(short = 'q', long)]
    quiet: bool,

    /// Verbose detection scoring details.
    #[arg(short = 'v', long)]
    verbose: bool,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let cli = Cli::parse();

    let filter = if cli.verbose {
        EnvFilter::new("logfold=debug")
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("logfold=warn"))
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    let sources: Vec<SourceKind> = if cli.sources.is_empty() {
        vec![SourceKind::Stdin]
    } else {
        cli.sources
            .into_iter()
            .map(|s| match s.as_str() {
                "-" => SourceKind::Stdin,
                _ => SourceKind::File(PathBuf::from(s)),
            })
            .collect()
    };

    let cfg = Config {
        sources,
        no_tui: cli.no_tui,
        json: cli.json,
        ndjson: cli.ndjson,
        follow: cli.follow,
        top: cli.top,
        min_fold: cli.min_fold,
        anomaly_threshold: cli.threshold,
        max_patterns: cli.max_patterns,
        quiet: cli.quiet,
        forced_bundle: cli.bundle,
        patterns_dir: cli.patterns_dir,
        detect: DetectConfig {
            probe_lines: cli.probe_lines,
            decision_timeout_ms: 500,
        },
        learn: cli.learn.then_some(LearnOptions {
            out_dir: cli.learn_out,
            min_count: cli.learn_min,
            top: 100,
        }),
    };

    logfold::run(cfg)
}
