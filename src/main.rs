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

    /// POST anomaly events to this URL. Requires the `webhook` feature.
    #[arg(long, value_name = "URL")]
    webhook: Option<String>,

    /// Payload flavor for `--webhook`: `generic` (default), `slack`, `pagerduty`.
    #[arg(long, default_value = "generic", value_name = "FLAVOR")]
    webhook_flavor: String,

    /// Only POST when the computed score is at least N (default: 70).
    #[arg(long, default_value_t = 70)]
    webhook_min_score: u32,

    /// Per-pattern cool-down (seconds) before a repeat POST.
    #[arg(long, default_value_t = 300)]
    webhook_dedup_secs: u64,

    /// PagerDuty routing key (required with --webhook-flavor pagerduty).
    /// Can also be set via `LOGFOLD_PD_ROUTING_KEY` env var; CLI wins.
    #[arg(long, value_name = "KEY")]
    webhook_pd_routing_key: Option<String>,

    /// IOC CSV (indicator,source,severity) consulted when scoring.
    /// Matches on any variable value nudge the score and surface
    /// as `IOC:` tags in the Detail view.
    #[arg(long, value_name = "FILE")]
    iocs: Option<PathBuf>,

    /// MaxMind GeoIP database (ASN or Country). Requires the
    /// `geoip` cargo feature.
    #[arg(long, value_name = "FILE")]
    geoip: Option<PathBuf>,

    /// Persist the pattern registry to this path. Loaded on start
    /// (if present) and saved on clean shutdown. Lets `--follow`
    /// sessions survive restarts without re-replaying history.
    #[arg(long, value_name = "FILE")]
    state: Option<PathBuf>,

    /// Serve Prometheus `/metrics` on HOST:PORT. Requires the
    /// `prometheus` cargo feature.
    #[arg(long, value_name = "ADDR")]
    prom_listen: Option<String>,

    /// Validate bundle TOML files instead of folding logs. The
    /// positional arguments are treated as paths to .toml files.
    /// Returns exit code 0 if every bundle parses and compiles.
    #[arg(long, conflicts_with_all = ["follow", "learn", "json", "ndjson"])]
    lint: bool,

    /// Remove the running binary plus user config / state. Prints
    /// a dry-run plan and prompts for confirmation; pair with
    /// `--yes` to skip the prompt. Operations that need sudo
    /// (service user, systemd unit, ACLs) are printed as commands
    /// for you to run.
    #[arg(long, conflicts_with_all = ["follow", "learn", "lint"])]
    uninstall: bool,

    /// Skip the interactive confirmation prompt for `--uninstall`.
    #[arg(long, requires = "uninstall")]
    yes: bool,
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

    if cli.uninstall {
        return logfold::uninstall::run(logfold::uninstall::UninstallOptions {
            yes: cli.yes,
            state: cli.state.clone(),
        });
    }

    if cli.lint {
        return run_lint(&cli.sources);
    }

    let sources: Vec<SourceKind> = if cli.sources.is_empty() {
        vec![SourceKind::Stdin]
    } else {
        cli.sources
            .into_iter()
            .map(|s| SourceKind::parse(&s))
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
        webhook: cli.webhook.map(|url| {
            let pd_key = cli
                .webhook_pd_routing_key
                .clone()
                .or_else(|| std::env::var("LOGFOLD_PD_ROUTING_KEY").ok());
            logfold::WebhookOptions {
                url,
                flavor: cli.webhook_flavor.clone(),
                min_score: cli.webhook_min_score,
                dedup_secs: cli.webhook_dedup_secs,
                pd_routing_key: pd_key,
            }
        }),
        enrichment: logfold::EnrichmentOptions {
            iocs: cli.iocs,
            geoip: cli.geoip,
        },
        state_path: cli.state,
        prom_listen: cli.prom_listen,
    };

    logfold::run(cfg)
}

/// Validate bundle TOML files. Prints one line per file plus a summary;
/// exits non-zero if any bundle fails to compile.
fn run_lint(paths: &[String]) -> Result<()> {
    if paths.is_empty() {
        eprintln!("logfold lint: no bundle paths given");
        std::process::exit(2);
    }
    let mut errors = 0usize;
    let mut ok = 0usize;
    for path in paths {
        let p = std::path::Path::new(path);
        if p.is_dir() {
            // Walk the directory for .toml bundles.
            let mut stack = vec![p.to_path_buf()];
            while let Some(dir) = stack.pop() {
                let read = match std::fs::read_dir(&dir) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  err  {}: {e}", dir.display());
                        errors += 1;
                        continue;
                    }
                };
                for entry in read.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        stack.push(path);
                    } else if path.extension().and_then(|s| s.to_str()) == Some("toml") {
                        match logfold::detect::registry::lint_bundle_file(&path) {
                            Ok(id) => {
                                println!("  ok   {} ({id})", path.display());
                                ok += 1;
                            }
                            Err(e) => {
                                println!("  err  {}: {e:#}", path.display());
                                errors += 1;
                            }
                        }
                    }
                }
            }
            continue;
        }
        match logfold::detect::registry::lint_bundle_file(p) {
            Ok(id) => {
                println!("  ok   {} ({id})", p.display());
                ok += 1;
            }
            Err(e) => {
                println!("  err  {}: {e:#}", p.display());
                errors += 1;
            }
        }
    }
    println!();
    println!("lint: {ok} ok, {errors} failed");
    if errors > 0 {
        std::process::exit(1);
    }
    Ok(())
}
