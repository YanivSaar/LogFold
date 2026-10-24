//! JSON / NDJSON output.
//!
//! `render` emits one JSON *object* per pattern. In NDJSON mode each
//! object is on its own line (greppable by consumers). In JSON mode we
//! emit a single top-level array.

use std::io::Write;

use serde::Serialize;

use crate::engine::pattern::PatternSnapshot;
use crate::engine::scorer;
use crate::ingest::source::SourceReport;

#[derive(Serialize)]
struct PatternOut<'a> {
    id: u64,
    skeleton: &'a str,
    bundle: &'a str,
    count: u64,
    score: u32,
    badge: &'static str,
    peak_bucket: u32,
    mean_bucket: f32,
    first_seen_unix_ms: u128,
    last_seen_unix_ms: u128,
    vars: Vec<VarOut<'a>>,
}

#[derive(Serialize)]
struct VarOut<'a> {
    ty: &'static str,
    distinct: u64,
    total: u64,
    top: Vec<ValueOut<'a>>,
}

#[derive(Serialize)]
struct ValueOut<'a> {
    value: &'a str,
    count: u64,
}

#[derive(Serialize)]
pub struct SourceReportOut<'a> {
    source: String,
    bundle: &'a str,
    score: f32,
    lines: u64,
}

pub struct Settings {
    pub ndjson: bool,
    pub min_fold: u64,
    pub top_values_per_var: usize,
}

pub fn render<W: Write>(
    out: &mut W,
    snaps: &[PatternSnapshot],
    reports: &[SourceReport],
    settings: &Settings,
) -> std::io::Result<()> {
    let peers = scorer::build_peer_vars(snaps);
    let process_start = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let now_instant = std::time::Instant::now();

    let converted: Vec<PatternOut<'_>> = snaps
        .iter()
        .map(|s| {
            let score = scorer::compute_score(s, &peers);
            let badge = scorer::classify_badge(s, score, settings.min_fold).label();
            let first_delta = now_instant
                .saturating_duration_since(s.first_seen)
                .as_millis();
            let last_delta = now_instant
                .saturating_duration_since(s.last_seen)
                .as_millis();
            PatternOut {
                id: s.id,
                skeleton: s.skeleton.as_str(),
                bundle: s.bundle_id.as_str(),
                count: s.count,
                score,
                badge,
                peak_bucket: s.peak_bucket,
                mean_bucket: s.mean_bucket,
                first_seen_unix_ms: process_start.saturating_sub(first_delta),
                last_seen_unix_ms: process_start.saturating_sub(last_delta),
                vars: s
                    .vars
                    .iter()
                    .map(|v| VarOut {
                        ty: v.ty.tag(),
                        distinct: v.distinct_approx,
                        total: v.total,
                        top: v
                            .top
                            .iter()
                            .take(settings.top_values_per_var)
                            .map(|(k, c)| ValueOut {
                                value: k.as_str(),
                                count: *c,
                            })
                            .collect(),
                    })
                    .collect(),
            }
        })
        .collect();

    if settings.ndjson {
        for ev in &converted {
            serde_json::to_writer(&mut *out, ev)?;
            writeln!(out)?;
        }
    } else {
        let report_rows: Vec<SourceReportOut<'_>> = reports
            .iter()
            .map(|r| SourceReportOut {
                source: r.source.label(),
                bundle: r.verdict.bundle_id.as_str(),
                score: r.verdict.score,
                lines: r.lines,
            })
            .collect();
        let doc = serde_json::json!({
            "sources": report_rows,
            "patterns": converted,
        });
        serde_json::to_writer_pretty(&mut *out, &doc)?;
        writeln!(out)?;
    }
    Ok(())
}
