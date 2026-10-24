//! Prometheus `/metrics` endpoint. v0.10.
//!
//! Serves a plain-text Prometheus exposition response on
//! `--prom-listen HOST:PORT`. Behind the `prometheus` cargo feature.
//! Reads a shared registry snapshot on each scrape; no sampling or
//! aggregation state outside the pattern registry itself.
//!
//! Metrics exposed:
//!
//! * `logfold_patterns_total` - gauge, total patterns in the registry.
//! * `logfold_lines_total` - gauge, total raw lines folded.
//! * `logfold_patterns_by_bundle{bundle=...}` - gauge, per-bundle
//!   pattern count.
//! * `logfold_uptime_seconds` - counter, seconds since the metrics
//!   server started.
//! * `logfold_build_info{version="..."}` - gauge, always 1; carries
//!   the build version as a label for inventory scrapes.

#![cfg(feature = "prometheus")]

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;

use crate::engine::registry::PatternRegistry;

/// Bind to `addr` and serve `/metrics` until the process ends. Runs
/// as a dedicated tokio task; the shared `registry` and `started_at`
/// let scrapes read live state.
pub async fn serve(addr: SocketAddr, registry: Arc<PatternRegistry>) {
    let started_at = Instant::now();
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(?addr, error = %e, "prometheus listener failed to bind");
            return;
        }
    };
    tracing::info!(?addr, "prometheus /metrics listener up");

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed on /metrics listener");
                continue;
            }
        };
        let registry = registry.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| {
                let r = registry.clone();
                async move { Ok::<_, Infallible>(handle(req, r, started_at)) }
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                tracing::debug!(error = %e, "/metrics connection ended");
            }
        });
    }
}

fn handle(
    req: Request<Incoming>,
    registry: Arc<PatternRegistry>,
    started_at: Instant,
) -> Response<Full<Bytes>> {
    if req.uri().path() != "/metrics" {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from_static(b"not found\n")))
            .unwrap();
    }
    let body = render(&registry, started_at);
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

/// Render the current snapshot as Prometheus exposition text.
pub fn render(registry: &PatternRegistry, started_at: Instant) -> String {
    let snaps = registry.snapshot();
    let total_patterns = snaps.len();
    let total_lines: u64 = snaps.iter().map(|s| s.count).sum();
    let uptime = started_at.elapsed().as_secs();

    let mut by_bundle: HashMap<&str, u64> = HashMap::new();
    for s in &snaps {
        *by_bundle.entry(s.bundle_id.as_str()).or_insert(0) += 1;
    }

    let mut out = String::with_capacity(4096);
    push_metric_header(
        &mut out,
        "logfold_patterns_total",
        "gauge",
        "Total patterns in the registry.",
    );
    out.push_str(&format!("logfold_patterns_total {total_patterns}\n"));

    push_metric_header(
        &mut out,
        "logfold_lines_total",
        "gauge",
        "Total raw lines folded across all patterns.",
    );
    out.push_str(&format!("logfold_lines_total {total_lines}\n"));

    push_metric_header(
        &mut out,
        "logfold_uptime_seconds",
        "counter",
        "Seconds since the metrics server started.",
    );
    out.push_str(&format!("logfold_uptime_seconds {uptime}\n"));

    push_metric_header(
        &mut out,
        "logfold_build_info",
        "gauge",
        "Build info; constant 1 with the version label.",
    );
    out.push_str(&format!(
        "logfold_build_info{{version=\"{}\"}} 1\n",
        env!("CARGO_PKG_VERSION")
    ));

    push_metric_header(
        &mut out,
        "logfold_patterns_by_bundle",
        "gauge",
        "Per-bundle pattern count.",
    );
    for (bundle, count) in by_bundle {
        out.push_str(&format!(
            "logfold_patterns_by_bundle{{bundle=\"{}\"}} {count}\n",
            escape_label(bundle)
        ));
    }
    out
}

fn push_metric_header(out: &mut String, name: &str, ty: &str, help: &str) {
    out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} {ty}\n"));
}

fn escape_label(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_includes_core_metrics() {
        let reg = PatternRegistry::new(1024);
        let out = render(&reg, Instant::now());
        assert!(out.contains("logfold_patterns_total 0"));
        assert!(out.contains("logfold_lines_total 0"));
        assert!(out.contains("logfold_build_info{version="));
        assert!(out.contains("# HELP"));
        assert!(out.contains("# TYPE"));
    }

    #[test]
    fn escape_label_handles_quotes_and_backslashes() {
        assert_eq!(escape_label("foo\"bar"), "foo\\\"bar");
        assert_eq!(escape_label("a\\b"), "a\\\\b");
    }
}
