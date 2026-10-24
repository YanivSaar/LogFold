//! Webhook / Slack / PagerDuty sink. v0.6.
//!
//! `WebhookSink` is created once at startup from CLI flags. Each
//! snapshot pass calls [`WebhookSink::try_notify`] on every pattern;
//! the sink filters by badge (NEW, SPIKE, CROSS only), score
//! threshold, and a per-pattern cool-down window before firing a
//! fire-and-forget tokio task that POSTs the alert payload.
//!
//! Flavours:
//! - [`Flavor::Generic`] - raw JSON of the pattern snapshot.
//! - [`Flavor::Slack`] - `{"text": "<markdown>"}` for Slack
//!   Incoming Webhooks.
//! - [`Flavor::PagerDuty`] - Events API v2 payload.
//!
//! Hot-path cost: one HashMap lookup under a short mutex per pattern,
//! then an async POST on firing. The POST runs in the background so
//! the fold path never blocks on the network.

#![cfg(feature = "webhook")]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use color_eyre::eyre::{Context, Result};
use parking_lot::Mutex;
use serde::Serialize;

use crate::engine::pattern::PatternSnapshot;
use crate::types::Badge;

/// Which payload shape to emit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Flavor {
    #[default]
    Generic,
    Slack,
    PagerDuty,
}

impl Flavor {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "generic" | "json" => Some(Flavor::Generic),
            "slack" => Some(Flavor::Slack),
            "pagerduty" | "pd" => Some(Flavor::PagerDuty),
            _ => None,
        }
    }
}

/// Configuration consumed by [`WebhookSink::new`].
#[derive(Debug, Clone)]
pub struct Config {
    pub url: String,
    pub flavor: Flavor,
    pub min_score: u32,
    pub dedup: Duration,
    /// PagerDuty routing key, required for `Flavor::PagerDuty`.
    pub pagerduty_routing_key: Option<String>,
}

/// A webhook sink. Cloneable; the internal state is Arc-shared.
#[derive(Clone)]
pub struct WebhookSink {
    cfg: Arc<Config>,
    client: reqwest::Client,
    last_sent: Arc<Mutex<HashMap<u64, Instant>>>,
}

impl WebhookSink {
    pub fn new(cfg: Config) -> Result<Self> {
        if matches!(cfg.flavor, Flavor::PagerDuty) && cfg.pagerduty_routing_key.is_none() {
            color_eyre::eyre::bail!(
                "pagerduty flavor requires a routing key (set --webhook-pd-routing-key)"
            );
        }
        let client = reqwest::Client::builder()
            .user_agent(concat!("logfold/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(10))
            .build()
            .context("building reqwest client")?;
        Ok(WebhookSink {
            cfg: Arc::new(cfg),
            client,
            last_sent: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Consider firing a webhook for `snap`. No-op when the badge
    /// isn't actionable, the score is below threshold, or the
    /// per-pattern cool-down window is still active.
    pub fn try_notify(&self, snap: &PatternSnapshot, score: u32, badge: Badge) {
        if score < self.cfg.min_score {
            return;
        }
        if !matches!(badge, Badge::New | Badge::Spike | Badge::Cross) {
            return;
        }
        let now = Instant::now();
        {
            let mut dedup = self.last_sent.lock();
            if let Some(&last) = dedup.get(&snap.id) {
                if now.duration_since(last) < self.cfg.dedup {
                    return;
                }
            }
            dedup.insert(snap.id, now);
        }
        self.fire(snap.clone(), score, badge);
    }

    fn fire(&self, snap: PatternSnapshot, score: u32, badge: Badge) {
        let cfg = self.cfg.clone();
        let client = self.client.clone();
        tokio::spawn(async move {
            let body = render_payload(&cfg, &snap, score, badge);
            let req = client.post(&cfg.url).json(&body);
            match req.send().await {
                Ok(resp) if resp.status().is_success() => {
                    tracing::debug!(url = %cfg.url, badge = %badge.label(), score, "webhook posted");
                }
                Ok(resp) => {
                    tracing::warn!(
                        url = %cfg.url,
                        status = %resp.status(),
                        badge = %badge.label(),
                        "webhook returned non-2xx"
                    );
                }
                Err(e) => {
                    tracing::warn!(url = %cfg.url, error = %e, "webhook POST failed");
                }
            }
        });
    }
}

fn render_payload(
    cfg: &Config,
    snap: &PatternSnapshot,
    score: u32,
    badge: Badge,
) -> serde_json::Value {
    match cfg.flavor {
        Flavor::Generic => serde_json::to_value(GenericPayload {
            event: "logfold.anomaly",
            badge: badge.label(),
            score,
            bundle: snap.bundle_id.as_str(),
            pattern: snap.skeleton.as_str(),
            count: snap.count,
            peak_bucket: snap.peak_bucket,
        })
        .unwrap_or(serde_json::Value::Null),
        Flavor::Slack => serde_json::to_value(SlackPayload {
            text: format!(
                ":rotating_light: *[{badge}]* score {score} in bundle `{bundle}`\n`{skel}` (count {count}, peak/5m {peak})",
                badge = badge.label(),
                bundle = snap.bundle_id,
                skel = snap.skeleton,
                count = snap.count,
                peak = snap.peak_bucket,
            ),
        })
        .unwrap_or(serde_json::Value::Null),
        Flavor::PagerDuty => {
            let routing_key = cfg.pagerduty_routing_key.clone().unwrap_or_default();
            serde_json::to_value(PdPayload {
                routing_key,
                event_action: "trigger",
                dedup_key: format!("logfold:{}", snap.id),
                payload: PdPayloadBody {
                    summary: format!(
                        "[{}] {} in {}",
                        badge.label(),
                        snap.skeleton,
                        snap.bundle_id,
                    ),
                    source: snap.bundle_id.to_string(),
                    severity: pd_severity(badge),
                    custom_details: PdCustomDetails {
                        badge: badge.label(),
                        score,
                        pattern: snap.skeleton.as_str(),
                        bundle: snap.bundle_id.as_str(),
                        count: snap.count,
                        peak_bucket: snap.peak_bucket,
                    },
                },
            })
            .unwrap_or(serde_json::Value::Null)
        }
    }
}

fn pd_severity(badge: Badge) -> &'static str {
    match badge {
        Badge::New | Badge::Cross => "error",
        Badge::Spike => "warning",
        _ => "info",
    }
}

#[derive(Serialize)]
struct GenericPayload<'a> {
    event: &'static str,
    badge: &'static str,
    score: u32,
    bundle: &'a str,
    pattern: &'a str,
    count: u64,
    peak_bucket: u32,
}

#[derive(Serialize)]
struct SlackPayload {
    text: String,
}

#[derive(Serialize)]
struct PdPayload<'a> {
    routing_key: String,
    event_action: &'static str,
    dedup_key: String,
    payload: PdPayloadBody<'a>,
}

#[derive(Serialize)]
struct PdPayloadBody<'a> {
    summary: String,
    source: String,
    severity: &'static str,
    custom_details: PdCustomDetails<'a>,
}

#[derive(Serialize)]
struct PdCustomDetails<'a> {
    badge: &'static str,
    score: u32,
    pattern: &'a str,
    bundle: &'a str,
    count: u64,
    peak_bucket: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use compact_str::CompactString;

    fn snap_for(id: u64, badge_hint: &str) -> PatternSnapshot {
        PatternSnapshot {
            id,
            skeleton: CompactString::new(format!("test pattern {id} {badge_hint}")),
            label: None,
            bundle_id: CompactString::new("test"),
            severity_hint: crate::types::Severity::Info,
            count: 1,
            first_seen: Instant::now(),
            last_seen: Instant::now(),
            peak_bucket: 1,
            mean_bucket: 0.1,
            rate_buckets: [0; 24],
            last_bucket_epoch: 0,
            vars: vec![],
        }
    }

    #[tokio::test]
    async fn below_min_score_is_dropped() {
        let sink = WebhookSink::new(Config {
            url: "http://127.0.0.1:1".into(),
            flavor: Flavor::Generic,
            min_score: 50,
            dedup: Duration::from_secs(60),
            pagerduty_routing_key: None,
        })
        .unwrap();
        sink.try_notify(&snap_for(1, "low"), 10, Badge::New);
        // No panic; nothing to assert beyond that. Dedup table stays empty.
        assert!(sink.last_sent.lock().is_empty());
    }

    #[tokio::test]
    async fn non_actionable_badge_is_dropped() {
        let sink = WebhookSink::new(Config {
            url: "http://127.0.0.1:1".into(),
            flavor: Flavor::Generic,
            min_score: 0,
            dedup: Duration::from_secs(60),
            pagerduty_routing_key: None,
        })
        .unwrap();
        sink.try_notify(&snap_for(2, "norm"), 100, Badge::Norm);
        sink.try_notify(&snap_for(3, "fold"), 100, Badge::Fold);
        assert!(sink.last_sent.lock().is_empty());
    }

    #[tokio::test]
    async fn dedup_window_blocks_second_notify() {
        let sink = WebhookSink::new(Config {
            url: "http://127.0.0.1:1".into(),
            flavor: Flavor::Generic,
            min_score: 0,
            dedup: Duration::from_secs(60),
            pagerduty_routing_key: None,
        })
        .unwrap();
        sink.try_notify(&snap_for(10, "first"), 100, Badge::New);
        let after_first = sink.last_sent.lock().get(&10).copied();
        assert!(after_first.is_some());
        // Second call within the dedup window should not update the timestamp.
        std::thread::sleep(Duration::from_millis(10));
        sink.try_notify(&snap_for(10, "second"), 100, Badge::New);
        let after_second = sink.last_sent.lock().get(&10).copied();
        assert_eq!(after_first, after_second);
    }

    #[test]
    fn flavor_parses_known_values() {
        assert_eq!(Flavor::parse("slack"), Some(Flavor::Slack));
        assert_eq!(Flavor::parse("SLACK"), Some(Flavor::Slack));
        assert_eq!(Flavor::parse("pd"), Some(Flavor::PagerDuty));
        assert_eq!(Flavor::parse("nope"), None);
    }

    #[test]
    fn pagerduty_requires_routing_key() {
        let err = WebhookSink::new(Config {
            url: "http://127.0.0.1:1".into(),
            flavor: Flavor::PagerDuty,
            min_score: 0,
            dedup: Duration::from_secs(60),
            pagerduty_routing_key: None,
        })
        .err()
        .expect("should bail");
        let msg = format!("{err}");
        assert!(msg.contains("routing key"));
    }
}
