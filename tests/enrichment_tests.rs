//! v0.7: IOC enrichment integration tests.

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use compact_str::CompactString;
use logfold::engine::pattern::{PatternSnapshot, VarStatsSnapshot};
use logfold::enrich::{self, Enricher};
use logfold::types::{Severity, TokenType};
use std::time::Instant;

fn write_tmp_csv(contents: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "logfold-enrich-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("iocs.csv");
    let mut f = File::create(&path).unwrap();
    f.write_all(contents.as_bytes()).unwrap();
    path
}

fn snap_with_ip(ip: &str) -> PatternSnapshot {
    PatternSnapshot {
        id: 1,
        skeleton: CompactString::new("Failed login from {IP}"),
        label: None,
        bundle_id: CompactString::new("sshd"),
        severity_hint: Severity::Low,
        count: 1,
        first_seen: Instant::now(),
        last_seen: Instant::now(),
        peak_bucket: 1,
        mean_bucket: 0.1,
        rate_buckets: [0; 24],
        last_bucket_epoch: 0,
        vars: vec![VarStatsSnapshot {
            ty: TokenType::Ip,
            distinct_approx: 1,
            total: 1,
            top: vec![(CompactString::new(ip), 1)],
        }],
    }
}

#[test]
fn ioc_hit_adds_score_bump() {
    let csv = write_tmp_csv("203.0.113.5,CERT-FR,high\n");
    let enricher = Enricher::load(Some(&csv), None).unwrap();
    let snap = snap_with_ip("203.0.113.5");
    assert_eq!(enrich::score_bump(&snap, &enricher), enrich::IOC_SCORE_BUMP);
}

#[test]
fn ioc_miss_adds_nothing() {
    let csv = write_tmp_csv("1.2.3.4,CERT-FR,high\n");
    let enricher = Enricher::load(Some(&csv), None).unwrap();
    let snap = snap_with_ip("203.0.113.5");
    assert_eq!(enrich::score_bump(&snap, &enricher), 0);
}

#[test]
fn pattern_annotations_dedup_across_vars() {
    let csv = write_tmp_csv("203.0.113.5,CERT-FR,high\n");
    let enricher = Enricher::load(Some(&csv), None).unwrap();
    let mut snap = snap_with_ip("203.0.113.5");
    // Add a second variable also containing the IP, same tag should fire once.
    snap.vars.push(VarStatsSnapshot {
        ty: TokenType::Ip,
        distinct_approx: 1,
        total: 1,
        top: vec![(CompactString::new("203.0.113.5"), 1)],
    });
    let anns = enrich::pattern_annotations(&snap, &enricher);
    assert_eq!(anns.len(), 1);
    match &anns[0] {
        enrich::Annotation::Ioc(m) => {
            assert_eq!(m.source.as_str(), "CERT-FR");
            assert_eq!(m.severity.as_str(), "high");
        }
        #[allow(unreachable_patterns)]
        _ => panic!("expected IOC annotation"),
    }
}

#[test]
fn empty_enricher_is_cheap_noop() {
    let enricher = Enricher::empty();
    assert!(enricher.is_empty());
    let snap = snap_with_ip("203.0.113.5");
    assert_eq!(enrich::score_bump(&snap, &enricher), 0);
    assert!(enrich::pattern_annotations(&snap, &enricher).is_empty());
}
