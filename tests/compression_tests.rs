//! v0.5: compressed input (.gz, .zst) tests.
//!
//! Compresses the sshd fixture into a tempfile, drives the engine
//! over it through `drive_source`, and asserts the fold result
//! matches the uncompressed baseline.

#![cfg(feature = "compression")]

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use logfold::detect::registry::{BundleRegistry, DetectConfig};
use logfold::engine::registry::PatternRegistry;
use logfold::ingest::source::{self, SourceKind};

fn baseline_pattern_count() -> usize {
    let bundles = BundleRegistry::load(None).unwrap();
    let eng = PatternRegistry::new(1024);
    let path = PathBuf::from("tests/fixtures/sshd/sample.log");
    source::drive_source(
        &SourceKind::File(path),
        &eng,
        &bundles,
        DetectConfig::default(),
        None,
        None,
        None,
    )
    .unwrap();
    eng.len()
}

#[test]
fn gz_file_folds_same_as_plain() {
    let text = std::fs::read("tests/fixtures/sshd/sample.log").unwrap();

    let tmp = tempdir();
    let gz_path = tmp.join("sample.log.gz");
    {
        let f = File::create(&gz_path).unwrap();
        let mut enc = flate2::write::GzEncoder::new(f, flate2::Compression::default());
        enc.write_all(&text).unwrap();
        enc.finish().unwrap();
    }

    let bundles = BundleRegistry::load(None).unwrap();
    let eng = PatternRegistry::new(1024);
    source::drive_source(
        &SourceKind::File(gz_path),
        &eng,
        &bundles,
        DetectConfig::default(),
        None,
        None,
        None,
    )
    .unwrap();
    assert_eq!(eng.len(), baseline_pattern_count());
}

#[test]
fn zst_file_folds_same_as_plain() {
    let text = std::fs::read("tests/fixtures/sshd/sample.log").unwrap();

    let tmp = tempdir();
    let zst_path = tmp.join("sample.log.zst");
    {
        let f = File::create(&zst_path).unwrap();
        let mut enc = zstd::stream::write::Encoder::new(f, 3).unwrap();
        enc.write_all(&text).unwrap();
        enc.finish().unwrap();
    }

    let bundles = BundleRegistry::load(None).unwrap();
    let eng = PatternRegistry::new(1024);
    source::drive_source(
        &SourceKind::File(zst_path),
        &eng,
        &bundles,
        DetectConfig::default(),
        None,
        None,
        None,
    )
    .unwrap();
    assert_eq!(eng.len(), baseline_pattern_count());
}

fn tempdir() -> PathBuf {
    // We don't take a `tempfile` dep for this one test; just carve out
    // a unique dir under the OS temp root and leak it (small, test-only).
    let base = std::env::temp_dir();
    let unique = format!(
        "logfold-compression-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let p = base.join(unique);
    std::fs::create_dir_all(&p).unwrap();
    p
}
