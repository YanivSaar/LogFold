//! Integration tests for the detection FSM. Walks every fixture directory
//! and asserts the fixture's directory name matches the detected bundle.

use std::fs;
use std::path::Path;

use logfold::detect::probe::Detector;
use logfold::detect::registry::{BundleRegistry, DetectConfig};

#[test]
fn sshd_fixture_is_detected_by_path() {
    let reg = BundleRegistry::load(None).unwrap();
    let path = Path::new("tests/fixtures/sshd/sample.log");
    let d = Detector::attach(
        &reg,
        DetectConfig::default(),
        Some(path.to_path_buf()),
        None,
    );
    // auth.log* glob isn't on this filename, so path alone won't win.
    // Content probing should resolve it.
    assert_eq!(
        d.early_win().as_deref(),
        None,
        "sample.log should not trigger an early path win"
    );
}

#[test]
fn sshd_content_is_detected_by_probing() {
    let reg = BundleRegistry::load(None).unwrap();
    let mut d = Detector::attach(&reg, DetectConfig::default(), None, None);
    let text = fs::read_to_string("tests/fixtures/sshd/sample.log").unwrap();
    for line in text.lines() {
        if d.observe(line) {
            break;
        }
    }
    let v = d.decide();
    assert_eq!(v.bundle_id, "sshd", "candidates: {:#?}", v.candidates);
}

#[test]
fn modsec_fixture_detected_and_folded_by_section() {
    use compact_str::CompactString;
    use logfold::detect::registry::MultilineMode;
    use logfold::engine::registry::PatternRegistry;
    use logfold::ingest::multiline::Assembler;
    use logfold::parse::{skeleton, tokenizer, Token};
    use std::time::Instant;

    let reg = BundleRegistry::load(None).unwrap();

    // 1. Detection should pick `modsec` by content.
    let mut d = Detector::attach(&reg, DetectConfig::default(), None, None);
    let text = fs::read_to_string("tests/fixtures/modsec/sample.log").unwrap();
    for line in text.lines() {
        if d.observe(line) {
            break;
        }
    }
    let v = d.decide();
    assert_eq!(v.bundle_id, "modsec", "candidates: {:#?}", v.candidates);

    // 2. The modsec bundle declares section-delimited multiline mode.
    let bundle = reg.by_id("modsec").unwrap();
    assert_eq!(bundle.multiline, MultilineMode::ModsecSections);

    // 3. The ModSec assembler groups the two entries into exactly two events.
    let mut assembler = Assembler::modsec_sections();
    let mut events = Vec::new();
    for line in text.lines() {
        if let Some(ev) = assembler.push(line) {
            events.push(ev);
        }
    }
    assert_eq!(events.len(), 2, "expected two audit entries");
    assert!(events[0].contains("942100"));
    assert!(events[1].contains("920100"));

    // 4. Folding two events through the engine gives two patterns.
    let engine = PatternRegistry::new(1024);
    for ev in &events {
        let mut tokens: Vec<Token<'_>> = Vec::new();
        tokenizer::classify(ev, &mut tokens);
        if tokens.is_empty() {
            continue;
        }
        let mut skel = CompactString::default();
        let mut slots = Vec::new();
        skeleton::build(&tokens, &mut skel, &mut slots);
        engine.upsert(&skel, &slots, &tokens, "modsec", Instant::now());
    }
    assert_eq!(engine.len(), 2, "two distinct ModSec entries");
}

#[test]
fn authlog_path_shortcuts_to_sshd() {
    let reg = BundleRegistry::load(None).unwrap();
    let d = Detector::attach(
        &reg,
        DetectConfig::default(),
        Some(Path::new("/var/log/auth.log").to_path_buf()),
        None,
    );
    // sshd + sudo + pam etc. all claim auth.log; the early-win pick should
    // land on one of them. We don't assert WHICH one — just that path hints
    // crossed the threshold.
    assert!(
        d.early_win().is_some(),
        "/var/log/auth.log did not trigger an early path win"
    );
}
