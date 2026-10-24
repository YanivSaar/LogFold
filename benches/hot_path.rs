//! Hot-path microbenches. Target: 500k lines/sec by P6.
//!
//! Run with `cargo bench --bench hot_path`.

use std::time::Instant;

use compact_str::CompactString;
use criterion::{criterion_group, criterion_main, Criterion};

use logfold::engine::registry::PatternRegistry;
use logfold::parse::{skeleton, tokenizer};

const SAMPLE: &[&str] = &[
    "Jan 10 12:34:56 host sshd[123]: Failed password for alice from 10.0.0.1 port 22 ssh2",
    "Jan 10 12:34:57 host sshd[124]: Failed password for bob from 10.0.0.2 port 22 ssh2",
    "Jan 10 12:34:58 host sshd[125]: Accepted publickey for carol from 10.0.0.3 port 22 ssh2",
    "Jan 10 12:35:00 host sshd[126]: Connection closed by 10.0.0.4 port 22 [preauth]",
];

fn bench_hot_path(c: &mut Criterion) {
    c.bench_function("fold_1k_lines", |b| {
        b.iter(|| {
            let reg = PatternRegistry::new(1024);
            let mut tokens = Vec::with_capacity(32);
            let mut skel = CompactString::default();
            let mut slots = Vec::with_capacity(8);
            for _ in 0..1_000 {
                for line in SAMPLE {
                    tokenizer::classify(line, &mut tokens);
                    skeleton::build(&tokens, &mut skel, &mut slots);
                    reg.upsert(&skel, &slots, &tokens, "unknown", Instant::now());
                }
            }
            reg
        })
    });
}

criterion_group!(benches, bench_hot_path);
criterion_main!(benches);
