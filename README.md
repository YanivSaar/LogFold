# logfold

> Zero-config log pattern folder and anomaly detector.

`logfold` reads any log stream, collapses repetitive noise into counted
patterns, and surfaces anomalies at the top — all inside a ratatui TUI.
Pipe anything in; get instant signal.

```sh
logfold /var/log/auth.log                       # single file, TUI
logfold /var/log/auth.log --no-tui              # plain-text table
tail -f /var/log/nginx/access.log | logfold     # live stdin
logfold /var/log/*.log --no-tui --json          # scripting
logfold -f /var/log/syslog                      # follow (tail -f)
logfold /var/log/auth.log --learn               # export learned bundles
```

## Status

**v0.1 engine complete.** All six phases of the engineering plan have
landed; the project is in use-and-iterate territory now.

| Phase | What ships | State |
|------:|-----------:|-------|
| P1 | Core engine: tokenize → skeleton → fold → score, plain-text output | ✓ |
| P2 | Bundle loader + detection FSM, ~20 bundles | ✓ |
| P3 | Ratatui TUI with four views, status bar, help overlay | ✓ |
| P4 | File watcher (notify, inode rotation), multiline, live redraw | ✓ |
| P5 | JSON / NDJSON output, `--learn` bundle export | ✓ |
| P6 | Criterion bench harness | ✓ |

Measured on `cargo bench`: **~1.29 M lines/sec** on the fold hot path
(release build, single thread, synthetic sshd lines) — exceeds the
500k target.

Still to come (post-v0.1): journald source (feature-gated, Linux only),
Prometheus `/metrics`, webhook sink, compressed input (`.gz`/`.zst`),
clipboard copy, Timeline/Detail view polish, and the bundle grind from
20 → 120.

## Design notes

Deviations from the original product brief, each a deliberate call:

- **Streaming-friendly detection** — the detector buffers up to
  `--probe-lines` events (or 500 ms) and replays them once a bundle is
  chosen; the brief implied a static first-N read, which doesn't work on
  live tails.
- **Specificity-aware probing** — a bundle's probe score blends ratio
  with how many *distinct* probe anchors matched, so a specific bundle
  (sshd, 6 probes, 4 matched) beats a generic one (syslog, 1 probe, 1
  matched) on content that fits both.
- **Lazy variable sketches** — a variable keeps an exact `IndexMap` up
  to 32 distinct values, promoted to a Count-Min Sketch beyond that.
  Keeps memory bounded without losing precision on the common case.
- **Extra deps** beyond the brief: `globset`, `tracing`, `color-eyre`,
  `smallvec`, `include_dir`, `insta`, `proptest`, `criterion`.

## Build

```sh
cargo build --release                                  # default: TUI + watcher
cargo build --release --no-default-features --features tui
cargo test --features "tui watcher"
cargo bench --bench hot_path
```

## CLI quick reference

```
logfold [OPTIONS] [SOURCE...]

  -w, --window <DUR>        time window (post-v0.1)
  -t, --top <N>             show top N anomalies [default: 20]
  -m, --min-fold <N>        min count for FOLD badge [default: 3]
  -T, --threshold <SCORE>   min score to appear in ANOMALIES [default: 40]
  -b, --bundle <ID>         force a specific bundle (skip detection)
  -P, --patterns-dir <DIR>  load additional *.toml bundles
  -f, --follow              tail -f each file source
      --probe-lines <N>     lines sampled before deciding [default: 64]
      --no-tui              plain-text output
      --json / --ndjson     JSON output (requires --no-tui)
      --learn               export learned bundles on exit
      --learn-out <DIR>     where to write learned bundles [default: ./learned]
      --learn-min <N>       min count to include [default: 5]
      --max-patterns <N>    soft cap in memory [default: 100_000]
  -q, --quiet               suppress banner
  -v, --verbose             debug-level tracing
```

## License

Dual licensed under MIT or Apache 2.0, at your option.
