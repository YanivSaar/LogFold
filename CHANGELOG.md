# Changelog

Notable changes per release. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/) and the project
tracks [Semantic Versioning](https://semver.org/) on the public
CLI surface and bundle schema.


## [Unreleased]

### Added
- `.github/workflows/ci.yml` runs fmt, clippy, tests on Linux and
  macOS, MSRV check against Rust 1.75, musl build sanity check,
  and `cargo audit` on every push and PR to main.
- `.github/workflows/release.yml` cross-compiles for six targets
  (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`,
  `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
  `x86_64-apple-darwin`, `aarch64-apple-darwin`) on tag push,
  gates on a format/clippy/test pre-release pass, uploads
  tarballs with SHA-256 checksums to the GitHub Release.
- `.github/workflows/audit.yml` runs a weekly cargo-audit and
  cargo-outdated check.
- `.github/dependabot.yml` groups patch and minor updates weekly.


## [0.1.0] - 2026-10-24

First tagged release.

### Added
- **Engine.** Byte-level tokenizer, skeleton builder with typed
  slots (`{IP}`, `{USER}`, `{NUM}`, ...), sharded `DashMap`
  registry (FNV-1a hash + ahash), fuzzy clustering via bounded
  token Levenshtein, lazy Count-Min Sketch per variable, 24-bucket
  rate ring over a 2-hour window.
- **Anomaly scoring.** Composite score from frequency, rate spike,
  cross-correlation, path suspicion, and severity hint. Badges:
  `NEW`, `RARE`, `SPIKE`, `CROSS`, `NORM`, `FOLD`.
- **Format detection.** Path-hint and line-probe FSM with a 500ms
  decision timeout. Specificity-aware scoring beats generic
  bundles on content that fits both.
- **TUI.** `ratatui`-based Overview, Detail, Sources, Timeline
  views at 20 Hz. Help overlay. Panic hook restores raw mode.
- **20 pattern bundles.** Auth (sshd, sudo, su, pam), web (nginx,
  apache), mail (postfix), database (postgres, mysql), firewall
  (iptables), containers (docker, k8s-kubelet), VPN (openvpn),
  security (fail2ban, modsec, auditd), system logs.
- **ModSecurity audit log support.** `A..Z` section marker
  grouping before folding, works for v2 serial format.
- **Streaming.** `--follow` with inode-aware rotation detection
  via `notify`, multiline assembly with 500ms flush, stdin tail.
- **Output modes.** TUI, plain-text table, JSON array, NDJSON.
- **Learn mode.** `--learn` exports observed patterns as a
  committable TOML bundle grouped by inferred source.

### Security
- Lossy UTF-8 reader with a 1 MiB per-line cap.
- Control-character stripping in the tokenizer blocks ANSI/CSI
  injection into the TUI or saved output.
- User-supplied bundles compiled with `RegexSetBuilder::size_limit`
  and `dfa_size_limit` of 100 KB each.
- Bundle id whitelist rejects path-traversal patterns in
  `--learn` output paths.
- Symlink and non-regular-file warnings before opening sources.
- Panic hook restores terminal state on crash in TUI mode.
- Full threat model documented in `SECURITY.md`.

### Performance
- About 1.29 M lines/sec on the fold hot path (single thread,
  release build, synthetic sshd lines; measured with the
  Criterion `hot_path` bench).

### Known gaps
Carried forward as audit items for v0.12:
- No LRU eviction when `--max-patterns` is hit (silent drop).
- Memory bound is advisory, not enforced.
- No per-match regex wall-clock timeout.
- No chroot or seccomp sandbox for root deployments.


[Unreleased]: https://github.com/YanivSaar/LogFold/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/YanivSaar/LogFold/releases/tag/v0.1.0
