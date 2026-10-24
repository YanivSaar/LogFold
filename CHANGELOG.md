# Changelog

Notable changes per release. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/) and the project
tracks [Semantic Versioning](https://semver.org/) on the public
CLI surface and bundle schema.


## [Unreleased]

### Added (v0.2 work)
- `src/parse/formats/syslog.rs`: RFC 3164 and 5424 parser. Strips the
  envelope (`<pri>`, timestamp, hostname, `process[pid]:`) so the fold
  hot path only sees the free-form `msg` body. 7 unit tests cover
  classic sshd shape, single-digit day padding, optional `<pri>`,
  5424 with and without structured data, and non-syslog fall-through.
- `ParseFormat` enum (`Raw` default, `Syslog`). `[parse] format = "..."`
  per bundle controls which path runs.
- `ParseSpec` struct carries bundle_id, format, multiline, and
  context_types through the fold path so follow-mode threads don't
  need the `BundleRegistry` on the hot path.
- `format = "syslog"` enabled on sshd, sudo, su, pam, cron, kern,
  syslog, postfix, iptables, fail2ban. ModSec and web bundles stay
  on raw tokenisation.
- Bundle `[[context_types]]` honored by the skeleton builder. Rules
  of the form `{ after = "<word>", type = "<TAG>" }` promote the
  WORD or NUM token immediately after a matching anchor to a typed
  slot. Case-insensitive match. Only WORD/NUM are promotable;
  already-specific types (IP, Email, Url, Path, Uuid, Hash, Date)
  stay as-is to avoid clobbering strong structural signals.
- sshd, sudo, su, pam bundles declare their context rules
  (`for→USER`, `user→USER`, `port→PORT`, `by→USER`).
- `tests/syslog_tests.rs` and `tests/context_types_tests.rs`: prove
  envelope stripping plus context promotion collapse the sshd
  fixture from ~10 patterns at v0.1 to ≤6 at v0.2, and that
  user/port tokens fold across the fixture.


## [0.1.1] - 2026-10-24

First distributable release. Same engine as v0.1.0 plus the
release pipeline, the one-liner installer, and the CI gates that
make v0.1 actually usable from a cold install. v0.1.0 remains as
a historical tag with no release artifacts attached.

### Added
- `.github/workflows/ci.yml` runs fmt, clippy, tests on Linux and
  macOS, MSRV check against Rust 1.75, musl build sanity check,
  and `cargo audit` (continue-on-error, advisory) on every push
  and PR to main.
- `.github/workflows/release.yml` cross-compiles for six targets
  (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`,
  `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
  `x86_64-apple-darwin`, `aarch64-apple-darwin`) on tag push,
  gates on a format/clippy/test pre-release pass, uploads
  tarballs with SHA-256 checksums plus `install.sh` to the
  GitHub Release.
- `.github/workflows/audit.yml` runs a weekly cargo-audit and
  cargo-outdated check (strict, opens issues).
- `.github/dependabot.yml` groups patch and minor updates weekly.
- `install.sh` one-liner installer that detects OS/arch, pulls
  the matching release tarball, verifies SHA-256, and installs
  to `/usr/local/bin` or `$HOME/.local/bin`. Served from main
  and included in every release.
- README gains full install matrix across distros, install
  one-liner, uninstall paths covering every install source.

### Fixed
- `--no-default-features` build broken by unused `AtomicBool`,
  `Ordering`, and `Arc` imports plus a dead `ctrlc_once` function.
  All now feature-gated behind the modules that use them.


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


[Unreleased]: https://github.com/YanivSaar/LogFold/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/YanivSaar/LogFold/releases/tag/v0.1.1
[0.1.0]: https://github.com/YanivSaar/LogFold/releases/tag/v0.1.0
