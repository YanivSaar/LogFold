# Changelog

Notable changes per release. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/) and the project
tracks [Semantic Versioning](https://semver.org/) on the public
CLI surface and bundle schema.


## [Unreleased]

(nothing yet)


## [0.12.1] - 2026-10-24

Install UX cleanup.

### Added
- `logfold --uninstall` built-in uninstaller. Prints the exact
  dry-run plan (binary + user patterns dir + system patterns dir
  + state dir + learn-mode output), prompts for confirmation,
  removes what the user approves. `--yes` skips the prompt for
  scripts. Sudo-only operations (service user, systemd unit,
  ACLs) are printed as commands rather than attempted.

### Removed
- `install.sh` and the `curl ... | bash` one-liner. The release
  workflow no longer uploads `install.sh` as a release asset.
- README "Package managers" matrix. The planned-but-not-shipped
  distro packages were misleading inventory; the right path is
  the release tarball or `cargo install`.
- Duplicate "Running as a service" section lower in the README.
  Service setup now lives in a single section alongside install.

### Changed
- README install section rewritten with two paths: release
  tarball (step-by-step, with checksum verification) and
  source build (clone + `cargo build --release`).
- README uninstall section points at `logfold --uninstall`
  instead of the per-platform shell list.
- CLI reference block in the README now covers every v0.1-v0.12
  flag the binary ships, including `--iocs`, `--geoip`,
  `--state`, `--webhook*`, `--prom-listen`, `--lint`,
  `--uninstall`.


## [0.12.0] - 2026-10-24

Fifth scheduled release in the "release every 3 versions" cadence.
Rolls up v0.11 (bundle linter + catalog expansion) and v0.12
(audit tooling + dependency sweep).

This is the pre-v1.0 audit checkpoint. The engine, CLI, bundle
schema, and output formats are now considered stable for the
purposes of patch releases; semver-visible breakage will land
with a v1.0.0 tag you cut when you're ready.

### Added (v0.12 work)
- `tests/fuzz_proptest.rs`: proptest coverage over the parse hot
  path. 2048 cases each on the tokenizer, skeleton builder, and
  every structured format parser (syslog, json, kv, cef, leef).
  No panics, no crashes, deterministic output for the same input.
- `deny.toml`: cargo-deny policy. Allow-list MIT / Apache / BSD /
  ISC / MPL / Unicode / Zlib / Unlicense / 0BSD, deny unknown
  registries and git sources, warn on multi-version pulls.
- Documented ignores for the three ratatui-transitive advisories
  (paste 1.0.15, lru 0.12.5 x2) with pointers to the ratatui 0.30
  bump that closed them.
- `cargo deny check` wired into the weekly audit workflow via
  `EmbarkStudios/cargo-deny-action@v2`.

### Changed
- Dependency sweep: ratatui 0.27 -> 0.30.2, crossterm 0.27 ->
  0.29, compact_str 0.7 -> 0.10, toml 0.8 -> 1.1, notify 6 -> 8,
  criterion 0.5 -> 0.8. ratatui breakage: `Frame::size()` ->
  `Frame::area()`, `Table::highlight_style` -> `row_highlight_style`.
  Everything else was a clean bump.
- The three cargo-audit advisories flagged on v0.1.1 are no
  longer flagged (paste and lru 0.12.5 both dropped out of the
  dep tree with the ratatui upgrade).
- GitHub Actions: `softprops/action-gh-release` -> v3,
  `actions/upload-artifact` -> v7, `actions/download-artifact`
  -> v8. `dtolnay/rust-toolchain` is now dependabot-ignored
  since its "versions" are Rust toolchain tags, not action
  releases.

### Known gaps carried into v1.0
Documented in `SECURITY.md`:
- No LRU eviction on `--max-patterns` cap (silent drop).
- Memory bound is advisory, not enforced.
- No per-match regex wall-clock timeout.
- No chroot/seccomp sandbox beyond the systemd unit's hardening.

### Added (v0.11 work)
- `logfold --lint <path>` subcommand validates one or more TOML
  bundles. Walks directories, prints `ok` / `err` per file, exits
  non-zero when any bundle fails to parse or compile. Runs under
  `Trust::Builtin` so the author doesn't trip over user-regex
  size limits during local authoring.
- `src/detect/registry.rs::lint_bundle_file()` surfaces the full
  error chain (`{err:#}` formatting) so the lint output names the
  offending regex, glob, or missing field.
- Catalog grew from 27 to 50 compiled-in bundles. New entries:
  web/caddy, web/haproxy, web/traefik, database/mongodb,
  database/redis, database/elasticsearch, firewall/nftables,
  firewall/ufw, vpn/wireguard, vpn/strongswan, vpn/tailscale,
  security/suricata, security/zeek, security/wazuh,
  cloud/aws-cloudtrail, cloud/aws-vpc-flow, cloud/cloudflare,
  containers/containerd, containers/k8s-apiserver, dns/bind,
  dns/unbound, mail/dovecot, system/systemd (journald).


## [0.10.0] - 2026-10-24

Fourth scheduled release in the "release every 3 versions" cadence.
Rolls up v0.8 (ModSec v3), v0.9 (correlation rules), v0.10
(Prometheus, state persistence, systemd packaging).

### Added (v0.10 work)
- `--state <FILE>` persists the pattern registry to disk on clean
  shutdown and reloads from it on start. Format: human-readable
  JSON, atomic write (temp + rename), schema versioned. Lets a
  `--follow` deployment survive restarts without replaying the
  log history. `src/state/mod.rs`.
- `PatternRegistry::restore_pattern` installs a prebuilt Pattern
  under its stored id, used only by the state restore path.
- `--prom-listen HOST:PORT` serves a Prometheus `/metrics`
  endpoint behind the `prometheus` cargo feature. Exposes
  `logfold_patterns_total`, `logfold_lines_total`,
  `logfold_patterns_by_bundle{bundle=...}`,
  `logfold_uptime_seconds`, and `logfold_build_info`.
  `src/metrics/mod.rs` built on hyper 1.x.
- `contrib/systemd/logfold.service` ships a hardened unit file
  with every systemd sandbox knob the SECURITY.md deployment
  recommendations call for (`NoNewPrivileges`, `ProtectSystem`,
  `MemoryDenyWriteExecute`, cleared `CapabilityBoundingSet`,
  etc.), plus a 512M `MemoryMax` ceiling.
- `contrib/systemd/README.md` walks through the one-time setup:
  dedicated service user, state directory, ACL grant, drop-in
  override for custom `ExecStart`.
- Without `--features prometheus`, `--prom-listen` logs a WARN
  and keeps running (same gentle-degrade pattern as webhook and
  compression).

### Added (v0.9 work)
- `src/rules/`: Sigma-lite correlation rule engine. Each rule
  implements the `Rule` trait: walk the snapshot set, return the
  pattern ids it wants to tag, and the engine aggregates
  per-pattern `RuleHit` records (fired rule ids + combined score
  bump). Runs on the snapshot path, not the hot path.
- Compiled-in rule pack with five rules:
  - `ssh-brute-force`: Failed-password count >= 20 in an sshd
    bundle. +25.
  - `exec-from-tmp`: PATH variable under /tmp/, /dev/shm/,
    /var/tmp/, /private/tmp/. +10 (complements the base scorer's
    `path_suspicion`).
  - `modsec-critical`: ModSec bundle with CRITICAL in the fold
    key. +30.
  - `nginx-error-flood`: web-bundle pattern with status NUM at
    count >= 100. +15.
  - `cross-sshd-brute-success`: cross-pattern. When any sshd
    Failed-password pattern has count >= 10, every sshd
    Accepted-password pattern gets +40 (classic brute-force to
    success).
- Rule bumps added into the composite score in text output,
  JSON output, and the webhook sink.
- JSON output's PatternOut gains a `rules: [&str]` field listing
  which rules fired.
- 7 unit tests covering individual rule logic and the
  aggregation path.

### Added (v0.8 work)
- `src/parse/formats/modsec_v3.rs`: ModSecurity v3 JSON serial
  audit log parser. One JSON object per transaction; extracts
  client_ip, method, uri, status, and the full ruleId list from
  `transaction.messages[].details`. Builds a synthesised fold-key
  of the form `modsec rule <id> <severity>: <msg> // <method>
  <uri> -> <status>` so unrelated attack payloads for the same
  rule fold together.
- `ParseFormat::ModsecV3` and the `format = "modsec-v3"` bundle
  opt-in.
- `patterns/security/modsec-v3.toml` bundle with path hints for
  `**/modsec_audit.log*` and line probes on the v3-specific
  fields.
- `tests/fixtures/modsec-v3/sample.log` fixture with four
  transactions (two of the same rule+severity on different URIs,
  one SQLi, one clean 200).
- `tests/modsec_v3_tests.rs` covers bundle schema, same-rule
  folding across URIs, and fixture pattern count.
- Long-message truncation in the fold key (cap 80 chars) so a
  giant embedded request body can't inflate the skeleton.


## [0.7.0] - 2026-10-24

Third scheduled release in the "release every 3 versions" cadence.
Rolls up v0.5 (compressed input + journald), v0.6 (webhook sink),
and v0.7 (IOC + GeoIP enrichment).

### Changed
- `x86_64-apple-darwin` dropped from the release matrix. Free-tier
  macOS Intel runners queue indefinitely; the target is being
  retired by Apple. Intel Mac users install via
  `cargo install logfold`. aarch64-apple-darwin (Apple Silicon)
  still ships as a prebuilt tarball.

### Added (v0.7 work)
- `src/enrich/{mod,ioc,geoip}.rs`: an `Enricher` that loads
  local IOC CSVs (indicator,source,severity) and optionally a
  MaxMind GeoIP mmdb (behind the `geoip` feature). Matching a
  variable value against the IOC set bumps the score by
  `IOC_SCORE_BUMP` (25). GeoIP contributes informational
  annotations only.
- CLI flags `--iocs <FILE>` and `--geoip <FILE>` plus a new
  `EnrichmentOptions` struct on `Config`.
- Scoring pipelines in text/JSON output, the TUI Overview, and
  the webhook sink all consult the enricher and add its score
  bump. `pattern_annotations()` produces de-duplicated tags for
  rendering (`IOC:source:severity`, `ASN:AS123 Org`, `CC:US`).
- IocSet parsing covers comments, blank lines, and
  severity-defaults-to-info; `is_safe_bundle_id`-style error
  surface so broken CSVs don't take down ingest.
- `tests/enrichment_tests.rs` covers IOC hit/miss, dedup across
  variables, and the empty-enricher cheap-noop path.

### Added (v0.6 work)
- Webhook sink behind the `webhook` cargo feature. Fires a
  fire-and-forget POST on NEW / SPIKE / CROSS badges whose score
  crosses `--webhook-min-score`.
- `src/output/webhook.rs` with a `WebhookSink` that holds a
  reqwest client plus a per-pattern cool-down map keyed by
  pattern id; a repeat alert for the same pattern inside
  `--webhook-dedup-secs` (default 300) is suppressed.
- Three payload flavors:
  - `generic` (default) - raw JSON `{event, badge, score,
    bundle, pattern, count, peak_bucket}`.
  - `slack` - `{"text": "<markdown>"}` sized for Slack Incoming
    Webhooks.
  - `pagerduty` - Events API v2 payload with
    `routing_key`, `event_action`, `dedup_key`, and
    `payload.custom_details`.
- CLI flags `--webhook`, `--webhook-flavor`,
  `--webhook-min-score`, `--webhook-dedup-secs`,
  `--webhook-pd-routing-key` (also reads `LOGFOLD_PD_ROUTING_KEY`
  from env).
- PagerDuty flavor refuses to start without a routing key.
- `WebhookOptions` struct lives at the `logfold` crate root so
  callers compile against both feature configurations; the sink
  only runs when the `webhook` feature is on.
- Without the feature, `--webhook` errors out instead of
  silently dropping alerts.
- CI gains a webhook-feature test step and a build with every
  feature on.

### Added (v0.5 work)
- Transparent decompression on file sources. `.gz` and `.zst` are
  auto-detected by extension when the `compression` feature is on;
  without the feature the file is read raw with a warning so a
  misconfigured host doesn't fail silently.
- `SourceKind::Journald { unit }` and the `journald:<unit>`
  argument shorthand. Pipes `journalctl -u <unit> -o cat --no-pager`
  into the fold path; the child process is owned by the reader so
  it exits cleanly when the ingest is done.
- Unit-name whitelist on journald sources rejects anything but
  alphanumerics, dot, dash, underscore, @ (same shape as the
  bundle-id whitelist).
- `--follow` now explicitly rejects stdin AND journald sources
  with a clear error.
- The `journald` cargo feature is now a no-op gate; v0.5 shells to
  `journalctl` instead of linking libsystemd for portability.
  Bundles can still declare `path_hints = ["journald:unit"]` as a
  routing hint.
- `tests/compression_tests.rs` compresses the sshd fixture with
  gzip and zstd and asserts the fold result is identical to the
  plain-text baseline.
- CI gains a dedicated step that runs the compression tests under
  `--features "tui watcher compression"` and a clippy pass for the
  all-features configuration.


## [0.4.0] - 2026-10-24

Second scheduled release (per the "release every 3 versions" cadence
from the roadmap). Rolls up v0.2 (parsing fundamentals), v0.3 (TUI
maturity), and v0.4 (structured parsers).

### Added (v0.4 work)
- Structured parsers: JSON, logfmt / key=value, CEF, LEEF. Each
  lives in `src/parse/formats/<name>.rs` and returns the fold-key
  (`msg` / `Name` / `EventID`) plus a handful of promoted-known
  fields. Enabled via `[parse] format = "..."` in bundle TOML.
- Four new bundles: `generic/json` and `generic/logfmt` for the
  common structured shapes, `security/cef` and `security/leef`
  for SIEM feeds. The existing `generic/json` bundle gained its
  `format = "json"` opt-in.
- `ParseFormat::{Json, Kv, Cef, Leef}` variants. `fold_one`
  dispatches on format and tokenises the chosen field; a parse
  miss falls through to raw tokenisation so a stray non-JSON
  line in a JSON-tagged file still folds.
- CEF parser respects `\|` escapes in header fields.
- Four new fixtures (`tests/fixtures/{json-logs,logfmt,cef,leef}/sample.log`)
  and a `tests/structured_tests.rs` integration suite covering
  bundle schema, format-dispatch, and end-to-end fold reduction.

### Added (v0.3 work)
- Timeline view: now reads the real `rate_buckets` ring instead of
  placeholder bars. 24 slots of 5-minute buckets covering the last
  2 hours, oldest-first. Each row shows peak/5m alongside the
  pattern skeleton.
- `PatternSnapshot` carries `rate_buckets: [u32; 24]` and
  `last_bucket_epoch: u64`. JSON output now exposes the ring.
- Detail view gains three sub-tabs: Variables (existing),
  Score Breakdown (new, shows per-component contribution from
  frequency / rate_spike / cross_correlation / path_suspicion /
  severity), Raw Lines (new, synthesises example lines by
  plugging top-K values into the skeleton; real raw retention
  lands with v0.6 webhooks).
- `scorer::compute_score_components` returns the per-component
  breakdown that the new Detail subtab reads.
- Filter / search: `f` or `/` enters filter mode, Backspace edits,
  Esc clears, Enter keeps. Live substring match on skeleton and
  bundle_id, case-insensitive. Filter state persists through 500ms
  refresh cycles.
- Help overlay rewritten to document the new keybindings and
  push stale P4/P6 placeholders to their real target versions.

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


[Unreleased]: https://github.com/YanivSaar/LogFold/compare/v0.12.1...HEAD
[0.12.1]: https://github.com/YanivSaar/LogFold/releases/tag/v0.12.1
[0.12.0]: https://github.com/YanivSaar/LogFold/releases/tag/v0.12.0
[0.10.0]: https://github.com/YanivSaar/LogFold/releases/tag/v0.10.0
[0.7.0]: https://github.com/YanivSaar/LogFold/releases/tag/v0.7.0
[0.4.0]: https://github.com/YanivSaar/LogFold/releases/tag/v0.4.0
[0.1.1]: https://github.com/YanivSaar/LogFold/releases/tag/v0.1.1
[0.1.0]: https://github.com/YanivSaar/LogFold/releases/tag/v0.1.0
