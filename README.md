# logfold

> Zero-config log pattern folder and anomaly detector for sysadmins,
> SREs, and blue teams.

[![CI](https://github.com/YanivSaar/LogFold/actions/workflows/ci.yml/badge.svg)](https://github.com/YanivSaar/LogFold/actions/workflows/ci.yml)
[![Release](https://github.com/YanivSaar/LogFold/actions/workflows/release.yml/badge.svg)](https://github.com/YanivSaar/LogFold/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![Status](https://img.shields.io/badge/status-v0.12-brightgreen.svg)](https://github.com/YanivSaar/LogFold/releases)

`logfold` reads any log stream, folds repetitive lines into counted
patterns, and surfaces anomalies at the top. It runs as a single
static binary with no config file, no agent, no server. Pipe
something into it and you get signal in seconds.

```sh
logfold /var/log/auth.log                       # single file, TUI
logfold /var/log/auth.log --no-tui              # plain-text table
tail -f /var/log/nginx/access.log | logfold     # live stdin
logfold /var/log/*.log --no-tui --json          # scripting
logfold -f /var/log/syslog                      # follow (tail -f)
logfold /var/log/auth.log --learn               # export learned bundles
```


## Features

- **Pattern folding.** Tokenise, build a skeleton with typed slots
  (`{IP}`, `{USER}`, `{PORT}`, `{NUM}`, ...), FNV-1a hash, upsert.
  Near-miss variants fold together via bounded token Levenshtein.
- **Format-aware parsing.** Six base parsers behind `[parse]
  format = "..."` in each bundle: raw, syslog (RFC 3164 / 5424),
  JSON, logfmt / key=value, ArcSight CEF, IBM LEEF, and
  ModSecurity v3 JSON. Falls back to raw tokenisation on parse
  miss.
- **Context promotion.** Bundle `[[context_types]]` entries
  coerce the WORD or NUM after a configured anchor into the
  right typed slot ("for alice" -> `{USER}`, "port 22" -> `{PORT}`).
- **Anomaly scoring.** Composite score from frequency, rate spike,
  cross-correlation, path suspicion, bundle severity, and a
  compiled-in correlation rule pack. Badges: `NEW`, `RARE`,
  `SPIKE`, `CROSS`, `NORM`, `FOLD`.
- **Blue-team enrichment.** `--iocs <csv>` tags variable values
  against a local indicator list; `--geoip <mmdb>` surfaces ASN
  / country alongside IPs (behind the `geoip` feature).
- **Correlation rules.** Shipped v0.9 rule pack covers SSH
  brute-force, exec-from-tmp, ModSec CRITICAL, HTTP error flood,
  and the classic brute-force-then-success cross-pattern rule.
- **Alerting sink.** `--webhook <url>` POSTs anomaly events as
  generic JSON, Slack message, or PagerDuty v2 payload
  (`webhook` feature). Per-pattern cool-down built in.
- **ModSecurity support.** v2 audit log section marker grouping
  and v3 JSON serial format, both opt-in via bundle `[parse]`.
- **50 compiled-in bundles.** auth / web / mail / database /
  firewall / vpn / security / cloud / containers / dns / system.
- **Live redraw TUI.** Overview, Detail (Variables / Score
  Breakdown / Raw Lines sub-tabs), Sources, Timeline (real
  bucket sparklines). Filter with `f` or `/`. Panic hook
  restores raw mode on crash.
- **Multiple output modes.** TUI, plain-text, JSON, NDJSON.
  Prometheus `/metrics` endpoint (`prometheus` feature).
- **Follow mode.** Inode-aware rotation detection via `notify`.
  journald sources via `journald:<unit>`. Transparent `.gz` and
  `.zst` decompression on file sources (`compression` feature).
- **State persistence.** `--state <path>` saves and restores the
  pattern registry across restarts.
- **Bundle linter.** `logfold --lint <path>` validates one or
  more bundle TOMLs.
- **Learn mode.** `--learn` exports observed patterns as a
  committable TOML bundle grouped by inferred source.
- **Fast.** About 1.29 M lines/sec on the fold hot path, single
  thread, release build.


## Installation

### One-line install (recommended)

Grabs the latest release tarball for your Linux architecture
(x86_64 or aarch64), verifies its sha256 against the published
sidecar, and drops the binary at `/usr/local/bin/logfold` (or
`~/.local/bin/logfold` without sudo).

```sh
curl -fsSL https://raw.githubusercontent.com/YanivSaar/LogFold/main/scripts/install.sh | bash
```

For a system-wide install:

```sh
curl -fsSL https://raw.githubusercontent.com/YanivSaar/LogFold/main/scripts/install.sh | sudo bash
```

Pin a specific version or install prefix:

```sh
curl -fsSL https://raw.githubusercontent.com/YanivSaar/LogFold/main/scripts/install.sh \
  | bash -s -- --version v0.14.3 --prefix /opt/logfold
```

Flags: `--version <tag>`, `--prefix <dir>`, `--target <triple>`,
`--no-verify` (skip sha256, discouraged). The script refuses on
macOS and tells you to use `cargo install logfold` instead; see
the "From source" section below for Windows / FreeBSD.


### Manual tarball install

If you'd rather not pipe to bash, grab the tarball directly from
the [releases page](https://github.com/YanivSaar/LogFold/releases).
Each release ships one tarball per target, a `.sha256` sidecar,
and a combined `SHA256SUMS`.

Pick the target that matches your host (`uname -s -m` tells you):

| Platform                           | Target                        |
|------------------------------------|-------------------------------|
| Linux x86_64 (static, recommended) | `x86_64-unknown-linux-musl`   |
| Linux x86_64 (dynamic, glibc)      | `x86_64-unknown-linux-gnu`    |
| Linux ARM64 (static, recommended)  | `aarch64-unknown-linux-musl`  |
| Linux ARM64 (dynamic, glibc)       | `aarch64-unknown-linux-gnu`   |
| macOS / Windows / FreeBSD          | build from source (below)     |

```sh
VERSION=v0.14.3
TARGET=x86_64-unknown-linux-musl
BASE="https://github.com/YanivSaar/LogFold/releases/download/${VERSION}"

curl -LO "${BASE}/logfold-${VERSION}-${TARGET}.tar.gz"
curl -LO "${BASE}/logfold-${VERSION}-${TARGET}.tar.gz.sha256"
sha256sum -c "logfold-${VERSION}-${TARGET}.tar.gz.sha256"

tar -xzf "logfold-${VERSION}-${TARGET}.tar.gz"
sudo install -m 0755 "logfold-${VERSION}-${TARGET}/logfold" /usr/local/bin/

logfold --version
```


### From source

Requires Rust 1.75 or newer. Install the toolchain with
[rustup](https://rustup.rs/) if you don't have it:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Then build and install:

```sh
git clone https://github.com/YanivSaar/LogFold.git
cd LogFold
cargo build --release
sudo install -m 0755 target/release/logfold /usr/local/bin/
logfold --version
```

Default features build the TUI and the file watcher. To tune the
build:

```sh
# No TUI, no watcher - smallest footprint, no interactive UI.
cargo build --release --no-default-features

# Everything on - webhook, compression, journald, geoip, prometheus.
cargo build --release --features "tui watcher webhook compression journald geoip prometheus"
```

Optional features:

| Feature       | What it adds                                              |
|---------------|-----------------------------------------------------------|
| `tui`         | ratatui interface (default)                               |
| `watcher`     | `notify`-based tail with rotation detection (default)     |
| `journald`    | `--source journald:<unit>` reads via `journalctl`         |
| `compression` | transparent `.gz` and `.zst` on file sources              |
| `webhook`     | `--webhook` POSTs anomaly events (generic/Slack/PagerDuty)|
| `geoip`       | `--geoip <mmdb>` for ASN / country annotation on IPs      |
| `prometheus`  | `--prom-listen HOST:PORT` serves `/metrics`               |
| `clipboard`   | copy a pattern or line to the clipboard                   |


## Uninstall

logfold ships a built-in uninstaller:

```sh
sudo logfold --uninstall
```

It prints a dry-run plan listing exactly what it will remove -
the running binary, user patterns dir, system patterns dir,
learn-mode output, state snapshot - and prompts for confirmation.
Pass `--yes` to skip the prompt in scripts:

```sh
sudo logfold --uninstall --yes
```

Operations that require sudo and sit outside logfold's own tree
(the dedicated service user, the systemd unit file, log-file
ACLs) are printed as the exact commands to run next, so nothing
magical happens to the rest of the system.

If you installed via `cargo install`, `cargo uninstall logfold`
also works and removes the Cargo-managed binary.


## Running as a service

logfold has a built-in `--install-service` on Linux. One command
creates the dedicated user, grants read ACLs on the logs you
name, drops a hardened systemd unit in place, reloads systemd,
and starts the daemon:

```sh
sudo logfold --install-service \
    --service-logs /var/log/auth.log \
    --service-logs /var/log/nginx/access.log \
    --service-extra "--webhook https://hooks.example.com/logfold"
```

What it does, in order:

1. `useradd -r -s /usr/sbin/nologin -d /var/lib/logfold -M logfold`
   (idempotent; "exists" is treated as success).
2. `install -d -o logfold -g logfold -m 0750 /var/lib/logfold` for
   the state snapshot directory.
3. `setfacl -m u:logfold:r <path>` on every `--service-logs` entry.
4. Writes `/etc/systemd/system/logfold.service` from the embedded
   template, substituting the current binary path, service user,
   and ExecStart args (`--no-tui --ndjson --follow` + sources +
   `--service-extra`).
5. `systemctl daemon-reload`.
6. `systemctl enable --now logfold.service`.

The embedded unit template enables every systemd sandbox knob
`SECURITY.md` recommends: `NoNewPrivileges`, `ProtectSystem=strict`,
`MemoryDenyWriteExecute`, empty `CapabilityBoundingSet`, 512 MiB
`MemoryMax`. If you need network for `--webhook` or
`--prom-listen`, drop in `RestrictAddressFamilies=AF_UNIX
AF_INET AF_INET6` via `systemctl edit logfold.service` after
install.

Watch it:

```sh
sudo journalctl -u logfold -f
```

### Flag reference for `--install-service`

| Flag                        | Meaning                                                 |
|-----------------------------|---------------------------------------------------------|
| `--service-logs <PATH>`     | Log file to ACL for the service user. Repeatable.       |
| `--service-user <NAME>`     | Service user name  [default: logfold]                   |
| `--service-source <SRC>`    | Log source for the daemon. Repeatable. Accepts files or `journald:<unit>`. Falls back to `--service-logs` when omitted. |
| `--service-extra <STRING>`  | Extra flags appended to ExecStart (webhook / state / iocs). |
| `--yes`                     | Skip the confirmation prompt.                            |

### Uninstalling the service

```sh
sudo logfold --uninstall --with-service
```

That stops and disables the unit, removes
`/etc/systemd/system/logfold.service`, reloads systemd, drops the
`logfold` user ACLs from the common `/var/log/*` locations, and
`userdel -r`s the service user. The regular `--uninstall` pass
then removes the binary and any config / state the operator
confirms.


## Quick start

### Investigate yesterday's auth log

```sh
logfold /var/log/auth.log
```

The TUI opens on the Overview tab. The top of the pattern list
holds whatever scored highest: a new pattern, a rate spike, an IP
that touched many services. `Tab` cycles views; `?` shows all
keybindings; `q` quits.


### One-shot scripting

```sh
logfold /var/log/nginx/access.log --no-tui --top 50
```

Prints an anomaly table followed by a pattern table. `--json`
emits a structured array; `--ndjson` emits one JSON object per
line, pipe-friendly for `jq`:

```sh
logfold /var/log/nginx/access.log --no-tui --ndjson \
  | jq 'select(.score >= 70) | {skeleton, count, score, badges}'
```


### Live tail with alerting (v0.6)

```sh
logfold -f /var/log/nginx/access.log \
        --webhook https://hooks.slack.com/services/XXX \
        --webhook-min-score 70
```


### Learn a new bundle from your own logs

```sh
logfold /var/log/myapp/*.log --no-tui --learn --learn-min 10
# Writes ./learned/myapp.toml
```

Review the file, edit the labels and severities, drop it into
`/etc/logfold/patterns/` for future runs via `--patterns-dir`.


## CLI reference

```
logfold [OPTIONS] [SOURCE...]

Sources:
  SOURCE                        File path, directory, `-` for stdin, or
                                `journald:<unit>` (requires journald feature).
                                Globs are expanded by the shell.

General:
  -t, --top <N>                 Show top N anomalies [default: 20]
  -m, --min-fold <N>            Min count for FOLD badge [default: 3]
  -T, --threshold <SCORE>       Min score to appear in ANOMALIES [default: 40]
  -q, --quiet                   Suppress banner
  -v, --verbose                 Debug-level tracing
      --max-patterns <N>        Soft memory cap [default: 100_000]

Detection:
  -b, --bundle <ID>             Force a specific bundle (skip detection)
  -P, --patterns-dir <DIR>      Load additional *.toml bundles
      --probe-lines <N>         Lines sampled before deciding [default: 64]

Streaming:
  -f, --follow                  Tail -f each file source (watcher feature)
      --state <FILE>            Persist registry on exit, reload on start

Enrichment:
      --iocs <FILE>             CSV of indicator,source,severity
      --geoip <FILE>            MaxMind GeoIP mmdb (geoip feature)

Output:
      --no-tui                  Plain-text output
      --json                    JSON array (requires --no-tui)
      --ndjson                  One JSON object per line (requires --no-tui)
      --webhook <URL>           POST anomaly events (webhook feature)
      --webhook-flavor <F>      generic | slack | pagerduty  [default: generic]
      --webhook-min-score <N>   Threshold to fire  [default: 70]
      --webhook-dedup-secs <N>  Per-pattern cool-down  [default: 300]
      --prom-listen <ADDR>      Serve /metrics (prometheus feature)

Learn:
      --learn                   Export learned bundles on exit
      --learn-out <DIR>         Where to write them  [default: ./learned]
      --learn-min <N>           Min count to include  [default: 5]

Utility:
      --lint <PATH>...          Validate TOML bundle files instead of folding
      --uninstall               Remove the binary + user config / state
      --yes                     Skip the confirmation prompt (with --uninstall)
```


## TUI keybindings

| Key         | Action                                          |
|-------------|-------------------------------------------------|
| `Tab`       | Next view (Overview / Detail / Sources / Timeline) |
| `Shift-Tab` | Previous view                                   |
| `1-4`       | Jump to view by number                          |
| `j` / `k`   | Move selection down / up                        |
| `g` / `G`   | Jump to top / bottom                            |
| `Enter`     | Open Detail view for the selected pattern       |
| `Esc`       | Back to Overview                                |
| `f`         | Filter pattern list (v0.3)                      |
| `/`         | Search (v0.3)                                   |
| `?`         | Help overlay                                    |
| `q` / `Ctrl-C` | Quit (also flushes `--learn` if set)         |


## Pattern bundles

A bundle is a TOML file telling logfold "lines that look like this
are from `sshd`" and "this canonical skeleton means `failed
password`". Bundles are compiled into the binary by default; extra
bundles live in `--patterns-dir`.

Minimal bundle:

```toml
[meta]
id   = "myapp"
name = "My App"
category = "custom"

[detect]
path_hints  = ["/var/log/myapp/*.log"]
line_probes = ['myapp\[\d+\]:', "connection accepted"]
probe_threshold = 0.15

[parse]
multiline = "heuristic"      # or "modsec-sections"

[[pattern]]
skeleton = "myapp[*]: client {IP} connected"
label    = "client-connect"
severity = "info"

[[pattern]]
skeleton = "myapp[*]: auth failure for {USER} from {IP}"
label    = "auth-failure"
severity = "warning"
```

Shipped bundles cover auth (sshd, sudo, su, pam), web (nginx,
apache), mail (postfix), database (postgres, mysql), firewall
(iptables), containers (docker, k8s-kubelet), VPN (openvpn),
security (fail2ban, modsec, auditd), and system logs. See
`patterns/` for the full set.


## Design notes

Deviations from the original product brief, each a deliberate call:

- **Streaming-friendly detection.** The detector buffers up to
  `--probe-lines` events (or 500 ms) and replays them once a bundle
  is chosen; a static first-N read doesn't work on live tails.
- **Specificity-aware probing.** A bundle's probe score blends
  ratio with how many distinct probe anchors matched, so a
  specific bundle (sshd, 6 probes, 4 matched) beats a generic one
  (syslog, 1 probe, 1 matched) on content that fits both.
- **Lazy variable sketches.** A variable keeps an exact `IndexMap`
  up to 32 distinct values, promoted to a Count-Min Sketch beyond
  that. Keeps memory bounded without losing precision on the
  common case.
- **Extra dependencies** beyond the brief: `globset`, `tracing`,
  `color-eyre`, `smallvec`, `include_dir`, `insta`, `proptest`,
  `criterion`.


## Development

```sh
# Build (default: tui + watcher)
cargo build --release

# Tests (unit + integration)
cargo test --features "tui watcher"

# Hot-path benchmark
cargo bench --bench hot_path

# Lint
cargo clippy --features "tui watcher" --no-deps -- -D warnings

# Format
cargo fmt
```

Project layout:

```
src/
  parse/       byte-level tokenizer, skeleton builder
  engine/      pattern registry, fuzzy clusterer, scorer, extractor
  detect/      bundle loader, path-hint + line-probe FSM
  ingest/      source drivers, multiline assembler, file watcher
  tui/         ratatui app, four views, status bar
  output/      text, JSON, NDJSON, learn-mode sinks
patterns/      compiled-in bundle library (TOML)
tests/         integration tests + fixtures
benches/       criterion harnesses
```

Run just one integration test:

```sh
cargo test --features "tui watcher" --test detection_tests
```


## Roadmap

v0.1 through v0.12 are shipped. v0.12 is the pre-1.0 audit
checkpoint; v1.0 is a semver commitment and gets cut by the
maintainer when the four known gaps in `SECURITY.md` are
closed.

Shipped on the way to v1.0:

- **v0.2** base syslog parser, bundle `context_types` wiring
- **v0.3** Detail sub-tabs, Timeline real buckets, filter and search
- **v0.4** JSON / KV / CEF / LEEF parsers
- **v0.5** journald source, `.gz` and `.zst` input
- **v0.6** webhook / Slack / PagerDuty alerting
- **v0.7** IOC enrichment, GeoIP annotation
- **v0.8** ModSec v3 JSON audit log parser
- **v0.9** Sigma-lite correlation rules
- **v0.10** Prometheus `/metrics`, state persistence, systemd unit
- **v0.11** bundle linter, catalog grown to 50 bundles
- **v0.12** proptest coverage, cargo-deny policy, dependency sweep

The four known gaps carried into v1.0 (see `SECURITY.md`):

- No LRU eviction on `--max-patterns` cap (silent drop).
- Memory bound is advisory, not enforced.
- No per-match regex wall-clock timeout.
- No chroot / seccomp sandbox beyond the systemd unit's hardening.


## Contributing

The project is small and PRs are read quickly. The high-value
areas today:

- **New pattern bundles.** Pick a log format you work with, add a
  TOML in `patterns/<category>/<name>.toml` plus a fixture under
  `tests/fixtures/<name>/sample.log`.
- **Bundle fixtures and expected outputs.** Even a single
  `sample.log` without a corresponding bundle is useful.
- **Distro packaging.** If you can turn out a `.deb`, an AUR
  `PKGBUILD`, a Homebrew formula, or similar, open an issue first
  so we can coordinate signing and release automation.
- **Documentation.** `--help` output, examples in this README,
  worked walk-throughs for specific log types.

Before you open a PR:

```sh
cargo fmt --check
cargo clippy --features "tui watcher" --no-deps -- -D warnings
cargo test --features "tui watcher"
```


## Release process

Releases are cut by pushing a signed annotated tag matching
`v*.*.*`. The `release.yml` workflow then:

1. Re-runs `cargo fmt --check`, `cargo clippy -- -D warnings`,
   and the full test suite on the exact tagged commit (the gate).
2. Cross-compiles for six targets: Linux x86_64 and aarch64 (musl
   and gnu), macOS x86_64 and aarch64.
3. Packages each build as a `.tar.gz` with the binary, `README.md`,
   `LICENSE`, and `SECURITY.md`.
4. Computes SHA-256 for every tarball plus a combined `SHA256SUMS`.
5. Creates the GitHub Release, uploads the tarballs and
   checksums, and auto-generates release notes from commits.

Pre-release tags (e.g. `v0.2.0-rc.1`) are published as
pre-releases automatically.

Local workflow to cut `vX.Y.Z`:

```sh
# All CI must be green on main first.
git tag -a vX.Y.Z -m "logfold vX.Y.Z"
git push origin vX.Y.Z
# Watch the Release workflow at:
#   https://github.com/YanivSaar/LogFold/actions/workflows/release.yml
```

To re-run a release for an already-pushed tag (e.g. after fixing
the workflow itself), use the "Run workflow" button on the
Release action and pass the tag name as input.


## Security

Threat model, mitigations, known gaps, and deployment guidance
live in [SECURITY.md](SECURITY.md). Short version:

- Lossy UTF-8 and a 1 MiB line cap keep hostile input bounded.
- User-supplied bundles are compiled with regex size limits.
- Control characters are stripped before anything reaches the TUI.
- Running as root is explicitly supported but discouraged.

Report vulnerabilities through a GitHub issue tagged `security`,
or contact the maintainer directly for coordinated disclosure.


## License

MIT. See [LICENSE](LICENSE).

Copyright (c) 2026 Yaniv Saar.


## Acknowledgments

Standing on the shoulders of several excellent crates:
[`ratatui`](https://github.com/ratatui-org/ratatui),
[`dashmap`](https://github.com/xacrimon/dashmap),
[`notify`](https://github.com/notify-rs/notify),
[`regex`](https://github.com/rust-lang/regex),
[`clap`](https://github.com/clap-rs/clap), and
[`tokio`](https://github.com/tokio-rs/tokio).

Format detection patterns informed by
[`lnav`](https://lnav.org/) and
[`angle-grinder`](https://github.com/rcoh/angle-grinder); the
anomaly-scoring approach draws on ideas from
[`loghub`](https://github.com/logpai/loghub) and the Drain family
of log parsers.
