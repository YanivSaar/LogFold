# logfold

> Zero-config log pattern folder and anomaly detector for sysadmins,
> SREs, and blue teams.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![Status](https://img.shields.io/badge/status-v0.1-brightgreen.svg)](https://github.com/YanivSaar/LogFold/releases)

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
  (`{IP}`, `{USER}`, `{NUM}`), FNV-1a hash, upsert. Near-miss
  variants fold together via bounded token Levenshtein.
- **Anomaly scoring.** Composite score from frequency, rate spike,
  cross-correlation, path suspicion, and severity hint. Badges:
  `NEW`, `RARE`, `SPIKE`, `CROSS`, `NORM`, `FOLD`.
- **Format detection.** Path hints and content probing pick the
  right bundle automatically. Falls back to a generic parser if
  nothing matches.
- **ModSecurity support.** Audit logs with `A..Z` section markers
  are grouped into whole-event records before folding.
- **Live redraw TUI.** Overview, Detail, Sources, Timeline views
  at 20 Hz. Panic hook restores raw mode on crash.
- **Multiple output modes.** TUI, plain-text, JSON, NDJSON.
- **Follow mode.** Inode-aware rotation detection via `notify`.
- **Learn mode.** Export observed patterns as a TOML bundle you
  can commit.
- **Fast.** About 1.29 M lines/sec on the fold hot path, single
  thread, release build.


## Installation

### From source (works on any Linux, macOS, or BSD)

Requires Rust 1.75 or newer. If you don't have it:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Then:

```sh
# Install the latest release from crates.io (planned for v0.2)
cargo install logfold

# Or build from a clone
git clone https://github.com/YanivSaar/LogFold.git
cd LogFold
cargo build --release
./target/release/logfold --help
```

Default features build with the TUI and file watcher. To slim it
down:

```sh
cargo build --release --no-default-features --features tui
cargo build --release --no-default-features           # no TUI, no watcher
```

Optional features:

| Feature       | What it adds                                   |
|---------------|------------------------------------------------|
| `tui`         | ratatui interface (default)                    |
| `watcher`     | `notify`-based tail with rotation (default)    |
| `journald`    | `--source journald:unit` on Linux (v0.5)       |
| `compression` | `.gz` and `.zst` input (v0.5)                  |
| `webhook`     | HTTP sink for alerts (v0.6)                    |
| `clipboard`   | copy a pattern or line to the clipboard        |


### Pre-built binaries

Static Linux and macOS binaries are published on the
[releases page](https://github.com/YanivSaar/LogFold/releases).

```sh
# Linux x86_64, as an example. Adjust the asset name to your platform.
curl -L https://github.com/YanivSaar/LogFold/releases/latest/download/logfold-x86_64-unknown-linux-musl.tar.gz \
  | tar xz
sudo mv logfold /usr/local/bin/
logfold --version
```


### Package managers

Package availability per distro. Items marked "planned" land with
v0.10 (ops integration + packaging). Pull requests to add a package
sooner are welcome.

| Distribution                | Command                                 | Status  |
|-----------------------------|-----------------------------------------|---------|
| Arch Linux (AUR)            | `yay -S logfold`                        | planned |
| Debian / Ubuntu             | `apt install logfold` (via `.deb`)      | planned |
| Fedora / RHEL / Rocky       | `dnf install logfold`                   | planned |
| openSUSE                    | `zypper install logfold`                | planned |
| Alpine Linux                | `apk add logfold`                       | planned |
| Gentoo                      | `emerge app-admin/logfold`              | planned |
| Void Linux                  | `xbps-install logfold`                  | planned |
| NixOS / Nix                 | `nix profile install nixpkgs#logfold`   | planned |
| Snap (universal)            | `snap install logfold`                  | planned |
| Flatpak (universal)         | `flatpak install logfold`               | planned |
| macOS (Homebrew)            | `brew install logfold`                  | planned |
| macOS (MacPorts)            | `port install logfold`                  | planned |
| FreeBSD                     | `pkg install logfold`                   | planned |
| crates.io (any OS)          | `cargo install logfold`                 | v0.2    |
| From source (any OS)        | `cargo build --release`                 | now     |


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
  SOURCE                    One or more files, directories, or `-` for stdin.
                            Globs are expanded by the shell.

General:
  -t, --top <N>             Show top N anomalies [default: 20]
  -m, --min-fold <N>        Min count for FOLD badge [default: 3]
  -T, --threshold <SCORE>   Min score to appear in ANOMALIES [default: 40]
  -q, --quiet               Suppress banner
  -v, --verbose             Debug-level tracing
      --max-patterns <N>    Soft memory cap [default: 100_000]

Detection:
  -b, --bundle <ID>         Force a specific bundle (skip detection)
  -P, --patterns-dir <DIR>  Load additional *.toml bundles
      --probe-lines <N>     Lines sampled before deciding [default: 64]

Streaming:
  -f, --follow              Tail -f each file source (requires watcher feature)

Output:
      --no-tui              Plain-text output
      --json                JSON array (requires --no-tui)
      --ndjson              One JSON object per line (requires --no-tui)

Learn:
      --learn               Export learned bundles on exit
      --learn-out <DIR>     Where to write learned bundles [default: ./learned]
      --learn-min <N>       Min count to include [default: 5]
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


## Running as a service

Running as root is convenient but unnecessary on most distros. The
recommended pattern is a dedicated unprivileged user with ACLs for
the specific logs it needs. Full guidance including a hardened
systemd unit lives in [SECURITY.md](SECURITY.md).

Short version:

```sh
useradd -r -s /usr/sbin/nologin logfold
setfacl -m u:logfold:r /var/log/auth.log
usermod -aG adm,systemd-journal logfold
sudo -u logfold logfold /var/log/auth.log --no-tui --ndjson
```


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

v0.1 shipped the engine, TUI, detection FSM, and the first 20
bundles. The next eleven releases ladder up to a full bug and
security audit before v1.0.

Headline items on the way:

- **v0.2** base syslog parser, bundle `context_types` wiring
- **v0.3** Detail sub-tabs, Timeline real buckets, filter and search
- **v0.4** JSON / KV / CEF / LEEF parsers
- **v0.5** journald source, `.gz` and `.zst` input
- **v0.6** webhook / Slack / PagerDuty alerting
- **v0.7** IOC enrichment, GeoIP and ASN annotation
- **v0.8** ModSec-aware Detail panel, v3 JSON audit log parser
- **v0.9** Sigma-lite correlation rules
- **v0.10** Prometheus `/metrics`, state persistence, packaging
- **v0.11** 100 more bundles, bundle linter, community index
- **v0.12** audit, performance regression, API freeze, v1.0


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
