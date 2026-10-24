# Security

## Threat model

`logfold` is designed to run on hosts with a live threat profile: web
servers, VPN concentrators, bastion hosts, mail gateways. It reads logs,
and logs frequently contain **attacker-controlled bytes**: HTTP request
paths, usernames, headers, request bodies, filenames, SQL fragments
observed by ModSecurity. It's often run as **root or via sudo** because
`/var/log/*` and `journald:*` require elevated access.

That combination — attacker-controlled input, privileged process — is
what this document is about. Each item below is a specific hardening in
the code or a deployment recommendation. Please file an issue if you can
break any of them.

## In-code mitigations shipped in v0.1

### Input sanitization

- **Lossy UTF-8** — the source reader uses `read_until(b'\n')` plus
  `String::from_utf8_lossy`, never `read_line`. A single malformed byte
  can no longer abort a whole source. (See `src/ingest/source.rs::read_bounded_line`.)
- **Line-length cap** — one logical line is capped at **1 MiB**
  ([`MAX_LINE_BYTES`](src/ingest/source.rs)); anything longer is truncated
  and the rest of the line is skipped. A multi-GB single-line stream
  cannot OOM the process.
- **Control-char stripping** — tokens containing ANSI/C0 control bytes
  (except TAB) are dropped at tokenize time, so a line like
  `GET /\x1b[31mATTACK\x1b[0m HTTP` can neither reshape the TUI nor
  inject terminal escape sequences into saved output.
  (`src/parse/tokenizer.rs::contains_control`.)

### Pattern bundles (`--patterns-dir`)

User-supplied bundles are **not** trusted the same way as compiled-in
ones:

- **Bundle id whitelist** — the id must match `[a-zA-Z0-9_\-/]{1,128}`,
  may not contain `..`, and may not start with `/`. Rejected before any
  file is written during `--learn`.
  (`src/detect/registry.rs::is_safe_bundle_id`.)
- **Regex size limit** — `line_probes` for user bundles compile with
  `RegexSetBuilder::size_limit(100 KB)` and `dfa_size_limit(100 KB)`.
  A pathological regex can't balloon the state machine.
- **TOML file size limit** — any `.toml` in `--patterns-dir` larger than
  **8 MiB** is skipped with a warning. (`collect_from_fs` in the same file.)

### Memory bounds

- **`--max-patterns N`** soft-caps registry entries (default 100 000).
  New insertions are silently dropped once the cap is hit; the cold path
  can be extended to LRU-evict (deferred, see "Known gaps").
- **Fuzzy index bucket cap** — the secondary clustering index caps each
  bucket at **16 candidates** and FIFO-evicts beyond that. A hostile
  input crowding one `(first-token, token-count)` bucket cannot cause
  unbounded growth.
- **Lazy Count-Min Sketch** — per-variable storage stays as an exact
  `IndexMap` up to 32 distinct values, only then promoting to a 16 KiB
  CountMinSketch. Common cases don't allocate the sketch.
- **Per-pattern variable cap** of 16.

### File sources

- **Symlink warning** — `symlink_metadata` is consulted before every
  file open; following a symlink logs a `WARN` with the resolved target.
  As root, pointing logfold at a symlink that targets `/etc/shadow` is
  still your bullet to fire, but you'll see it in the terminal.
- **Non-regular-file warning** — opening a FIFO or socket also logs.

### Terminal

- **Panic hook** — a panic anywhere in the TUI restores raw-mode cleanly
  before the default handler runs; no more "my terminal is dead" after a
  crash. (`src/tui/app.rs::install_panic_hook`.)

## Known gaps (post-v0.1)

The following are known weaknesses that didn't ship a fix in v0.1 but
have an owner in the roadmap:

1. **No LRU eviction on `max_patterns`** — once the cap is hit, new
   patterns are silently dropped. Pathological inputs that keep producing
   near-unique patterns will miss some. Fix: LRU by `last_seen`.
2. **Memory bound is advisory, not enforced** — at 100 000 patterns × 16
   vars × 16 KiB (worst case, every var promoted) ≈ 25 GiB. In practice
   the lazy sketch keeps us well under this; aggressive attack logs can
   push closer to it. Mitigation today: run with a lower `--max-patterns`
   (e.g. `10000`) on untrusted inputs.
3. **No regex timeout on probe matches** — the `regex` crate is DFA-based
   so no catastrophic backtracking, but a pathological user-supplied
   pattern can still take non-trivial CPU per line. The size limits
   above bound compile cost; per-match cost is bounded only by the DFA
   size limit. Fix: run detection in a thread with a wall-clock cutoff.
4. **No chroot/sandbox** — logfold runs with the full ambient privilege
   of the launching user. See "Deployment recommendations" below.

## Deployment recommendations

### Prefer a dedicated unprivileged user over root

Running as root is convenient but unnecessary. On most distributions you
can:

```sh
# Create a dedicated user and let it read the specific logs it needs.
useradd -r -s /usr/sbin/nologin logfold
setfacl -m u:logfold:r /var/log/auth.log
setfacl -m u:logfold:r /var/log/nginx/access.log
# Or add logfold to the `adm` group on Debian/Ubuntu for /var/log/* read.
usermod -aG adm,systemd-journal logfold
sudo -u logfold logfold /var/log/auth.log
```

Members of `systemd-journal` can read the journal without root. Members
of `adm` can read most `/var/log/*` entries on Debian-family systems.

### Running inside a container

The published binary is static-friendly (no C deps beyond libc) and
copies cleanly into a minimal container. A read-only root filesystem
with the log directories bind-mounted read-only is a strong baseline.

### systemd hardening

```ini
[Service]
ExecStart=/usr/local/bin/logfold /var/log/auth.log --no-tui --ndjson
# No new privileges, no net, no device access, strong fs isolation.
NoNewPrivileges=true
PrivateDevices=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/var/log
CapabilityBoundingSet=
AmbientCapabilities=
```

### If you must run as root

- Pass `--patterns-dir` only to a directory you fully control (e.g.
  `/etc/logfold/patterns`, mode `0755` owned by root).
- Set `--max-patterns` well below the default on untrusted inputs.
- Prefer `--no-tui --ndjson` output into a logging pipeline (`jq`,
  `vector`, `rsyslog`) rather than reading the TUI directly over an SSH
  session that might also be logged.

## Reporting a vulnerability

Open an issue, mark it `security`, and give a reproduction. For a
real-world embargo request, contact the maintainers before filing
publicly; the project is small enough that a direct message beats a
coordinated-disclosure process.

## Audit history

- **v0.1.0** — initial hardening pass covering the items above. No
  external audit yet.
