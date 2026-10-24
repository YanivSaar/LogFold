//! Built-in systemd service install / uninstall. v0.13.
//!
//! `logfold --install-service --service-logs /var/log/auth.log ...`
//! does what the manual walkthrough in `contrib/systemd/README.md`
//! did, but in-process. On Linux only. All intermediate commands
//! shell out to stock utilities (`useradd`, `setfacl`, `install`,
//! `systemctl`) so the binary adds no C deps.
//!
//! Flow:
//!
//! 1. Create the dedicated service user (`useradd -r`), idempotent.
//! 2. Create the state dir (`install -d`), chown to the user.
//! 3. For each `--service-logs` path, grant it read via setfacl.
//! 4. Render the unit from the compiled-in template, substituting
//!    `BIN_PATH`, `SERVICE_USER`, and `EXEC_ARGS`, and drop it at
//!    `/etc/systemd/system/logfold.service`.
//! 5. `systemctl daemon-reload`.
//! 6. `systemctl enable --now logfold.service`.
//!
//! Teardown reverses the order:
//!
//! 1. `systemctl stop logfold.service`.
//! 2. `systemctl disable logfold.service`.
//! 3. Remove the unit file + `daemon-reload`.
//! 4. For each known log file, best-effort `setfacl -x u:<user>`.
//! 5. `userdel -r <user>` (removes the state dir).
//!
//! Every step logs its outcome and keeps going on best-effort
//! operations (ACL removal, user removal) so a partial install
//! can still be cleaned up.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::Command;

use color_eyre::eyre::{Context, Result};

/// Path we drop the systemd unit at. Not configurable - every
/// distro that ships systemd uses `/etc/systemd/system` as the
/// admin unit location.
const UNIT_PATH: &str = "/etc/systemd/system/logfold.service";

/// Compiled-in template. `{BIN_PATH}`, `{SERVICE_USER}`, and
/// `{EXEC_ARGS}` are the only placeholders.
const UNIT_TEMPLATE: &str = include_str!("service_unit.template");

/// Default service user name. Overridable via `--service-user`.
pub const DEFAULT_USER: &str = "logfold";

/// Default state dir created with the service user. Not currently
/// configurable; matches `contrib/systemd/logfold.service`.
pub const DEFAULT_STATE_DIR: &str = "/var/lib/logfold";

/// Options parsed from the CLI.
#[derive(Debug)]
pub struct InstallOptions {
    /// Service user to create (idempotent).
    pub user: String,
    /// Log file paths to grant read access via `setfacl -m u:<user>:r`.
    pub logs: Vec<PathBuf>,
    /// What to pass as `ExecStart` after the binary path. Should
    /// at minimum include `--no-tui --ndjson --follow` and the
    /// log sources, so the daemon has something useful to do.
    /// Supplied as a single pre-split argv.
    pub exec_args: Vec<String>,
    /// Enable + start the unit after install.
    pub enable_now: bool,
    /// Skip the interactive confirmation prompt.
    pub yes: bool,
}

/// Install the service end-to-end. Returns on first failure after
/// printing which step broke, so the operator can inspect state
/// before the next attempt.
pub fn install(opts: InstallOptions) -> Result<()> {
    require_root()?;

    let bin_path = std::env::current_exe()
        .context("resolving the running binary path")?
        .canonicalize()
        .context("canonicalising the running binary path")?;

    println!("logfold --install-service:");
    println!("  binary       : {}", bin_path.display());
    println!("  service user : {}", opts.user);
    println!("  state dir    : {DEFAULT_STATE_DIR}");
    println!("  unit path    : {UNIT_PATH}");
    println!("  logs ACL'd   :");
    if opts.logs.is_empty() {
        println!("    (none - pass --service-logs <path> for every file the daemon reads)");
    } else {
        for p in &opts.logs {
            println!("    {}", p.display());
        }
    }
    println!(
        "  ExecStart    : {} {}",
        bin_path.display(),
        opts.exec_args.join(" ")
    );
    println!("  enable+start : {}", opts.enable_now);
    println!();

    if !opts.yes && !confirm("Proceed? [y/N] ")? {
        println!("Aborted.");
        return Ok(());
    }

    create_user(&opts.user)?;
    ensure_state_dir(&opts.user)?;
    for log in &opts.logs {
        grant_acl(&opts.user, log)?;
    }
    write_unit(&bin_path, &opts.user, &opts.exec_args)?;
    run("systemctl", &["daemon-reload"])?;
    if opts.enable_now {
        run("systemctl", &["enable", "--now", "logfold.service"])?;
    } else {
        run("systemctl", &["enable", "logfold.service"])?;
    }

    println!();
    println!("Done. Watch it with:");
    println!("  sudo journalctl -u logfold -f");
    Ok(())
}

/// Tear the service down. Opposite order of install; every step is
/// best-effort so a half-installed service can still be cleaned up.
pub fn uninstall(user: &str) -> Result<()> {
    require_root()?;

    println!("logfold service uninstall:");
    println!("  service user : {user}");
    println!("  unit path    : {UNIT_PATH}");
    println!();

    best_effort("systemctl", &["stop", "logfold.service"]);
    best_effort("systemctl", &["disable", "logfold.service"]);
    if Path::new(UNIT_PATH).exists() {
        if let Err(e) = std::fs::remove_file(UNIT_PATH) {
            println!("note: could not remove {UNIT_PATH}: {e}");
        } else {
            println!("removed  {UNIT_PATH}");
        }
    }
    best_effort("systemctl", &["daemon-reload"]);

    // ACL cleanup: we don't track which logs the install granted, so
    // iterate the common ones. The `setfacl -x` is a no-op on a
    // path that didn't have the ACE.
    for log in [
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
    ] {
        if Path::new(log).exists() {
            best_effort("setfacl", &["-x", &format!("u:{user}"), log]);
        }
    }

    // Remove the service user. `-r` wipes its home / state dir too.
    best_effort("userdel", &["-r", user]);

    println!();
    println!("Done.");
    Ok(())
}

/// Whether a logfold unit is installed on this host. Called by
/// `--uninstall` so it can offer to tear the service down too.
pub fn is_installed() -> bool {
    Path::new(UNIT_PATH).exists()
}

// ---- helpers ----

fn require_root() -> Result<()> {
    // No FFI (`#![forbid(unsafe_code)]` in lib.rs forbids libc
    // bindings). Read the current uid out of /proc/self/status
    // instead - works on every Linux distro that ships systemd.
    let is_root = std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .map(|u| u == "0")
        .unwrap_or(false);
    if !is_root {
        color_eyre::eyre::bail!(
            "--install-service / --uninstall-service must run as root (try `sudo logfold ...`)"
        );
    }
    Ok(())
}

fn create_user(user: &str) -> Result<()> {
    // useradd -r is idempotent via its own exit code semantics (9 =
    // user already exists). Treat 0 and 9 as success.
    let status = Command::new("useradd")
        .args([
            "-r",
            "-s",
            "/usr/sbin/nologin",
            "-d",
            DEFAULT_STATE_DIR,
            "-M",
            user,
        ])
        .status()
        .with_context(|| format!("spawning `useradd -r {user}`"))?;
    match status.code() {
        Some(0) => println!("created  user {user}"),
        Some(9) => println!("exists   user {user}"),
        other => color_eyre::eyre::bail!("useradd for {user} exited with {other:?}"),
    }
    Ok(())
}

fn ensure_state_dir(user: &str) -> Result<()> {
    run(
        "install",
        &[
            "-d",
            "-o",
            user,
            "-g",
            user,
            "-m",
            "0750",
            DEFAULT_STATE_DIR,
        ],
    )?;
    println!("ok       {DEFAULT_STATE_DIR}");
    Ok(())
}

fn grant_acl(user: &str, path: &Path) -> Result<()> {
    if !path.exists() {
        println!("skip     {} (not present yet)", path.display());
        return Ok(());
    }
    let spec = format!("u:{user}:r");
    run("setfacl", &["-m", &spec, &path.display().to_string()])?;
    println!("acl'd    {} <- {spec}", path.display());
    Ok(())
}

fn write_unit(bin_path: &Path, user: &str, exec_args: &[String]) -> Result<()> {
    let joined = exec_args.join(" ");
    let body = UNIT_TEMPLATE
        .replace("{BIN_PATH}", &bin_path.display().to_string())
        .replace("{SERVICE_USER}", user)
        .replace("{EXEC_ARGS}", &joined);
    std::fs::write(UNIT_PATH, body).with_context(|| format!("writing {UNIT_PATH}"))?;
    // Mode 0644 for a unit file.
    {
        use std::os::unix::fs::PermissionsExt;
        let perm = std::fs::Permissions::from_mode(0o644);
        let _ = std::fs::set_permissions(UNIT_PATH, perm);
    }
    println!("wrote    {UNIT_PATH}");
    Ok(())
}

fn run(prog: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(prog)
        .args(args)
        .status()
        .with_context(|| format!("spawning `{prog} {}`", args.join(" ")))?;
    if !status.success() {
        color_eyre::eyre::bail!("`{prog} {}` exited with {status}", args.join(" "));
    }
    Ok(())
}

fn best_effort(prog: &str, args: &[&str]) {
    match Command::new(prog).args(args).status() {
        Ok(s) if s.success() => println!("ok       {prog} {}", args.join(" ")),
        Ok(s) => println!("note     {prog} {} -> {}", args.join(" "), s),
        Err(e) => println!("note     {prog} {} -> {e}", args.join(" ")),
    }
}

fn confirm(prompt: &str) -> Result<bool> {
    use std::io::{self, BufRead, Write};
    let mut out = io::stdout().lock();
    write!(out, "{prompt}").ok();
    out.flush().ok();
    drop(out);
    let mut buf = String::new();
    io::stdin()
        .lock()
        .read_line(&mut buf)
        .context("reading stdin")?;
    Ok(matches!(
        buf.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}
