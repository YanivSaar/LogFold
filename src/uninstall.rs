//! Built-in `logfold --uninstall`. v0.13.
//!
//! Removes the binary that's currently running plus any config /
//! state paths the user confirms. Interactive by default; pass
//! `--yes` to skip the confirmation prompt.
//!
//! What this handles:
//! - The running binary (`std::env::current_exe()`).
//! - User-level patterns dir: `$XDG_CONFIG_HOME/logfold` or
//!   `~/.config/logfold`.
//! - System-wide patterns dir: `/etc/logfold`.
//! - Learn-mode output dir: `./learned`.
//! - State snapshot: default `/var/lib/logfold/state.bin` plus a
//!   user-supplied path via `--state`.
//! - The systemd service when it's detected AND we're running as
//!   root (opt out with `--no-service`). Pre-v0.14 this was the
//!   `--with-service` combo flag; now it happens automatically so
//!   `logfold --uninstall` on a service host doesn't quietly leave
//!   the daemon running.
//!
//! When the service is detected but we're not root, we bail with
//! the exact `sudo logfold --uninstall` command to re-run instead
//! of silently skipping it.
//!
//! What this does NOT handle (prints instructions instead):
//! - ACLs on log files other than the standard set `install`
//!   knew about (we can't track them).

use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use color_eyre::eyre::{Context, Result};

/// Options accepted by `logfold --uninstall`.
#[derive(Debug, Default)]
pub struct UninstallOptions {
    /// Skip the "proceed? [y/N]" prompt.
    pub yes: bool,
    /// Optional extra state path (`--state <FILE>` from the CLI).
    pub state: Option<PathBuf>,
    /// Skip the systemd service tear-down even when a unit is
    /// detected. The default is to also stop + disable + remove it,
    /// since leaving a daemon running after `--uninstall` is a
    /// footgun. Set via `--no-service` from the CLI.
    pub no_service: bool,
    /// Service user name to tear down with the service. Comes from
    /// `--service-user` and defaults to `"logfold"` upstream.
    pub service_user: String,
}

/// Run the uninstall flow. Returns `Ok(())` on success or if the
/// user declined. Any filesystem error during cleanup is logged
/// and does not abort the removal of other targets.
pub fn run(opts: UninstallOptions) -> Result<()> {
    let self_path = std::env::current_exe().context("resolving the running binary's path")?;
    let targets = collect_targets(&self_path, opts.state.as_deref());

    let service_detected = service_is_installed();
    let user = if opts.service_user.is_empty() {
        "logfold".to_string()
    } else {
        opts.service_user.clone()
    };
    let tear_down_service = service_detected && !opts.no_service;

    println!("logfold --uninstall will remove:");
    for t in &targets {
        println!("  {} {}", if t.exists { "x" } else { "-" }, t.describe());
    }
    if tear_down_service {
        println!();
        println!("Detected systemd service — will also:");
        println!("  - systemctl stop logfold.service");
        println!("  - systemctl disable logfold.service");
        println!("  - rm /etc/systemd/system/logfold.service && daemon-reload");
        println!("  - setfacl -x u:{user} /var/log/<common log files>");
        println!("  - userdel -r {user}");
        if !is_root_process() {
            println!();
            println!("The service needs root. Re-run as:  sudo logfold --uninstall");
            println!(
                "(or pass --no-service to leave the service in place and only remove user-level files)"
            );
            color_eyre::eyre::bail!("service tear-down needs root; aborting without changes");
        }
    } else if service_detected && opts.no_service {
        println!();
        println!("Detected systemd service — leaving in place (--no-service).");
    }
    println!();

    if !opts.yes && !confirm("Proceed? [y/N] ")? {
        println!("Aborted. Nothing removed.");
        return Ok(());
    }

    let mut service_failed = false;
    if tear_down_service {
        match uninstall_service(&user) {
            Ok(()) => println!("service removed."),
            Err(e) => {
                println!("service tear-down failed: {e:#}");
                service_failed = true;
            }
        }
        println!();
    }

    let mut removed = 0usize;
    let mut failed = 0usize;
    for t in &targets {
        if !t.exists {
            continue;
        }
        match remove_target(&t.path) {
            Ok(()) => {
                println!("removed  {}", t.path.display());
                removed += 1;
            }
            Err(e) => {
                println!("failed   {}: {e:#}", t.path.display());
                failed += 1;
            }
        }
    }

    println!();
    println!("Done. {removed} removed, {failed} failed.");
    if failed > 0 || service_failed {
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn service_is_installed() -> bool {
    crate::service::is_installed()
}

#[cfg(not(target_os = "linux"))]
fn service_is_installed() -> bool {
    false
}

#[cfg(target_os = "linux")]
fn is_root_process() -> bool {
    crate::service::is_root()
}

#[cfg(not(target_os = "linux"))]
fn is_root_process() -> bool {
    false
}

#[cfg(target_os = "linux")]
fn uninstall_service(user: &str) -> Result<()> {
    crate::service::uninstall(user)
}

#[cfg(not(target_os = "linux"))]
fn uninstall_service(_user: &str) -> Result<()> {
    Ok(())
}

/// What we propose to delete.
struct Target {
    path: PathBuf,
    label: &'static str,
    exists: bool,
}

impl Target {
    fn describe(&self) -> String {
        format!("{:<24} {}", self.label, self.path.display())
    }
}

fn collect_targets(self_path: &Path, extra_state: Option<&Path>) -> Vec<Target> {
    let mut out = Vec::new();

    out.push(mk(self_path.to_path_buf(), "binary"));

    if let Some(home) = std::env::var_os("HOME") {
        let p = PathBuf::from(home);
        let xdg = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| p.join(".config"));
        out.push(mk(xdg.join("logfold"), "user patterns dir"));
    }

    out.push(mk(PathBuf::from("/etc/logfold"), "system patterns dir"));
    out.push(mk(PathBuf::from("/var/lib/logfold"), "default state dir"));
    // `./learned` is CWD-relative and only exists when the user ran
    // `--learn` from this directory. Canonicalise so the confirmation
    // prompt shows the absolute path the uninstall will actually touch,
    // and so is_safe_target can reject a symlink pointing elsewhere.
    if let Ok(abs) = std::fs::canonicalize("./learned") {
        out.push(mk(abs, "learn-mode output"));
    } else {
        out.push(mk(PathBuf::from("./learned"), "learn-mode output"));
    }

    if let Some(extra) = extra_state {
        // Don't double-list if the user passed the default path.
        if !out.iter().any(|t| t.path.as_path() == extra) {
            out.push(mk(extra.to_path_buf(), "user-specified state"));
        }
    }

    out
}

fn mk(path: PathBuf, label: &'static str) -> Target {
    let exists = std::fs::symlink_metadata(&path).is_ok();
    Target {
        path,
        label,
        exists,
    }
}

/// Allowlist of path prefixes we're willing to recursively delete.
/// Anything else — a symlinked `/etc/logfold -> /`, a hostile
/// `./learned -> /home/user` — is refused with a visible warning.
fn is_safe_target(path: &Path) -> bool {
    // Running binary (resolved via current_exe) is trusted.
    if let Ok(me) = std::env::current_exe() {
        if path == me.as_path() {
            return true;
        }
    }
    // Canonicalise if we can — follows symlinks so the check runs on
    // the actual destination, not the link. If canonicalise fails
    // (path missing, permission denied), fall back to the raw path:
    // remove_dir_all on a missing path will error cleanly anyway.
    let canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    const SAFE_PREFIXES: &[&str] = &["/etc/logfold", "/var/lib/logfold"];
    for p in SAFE_PREFIXES {
        if canon.starts_with(p) {
            return true;
        }
    }
    // User-config and learn-output must live under the user's home.
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        if canon.starts_with(&home) {
            return true;
        }
    }
    // Allow a learn-output directly under the current working dir.
    if let Ok(cwd) = std::env::current_dir() {
        if canon.starts_with(cwd.join("learned")) || canon == cwd.join("learned") {
            return true;
        }
    }
    false
}

fn remove_target(path: &Path) -> Result<()> {
    let md = std::fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
    // Refuse to follow symlinks on uninstall. A symlinked /etc/logfold
    // -> / would otherwise send remove_dir_all into the filesystem
    // root as root.
    if md.file_type().is_symlink() {
        color_eyre::eyre::bail!(
            "refusing to follow symlink {} — remove it manually if intentional",
            path.display()
        );
    }
    if !is_safe_target(path) {
        color_eyre::eyre::bail!(
            "refusing to remove {} — not under a known-safe root",
            path.display()
        );
    }
    if md.file_type().is_dir() {
        std::fs::remove_dir_all(path).with_context(|| format!("remove_dir_all {}", path.display()))
    } else {
        std::fs::remove_file(path).with_context(|| format!("remove_file {}", path.display()))
    }
}

fn confirm(prompt: &str) -> Result<bool> {
    let mut out = io::stdout().lock();
    write!(out, "{prompt}").ok();
    out.flush().ok();
    drop(out);

    let stdin = io::stdin();
    let mut buf = String::new();
    stdin.lock().read_line(&mut buf).context("reading stdin")?;
    Ok(matches!(
        buf.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_describe_pads_label() {
        let t = Target {
            path: PathBuf::from("/etc/logfold"),
            label: "system patterns dir",
            exists: true,
        };
        let s = t.describe();
        assert!(s.contains("system patterns dir"));
        assert!(s.contains("/etc/logfold"));
    }

    #[test]
    fn collect_targets_always_includes_binary_and_etc() {
        let targets = collect_targets(Path::new("/tmp/fake-logfold"), None);
        assert!(targets.iter().any(|t| t.label == "binary"));
        assert!(targets.iter().any(|t| t.label == "system patterns dir"));
    }

    #[test]
    fn safe_target_allows_known_roots_refuses_strangers() {
        assert!(is_safe_target(Path::new("/etc/logfold")));
        assert!(is_safe_target(Path::new("/etc/logfold/sub")));
        assert!(is_safe_target(Path::new("/var/lib/logfold")));
        // These must be refused — a hostile symlink pointing here
        // would otherwise send uninstall into the filesystem root.
        assert!(!is_safe_target(Path::new("/")));
        assert!(!is_safe_target(Path::new("/etc")));
        assert!(!is_safe_target(Path::new("/var")));
        assert!(!is_safe_target(Path::new("/boot")));
    }
}
