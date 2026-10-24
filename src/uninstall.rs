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
//!
//! What this does NOT handle (prints instructions instead):
//! - The dedicated service user (`sudo userdel logfold`).
//! - The systemd unit file (`sudo rm /etc/systemd/system/logfold.service`).
//! - ACLs granted via `setfacl`.
//!
//! Those three require sudo and touch state outside the user's
//! control, so we show the exact commands and let the operator
//! run them. Keeps the uninstall non-magical.

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
}

/// Run the uninstall flow. Returns `Ok(())` on success or if the
/// user declined. Any filesystem error during cleanup is logged
/// and does not abort the removal of other targets.
pub fn run(opts: UninstallOptions) -> Result<()> {
    let self_path = std::env::current_exe().context("resolving the running binary's path")?;
    let targets = collect_targets(&self_path, opts.state.as_deref());

    println!("logfold --uninstall will remove:");
    for t in &targets {
        println!("  {} {}", if t.exists { "x" } else { "-" }, t.describe());
    }
    println!();
    println!("Not touched (requires sudo; see commands below if you need them):");
    println!("  - dedicated service user:  sudo userdel -r logfold");
    println!(
        "  - systemd unit file:       sudo rm -f /etc/systemd/system/logfold.service && sudo systemctl daemon-reload"
    );
    println!("  - log-file ACLs:           sudo setfacl -x u:logfold /var/log/<file>");
    println!();

    if !opts.yes && !confirm("Proceed? [y/N] ")? {
        println!("Aborted. Nothing removed.");
        return Ok(());
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
    if failed > 0 {
        std::process::exit(1);
    }
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
    out.push(mk(PathBuf::from("./learned"), "learn-mode output"));

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

fn remove_target(path: &Path) -> Result<()> {
    let md = std::fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
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
}
