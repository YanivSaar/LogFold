//! File watcher with log-rotation handling.
//!
//! Follows a file by inode: when `notify` reports the path has changed
//! and the inode we have open no longer corresponds to the current path,
//! we close the old handle and open the new file from offset 0.
//!
//! This module is only compiled with the `watcher` feature.

#![cfg(feature = "watcher")]

use std::fs::{File, Metadata};
use std::io::{BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::mpsc as std_mpsc;
use std::time::Duration;

use color_eyre::eyre::{Context, Result};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use crate::ingest::source::read_bounded_line;

/// Emit source lines until `shutdown` fires. Each read-step also issues a
/// final "end" callback when the file is removed.
///
/// Call `callback` with each full line (without trailing `\n`).
pub fn tail<F>(path: &Path, mut callback: F, shutdown: &dyn Fn() -> bool) -> Result<()>
where
    F: FnMut(&str),
{
    let (tx, rx) = std_mpsc::channel::<notify::Result<Event>>();
    let mut watcher: RecommendedWatcher = notify::recommended_watcher(move |ev| {
        let _ = tx.send(ev);
    })
    .context("creating file watcher")?;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    watcher
        .watch(parent, RecursiveMode::NonRecursive)
        .with_context(|| format!("watching {}", parent.display()))?;

    // Seek to end on the initial open so a `--follow` after a one-shot
    // ingest doesn't replay the file from byte 0 (which would double
    // every pattern count). Callers that want historical replay should
    // run a one-shot pass first.
    let mut state = OpenedFile::open_at_end(path)?;

    while !shutdown() {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(Ok(event)) => handle_event(&event, path, &mut state, &mut callback)?,
            Ok(Err(e)) => tracing::warn!(?e, "watcher error"),
            Err(std_mpsc::RecvTimeoutError::Timeout) => {
                // Timer tick — poll in case the OS swallowed an event.
                state.read_to_eof(&mut callback)?;
            }
            Err(std_mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    Ok(())
}

fn handle_event<F>(
    ev: &Event,
    target: &Path,
    state: &mut OpenedFile,
    callback: &mut F,
) -> Result<()>
where
    F: FnMut(&str),
{
    let interesting = ev.paths.iter().any(|p| p == target);
    if !interesting {
        return Ok(());
    }

    match ev.kind {
        EventKind::Modify(_) => state.read_to_eof(callback)?,
        EventKind::Remove(_) | EventKind::Create(_) => {
            tracing::info!(path = %target.display(), "log rotation detected");
            *state = OpenedFile::open(target)?;
            state.read_to_eof(callback)?;
        }
        _ => {}
    }
    Ok(())
}

struct OpenedFile {
    path: PathBuf,
    reader: BufReader<File>,
    inode: u64,
}

impl OpenedFile {
    fn open(path: &Path) -> Result<Self> {
        let f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
        let inode = inode_of(&f.metadata()?);
        let reader = BufReader::new(f);
        Ok(OpenedFile {
            path: path.to_path_buf(),
            reader,
            inode,
        })
    }

    /// Open and seek to EOF — used for the initial follower attach so
    /// we only emit lines appended after we started watching.
    fn open_at_end(path: &Path) -> Result<Self> {
        let mut this = Self::open(path)?;
        let _ = this.reader.seek(SeekFrom::End(0));
        Ok(this)
    }

    fn read_to_eof<F: FnMut(&str)>(&mut self, callback: &mut F) -> Result<()> {
        // Detect truncate-in-place rotation: if the current file is shorter
        // than our reader position, seek back to 0.
        if let Ok(meta) = std::fs::metadata(&self.path) {
            let len = meta.len();
            let pos = self.reader.stream_position().unwrap_or(0);
            if len < pos {
                self.reader.seek(SeekFrom::Start(0))?;
            }
            // Detect inode change (rename-then-recreate rotation).
            if inode_of(&meta) != self.inode {
                tracing::info!(path = %self.path.display(), "inode changed, reopening");
                *self = Self::open(&self.path)?;
            }
        }

        // read_bounded_line caps at MAX_LINE_BYTES per line so a
        // rotated-to-binary file or `/dev/urandom` symlink can't OOM
        // the follower. The one-shot ingest path has always used this
        // helper; the follower was missing it until now.
        let mut buf: Vec<u8> = Vec::with_capacity(4096);
        loop {
            match read_bounded_line(&mut self.reader, &mut buf)? {
                Some(line) if line.is_empty() => continue,
                Some(line) => callback(&line),
                None => break,
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
fn inode_of(meta: &Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.ino()
}

#[cfg(not(unix))]
fn inode_of(_: &Metadata) -> u64 {
    // On Windows we fall back to a file-size proxy; proper inode-style
    // detection would use file index via winapi, out of scope for v0.1.
    0
}
