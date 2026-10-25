//! App state machine + event loop.
//!
//! The TUI thread owns the terminal, polls crossterm events, and
//! reads from the shared `PatternRegistry` + per-source progress
//! counters that the ingest threads write to. All cleanup goes
//! through [`TerminalGuard`]'s `Drop`, so panics and early returns
//! can't leave raw mode or the alt screen on.

use std::io::{self, Stdout};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use color_eyre::eyre::{Context, Result};
use crossterm::cursor::Show;
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers, MouseEventKind,
};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::{execute, ExecutableCommand};
use parking_lot::Mutex;
use ratatui::prelude::*;
use ratatui::widgets::{Block, Paragraph};

use crate::engine::pattern::PatternSnapshot;
use crate::engine::registry::PatternRegistry;
use crate::engine::scorer;
use crate::enrich::Enricher;
use crate::ingest::source::{SourceProgress, SourceReport};
use crate::tui::format::fmt_count;
use crate::tui::theme;
use crate::tui::views::{detail, help as helpv, overview, sources, timeline};
use crate::tui::widgets::status_bar;
use crate::types::TokenType;

/// How long we block in `event::poll` between frames. Short enough
/// that Ctrl+C / SIGTERM are responded to within one frame, long
/// enough that an idle TUI uses ~0% CPU.
const IDLE_POLL: Duration = Duration::from_millis(100);
/// Poll timeout when we know something is dirty / pending — matches
/// a 60 Hz redraw ceiling.
const ACTIVE_POLL: Duration = Duration::from_millis(16);
/// How often we recompute the overview + reports from the shared
/// state the ingest threads write to.
const REFRESH_PERIOD: Duration = Duration::from_millis(500);
/// Debounce for filter keystrokes before rebuilding the overview.
const FILTER_DEBOUNCE: Duration = Duration::from_millis(80);

/// Shared progress snapshot the TUI reads from. Lives at least as
/// long as the TUI run.
#[derive(Clone)]
pub struct ProgressHandle {
    pub source_label: String,
    pub progress: Arc<SourceProgress>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    Overview,
    Detail,
    Sources,
    Timeline,
}

impl View {
    fn next(self) -> Self {
        match self {
            View::Overview => View::Detail,
            View::Detail => View::Sources,
            View::Sources => View::Timeline,
            View::Timeline => View::Overview,
        }
    }

    fn label(self) -> &'static str {
        match self {
            View::Overview => "Overview",
            View::Detail => "Detail",
            View::Sources => "Sources",
            View::Timeline => "Timeline",
        }
    }
}

struct App {
    view: View,
    detail_tab: detail::Tab,
    filter: String,
    filter_mode: bool,
    filter_pending: Option<Instant>,
    overview: overview::OverviewState,
    snaps: Vec<PatternSnapshot>,
    /// Peer-var table, owned so it's not tied to `snaps`'s lifetime.
    /// Rebuilt on every refresh. One clone of ~hundreds of short
    /// strings per 500 ms is cheap next to what it replaces (a full
    /// per-render recompute at 20 Hz).
    peers_owned: Vec<(u64, TokenType, String)>,
    reports: Vec<SourceReport>,
    progress: Vec<ProgressHandle>,
    show_help: bool,
    help_state: helpv::HelpState,
    quit: bool,
    dirty: bool,
    mouse_enabled: bool,
    anomaly_threshold: u32,
    min_fold: u64,
    enricher: Arc<Enricher>,
    last_generation: u64,
    last_reports_len: usize,
}

impl App {
    fn new(
        registry: &PatternRegistry,
        reports: Vec<SourceReport>,
        progress: Vec<ProgressHandle>,
        anomaly_threshold: u32,
        min_fold: u64,
        enricher: Arc<Enricher>,
    ) -> Self {
        let snaps = registry.snapshot();
        let peers_owned = owned_peers(&snaps);
        let peers_borrow = borrow_peers(&peers_owned);
        let overview = overview::OverviewState::build_filtered(
            &snaps,
            &peers_borrow,
            min_fold,
            anomaly_threshold,
            None,
            &enricher,
        );
        let last_generation = registry.generation();
        let last_reports_len = reports.len();
        App {
            view: View::Overview,
            detail_tab: detail::Tab::default(),
            filter: String::new(),
            filter_mode: false,
            filter_pending: None,
            overview,
            snaps,
            peers_owned,
            reports,
            progress,
            show_help: false,
            help_state: helpv::HelpState::default(),
            quit: false,
            dirty: true,
            mouse_enabled: true,
            anomaly_threshold,
            min_fold,
            enricher,
            last_generation,
            last_reports_len,
        }
    }

    fn selected_snap(&self) -> Option<&PatternSnapshot> {
        self.overview.selected_row().map(|r| &r.snap)
    }

    /// Build the three-cell status bar as (left, middle, right).
    /// Each cell truncates independently so a long bundle name on the
    /// left can't push the key-hints off the right.
    fn status_cells(&self) -> (String, String, String) {
        let completed_lines: u64 = self.reports.iter().map(|r| r.lines).sum();
        let in_flight: u64 = self.progress.iter().map(|h| h.progress.load()).sum();
        let total_lines = completed_lines.max(in_flight);
        let bundle_summary = self
            .reports
            .first()
            .map(|r| format!("{} ({})", r.verdict.bundle_id, r.source.label()))
            .unwrap_or_else(|| {
                self.progress
                    .first()
                    .map(|h| format!("ingesting ({})", h.source_label))
                    .unwrap_or_else(|| "no sources".to_string())
            });

        let anomalies = self.overview.anomaly_count();
        let folds = self.overview.rows.len().saturating_sub(anomalies);
        let filter_part = if self.filter_mode {
            format!("  filter: {}_", self.filter)
        } else if !self.filter.is_empty() {
            format!(
                "  filter: {} ({} matches)",
                self.filter,
                self.overview.rows.len()
            )
        } else {
            String::new()
        };

        let left = format!(" {} lines  |  {} ", fmt_count(total_lines), bundle_summary);
        let middle = format!(
            " anomalies {} / folds {}  |  threshold >= {}{} ",
            anomalies, folds, self.anomaly_threshold, filter_part,
        );
        let right = " [?]help [f]ilter [t/T]threshold [q]uit ".to_string();
        (left, middle, right)
    }

    fn handle_key(&mut self, code: KeyCode, mods: KeyModifiers) {
        // Help overlay is sticky: only `?`, Esc, q, Ctrl+C close it.
        // Scroll keys scroll; everything else is a no-op so a user who
        // bumps a letter while reading doesn't lose their place.
        if self.show_help {
            match code {
                KeyCode::Char('?') | KeyCode::Esc | KeyCode::Char('q') => {
                    self.show_help = false;
                    self.help_state.reset();
                    self.dirty = true;
                }
                KeyCode::Char('c') if mods.contains(KeyModifiers::CONTROL) => {
                    self.quit = true;
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.help_state.scroll_down();
                    self.dirty = true;
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.help_state.scroll_up();
                    self.dirty = true;
                }
                _ => {}
            }
            return;
        }

        // Filter capture mode intercepts everything except Enter/Esc.
        if self.filter_mode {
            match code {
                KeyCode::Esc => {
                    self.filter.clear();
                    self.filter_mode = false;
                    self.schedule_filter_rebuild();
                }
                KeyCode::Enter => {
                    self.filter_mode = false;
                    self.rebuild_overview_filter();
                }
                KeyCode::Backspace => {
                    self.filter.pop();
                    self.schedule_filter_rebuild();
                }
                KeyCode::Char(c) if mods.contains(KeyModifiers::CONTROL) && c == 'c' => {
                    self.quit = true;
                }
                KeyCode::Char(c) => {
                    self.filter.push(c);
                    self.schedule_filter_rebuild();
                }
                _ => {}
            }
            self.dirty = true;
            return;
        }

        // Esc in Detail returns to Overview; everywhere else it quits.
        match code {
            KeyCode::Esc if self.view == View::Detail => self.view = View::Overview,
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Char('c') if mods.contains(KeyModifiers::CONTROL) => self.quit = true,
            KeyCode::Char('?') => {
                self.show_help = !self.show_help;
                self.help_state.reset();
            }
            KeyCode::Char('1') => self.view = View::Overview,
            KeyCode::Char('2') => self.view = View::Detail,
            KeyCode::Char('3') => self.view = View::Sources,
            KeyCode::Char('4') => self.view = View::Timeline,
            // Detail sub-tab shortcuts (only in Detail).
            KeyCode::Char('v') if self.view == View::Detail => {
                self.detail_tab = detail::Tab::Variables
            }
            KeyCode::Char('s') if self.view == View::Detail => {
                self.detail_tab = detail::Tab::ScoreBreakdown
            }
            KeyCode::Char('r') if self.view == View::Detail => {
                self.detail_tab = detail::Tab::RawLines
            }
            // Filter: `f` or `/` opens filter capture mode.
            KeyCode::Char('f') | KeyCode::Char('/') => {
                self.filter_mode = true;
                self.view = View::Overview;
            }
            KeyCode::Tab => {
                if self.view == View::Detail {
                    self.detail_tab = self.detail_tab.next();
                } else {
                    self.view = self.view.next();
                }
            }
            KeyCode::Up | KeyCode::Char('k') => self.overview.move_up(),
            KeyCode::Down | KeyCode::Char('j') => self.overview.move_down(),
            KeyCode::Char('g') => self.overview.jump_top(),
            KeyCode::Char('G') => self.overview.jump_bottom(),
            KeyCode::Char('n') => self.overview.next_anomaly(self.anomaly_threshold),
            KeyCode::Char('N') => self.overview.prev_anomaly(self.anomaly_threshold),
            // Live-tune the anomaly threshold. `t` lowers, `T` raises.
            // Range: 5..=95, step 5. Rebuilds the overview so the
            // anomalies / folds partition updates immediately.
            KeyCode::Char('t') => {
                self.anomaly_threshold = self.anomaly_threshold.saturating_sub(5).max(5);
                self.rebuild_overview_filter();
            }
            KeyCode::Char('T') => {
                self.anomaly_threshold = (self.anomaly_threshold + 5).min(95);
                self.rebuild_overview_filter();
            }
            KeyCode::Char('m') => self.mouse_enabled = !self.mouse_enabled,
            KeyCode::Enter | KeyCode::Right => self.view = View::Detail,
            _ => {}
        }
        self.dirty = true;
    }

    fn handle_mouse(&mut self, kind: MouseEventKind) {
        if !self.mouse_enabled {
            return;
        }
        match kind {
            MouseEventKind::ScrollDown => {
                self.overview.move_down();
                self.dirty = true;
            }
            MouseEventKind::ScrollUp => {
                self.overview.move_up();
                self.dirty = true;
            }
            _ => {}
        }
    }

    fn schedule_filter_rebuild(&mut self) {
        self.filter_pending = Some(Instant::now());
    }

    fn maybe_apply_pending_filter(&mut self) {
        if let Some(t) = self.filter_pending {
            if t.elapsed() >= FILTER_DEBOUNCE {
                self.rebuild_overview_filter();
                self.filter_pending = None;
                self.dirty = true;
            }
        }
    }

    fn rebuild_overview_filter(&mut self) {
        let selected = self.overview.selected;
        let peers = borrow_peers(&self.peers_owned);
        self.overview = overview::OverviewState::build_filtered(
            &self.snaps,
            &peers,
            self.min_fold,
            self.anomaly_threshold,
            if self.filter.is_empty() {
                None
            } else {
                Some(&self.filter)
            },
            &self.enricher,
        );
        if selected < self.overview.rows.len() {
            self.overview.selected = selected;
        }
    }

    /// Pull fresh state from the shared registry + reports. Only
    /// rebuilds derived data when the generation or reports vector
    /// actually changed since the last refresh.
    fn refresh(&mut self, registry: &PatternRegistry, reports: &Mutex<Vec<SourceReport>>) -> bool {
        let gen = registry.generation();
        let new_reports = reports.lock().clone();
        let changed = gen != self.last_generation || new_reports.len() != self.last_reports_len;
        if !changed {
            return false;
        }
        self.last_generation = gen;
        self.last_reports_len = new_reports.len();
        self.reports = new_reports;
        let old_selected = self.overview.selected;
        self.snaps = registry.snapshot();
        self.peers_owned = owned_peers(&self.snaps);
        let peers = borrow_peers(&self.peers_owned);
        self.overview = overview::OverviewState::build_filtered(
            &self.snaps,
            &peers,
            self.min_fold,
            self.anomaly_threshold,
            if self.filter.is_empty() {
                None
            } else {
                Some(&self.filter)
            },
            &self.enricher,
        );
        if old_selected < self.overview.rows.len() {
            self.overview.selected = old_selected;
        }
        true
    }

    /// Progress-only tick: did any in-flight counter advance? If so
    /// we want to redraw the Sources / status line, but we don't
    /// need to rebuild the overview (that's registry-driven).
    fn progress_dirty(&self) -> bool {
        // Shows up as a line-count delta against the sum we drew
        // last frame. Cheap: a few atomic loads.
        self.progress.iter().any(|h| h.progress.load() > 0)
    }
}

/// Build the peer-vars table owning its strings, so the vec can
/// outlive the snapshot slice it was derived from. `App` stores this
/// and reconstructs the `&str` view on demand via [`borrow_peers`].
fn owned_peers(snaps: &[PatternSnapshot]) -> Vec<(u64, TokenType, String)> {
    scorer::build_peer_vars(snaps)
        .into_iter()
        .map(|(id, ty, s)| (id, ty, s.to_string()))
        .collect()
}

fn borrow_peers(owned: &[(u64, TokenType, String)]) -> Vec<(u64, TokenType, &str)> {
    owned
        .iter()
        .map(|(id, ty, s)| (*id, *ty, s.as_str()))
        .collect()
}

pub fn run(
    registry: Arc<PatternRegistry>,
    reports: Arc<Mutex<Vec<SourceReport>>>,
    shutdown: Arc<AtomicBool>,
    progress: Vec<ProgressHandle>,
    anomaly_threshold: u32,
    min_fold: u64,
    enricher: Arc<Enricher>,
) -> Result<()> {
    let guard = TerminalGuard::enter()?;
    let mut terminal = guard;
    let result = run_loop(
        &mut terminal,
        registry,
        reports,
        shutdown.clone(),
        progress,
        anomaly_threshold,
        min_fold,
        enricher,
    );
    shutdown.store(true, Ordering::Relaxed);
    // Guard's Drop restores the terminal even if we return Err.
    result
}

#[allow(clippy::too_many_arguments)]
fn run_loop(
    guard: &mut TerminalGuard,
    registry: Arc<PatternRegistry>,
    reports: Arc<Mutex<Vec<SourceReport>>>,
    shutdown: Arc<AtomicBool>,
    progress: Vec<ProgressHandle>,
    anomaly_threshold: u32,
    min_fold: u64,
    enricher: Arc<Enricher>,
) -> Result<()> {
    let initial_reports = reports.lock().clone();
    let mut app = App::new(
        &registry,
        initial_reports,
        progress,
        anomaly_threshold,
        min_fold,
        enricher,
    );
    let mut last_refresh = Instant::now();
    let mut last_progress_sum: u64 = 0;

    while !app.quit {
        // Check external shutdown (Ctrl+C from parent, SIGTERM) before
        // doing any work this iteration.
        if shutdown.load(Ordering::Relaxed) {
            app.quit = true;
            break;
        }

        if app.dirty {
            guard.terminal.draw(|frame| render(frame, &app))?;
            app.dirty = false;
        }

        let poll_timeout = if app.filter_pending.is_some() {
            ACTIVE_POLL
        } else {
            IDLE_POLL
        };

        // Coalesce input: drain everything available in one iteration
        // so a paste or held key doesn't trigger one frame per char.
        let mut resized = false;
        if event::poll(poll_timeout)? {
            loop {
                let ev = event::read()?;
                match ev {
                    Event::Key(key) if key.kind == event::KeyEventKind::Press => {
                        app.handle_key(key.code, key.modifiers);
                    }
                    Event::Mouse(m) => app.handle_mouse(m.kind),
                    Event::Resize(_, _) => {
                        resized = true;
                        app.dirty = true;
                    }
                    _ => {}
                }
                // Peek without blocking; break when the burst's drained.
                if !event::poll(Duration::from_millis(0))? {
                    break;
                }
            }
        }
        // Debounce the full terminal clear: terminals (and tmux, screen)
        // emit a Resize per drag step, and clearing on each one spammed
        // redraws and flashed the screen. Clear only once per burst,
        // after the drain loop above has settled.
        if resized {
            let _ = guard.terminal.clear();
        }

        app.maybe_apply_pending_filter();

        if last_refresh.elapsed() >= REFRESH_PERIOD {
            if app.refresh(&registry, &reports) {
                app.dirty = true;
            }
            // Even if registry hasn't changed, the per-source progress
            // counter may have moved; redraw just the status/sources line.
            if app.progress_dirty() {
                let sum: u64 = app.progress.iter().map(|h| h.progress.load()).sum();
                if sum != last_progress_sum {
                    last_progress_sum = sum;
                    app.dirty = true;
                }
            }
            last_refresh = Instant::now();
        }
    }
    shutdown.store(true, Ordering::Relaxed);
    Ok(())
}

fn render(frame: &mut Frame<'_>, app: &App) {
    let area = frame.area();

    // Paint a single background block at theme body-style over the
    // frame area. This is enough to establish every cell's bg colour
    // on first draw without defeating ratatui's cell-level diff on
    // subsequent frames — the old v0.14.2 code pushed a Clear every
    // tick, which marked the whole buffer dirty every 100 ms and
    // flickered over SSH / tmux. True first-paint cleanup lives in
    // TerminalGuard::enter via terminal.clear().
    frame.render_widget(Block::default().style(theme::body_style()), area);

    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .split(area);

    // Header tabs. Pad to the full width so the header style's
    // background colour reaches both edges (ratatui's Paragraph does
    // not auto-pad trailing cells, which is why unpainted cells on the
    // right were taking on whatever was there before).
    let header_body = format!(
        " logfold v{}   [1] Overview  [2] Detail  [3] Sources  [4] Timeline   ← {} ",
        env!("CARGO_PKG_VERSION"),
        app.view.label()
    );
    let tabs = Paragraph::new(header_body).style(theme::header_style());
    frame.render_widget(tabs, chunks[0]);

    match app.view {
        View::Overview => overview::render(frame, chunks[1], &app.overview),
        View::Detail => {
            let peers = borrow_peers(&app.peers_owned);
            detail::render(
                frame,
                chunks[1],
                app.selected_snap(),
                &peers,
                app.detail_tab,
            );
        }
        View::Sources => sources::render(frame, chunks[1], &app.reports),
        View::Timeline => timeline::render(frame, chunks[1], &app.snaps),
    }

    let (sl, sm, sr) = app.status_cells();
    status_bar::render(frame, chunks[2], &sl, &sm, &sr);

    if app.show_help {
        helpv::render(frame, area, &app.help_state);
    }
}

/// Owns the terminal from `enter()` until `Drop`. Guarantees cleanup
/// runs even on panic or early return, and runs each step
/// independently so a failure in one doesn't skip the others.
struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    mouse_enabled: bool,
}

impl TerminalGuard {
    fn enter() -> Result<Self> {
        install_panic_hook();
        enable_raw_mode().context("enabling raw mode")?;
        let mut stdout = io::stdout();
        stdout.execute(EnterAlternateScreen)?;
        let _ = stdout.execute(EnableMouseCapture);
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        // Blank the alt screen explicitly: some terminals (notably
        // GNU screen without altscreen on, or passthroughs) will leave
        // the previous content visible. Ratatui's diff-based renderer
        // would then only overwrite cells it touches, letting shell
        // output show through transparent gaps. clear() guarantees a
        // clean slate before the first draw.
        terminal.clear().context("clearing terminal")?;
        Ok(TerminalGuard {
            terminal,
            mouse_enabled: true,
        })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if self.mouse_enabled {
            let _ = execute!(self.terminal.backend_mut(), DisableMouseCapture);
        }
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        let _ = disable_raw_mode();
        let _ = self.terminal.show_cursor();
        let _ = execute!(io::stdout(), Show);
        // Terminals that don't honour the alt-screen leave the cursor
        // somewhere mid-row and the next shell prompt lands on top of
        // leftover TUI content. A trailing newline parks the cursor
        // at column 0 of a fresh line.
        use std::io::Write;
        let _ = writeln!(io::stdout());
    }
}

/// Install a panic hook that restores the terminal before the default
/// panic path writes to stderr. Without this, a crash inside a `draw`
/// closure leaves the user staring at a locked raw-mode terminal with
/// a hidden cursor. Idempotent on repeat calls.
fn install_panic_hook() {
    use std::sync::Once;
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let default = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let mut stdout = io::stdout();
            let _ = execute!(stdout, DisableMouseCapture);
            let _ = execute!(stdout, LeaveAlternateScreen);
            let _ = disable_raw_mode();
            let _ = execute!(stdout, Show);
            default(info);
        }));
    });
}
