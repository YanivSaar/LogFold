//! App state machine + event loop.
//!
//! P3 implementation runs synchronously: the caller first drives all
//! sources through the engine, then invokes [`run`] which takes over the
//! terminal, draws the four views, and returns on `q`. Live redraw
//! (streaming ingest in the background) lands in P4.

use std::io::{self, Stdout};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use color_eyre::eyre::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::{execute, ExecutableCommand};
use parking_lot::Mutex;
use ratatui::prelude::*;
use ratatui::widgets::Paragraph;

use crate::engine::pattern::PatternSnapshot;
use crate::engine::registry::PatternRegistry;
use crate::enrich::Enricher;
use crate::ingest::source::SourceReport;
use crate::tui::theme;
use crate::tui::views::{detail, help as helpv, overview, sources, timeline};
use crate::tui::widgets::status_bar;

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
    overview: overview::OverviewState,
    snaps: Vec<PatternSnapshot>,
    reports: Vec<SourceReport>,
    show_help: bool,
    quit: bool,
    anomaly_threshold: u32,
    min_fold: u64,
    enricher: Arc<Enricher>,
}

impl App {
    fn new(
        registry: &PatternRegistry,
        reports: Vec<SourceReport>,
        anomaly_threshold: u32,
        min_fold: u64,
        enricher: Arc<Enricher>,
    ) -> Self {
        let snaps = registry.snapshot();
        let overview = overview::OverviewState::build_filtered(
            &snaps,
            min_fold,
            anomaly_threshold,
            None,
            &enricher,
        );
        App {
            view: View::Overview,
            detail_tab: detail::Tab::default(),
            filter: String::new(),
            filter_mode: false,
            overview,
            snaps,
            reports,
            show_help: false,
            quit: false,
            anomaly_threshold,
            min_fold,
            enricher,
        }
    }

    fn selected_snap(&self) -> Option<&PatternSnapshot> {
        self.overview.selected_row().map(|r| &r.snap)
    }

    fn status_line(&self) -> String {
        let total_lines: u64 = self.reports.iter().map(|r| r.lines).sum();
        let bundle_summary = self
            .reports
            .first()
            .map(|r| format!("{} ({})", r.verdict.bundle_id, r.source.label()))
            .unwrap_or_else(|| "no sources".to_string());
        let filter_part = if self.filter_mode {
            format!("  |  filter: {}_", self.filter)
        } else if !self.filter.is_empty() {
            format!("  |  filter: {}", self.filter)
        } else {
            String::new()
        };
        format!(
            " {} lines  |  {} patterns  |  {}  |  threshold >= {}{}  |  [?]help [f]ilter [q]uit ",
            fmt_count(total_lines),
            self.overview.rows.len(),
            bundle_summary,
            self.anomaly_threshold,
            filter_part,
        )
    }

    fn handle_key(&mut self, code: KeyCode, mods: KeyModifiers) {
        // Filter capture mode intercepts everything except Enter/Esc.
        if self.filter_mode {
            match code {
                KeyCode::Esc => {
                    self.filter.clear();
                    self.filter_mode = false;
                    self.rebuild_overview_filter();
                }
                KeyCode::Enter => {
                    self.filter_mode = false;
                }
                KeyCode::Backspace => {
                    self.filter.pop();
                    self.rebuild_overview_filter();
                }
                KeyCode::Char(c) => {
                    self.filter.push(c);
                    self.rebuild_overview_filter();
                }
                _ => {}
            }
            return;
        }

        if self.show_help && !matches!(code, KeyCode::Char('?') | KeyCode::Esc) {
            self.show_help = false;
        }

        // Esc in Detail returns to Overview; everywhere else it quits.
        match code {
            KeyCode::Esc if self.view == View::Detail => self.view = View::Overview,
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Char('c') if mods.contains(KeyModifiers::CONTROL) => self.quit = true,
            KeyCode::Char('?') => self.show_help = !self.show_help,
            KeyCode::Char('1') => self.view = View::Overview,
            KeyCode::Char('2') => self.view = View::Detail,
            KeyCode::Char('3') => self.view = View::Sources,
            KeyCode::Char('4') => self.view = View::Timeline,
            // Detail sub-tab shortcuts (available in any view; enters Detail).
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
            KeyCode::Enter | KeyCode::Right => self.view = View::Detail,
            _ => {}
        }
    }

    fn rebuild_overview_filter(&mut self) {
        self.overview = overview::OverviewState::build_filtered(
            &self.snaps,
            self.min_fold,
            self.anomaly_threshold,
            Some(&self.filter),
            &self.enricher,
        );
    }

    fn refresh(&mut self, registry: &PatternRegistry) {
        let old_selected = self.overview.selected;
        self.snaps = registry.snapshot();
        self.overview = overview::OverviewState::build_filtered(
            &self.snaps,
            self.min_fold,
            self.anomaly_threshold,
            if self.filter.is_empty() {
                None
            } else {
                Some(&self.filter)
            },
            &self.enricher,
        );
        // Preserve selection if it still fits.
        if old_selected < self.overview.rows.len() {
            self.overview.selected = old_selected;
        }
    }
}

pub fn run(
    registry: Arc<PatternRegistry>,
    reports: Arc<Mutex<Vec<SourceReport>>>,
    shutdown: Arc<AtomicBool>,
    anomaly_threshold: u32,
    min_fold: u64,
    enricher: Arc<Enricher>,
) -> Result<()> {
    let mut terminal = enter_terminal()?;
    let result = run_loop(
        &mut terminal,
        registry,
        reports,
        shutdown.clone(),
        anomaly_threshold,
        min_fold,
        enricher,
    );
    leave_terminal(&mut terminal)?;
    shutdown.store(true, Ordering::Relaxed);
    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    registry: Arc<PatternRegistry>,
    reports: Arc<Mutex<Vec<SourceReport>>>,
    shutdown: Arc<AtomicBool>,
    anomaly_threshold: u32,
    min_fold: u64,
    enricher: Arc<Enricher>,
) -> Result<()> {
    let initial_reports = reports.lock().clone();
    let mut app = App::new(
        &registry,
        initial_reports,
        anomaly_threshold,
        min_fold,
        enricher,
    );
    let mut last_refresh = Instant::now();
    let refresh_period = Duration::from_millis(500);

    while !app.quit {
        terminal.draw(|frame| render(frame, &app))?;
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == event::KeyEventKind::Press {
                    app.handle_key(key.code, key.modifiers);
                }
            }
        }
        if last_refresh.elapsed() >= refresh_period {
            app.reports = reports.lock().clone();
            app.refresh(&registry);
            last_refresh = Instant::now();
        }
    }
    shutdown.store(true, Ordering::Relaxed);
    Ok(())
}

fn render(frame: &mut Frame<'_>, app: &App) {
    let area = frame.area();
    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .split(area);

    // Header tabs.
    let tab_text = format!(
        " logfold v{}   [1] Overview  [2] Detail  [3] Sources  [4] Timeline   ← {} ",
        env!("CARGO_PKG_VERSION"),
        app.view.label()
    );
    let tabs = Paragraph::new(tab_text).style(theme::header_style());
    frame.render_widget(tabs, chunks[0]);

    match app.view {
        View::Overview => overview::render(frame, chunks[1], &app.overview),
        View::Detail => {
            let peers = crate::engine::scorer::build_peer_vars(&app.snaps);
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

    status_bar::render(frame, chunks[2], &app.status_line());

    if app.show_help {
        helpv::render(frame, area);
    }
}

fn enter_terminal() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    install_panic_hook();
    enable_raw_mode().context("enabling raw mode")?;
    let mut stdout = io::stdout();
    stdout.execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;
    Ok(terminal)
}

fn leave_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

/// Install a panic hook that restores the terminal before the default
/// panic path writes to stderr. Without this, a crash inside a `draw`
/// closure leaves the user staring at a locked raw-mode terminal.
/// Idempotent on repeat calls.
fn install_panic_hook() {
    use std::sync::Once;
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let default = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let _ = disable_raw_mode();
            let _ = execute!(io::stdout(), LeaveAlternateScreen);
            default(info);
        }));
    });
}

fn fmt_count(n: u64) -> String {
    if n < 1_000 {
        return n.to_string();
    }
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    let first = bytes.len() % 3;
    if first > 0 {
        out.push_str(&s[..first]);
    }
    for (i, chunk) in s.as_bytes()[first..].chunks(3).enumerate() {
        if i > 0 || first > 0 {
            out.push(',');
        }
        out.push_str(std::str::from_utf8(chunk).unwrap());
    }
    out
}
