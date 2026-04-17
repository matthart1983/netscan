use crate::app::{
    AiState, App, FormField, FormMode, ProfileFormField, ScanState, Tab,
};
use crate::diff::{HostChangeKind, PortChangeKind, ScanDiff};
use crate::history::{self, ScanSummary};
use crate::theme::{self, Theme};
use crate::types::{Host, HostStatus, Port, PortState};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
#[allow(unused_imports)]
use ratatui::style::Stylize;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Tabs, Wrap};
use ratatui::Frame;

// Runtime-switchable theme. `render(&mut Frame, &App)` sets this once per
// frame; every helper below reads it via these accessors. Single-threaded
// by construction (the TUI event loop).
thread_local! {
    static CURRENT_THEME: std::cell::Cell<Theme> = std::cell::Cell::new(theme::DARK);
}

fn set_theme(t: Theme) { CURRENT_THEME.with(|c| c.set(t)); }
fn theme_now() -> Theme { CURRENT_THEME.with(|c| c.get()) }

#[allow(non_snake_case)]
fn ACCENT() -> Color { theme_now().accent }
#[allow(non_snake_case)]
fn DIM() -> Color { theme_now().dim }
#[allow(non_snake_case)]
fn BORDER() -> Color { theme_now().border }
#[allow(non_snake_case)]
fn TEXT() -> Color { theme_now().text }
#[allow(non_snake_case)]
fn DANGER() -> Color { theme_now().danger }
#[allow(non_snake_case)]
fn WARN() -> Color { theme_now().warn }
#[allow(non_snake_case)]
fn OK() -> Color { theme_now().ok }
#[allow(non_snake_case)]
fn SELECTION_BG() -> Color { theme_now().selection_bg }

pub fn render(f: &mut Frame, app: &App) {
    set_theme(app.theme);
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

    render_header(f, app, chunks[0]);
    match app.tab {
        Tab::Targets => render_targets(f, app, chunks[1]),
        Tab::Profiles => render_profiles(f, app, chunks[1]),
        Tab::Scan => render_scan(f, app, chunks[1]),
        Tab::History => render_history(f, app, chunks[1]),
    }
    render_status(f, app, chunks[2]);

    match &app.form_mode {
        FormMode::None => {}
        FormMode::AddTarget | FormMode::EditTarget(_) => {
            render_target_form_overlay(f, app, area)
        }
        FormMode::DeleteTargetConfirm(_) => {
            render_delete_confirm_overlay(f, app, area, false)
        }
        FormMode::AddProfile | FormMode::EditProfile(_) => {
            render_profile_form_overlay(f, app, area)
        }
        FormMode::DeleteProfileConfirm(_) => {
            render_delete_confirm_overlay(f, app, area, true)
        }
    }

    if app.show_help {
        render_help_overlay(f, area);
    }
}

fn render_header(f: &mut Frame, app: &App, area: Rect) {
    let titles = [Tab::Targets, Tab::Profiles, Tab::Scan, Tab::History]
        .iter()
        .enumerate()
        .map(|(i, t)| {
            Line::from(vec![
                Span::styled(
                    format!("[{}] ", i + 1),
                    Style::default().fg(DIM()),
                ),
                Span::styled(t.label(), Style::default().fg(TEXT())),
            ])
        })
        .collect::<Vec<_>>();

    let selected = match app.tab {
        Tab::Targets => 0,
        Tab::Profiles => 1,
        Tab::Scan => 2,
        Tab::History => 3,
    };

    let tabs = Tabs::new(titles)
        .select(selected)
        .style(Style::default().fg(TEXT()))
        .highlight_style(
            Style::default()
                .fg(ACCENT())
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        )
        .divider(Span::styled("│", Style::default().fg(BORDER())))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BORDER()))
                .title(Line::from(vec![
                    Span::styled(" netscan ", Style::default().fg(ACCENT()).bold()),
                    Span::styled("· nmap workflow TUI ", Style::default().fg(DIM())),
                ])),
        );

    f.render_widget(tabs, area);
}

fn render_targets(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

    let items: Vec<ListItem> = app
        .targets
        .iter()
        .map(|g| {
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!(" {} ", g.name),
                    Style::default().fg(TEXT()).bold(),
                ),
                Span::styled(
                    format!("({})", g.targets.len()),
                    Style::default().fg(DIM()),
                ),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BORDER()))
                .title(" Target groups "),
        )
        .highlight_style(
            Style::default()
                .bg(SELECTION_BG())
                .fg(ACCENT())
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▸ ");

    let mut state = ListState::default();
    state.select(Some(app.target_index));
    f.render_stateful_widget(list, chunks[0], &mut state);

    // Detail pane
    let detail_lines = if let Some(g) = app.current_target() {
        let mut lines = vec![
            Line::from(vec![Span::styled(
                format!(" {}", g.name),
                Style::default().fg(ACCENT()).bold(),
            )]),
            Line::from(Span::styled(
                format!("   {}", g.description),
                Style::default().fg(DIM()),
            )),
            Line::raw(""),
            Line::from(Span::styled(
                " Targets:",
                Style::default().fg(TEXT()).bold(),
            )),
        ];
        for t in &g.targets {
            lines.push(Line::from(Span::styled(
                format!("   • {t}"),
                Style::default().fg(TEXT()),
            )));
        }
        lines.push(Line::raw(""));
        if let Some(p) = app.current_profile() {
            lines.push(Line::from(Span::styled(
                " Selected profile:",
                Style::default().fg(TEXT()).bold(),
            )));
            lines.push(Line::from(vec![
                Span::styled(format!("   {} ", p.name), Style::default().fg(ACCENT())),
                Span::styled(p.description.clone(), Style::default().fg(DIM())),
            ]));
            lines.push(Line::raw(""));
            lines.push(Line::from(Span::styled(
                " Command preview:",
                Style::default().fg(TEXT()).bold(),
            )));
            let args = crate::nmap::build_command(p, g);
            lines.push(Line::from(Span::styled(
                format!("   nmap {}", args.join(" ")),
                Style::default().fg(OK()),
            )));
        }
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            " Enter — run scan   [2] — pick profile",
            Style::default().fg(DIM()),
        )));
        lines
    } else {
        vec![Line::from(Span::styled(
            "No target groups configured",
            Style::default().fg(WARN()),
        ))]
    };

    let para = Paragraph::new(detail_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BORDER()))
                .title(" Details "),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(para, chunks[1]);
}

fn render_profiles(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(area);

    let items: Vec<ListItem> = app
        .profiles
        .iter()
        .map(|p| {
            ListItem::new(Line::from(vec![Span::styled(
                format!(" {} ", p.name),
                Style::default().fg(TEXT()).bold(),
            )]))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BORDER()))
                .title(" Profiles "),
        )
        .highlight_style(
            Style::default()
                .bg(SELECTION_BG())
                .fg(ACCENT())
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▸ ");

    let mut state = ListState::default();
    state.select(Some(app.profile_index));
    f.render_stateful_widget(list, chunks[0], &mut state);

    let detail_lines = if let Some(p) = app.current_profile() {
        vec![
            Line::from(Span::styled(
                format!(" {}", p.name),
                Style::default().fg(ACCENT()).bold(),
            )),
            Line::from(Span::styled(
                format!("   {}", p.description),
                Style::default().fg(DIM()),
            )),
            Line::raw(""),
            Line::from(Span::styled(" Flags:", Style::default().fg(TEXT()).bold())),
            Line::from(Span::styled(
                format!("   {}", p.flags),
                Style::default().fg(OK()),
            )),
            Line::raw(""),
            Line::from(Span::styled(
                " Enter — run against selected target group",
                Style::default().fg(DIM()),
            )),
        ]
    } else {
        vec![Line::from(Span::styled(
            "No profiles configured",
            Style::default().fg(WARN()),
        ))]
    };

    let para = Paragraph::new(detail_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(BORDER()))
            .title(" Details "),
    );
    f.render_widget(para, chunks[1]);
}

fn render_scan(f: &mut Frame, app: &App, area: Rect) {
    let has_diff = app
        .last_diff
        .as_ref()
        .map(|d| !d.is_empty())
        .unwrap_or(false);
    let has_ai = !matches!(app.ai_state, AiState::Off);

    // Build vertical layout based on which panes are active.
    let summary_height =
        if matches!(app.scan_state, ScanState::Running | ScanState::Paused) {
            5 // adds a progress bar row
        } else {
            4
        };
    let mut constraints: Vec<Constraint> = Vec::new();
    constraints.push(Constraint::Length(summary_height)); // summary
    constraints.push(Constraint::Min(0)); // host list + detail
    if has_diff {
        constraints.push(Constraint::Length(10));
    }
    if has_ai {
        constraints.push(Constraint::Length(ai_pane_height(app)));
    }

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    render_scan_summary(f, app, layout[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(layout[1]);

    render_host_list(f, app, body[0]);
    render_host_detail(f, app, body[1]);

    let mut idx = 2;
    if has_diff {
        render_diff_pane(f, app.last_diff.as_ref().unwrap(), layout[idx]);
        idx += 1;
    }
    if has_ai {
        render_ai_pane(f, app, layout[idx]);
    }
}

fn ai_pane_height(app: &App) -> u16 {
    match &app.ai_state {
        AiState::Off => 0,
        AiState::Pending => 3,
        AiState::Ready(text) => {
            let lines = text.lines().count() as u16 + 2;
            lines.clamp(4, 14)
        }
        AiState::Failed(_) => 4,
    }
}

fn render_ai_pane(f: &mut Frame, app: &App, area: Rect) {
    let title = Line::from(vec![
        Span::styled(" AI triage ", Style::default().fg(ACCENT()).bold()),
        Span::styled(
            format!("· {} ", app_model_label(app)),
            Style::default().fg(DIM()),
        ),
    ]);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT()))
        .title(title);

    let lines: Vec<Line> = match &app.ai_state {
        AiState::Off => vec![],
        AiState::Pending => vec![Line::from(Span::styled(
            " analyzing scan… ",
            Style::default().fg(DIM()),
        ))],
        AiState::Ready(text) => text
            .lines()
            .map(|l| Line::from(Span::styled(format!(" {l}"), Style::default().fg(TEXT()))))
            .collect(),
        AiState::Failed(err) => vec![
            Line::from(Span::styled(
                " AI triage failed",
                Style::default().fg(DANGER()).bold(),
            )),
            Line::from(Span::styled(format!(" {err}"), Style::default().fg(DIM()))),
            Line::from(Span::styled(
                " check ~/.config/netscan/config.toml — endpoint, model, or Ollama daemon",
                Style::default().fg(DIM()),
            )),
        ],
    };

    let para = Paragraph::new(lines).block(block).wrap(Wrap { trim: false });
    f.render_widget(para, area);
}

fn app_model_label(app: &App) -> &str {
    // Displayed next to the AI title — model name + endpoint if useful.
    // Kept intentionally narrow; full config lives in the TOML file.
    match &app.ai_state {
        AiState::Pending => "working",
        AiState::Ready(_) => "ready",
        AiState::Failed(_) => "error",
        AiState::Off => "",
    }
}

fn render_diff_pane(f: &mut Frame, diff: &ScanDiff, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(vec![
        Span::styled(" Changes since ", Style::default().fg(DIM())),
        Span::styled(
            history::format_timestamp(diff.prev_started),
            Style::default().fg(TEXT()),
        ),
        Span::styled("  — ", Style::default().fg(DIM())),
        Span::styled(diff.summary(), Style::default().fg(ACCENT()).bold()),
    ]));
    for hc in diff.host_changes.iter().take(8) {
        let (tag, color) = match hc.kind {
            HostChangeKind::New => ("+ NEW    ", OK()),
            HostChangeKind::Removed => ("- RMV    ", DANGER()),
            HostChangeKind::StatusChanged => ("~ STATUS ", WARN()),
            HostChangeKind::Modified => ("~ MOD    ", WARN()),
            HostChangeKind::Unchanged => continue,
        };
        let host_label = match &hc.hostname {
            Some(h) => format!("{} ({})", hc.address, h),
            None => hc.address.clone(),
        };
        let mut spans = vec![
            Span::styled(tag, Style::default().fg(color).bold()),
            Span::styled(host_label, Style::default().fg(TEXT())),
        ];
        if !hc.port_changes.is_empty() {
            let openings = hc
                .port_changes
                .iter()
                .filter(|p| p.kind == PortChangeKind::NewlyOpen)
                .count();
            let closings = hc
                .port_changes
                .iter()
                .filter(|p| p.kind == PortChangeKind::NewlyClosed)
                .count();
            let version_changes = hc
                .port_changes
                .iter()
                .filter(|p| p.kind == PortChangeKind::VersionChanged)
                .count();
            let service_changes = hc
                .port_changes
                .iter()
                .filter(|p| p.kind == PortChangeKind::ServiceChanged)
                .count();
            let mut bits = Vec::new();
            if openings > 0 {
                bits.push(format!("+{openings}"));
            }
            if closings > 0 {
                bits.push(format!("-{closings}"));
            }
            if version_changes > 0 {
                bits.push(format!("v{version_changes}"));
            }
            if service_changes > 0 {
                bits.push(format!("s{service_changes}"));
            }
            if !bits.is_empty() {
                spans.push(Span::raw("  "));
                spans.push(Span::styled(
                    format!("[{}]", bits.join(" ")),
                    Style::default().fg(DIM()),
                ));
            }
        }
        lines.push(Line::from(spans));
    }
    if diff.host_changes.len() > 8 {
        lines.push(Line::from(Span::styled(
            format!("  … and {} more. Open in History for full diff.", diff.host_changes.len() - 8),
            Style::default().fg(DIM()),
        )));
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT()))
        .title(" Diff ");
    let para = Paragraph::new(lines).block(block).wrap(Wrap { trim: false });
    f.render_widget(para, area);
}

fn render_scan_summary(f: &mut Frame, app: &App, area: Rect) {
    let state_str = match app.scan_state {
        ScanState::Idle => Span::styled(" idle ", Style::default().fg(DIM())),
        ScanState::Running => Span::styled(
            " running ",
            Style::default().fg(ACCENT()).add_modifier(Modifier::BOLD),
        ),
        ScanState::Paused => Span::styled(
            " paused ",
            Style::default().fg(WARN()).add_modifier(Modifier::BOLD),
        ),
        ScanState::Finished => Span::styled(
            " finished ",
            Style::default().fg(OK()).add_modifier(Modifier::BOLD),
        ),
        ScanState::Failed => Span::styled(
            " failed ",
            Style::default().fg(DANGER()).add_modifier(Modifier::BOLD),
        ),
    };

    let elapsed = format!(
        "{:>02}:{:>02}",
        app.scan_elapsed.as_secs() / 60,
        app.scan_elapsed.as_secs() % 60
    );

    let mut header_spans = vec![
        Span::styled(" state: ", Style::default().fg(DIM())),
        state_str,
        Span::styled("  elapsed: ", Style::default().fg(DIM())),
        Span::styled(elapsed, Style::default().fg(TEXT())),
        Span::styled("  hosts: ", Style::default().fg(DIM())),
        Span::styled(
            format!("{}", app.scan_hosts.len()),
            Style::default().fg(TEXT()),
        ),
    ];
    if app.hosts_up + app.hosts_down > 0 {
        header_spans.push(Span::styled(
            format!("  (up {} / down {})", app.hosts_up, app.hosts_down),
            Style::default().fg(DIM()),
        ));
    }
    if let Some(eta) = app.scan_eta_secs {
        if matches!(
            app.scan_state,
            ScanState::Running | ScanState::Paused
        ) {
            header_spans.push(Span::styled(
                format!("  eta: {}", format_hms(eta)),
                Style::default().fg(DIM()),
            ));
        }
    }
    let header = Line::from(header_spans);

    // Progress bar line — only rendered during Running or Paused with a known percent.
    let progress_line = if matches!(app.scan_state, ScanState::Running | ScanState::Paused) {
        Some(progress_bar_line(app.scan_progress))
    } else {
        None
    };

    let command_line = if app.scan_command.is_empty() {
        "no scan yet — press Enter on a target group to start".to_string()
    } else {
        app.scan_command.clone()
    };
    let cmd = Line::from(vec![
        Span::styled(" cmd:   ", Style::default().fg(DIM())),
        Span::styled(command_line, Style::default().fg(OK())),
    ]);

    let mut lines = vec![header];
    if let Some(pl) = progress_line {
        lines.push(pl);
    }
    lines.push(cmd);

    let para = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(BORDER()))
            .title(" Scan "),
    );
    f.render_widget(para, area);
}

fn progress_bar_line(percent: Option<f32>) -> Line<'static> {
    let width: usize = 36;
    let (pct, label) = match percent {
        Some(p) => (p.clamp(0.0, 100.0), format!("{:>5.1}%", p)),
        None => (0.0, "  …  ".to_string()),
    };
    let filled = ((pct / 100.0) * width as f32).round() as usize;
    let filled = filled.min(width);
    let bar_filled: String = "█".repeat(filled);
    let bar_empty: String = "·".repeat(width - filled);
    Line::from(vec![
        Span::styled(" prog:  ", Style::default().fg(DIM())),
        Span::styled("[", Style::default().fg(DIM())),
        Span::styled(bar_filled, Style::default().fg(ACCENT()).bold()),
        Span::styled(bar_empty, Style::default().fg(DIM())),
        Span::styled("] ", Style::default().fg(DIM())),
        Span::styled(label, Style::default().fg(TEXT())),
    ])
}

fn format_hms(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{}h{:02}m{:02}s", h, m, s)
    } else if m > 0 {
        format!("{}m{:02}s", m, s)
    } else {
        format!("{}s", s)
    }
}

fn render_host_list(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .scan_hosts
        .iter()
        .map(|h| {
            let dot = match h.status {
                HostStatus::Up => Span::styled("● ", Style::default().fg(OK())),
                HostStatus::Down => Span::styled("● ", Style::default().fg(DANGER())),
                HostStatus::Unknown => Span::styled("● ", Style::default().fg(DIM())),
            };
            let label = match &h.hostname {
                Some(hn) => format!("{hn} ({})", h.address),
                None => h.address.clone(),
            };
            let open_ports = h.ports.iter().filter(|p| p.state == PortState::Open).count();
            ListItem::new(Line::from(vec![
                dot,
                Span::styled(label, Style::default().fg(TEXT())),
                Span::raw("  "),
                Span::styled(
                    format!("{} open", open_ports),
                    Style::default().fg(DIM()),
                ),
            ]))
        })
        .collect();

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER()))
        .title(" Hosts ");

    if items.is_empty() {
        let msg = match app.scan_state {
            ScanState::Idle => "No scan yet. Press [1], select a group, press Enter.",
            ScanState::Running => "Scanning… hosts will appear as nmap reports them.",
            ScanState::Paused => "Scan paused. Press [p] to resume.",
            ScanState::Finished => "Scan finished with no hosts (filtered or down).",
            ScanState::Failed => "Scan failed. See status bar.",
        };
        let para = Paragraph::new(msg)
            .style(Style::default().fg(DIM()))
            .block(block);
        f.render_widget(para, area);
        return;
    }

    let list = List::new(items)
        .block(block)
        .highlight_style(
            Style::default()
                .bg(SELECTION_BG())
                .fg(ACCENT())
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▸ ");

    let mut state = ListState::default();
    state.select(Some(app.scan_host_index.min(app.scan_hosts.len().saturating_sub(1))));
    f.render_stateful_widget(list, area, &mut state);
}

fn render_host_detail(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER()))
        .title(" Ports & scripts ");

    let lines: Vec<Line> = if let Some(host) = app.current_host() {
        let mut lines: Vec<Line> = Vec::new();
        lines.push(host_header_line(host));
        if let Some(os) = &host.os_guess {
            lines.push(Line::from(Span::styled(
                format!(" OS guess: {os}"),
                Style::default().fg(DIM()),
            )));
        }
        lines.push(Line::raw(""));

        if host.ports.is_empty() {
            lines.push(Line::from(Span::styled(
                " (no ports reported)",
                Style::default().fg(DIM()),
            )));
        } else {
            lines.push(Line::from(Span::styled(
                " PORT       STATE     SERVICE                VERSION",
                Style::default().fg(DIM()).add_modifier(Modifier::BOLD),
            )));
            for p in &host.ports {
                lines.push(port_line(p));
                for script in &p.scripts {
                    for (i, l) in script.output.lines().enumerate() {
                        let prefix = if i == 0 {
                            format!("    └─ {}: ", script.id)
                        } else {
                            "       ".to_string()
                        };
                        lines.push(Line::from(vec![
                            Span::styled(prefix, Style::default().fg(WARN())),
                            Span::styled(l.to_string(), Style::default().fg(DIM())),
                        ]));
                    }
                }
            }
        }
        lines
    } else {
        vec![Line::from(Span::styled(
            "Select a host on the left.",
            Style::default().fg(DIM()),
        ))]
    };

    let para = Paragraph::new(lines).block(block).wrap(Wrap { trim: false });
    f.render_widget(para, area);
}

fn host_header_line(host: &Host) -> Line<'static> {
    let status_span = match host.status {
        HostStatus::Up => Span::styled(" up ", Style::default().fg(OK()).bold()),
        HostStatus::Down => Span::styled(" down ", Style::default().fg(DANGER()).bold()),
        HostStatus::Unknown => Span::styled(" unknown ", Style::default().fg(DIM())),
    };
    let mut spans = vec![
        Span::styled(
            format!(" {} ", host.address),
            Style::default().fg(ACCENT()).bold(),
        ),
        status_span,
    ];
    if let Some(hn) = &host.hostname {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(hn.clone(), Style::default().fg(DIM())));
    }
    Line::from(spans)
}

fn port_line(p: &Port) -> Line<'static> {
    let state_color = match p.state {
        PortState::Open => OK(),
        PortState::Closed => DIM(),
        PortState::Filtered => WARN(),
        PortState::Other => DIM(),
    };
    let port_col = format!(" {}/{:<6}", p.port, p.protocol);
    let state_col = format!("{:<10}", p.state.label());
    let service_col = format!("{:<22}", p.service.clone().unwrap_or_default());
    let version = match (p.product.as_deref(), p.version.as_deref()) {
        (Some(prod), Some(ver)) => format!("{prod} {ver}"),
        (Some(prod), None) => prod.to_string(),
        (None, Some(ver)) => ver.to_string(),
        (None, None) => String::new(),
    };

    Line::from(vec![
        Span::styled(port_col, Style::default().fg(TEXT())),
        Span::styled(state_col, Style::default().fg(state_color)),
        Span::styled(service_col, Style::default().fg(TEXT())),
        Span::styled(version, Style::default().fg(DIM())),
    ])
}

fn render_history(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .split(area);

    render_history_list(f, app, chunks[0]);
    render_history_detail(f, app, chunks[1]);
}

fn render_full_diff(f: &mut Frame, diff: &ScanDiff, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT()))
        .title(Line::from(vec![
            Span::styled(" Diff view ", Style::default().fg(ACCENT()).bold()),
            Span::styled("(Esc to close)", Style::default().fg(DIM())),
        ]));

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(vec![
        Span::styled(" prev: ", Style::default().fg(DIM())),
        Span::styled(
            format!("{}  ({})", &diff.prev_id[..diff.prev_id.len().min(8)], history::format_timestamp(diff.prev_started)),
            Style::default().fg(TEXT()),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled(" curr: ", Style::default().fg(DIM())),
        Span::styled(
            &diff.curr_id[..diff.curr_id.len().min(8)],
            Style::default().fg(TEXT()),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled(" summary: ", Style::default().fg(DIM())),
        Span::styled(diff.summary(), Style::default().fg(ACCENT()).bold()),
    ]));
    lines.push(Line::raw(""));

    if diff.is_empty() {
        lines.push(Line::from(Span::styled(
            "No changes between these scans.",
            Style::default().fg(DIM()),
        )));
    }

    for hc in &diff.host_changes {
        let (tag, color) = match hc.kind {
            HostChangeKind::New => ("+ NEW   ", OK()),
            HostChangeKind::Removed => ("- RMV   ", DANGER()),
            HostChangeKind::StatusChanged => ("~ STATUS", WARN()),
            HostChangeKind::Modified => ("~ MOD   ", WARN()),
            HostChangeKind::Unchanged => continue,
        };
        let host_label = match &hc.hostname {
            Some(h) => format!("{} ({})", hc.address, h),
            None => hc.address.clone(),
        };
        lines.push(Line::from(vec![
            Span::styled(" ", Style::default()),
            Span::styled(tag, Style::default().fg(color).bold()),
            Span::raw("  "),
            Span::styled(host_label, Style::default().fg(TEXT()).bold()),
        ]));
        for pc in &hc.port_changes {
            let (prefix, pcolor, detail) = match pc.kind {
                PortChangeKind::NewlyOpen => (
                    "     + ",
                    OK(),
                    format!(
                        "{}/{} {} {}",
                        pc.port,
                        pc.protocol,
                        pc.curr_service.clone().unwrap_or_default(),
                        pc.curr_version.clone().unwrap_or_default()
                    ),
                ),
                PortChangeKind::NewlyClosed => (
                    "     - ",
                    DANGER(),
                    format!(
                        "{}/{} {} {}",
                        pc.port,
                        pc.protocol,
                        pc.prev_service.clone().unwrap_or_default(),
                        pc.prev_version.clone().unwrap_or_default()
                    ),
                ),
                PortChangeKind::StateChanged => (
                    "     ~ ",
                    WARN(),
                    format!(
                        "{}/{}  {} → {}",
                        pc.port,
                        pc.protocol,
                        state_label(pc.prev_state),
                        state_label(pc.curr_state)
                    ),
                ),
                PortChangeKind::ServiceChanged => (
                    "     ~ ",
                    WARN(),
                    format!(
                        "{}/{}  service {} → {}",
                        pc.port,
                        pc.protocol,
                        pc.prev_service.clone().unwrap_or_else(|| "?".to_string()),
                        pc.curr_service.clone().unwrap_or_else(|| "?".to_string())
                    ),
                ),
                PortChangeKind::VersionChanged => (
                    "     ~ ",
                    WARN(),
                    format!(
                        "{}/{}  version {} → {}",
                        pc.port,
                        pc.protocol,
                        pc.prev_version.clone().unwrap_or_else(|| "?".to_string()),
                        pc.curr_version.clone().unwrap_or_else(|| "?".to_string())
                    ),
                ),
            };
            lines.push(Line::from(vec![
                Span::styled(prefix, Style::default().fg(pcolor).bold()),
                Span::styled(detail, Style::default().fg(DIM())),
            ]));
        }
    }

    let para = Paragraph::new(lines).block(block).wrap(Wrap { trim: false });
    f.render_widget(para, area);
}

fn state_label(s: Option<PortState>) -> String {
    match s {
        Some(st) => st.label().to_string(),
        None => "—".to_string(),
    }
}

fn render_history_list(f: &mut Frame, app: &App, area: Rect) {
    let title = match &app.history_marked_id {
        Some(id) => format!(
            " History ({})  ★ {} marked ",
            app.history_entries.len(),
            &id[..id.len().min(8)]
        ),
        None => format!(" History ({}) ", app.history_entries.len()),
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER()))
        .title(title);

    if app.history_entries.is_empty() {
        let para = Paragraph::new("No scans in history yet. Run a scan from the Targets tab.")
            .style(Style::default().fg(DIM()))
            .block(block);
        f.render_widget(para, area);
        return;
    }

    let now = history::now_secs();
    let items: Vec<ListItem> = app
        .history_entries
        .iter()
        .map(|s: &ScanSummary| {
            let ago = history::human_ago(now - s.started_at);
            let status_color = match s.status.as_str() {
                "finished" => OK(),
                "running" => ACCENT(),
                _ => DANGER(),
            };
            let is_marked = app.history_marked_id.as_deref() == Some(s.id.as_str());
            let marker = if is_marked {
                Span::styled("★ ", Style::default().fg(WARN()).bold())
            } else {
                Span::raw("  ")
            };
            ListItem::new(Line::from(vec![
                marker,
                Span::styled(
                    s.group_name.clone(),
                    Style::default().fg(TEXT()).bold(),
                ),
                Span::styled(
                    format!(" · {}", s.profile_name),
                    Style::default().fg(DIM()),
                ),
                Span::raw("  "),
                Span::styled(
                    format!("{}↑", s.hosts_up),
                    Style::default().fg(status_color),
                ),
                Span::raw("  "),
                Span::styled(ago, Style::default().fg(DIM())),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(block)
        .highlight_style(
            Style::default()
                .bg(SELECTION_BG())
                .fg(ACCENT())
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▸ ");
    let mut state = ListState::default();
    state.select(Some(app.history_index));
    f.render_stateful_widget(list, area, &mut state);
}

fn render_history_detail(f: &mut Frame, app: &App, area: Rect) {
    if let Some(diff) = app.history_diff_view.as_ref() {
        render_full_diff(f, diff, area);
        return;
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER()))
        .title(" Scan details ");

    let Some(rec) = app.history_selected.as_ref() else {
        let para = Paragraph::new("Select a scan from the list.")
            .style(Style::default().fg(DIM()))
            .block(block);
        f.render_widget(para, area);
        return;
    };

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(vec![
        Span::styled(" ", Style::default()),
        Span::styled(rec.id.clone(), Style::default().fg(ACCENT()).bold()),
        Span::raw("  "),
        Span::styled(
            format!("{} / {}", rec.group_name, rec.profile_name),
            Style::default().fg(TEXT()),
        ),
    ]));
    lines.push(Line::from(vec![Span::styled(
        format!(" started: {}", history::format_timestamp(rec.started_at)),
        Style::default().fg(DIM()),
    )]));
    lines.push(Line::from(vec![Span::styled(
        format!(" cmd:     {}", rec.command),
        Style::default().fg(OK()),
    )]));
    lines.push(Line::from(vec![Span::styled(
        format!(
            " hosts:   {} up / {} down   ({} recorded)",
            rec.hosts_up,
            rec.hosts_down,
            rec.hosts.len()
        ),
        Style::default().fg(DIM()),
    )]));
    lines.push(Line::raw(""));

    for host in &rec.hosts {
        lines.push(host_header_line(host));
        if host.ports.is_empty() {
            lines.push(Line::from(Span::styled(
                "  (no ports)",
                Style::default().fg(DIM()),
            )));
            continue;
        }
        for p in &host.ports {
            lines.push(port_line(p));
        }
        lines.push(Line::raw(""));
    }

    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        " [e] export bundle   [r] reload list",
        Style::default().fg(DIM()),
    )));

    let para = Paragraph::new(lines).block(block).wrap(Wrap { trim: false });
    f.render_widget(para, area);
}

fn render_status(f: &mut Frame, app: &App, area: Rect) {
    let hint = match app.tab {
        Tab::Targets => " [↑↓/jk] nav   [Enter] run scan   [a]dd   [e]dit   [d]elete   [t] theme   [?] help ",
        Tab::Profiles => " [↑↓/jk] nav   [Enter] run scan   [a]dd   [e]dit   [d]elete   [t] theme   [?] help ",
        Tab::Scan => " [↑↓/jk] hosts   [p]ause   [x] stop   [Enter] rerun   [Shift+E] export ",
        Tab::History => " [↑↓/jk] navigate   [m] mark   [d] diff marked↔current   [e] export   [r] reload   [Esc] clear ",
    };
    let mut spans: Vec<Span> = vec![Span::styled(hint, Style::default().fg(DIM()))];

    if let Some((msg, _)) = &app.toast {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(msg.clone(), Style::default().fg(OK()).bold()));
    } else if let Some(err) = &app.scan_error {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            format!("error: {err}"),
            Style::default().fg(DANGER()),
        ));
    } else if matches!(app.scan_state, ScanState::Finished) && !app.scan_summary.is_empty() {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            app.scan_summary.clone(),
            Style::default().fg(OK()),
        ));
    }

    if app.has_schedules() {
        if let Some((next_at, target, profile)) = app.next_scheduled() {
            let now = crate::history::now_secs();
            let secs_left = (next_at - now).max(0);
            let label = if secs_left <= 0 {
                format!("  [{target}/{profile} due]")
            } else if secs_left < 60 {
                format!("  [{target}/{profile} in {secs_left}s]")
            } else if secs_left < 3600 {
                format!("  [{target}/{profile} in {}m]", secs_left / 60)
            } else {
                format!("  [{target}/{profile} in {}h {}m]", secs_left / 3600, (secs_left % 3600) / 60)
            };
            spans.push(Span::styled(label, Style::default().fg(DIM())));
        }
    }

    let para = Paragraph::new(Line::from(spans));
    f.render_widget(para, area);
}

fn render_target_form_overlay(f: &mut Frame, app: &App, area: Rect) {
    let (title, mode_label) = match app.form_mode {
        FormMode::AddTarget => (" Add target group ", "Add"),
        FormMode::EditTarget(_) => (" Edit target group ", "Edit"),
        _ => (" Target group ", ""),
    };
    let _ = mode_label;

    let target_lines = app.form.targets.len().max(1) as u16;
    let body_lines: u16 = 1 /*name*/ + 1 /*desc*/ + 1 /*targets label*/ + target_lines + 1 /*blank*/ + 2 /*hints*/;
    let error_bonus: u16 = if app.form.error.is_some() { 2 } else { 0 };
    let h = (body_lines + error_bonus + 4).min(area.height.saturating_sub(4)).max(12);
    let w = 68.min(area.width.saturating_sub(4));
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    let rect = Rect { x, y, width: w, height: h };

    f.render_widget(Clear, rect);

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::raw(""));
    lines.push(form_field_line(
        "Name       ",
        &app.form.name,
        app.form.field == FormField::Name,
        false,
    ));
    lines.push(form_field_line(
        "Description",
        &app.form.description,
        app.form.field == FormField::Description,
        false,
    ));
    lines.push(Line::from(vec![
        Span::styled("  ", Style::default()),
        Span::styled(
            if app.form.field == FormField::Targets {
                "Targets    ▸".to_string()
            } else {
                "Targets    ·".to_string()
            },
            Style::default().fg(if app.form.field == FormField::Targets {
                ACCENT()
            } else {
                DIM()
            }),
        ),
    ]));
    let targets_focused = app.form.field == FormField::Targets;
    let last_idx = app.form.targets.len().saturating_sub(1);
    for (i, t) in app.form.targets.iter().enumerate() {
        let is_current = targets_focused && i == last_idx;
        let cursor = if is_current { "█" } else { "" };
        let bullet_color = if t.trim().is_empty() { DIM() } else { OK() };
        lines.push(Line::from(vec![
            Span::styled("              ", Style::default()),
            Span::styled("• ", Style::default().fg(bullet_color)),
            Span::styled(t.clone(), Style::default().fg(TEXT())),
            Span::styled(cursor, Style::default().fg(ACCENT()).bold()),
        ]));
    }
    lines.push(Line::raw(""));

    if let Some(err) = &app.form.error {
        lines.push(Line::from(vec![Span::styled(
            format!("  error: {err}"),
            Style::default().fg(DANGER()),
        )]));
        lines.push(Line::raw(""));
    }

    lines.push(Line::from(vec![Span::styled(
        "  [Tab/Shift+Tab] switch fields   [Enter] next / new target line",
        Style::default().fg(DIM()),
    )]));
    lines.push(Line::from(vec![Span::styled(
        "  [Ctrl+S] save                   [Esc] cancel",
        Style::default().fg(DIM()),
    )]));

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT()))
        .title(Span::styled(title, Style::default().fg(ACCENT()).bold()));
    let para = Paragraph::new(lines).block(block).wrap(Wrap { trim: false });
    f.render_widget(para, rect);
}

fn form_field_line(label: &str, value: &str, focused: bool, _last: bool) -> Line<'static> {
    let marker = if focused { "▸" } else { "·" };
    let label_color = if focused { ACCENT() } else { DIM() };
    let cursor = if focused { "█" } else { "" };
    Line::from(vec![
        Span::styled("  ", Style::default()),
        Span::styled(format!("{label} {marker} "), Style::default().fg(label_color)),
        Span::styled(value.to_string(), Style::default().fg(TEXT())),
        Span::styled(cursor, Style::default().fg(ACCENT()).bold()),
    ])
}

fn render_profile_form_overlay(f: &mut Frame, app: &App, area: Rect) {
    let title = match app.form_mode {
        FormMode::AddProfile => " Add scan profile ",
        FormMode::EditProfile(_) => " Edit scan profile ",
        _ => " Scan profile ",
    };

    let body_lines: u16 = 1 + 1 + 1 + 1 + 3;
    let error_bonus: u16 = if app.profile_form.error.is_some() { 2 } else { 0 };
    let h = (body_lines + error_bonus + 4)
        .min(area.height.saturating_sub(4))
        .max(12);
    let w = 78.min(area.width.saturating_sub(4));
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    let rect = Rect { x, y, width: w, height: h };

    f.render_widget(Clear, rect);

    let f_ = &app.profile_form;
    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::raw(""));
    lines.push(profile_field_line(
        "Name       ",
        &f_.name,
        f_.field == ProfileFormField::Name,
    ));
    lines.push(profile_field_line(
        "Description",
        &f_.description,
        f_.field == ProfileFormField::Description,
    ));
    lines.push(profile_field_line(
        "Flags      ",
        &f_.flags,
        f_.field == ProfileFormField::Flags,
    ));
    lines.push(Line::raw(""));
    lines.push(Line::from(vec![Span::styled(
        "  example flags: -T4 --top-ports 100 -sV -sC",
        Style::default().fg(DIM()),
    )]));

    if let Some(err) = &f_.error {
        lines.push(Line::raw(""));
        lines.push(Line::from(vec![Span::styled(
            format!("  error: {err}"),
            Style::default().fg(DANGER()),
        )]));
    }

    lines.push(Line::raw(""));
    lines.push(Line::from(vec![Span::styled(
        "  [Tab/Shift+Tab] switch fields   [Ctrl+S] save   [Esc] cancel",
        Style::default().fg(DIM()),
    )]));

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT()))
        .title(Span::styled(title, Style::default().fg(ACCENT()).bold()));
    let para = Paragraph::new(lines).block(block).wrap(Wrap { trim: false });
    f.render_widget(para, rect);
}

fn profile_field_line(label: &str, value: &str, focused: bool) -> Line<'static> {
    let marker = if focused { "▸" } else { "·" };
    let label_color = if focused { ACCENT() } else { DIM() };
    let cursor = if focused { "█" } else { "" };
    Line::from(vec![
        Span::styled("  ", Style::default()),
        Span::styled(format!("{label} {marker} "), Style::default().fg(label_color)),
        Span::styled(value.to_string(), Style::default().fg(TEXT())),
        Span::styled(cursor, Style::default().fg(ACCENT()).bold()),
    ])
}

fn render_delete_confirm_overlay(f: &mut Frame, app: &App, area: Rect, is_profile: bool) {
    let (name, kind) = match (&app.form_mode, is_profile) {
        (FormMode::DeleteTargetConfirm(idx), false) => (
            app.targets
                .get(*idx)
                .map(|g| g.name.clone())
                .unwrap_or_default(),
            "target group",
        ),
        (FormMode::DeleteProfileConfirm(idx), true) => (
            app.profiles
                .get(*idx)
                .map(|p| p.name.clone())
                .unwrap_or_default(),
            "profile",
        ),
        _ => return,
    };

    let w = 56.min(area.width.saturating_sub(4));
    let h = 9u16.min(area.height.saturating_sub(4));
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    let rect = Rect { x, y, width: w, height: h };
    f.render_widget(Clear, rect);

    let lines = vec![
        Line::raw(""),
        Line::from(vec![Span::styled(
            format!("  Delete {kind}?"),
            Style::default().fg(DANGER()).bold(),
        )]),
        Line::raw(""),
        Line::from(vec![
            Span::styled("    ", Style::default()),
            Span::styled(name, Style::default().fg(TEXT()).bold()),
        ]),
        Line::raw(""),
        Line::from(vec![Span::styled(
            "  [y] yes, delete       [any other key] cancel",
            Style::default().fg(DIM()),
        )]),
    ];
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(DANGER()))
        .title(Span::styled(
            " Confirm delete ",
            Style::default().fg(DANGER()).bold(),
        ));
    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, rect);
}

fn render_help_overlay(f: &mut Frame, area: Rect) {
    let w = 62.min(area.width.saturating_sub(4));
    let h = 18.min(area.height.saturating_sub(4));
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    let rect = Rect {
        x,
        y,
        width: w,
        height: h,
    };

    f.render_widget(Clear, rect);

    let lines = vec![
        Line::from(Span::styled(
            " netscan — keybindings ",
            Style::default().fg(ACCENT()).bold(),
        )),
        Line::raw(""),
        Line::from(" [1/2/3/4] switch tabs (Targets / Profiles / Scan / History)"),
        Line::from(" [Tab]     next tab"),
        Line::from(" [↑↓/jk]   navigate lists"),
        Line::from(" [Enter]   run scan with selected target + profile"),
        Line::from(" [a/e/d]   add / edit / delete (Targets & Profiles tabs)"),
        Line::from(" [t]       cycle theme (dark / solarized / dracula / nord / gruvbox)"),
        Line::from(" [Ctrl+S]  save form   [Esc]  cancel form"),
        Line::from(" [p]       pause / resume a running scan (SIGSTOP/SIGCONT)"),
        Line::from(" [x]       stop a running scan"),
        Line::from(" [Shift+E] export incident bundle (Scan tab)"),
        Line::from(" [m]       mark scan for diff  (History tab)"),
        Line::from(" [d]       diff marked ↔ current  (History tab)"),
        Line::from(" [e]       export selected history entry"),
        Line::from(" [r]       reload history list"),
        Line::from(" [Esc]     close diff view / clear mark"),
        Line::from(" [?]       this help"),
        Line::from(" [q]       quit (or stop a running scan)"),
        Line::raw(""),
        Line::from(Span::styled(
            " Config files (edit in your editor):",
            Style::default().fg(TEXT()).bold(),
        )),
        Line::from(Span::styled(
            "  ~/.config/netscan/targets.toml",
            Style::default().fg(DIM()),
        )),
        Line::from(Span::styled(
            "  ~/.config/netscan/profiles.toml",
            Style::default().fg(DIM()),
        )),
        Line::from(Span::styled(
            "  ~/.config/netscan/config.toml  (AI triage)",
            Style::default().fg(DIM()),
        )),
        Line::raw(""),
        Line::from(Span::styled(
            " press Esc, ?, or q to close ",
            Style::default().fg(DIM()),
        )),
    ];
    let para = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(ACCENT()))
            .title(" Help "),
    );
    f.render_widget(para, rect);
}
