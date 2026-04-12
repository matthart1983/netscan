use crate::app::{App, ScanState, Tab};
use crate::types::{Host, HostStatus, Port, PortState};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
#[allow(unused_imports)]
use ratatui::style::Stylize;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Tabs, Wrap};
use ratatui::Frame;

const ACCENT: Color = Color::Rgb(61, 214, 198);
const DIM: Color = Color::Rgb(144, 166, 185);
const BORDER: Color = Color::Rgb(60, 80, 98);
const TEXT: Color = Color::Rgb(237, 246, 251);
const DANGER: Color = Color::Rgb(251, 113, 133);
const WARN: Color = Color::Rgb(245, 182, 77);
const OK: Color = Color::Rgb(110, 231, 183);

pub fn render(f: &mut Frame, app: &App) {
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
    }
    render_status(f, app, chunks[2]);

    if app.show_help {
        render_help_overlay(f, area);
    }
}

fn render_header(f: &mut Frame, app: &App, area: Rect) {
    let titles = [Tab::Targets, Tab::Profiles, Tab::Scan]
        .iter()
        .enumerate()
        .map(|(i, t)| {
            Line::from(vec![
                Span::styled(
                    format!("[{}] ", i + 1),
                    Style::default().fg(DIM),
                ),
                Span::styled(t.label(), Style::default().fg(TEXT)),
            ])
        })
        .collect::<Vec<_>>();

    let selected = match app.tab {
        Tab::Targets => 0,
        Tab::Profiles => 1,
        Tab::Scan => 2,
    };

    let tabs = Tabs::new(titles)
        .select(selected)
        .style(Style::default().fg(TEXT))
        .highlight_style(
            Style::default()
                .fg(ACCENT)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        )
        .divider(Span::styled("│", Style::default().fg(BORDER)))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BORDER))
                .title(Line::from(vec![
                    Span::styled(" netscan ", Style::default().fg(ACCENT).bold()),
                    Span::styled("· nmap workflow TUI ", Style::default().fg(DIM)),
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
                    Style::default().fg(TEXT).bold(),
                ),
                Span::styled(
                    format!("({})", g.targets.len()),
                    Style::default().fg(DIM),
                ),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BORDER))
                .title(" Target groups "),
        )
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(18, 42, 54))
                .fg(ACCENT)
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
                Style::default().fg(ACCENT).bold(),
            )]),
            Line::from(Span::styled(
                format!("   {}", g.description),
                Style::default().fg(DIM),
            )),
            Line::raw(""),
            Line::from(Span::styled(
                " Targets:",
                Style::default().fg(TEXT).bold(),
            )),
        ];
        for t in &g.targets {
            lines.push(Line::from(Span::styled(
                format!("   • {t}"),
                Style::default().fg(TEXT),
            )));
        }
        lines.push(Line::raw(""));
        if let Some(p) = app.current_profile() {
            lines.push(Line::from(Span::styled(
                " Selected profile:",
                Style::default().fg(TEXT).bold(),
            )));
            lines.push(Line::from(vec![
                Span::styled(format!("   {} ", p.name), Style::default().fg(ACCENT)),
                Span::styled(p.description.clone(), Style::default().fg(DIM)),
            ]));
            lines.push(Line::raw(""));
            lines.push(Line::from(Span::styled(
                " Command preview:",
                Style::default().fg(TEXT).bold(),
            )));
            let args = crate::nmap::build_command(p, g);
            lines.push(Line::from(Span::styled(
                format!("   nmap {}", args.join(" ")),
                Style::default().fg(OK),
            )));
        }
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            " Enter — run scan   [2] — pick profile",
            Style::default().fg(DIM),
        )));
        lines
    } else {
        vec![Line::from(Span::styled(
            "No target groups configured",
            Style::default().fg(WARN),
        ))]
    };

    let para = Paragraph::new(detail_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BORDER))
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
                Style::default().fg(TEXT).bold(),
            )]))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BORDER))
                .title(" Profiles "),
        )
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(18, 42, 54))
                .fg(ACCENT)
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
                Style::default().fg(ACCENT).bold(),
            )),
            Line::from(Span::styled(
                format!("   {}", p.description),
                Style::default().fg(DIM),
            )),
            Line::raw(""),
            Line::from(Span::styled(" Flags:", Style::default().fg(TEXT).bold())),
            Line::from(Span::styled(
                format!("   {}", p.flags),
                Style::default().fg(OK),
            )),
            Line::raw(""),
            Line::from(Span::styled(
                " Enter — run against selected target group",
                Style::default().fg(DIM),
            )),
        ]
    } else {
        vec![Line::from(Span::styled(
            "No profiles configured",
            Style::default().fg(WARN),
        ))]
    };

    let para = Paragraph::new(detail_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(BORDER))
            .title(" Details "),
    );
    f.render_widget(para, chunks[1]);
}

fn render_scan(f: &mut Frame, app: &App, area: Rect) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(0)])
        .split(area);

    render_scan_summary(f, app, layout[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(layout[1]);

    render_host_list(f, app, body[0]);
    render_host_detail(f, app, body[1]);
}

fn render_scan_summary(f: &mut Frame, app: &App, area: Rect) {
    let state_str = match app.scan_state {
        ScanState::Idle => Span::styled(" idle ", Style::default().fg(DIM)),
        ScanState::Running => Span::styled(
            " running ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        ScanState::Finished => Span::styled(
            " finished ",
            Style::default().fg(OK).add_modifier(Modifier::BOLD),
        ),
        ScanState::Failed => Span::styled(
            " failed ",
            Style::default().fg(DANGER).add_modifier(Modifier::BOLD),
        ),
    };

    let elapsed = format!("{:>02}:{:>02}", app.scan_elapsed.as_secs() / 60, app.scan_elapsed.as_secs() % 60);

    let header = Line::from(vec![
        Span::styled(" state: ", Style::default().fg(DIM)),
        state_str,
        Span::styled("  elapsed: ", Style::default().fg(DIM)),
        Span::styled(elapsed, Style::default().fg(TEXT)),
        Span::styled("  hosts: ", Style::default().fg(DIM)),
        Span::styled(
            format!("{}", app.scan_hosts.len()),
            Style::default().fg(TEXT),
        ),
        if app.hosts_up + app.hosts_down > 0 {
            Span::styled(
                format!("  (up {} / down {})", app.hosts_up, app.hosts_down),
                Style::default().fg(DIM),
            )
        } else {
            Span::raw("")
        },
    ]);

    let command_line = if app.scan_command.is_empty() {
        "no scan yet — press Enter on a target group to start".to_string()
    } else {
        app.scan_command.clone()
    };
    let cmd = Line::from(vec![
        Span::styled(" cmd:   ", Style::default().fg(DIM)),
        Span::styled(command_line, Style::default().fg(OK)),
    ]);

    let para = Paragraph::new(vec![header, cmd]).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(BORDER))
            .title(" Scan "),
    );
    f.render_widget(para, area);
}

fn render_host_list(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .scan_hosts
        .iter()
        .map(|h| {
            let dot = match h.status {
                HostStatus::Up => Span::styled("● ", Style::default().fg(OK)),
                HostStatus::Down => Span::styled("● ", Style::default().fg(DANGER)),
                HostStatus::Unknown => Span::styled("● ", Style::default().fg(DIM)),
            };
            let label = match &h.hostname {
                Some(hn) => format!("{hn} ({})", h.address),
                None => h.address.clone(),
            };
            let open_ports = h.ports.iter().filter(|p| p.state == PortState::Open).count();
            ListItem::new(Line::from(vec![
                dot,
                Span::styled(label, Style::default().fg(TEXT)),
                Span::raw("  "),
                Span::styled(
                    format!("{} open", open_ports),
                    Style::default().fg(DIM),
                ),
            ]))
        })
        .collect();

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER))
        .title(" Hosts ");

    if items.is_empty() {
        let msg = match app.scan_state {
            ScanState::Idle => "No scan yet. Press [1], select a group, press Enter.",
            ScanState::Running => "Scanning… hosts will appear as nmap reports them.",
            ScanState::Finished => "Scan finished with no hosts (filtered or down).",
            ScanState::Failed => "Scan failed. See status bar.",
        };
        let para = Paragraph::new(msg)
            .style(Style::default().fg(DIM))
            .block(block);
        f.render_widget(para, area);
        return;
    }

    let list = List::new(items)
        .block(block)
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(18, 42, 54))
                .fg(ACCENT)
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
        .border_style(Style::default().fg(BORDER))
        .title(" Ports & scripts ");

    let lines: Vec<Line> = if let Some(host) = app.current_host() {
        let mut lines: Vec<Line> = Vec::new();
        lines.push(host_header_line(host));
        if let Some(os) = &host.os_guess {
            lines.push(Line::from(Span::styled(
                format!(" OS guess: {os}"),
                Style::default().fg(DIM),
            )));
        }
        lines.push(Line::raw(""));

        if host.ports.is_empty() {
            lines.push(Line::from(Span::styled(
                " (no ports reported)",
                Style::default().fg(DIM),
            )));
        } else {
            lines.push(Line::from(Span::styled(
                " PORT       STATE     SERVICE                VERSION",
                Style::default().fg(DIM).add_modifier(Modifier::BOLD),
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
                            Span::styled(prefix, Style::default().fg(WARN)),
                            Span::styled(l.to_string(), Style::default().fg(DIM)),
                        ]));
                    }
                }
            }
        }
        lines
    } else {
        vec![Line::from(Span::styled(
            "Select a host on the left.",
            Style::default().fg(DIM),
        ))]
    };

    let para = Paragraph::new(lines).block(block).wrap(Wrap { trim: false });
    f.render_widget(para, area);
}

fn host_header_line(host: &Host) -> Line<'static> {
    let status_span = match host.status {
        HostStatus::Up => Span::styled(" up ", Style::default().fg(OK).bold()),
        HostStatus::Down => Span::styled(" down ", Style::default().fg(DANGER).bold()),
        HostStatus::Unknown => Span::styled(" unknown ", Style::default().fg(DIM)),
    };
    let mut spans = vec![
        Span::styled(
            format!(" {} ", host.address),
            Style::default().fg(ACCENT).bold(),
        ),
        status_span,
    ];
    if let Some(hn) = &host.hostname {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(hn.clone(), Style::default().fg(DIM)));
    }
    Line::from(spans)
}

fn port_line(p: &Port) -> Line<'static> {
    let state_color = match p.state {
        PortState::Open => OK,
        PortState::Closed => DIM,
        PortState::Filtered => WARN,
        PortState::Other => DIM,
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
        Span::styled(port_col, Style::default().fg(TEXT)),
        Span::styled(state_col, Style::default().fg(state_color)),
        Span::styled(service_col, Style::default().fg(TEXT)),
        Span::styled(version, Style::default().fg(DIM)),
    ])
}

fn render_status(f: &mut Frame, app: &App, area: Rect) {
    let hint = match app.tab {
        Tab::Targets => " [↑↓/jk] navigate   [Enter] run scan   [Tab] next tab   [?] help   [q] quit ",
        Tab::Profiles => " [↑↓/jk] navigate   [Enter] run scan   [Tab] next tab   [?] help   [q] quit ",
        Tab::Scan => " [↑↓/jk] navigate hosts   [x] stop scan   [Enter] rerun   [Tab] next tab   [?] help ",
    };
    let mut spans: Vec<Span> = vec![Span::styled(hint, Style::default().fg(DIM))];
    if let Some(err) = &app.scan_error {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            format!("error: {err}"),
            Style::default().fg(DANGER),
        ));
    } else if matches!(app.scan_state, ScanState::Finished) && !app.scan_summary.is_empty() {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            app.scan_summary.clone(),
            Style::default().fg(OK),
        ));
    }
    let para = Paragraph::new(Line::from(spans));
    f.render_widget(para, area);
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
            Style::default().fg(ACCENT).bold(),
        )),
        Line::raw(""),
        Line::from(" [1/2/3]  switch tabs (Targets / Profiles / Scan)"),
        Line::from(" [Tab]    next tab"),
        Line::from(" [↑↓/jk]  navigate lists"),
        Line::from(" [Enter]  run scan with selected target + profile"),
        Line::from(" [x]      stop a running scan"),
        Line::from(" [?]      this help"),
        Line::from(" [q]      quit (or stop a running scan)"),
        Line::raw(""),
        Line::from(Span::styled(
            " Config files (edit in your editor):",
            Style::default().fg(TEXT).bold(),
        )),
        Line::from(Span::styled(
            "  ~/.config/netscan/targets.toml",
            Style::default().fg(DIM),
        )),
        Line::from(Span::styled(
            "  ~/.config/netscan/profiles.toml",
            Style::default().fg(DIM),
        )),
        Line::raw(""),
        Line::from(Span::styled(
            " press Esc, ?, or q to close ",
            Style::default().fg(DIM),
        )),
    ];
    let para = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(ACCENT))
            .title(" Help "),
    );
    f.render_widget(para, rect);
}
