use crate::config::Paths;
use crate::diff::{self, ScanDiff};
use crate::history::{self, ScanRecord, ScanSummary, Store};
use crate::nmap::{self, ScanEvent, ScanHandle};
use crate::types::{Host, Profile, TargetGroup};
use crate::ui;
use crate::Tui;
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Targets,
    Profiles,
    Scan,
    History,
}

impl Tab {
    pub fn label(self) -> &'static str {
        match self {
            Self::Targets => "Targets",
            Self::Profiles => "Profiles",
            Self::Scan => "Scan",
            Self::History => "History",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanState {
    Idle,
    Running,
    Finished,
    Failed,
}

pub struct App {
    pub tab: Tab,
    pub targets: Vec<TargetGroup>,
    pub profiles: Vec<Profile>,
    pub target_index: usize,
    pub profile_index: usize,

    pub scan_state: ScanState,
    pub scan_id: String,
    pub scan_command: String,
    pub scan_flags: String,
    pub scan_group: String,
    pub scan_profile_name: String,
    pub scan_started_wall: i64,
    pub scan_started: Option<Instant>,
    pub scan_elapsed: Duration,
    pub scan_summary: String,
    pub scan_hosts: Vec<Host>,
    pub scan_host_index: usize,
    pub scan_error: Option<String>,
    pub hosts_up: usize,
    pub hosts_down: usize,
    pub last_diff: Option<ScanDiff>,
    pub toast: Option<(String, Instant)>,

    // History tab state
    pub history_entries: Vec<ScanSummary>,
    pub history_index: usize,
    pub history_selected: Option<ScanRecord>,

    store: Store,
    paths: Paths,
    handle: Option<ScanHandle>,
    last_tick: Instant,
    pub show_help: bool,
    should_quit: bool,
}

impl App {
    pub fn new(
        targets: Vec<TargetGroup>,
        profiles: Vec<Profile>,
        store: Store,
        paths: Paths,
    ) -> Self {
        Self {
            tab: Tab::Targets,
            targets,
            profiles,
            target_index: 0,
            profile_index: 0,
            scan_state: ScanState::Idle,
            scan_id: String::new(),
            scan_command: String::new(),
            scan_flags: String::new(),
            scan_group: String::new(),
            scan_profile_name: String::new(),
            scan_started_wall: 0,
            scan_started: None,
            scan_elapsed: Duration::ZERO,
            scan_summary: String::new(),
            scan_hosts: Vec::new(),
            scan_host_index: 0,
            scan_error: None,
            hosts_up: 0,
            hosts_down: 0,
            last_diff: None,
            toast: None,
            history_entries: Vec::new(),
            history_index: 0,
            history_selected: None,
            store,
            paths,
            handle: None,
            last_tick: Instant::now(),
            show_help: false,
            should_quit: false,
        }
    }

    pub fn run(mut self, terminal: &mut Tui) -> Result<()> {
        let tick_rate = Duration::from_millis(100);
        while !self.should_quit {
            self.drain_scan_events();

            terminal.draw(|f| ui::render(f, &self))?;

            let timeout = tick_rate
                .checked_sub(self.last_tick.elapsed())
                .unwrap_or(Duration::ZERO);

            if event::poll(timeout)? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        self.on_key(key);
                    }
                }
            }

            if self.last_tick.elapsed() >= tick_rate {
                self.tick();
                self.last_tick = Instant::now();
            }
        }

        // Kill any lingering scan.
        if let Some(h) = self.handle.as_mut() {
            h.try_kill();
        }
        Ok(())
    }

    fn tick(&mut self) {
        if let Some(started) = self.scan_started {
            if matches!(self.scan_state, ScanState::Running) {
                self.scan_elapsed = started.elapsed();
            }
        }
        if let Some((_, at)) = &self.toast {
            if at.elapsed() > Duration::from_secs(4) {
                self.toast = None;
            }
        }
    }

    fn drain_scan_events(&mut self) {
        let mut just_finished = false;
        if let Some(h) = self.handle.as_ref() {
            while let Ok(ev) = h.rx.try_recv() {
                match ev {
                    ScanEvent::Started { command } => {
                        self.scan_command = command;
                    }
                    ScanEvent::HostComplete(host) => {
                        self.scan_hosts.push(host);
                    }
                    ScanEvent::RunFinished {
                        summary,
                        hosts_up,
                        hosts_down,
                    } => {
                        self.scan_summary = summary;
                        self.hosts_up = hosts_up;
                        self.hosts_down = hosts_down;
                    }
                    ScanEvent::Error(e) => {
                        self.scan_error = Some(e);
                        self.scan_state = ScanState::Failed;
                    }
                    ScanEvent::Exited { success } => {
                        if matches!(self.scan_state, ScanState::Running) {
                            self.scan_state = if success {
                                ScanState::Finished
                            } else {
                                ScanState::Failed
                            };
                            if success {
                                just_finished = true;
                            }
                        }
                    }
                }
            }
        }
        if just_finished {
            self.persist_completed_scan();
        }
    }

    fn persist_completed_scan(&mut self) {
        let record = ScanRecord {
            id: self.scan_id.clone(),
            group_name: self.scan_group.clone(),
            profile_name: self.scan_profile_name.clone(),
            flags: self.scan_flags.clone(),
            command: self.scan_command.clone(),
            started_at: self.scan_started_wall,
            ended_at: Some(history::now_secs()),
            status: "finished".to_string(),
            summary: self.scan_summary.clone(),
            hosts_up: self.hosts_up,
            hosts_down: self.hosts_down,
            hosts: self.scan_hosts.clone(),
        };
        if let Err(e) = self.store.insert_scan(&record) {
            self.scan_error = Some(format!("history save failed: {e}"));
            return;
        }

        // Compute diff against the previous scan for the same group + profile.
        match self
            .store
            .previous_scan(&record.group_name, &record.profile_name, record.started_at)
        {
            Ok(Some(prev)) => {
                let d = diff::compute(&prev, &record);
                self.last_diff = Some(d);
            }
            Ok(None) => {
                self.last_diff = None;
            }
            Err(e) => {
                self.scan_error = Some(format!("diff lookup failed: {e}"));
            }
        }

        // Invalidate cached history list so next visit reloads.
        self.history_entries.clear();
        self.history_selected = None;

        self.toast = Some(("scan saved to history".to_string(), Instant::now()));
    }

    fn reload_history(&mut self) {
        match self.store.list_scans(200) {
            Ok(list) => {
                self.history_entries = list;
                if self.history_index >= self.history_entries.len() {
                    self.history_index = 0;
                }
                self.load_history_detail();
            }
            Err(e) => {
                self.scan_error = Some(format!("history load failed: {e}"));
            }
        }
    }

    fn load_history_detail(&mut self) {
        if let Some(entry) = self.history_entries.get(self.history_index) {
            match self.store.get_scan(&entry.id) {
                Ok(rec) => self.history_selected = rec,
                Err(e) => {
                    self.scan_error = Some(format!("load scan {}: {e}", entry.id));
                    self.history_selected = None;
                }
            }
        } else {
            self.history_selected = None;
        }
    }

    fn on_key(&mut self, key: KeyEvent) {
        if self.show_help {
            match key.code {
                KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q') => {
                    self.show_help = false;
                }
                _ => {}
            }
            return;
        }

        // Global keys
        match (key.code, key.modifiers) {
            (KeyCode::Char('q'), _) => {
                if matches!(self.scan_state, ScanState::Running) {
                    self.stop_scan();
                } else {
                    self.should_quit = true;
                }
                return;
            }
            (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                self.should_quit = true;
                return;
            }
            (KeyCode::Char('?'), _) => {
                self.show_help = true;
                return;
            }
            (KeyCode::Char('1'), _) => {
                self.tab = Tab::Targets;
                return;
            }
            (KeyCode::Char('2'), _) => {
                self.tab = Tab::Profiles;
                return;
            }
            (KeyCode::Char('3'), _) => {
                self.tab = Tab::Scan;
                return;
            }
            (KeyCode::Char('4'), _) => {
                self.tab = Tab::History;
                if self.history_entries.is_empty() {
                    self.reload_history();
                }
                return;
            }
            (KeyCode::Tab, _) => {
                self.tab = match self.tab {
                    Tab::Targets => Tab::Profiles,
                    Tab::Profiles => Tab::Scan,
                    Tab::Scan => Tab::History,
                    Tab::History => Tab::Targets,
                };
                if matches!(self.tab, Tab::History) && self.history_entries.is_empty() {
                    self.reload_history();
                }
                return;
            }
            _ => {}
        }

        match self.tab {
            Tab::Targets => self.on_key_targets(key),
            Tab::Profiles => self.on_key_profiles(key),
            Tab::Scan => self.on_key_scan(key),
            Tab::History => self.on_key_history(key),
        }
    }

    fn on_key_history(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.history_index > 0 {
                    self.history_index -= 1;
                    self.load_history_detail();
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.history_index + 1 < self.history_entries.len() {
                    self.history_index += 1;
                    self.load_history_detail();
                }
            }
            KeyCode::Char('r') => {
                self.reload_history();
            }
            KeyCode::Char('e') | KeyCode::Char('E') => {
                self.export_selected();
            }
            _ => {}
        }
    }

    fn export_selected(&mut self) {
        let rec = match &self.history_selected {
            Some(r) => r.clone(),
            None => return,
        };

        let diff_opt: Option<ScanDiff> = self
            .store
            .previous_scan(&rec.group_name, &rec.profile_name, rec.started_at)
            .ok()
            .flatten()
            .map(|prev| diff::compute(&prev, &rec));

        match export_bundle(&self.paths, &rec, diff_opt.as_ref()) {
            Ok(dir) => {
                self.toast = Some((
                    format!("exported → {}", dir.display()),
                    Instant::now(),
                ));
            }
            Err(e) => {
                self.scan_error = Some(format!("export failed: {e}"));
            }
        }
    }

    fn on_key_targets(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.target_index > 0 {
                    self.target_index -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.target_index + 1 < self.targets.len() {
                    self.target_index += 1;
                }
            }
            KeyCode::Enter => {
                self.start_scan();
            }
            _ => {}
        }
    }

    fn on_key_profiles(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.profile_index > 0 {
                    self.profile_index -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.profile_index + 1 < self.profiles.len() {
                    self.profile_index += 1;
                }
            }
            KeyCode::Enter => {
                self.start_scan();
            }
            _ => {}
        }
    }

    fn on_key_scan(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.scan_host_index > 0 {
                    self.scan_host_index -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.scan_host_index + 1 < self.scan_hosts.len() {
                    self.scan_host_index += 1;
                }
            }
            KeyCode::Char('x') => {
                self.stop_scan();
            }
            KeyCode::Enter => {
                if matches!(
                    self.scan_state,
                    ScanState::Idle | ScanState::Finished | ScanState::Failed
                ) {
                    self.start_scan();
                }
            }
            KeyCode::Char('E') => {
                if matches!(self.scan_state, ScanState::Finished) {
                    self.export_last_scan();
                }
            }
            _ => {}
        }
    }

    fn export_last_scan(&mut self) {
        let rec = ScanRecord {
            id: self.scan_id.clone(),
            group_name: self.scan_group.clone(),
            profile_name: self.scan_profile_name.clone(),
            flags: self.scan_flags.clone(),
            command: self.scan_command.clone(),
            started_at: self.scan_started_wall,
            ended_at: Some(history::now_secs()),
            status: "finished".to_string(),
            summary: self.scan_summary.clone(),
            hosts_up: self.hosts_up,
            hosts_down: self.hosts_down,
            hosts: self.scan_hosts.clone(),
        };
        match export_bundle(&self.paths, &rec, self.last_diff.as_ref()) {
            Ok(dir) => {
                self.toast = Some((
                    format!("exported → {}", dir.display()),
                    Instant::now(),
                ));
            }
            Err(e) => {
                self.scan_error = Some(format!("export failed: {e}"));
            }
        }
    }

    fn start_scan(&mut self) {
        if matches!(self.scan_state, ScanState::Running) {
            return;
        }
        let Some(group) = self.targets.get(self.target_index).cloned() else {
            return;
        };
        let Some(profile) = self.profiles.get(self.profile_index).cloned() else {
            return;
        };

        match nmap::spawn(&profile, &group) {
            Ok(handle) => {
                self.scan_id = history::short_id();
                self.scan_flags = profile.flags.clone();
                self.scan_group = group.name.clone();
                self.scan_profile_name = profile.name.clone();
                self.scan_started_wall = history::now_secs();
                self.handle = Some(handle);
                self.scan_state = ScanState::Running;
                self.scan_started = Some(Instant::now());
                self.scan_elapsed = Duration::ZERO;
                self.scan_hosts.clear();
                self.scan_host_index = 0;
                self.scan_summary.clear();
                self.scan_error = None;
                self.hosts_up = 0;
                self.hosts_down = 0;
                self.last_diff = None;
                self.tab = Tab::Scan;
            }
            Err(e) => {
                self.scan_state = ScanState::Failed;
                self.scan_error = Some(format!("spawn failed: {e}"));
            }
        }
    }

    fn stop_scan(&mut self) {
        if let Some(h) = self.handle.as_mut() {
            h.try_kill();
        }
        self.scan_state = ScanState::Failed;
        if self.scan_error.is_none() {
            self.scan_error = Some("scan cancelled by user".to_string());
        }
    }

    pub fn current_target(&self) -> Option<&TargetGroup> {
        self.targets.get(self.target_index)
    }

    pub fn current_profile(&self) -> Option<&Profile> {
        self.profiles.get(self.profile_index)
    }

    pub fn current_host(&self) -> Option<&Host> {
        self.scan_hosts.get(self.scan_host_index)
    }

    #[allow(dead_code)]
    pub fn history_detail_host(&self) -> Option<&Host> {
        self.history_selected
            .as_ref()
            .and_then(|r| r.hosts.first())
    }
}

fn export_bundle(
    paths: &Paths,
    rec: &ScanRecord,
    diff: Option<&ScanDiff>,
) -> Result<std::path::PathBuf> {
    use std::fmt::Write as _;
    use std::fs;

    let ts = history::format_timestamp(rec.started_at).replace([' ', ':'], "-");
    let dir_name = format!("netscan_{}_{}_{}", ts, rec.group_name, rec.id);
    let dir = paths.data_dir.join("exports").join(dir_name);
    fs::create_dir_all(&dir)?;

    // manifest.json
    let manifest = format!(
        r#"{{
  "scan_id": "{}",
  "group": "{}",
  "profile": "{}",
  "flags": "{}",
  "command": "{}",
  "started_at": {},
  "ended_at": {},
  "status": "{}",
  "hosts_up": {},
  "hosts_down": {},
  "hosts_count": {}
}}
"#,
        json_escape(&rec.id),
        json_escape(&rec.group_name),
        json_escape(&rec.profile_name),
        json_escape(&rec.flags),
        json_escape(&rec.command),
        rec.started_at,
        rec.ended_at.unwrap_or(0),
        json_escape(&rec.status),
        rec.hosts_up,
        rec.hosts_down,
        rec.hosts.len(),
    );
    fs::write(dir.join("manifest.json"), manifest)?;

    // hosts.json
    let mut hosts_json = String::from("[\n");
    for (i, h) in rec.hosts.iter().enumerate() {
        if i > 0 {
            hosts_json.push_str(",\n");
        }
        let _ = write!(
            hosts_json,
            r#"  {{"address": "{}", "hostname": {}, "status": "{}", "os_guess": {}, "ports": ["#,
            json_escape(&h.address),
            opt_json(h.hostname.as_deref()),
            h.status.label(),
            opt_json(h.os_guess.as_deref())
        );
        for (j, p) in h.ports.iter().enumerate() {
            if j > 0 {
                hosts_json.push_str(", ");
            }
            let _ = write!(
                hosts_json,
                r#"{{"proto": "{}", "port": {}, "state": "{}", "service": {}, "product": {}, "version": {}}}"#,
                json_escape(&p.protocol),
                p.port,
                p.state.label(),
                opt_json(p.service.as_deref()),
                opt_json(p.product.as_deref()),
                opt_json(p.version.as_deref())
            );
        }
        hosts_json.push_str("]}");
    }
    hosts_json.push_str("\n]\n");
    fs::write(dir.join("hosts.json"), hosts_json)?;

    // summary.md
    let mut summary = String::new();
    let _ = writeln!(summary, "# netscan scan {}", rec.id);
    let _ = writeln!(summary);
    let _ = writeln!(
        summary,
        "- **Group:** `{}`",
        rec.group_name
    );
    let _ = writeln!(
        summary,
        "- **Profile:** `{}`",
        rec.profile_name
    );
    let _ = writeln!(summary, "- **Command:** `{}`", rec.command);
    let _ = writeln!(
        summary,
        "- **Started:** {}",
        history::format_timestamp(rec.started_at)
    );
    if let Some(ea) = rec.ended_at {
        let _ = writeln!(summary, "- **Ended:** {}", history::format_timestamp(ea));
    }
    let _ = writeln!(
        summary,
        "- **Hosts up:** {}  **Hosts down:** {}",
        rec.hosts_up, rec.hosts_down
    );
    let _ = writeln!(summary, "- **Status:** {}", rec.status);
    if !rec.summary.is_empty() {
        let _ = writeln!(summary, "- **Nmap summary:** {}", rec.summary);
    }
    summary.push('\n');

    let _ = writeln!(summary, "## Hosts\n");
    for host in &rec.hosts {
        let name = match &host.hostname {
            Some(h) => format!("{} ({})", host.address, h),
            None => host.address.clone(),
        };
        let _ = writeln!(summary, "### {} — {}", name, host.status.label());
        if let Some(os) = &host.os_guess {
            let _ = writeln!(summary, "OS guess: {os}");
        }
        if host.ports.is_empty() {
            let _ = writeln!(summary, "_no ports reported_\n");
            continue;
        }
        let _ = writeln!(summary);
        let _ = writeln!(summary, "| Port | State | Service | Version |");
        let _ = writeln!(summary, "|------|-------|---------|---------|");
        for p in &host.ports {
            let ver = match (p.product.as_deref(), p.version.as_deref()) {
                (Some(pr), Some(v)) => format!("{pr} {v}"),
                (Some(pr), None) => pr.to_string(),
                (None, Some(v)) => v.to_string(),
                _ => "".to_string(),
            };
            let _ = writeln!(
                summary,
                "| {}/{} | {} | {} | {} |",
                p.port,
                p.protocol,
                p.state.label(),
                p.service.as_deref().unwrap_or(""),
                ver
            );
        }
        summary.push('\n');
    }
    fs::write(dir.join("summary.md"), summary)?;

    if let Some(d) = diff {
        fs::write(dir.join("diff.md"), diff::render_markdown(d))?;
    }

    Ok(dir)
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn opt_json(s: Option<&str>) -> String {
    match s {
        Some(v) => format!("\"{}\"", json_escape(v)),
        None => "null".to_string(),
    }
}
