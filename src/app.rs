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
}

impl Tab {
    pub fn label(self) -> &'static str {
        match self {
            Self::Targets => "Targets",
            Self::Profiles => "Profiles",
            Self::Scan => "Scan",
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
    pub scan_command: String,
    pub scan_started: Option<Instant>,
    pub scan_elapsed: Duration,
    pub scan_summary: String,
    pub scan_hosts: Vec<Host>,
    pub scan_host_index: usize,
    pub scan_error: Option<String>,
    pub hosts_up: usize,
    pub hosts_down: usize,

    handle: Option<ScanHandle>,
    last_tick: Instant,
    pub show_help: bool,
    should_quit: bool,
}

impl App {
    pub fn new(targets: Vec<TargetGroup>, profiles: Vec<Profile>) -> Self {
        Self {
            tab: Tab::Targets,
            targets,
            profiles,
            target_index: 0,
            profile_index: 0,
            scan_state: ScanState::Idle,
            scan_command: String::new(),
            scan_started: None,
            scan_elapsed: Duration::ZERO,
            scan_summary: String::new(),
            scan_hosts: Vec::new(),
            scan_host_index: 0,
            scan_error: None,
            hosts_up: 0,
            hosts_down: 0,
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
    }

    fn drain_scan_events(&mut self) {
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
                        }
                    }
                }
            }
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
            (KeyCode::Tab, _) => {
                self.tab = match self.tab {
                    Tab::Targets => Tab::Profiles,
                    Tab::Profiles => Tab::Scan,
                    Tab::Scan => Tab::Targets,
                };
                return;
            }
            _ => {}
        }

        match self.tab {
            Tab::Targets => self.on_key_targets(key),
            Tab::Profiles => self.on_key_profiles(key),
            Tab::Scan => self.on_key_scan(key),
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
                if matches!(self.scan_state, ScanState::Idle | ScanState::Finished | ScanState::Failed) {
                    self.start_scan();
                }
            }
            _ => {}
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
}
