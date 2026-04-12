use crate::ai::{self, AiResult};
use crate::config::{AppConfig, Paths};
use crate::diff::{self, ScanDiff};
use crate::history::{self, ScanRecord, ScanSummary, Store};
use crate::nmap::{self, ScanEvent, ScanHandle};
use crate::types::{Host, Profile, TargetGroup};
use crate::ui;
use crate::Tui;
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use std::sync::mpsc::Receiver;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AiState {
    Off,
    Pending,
    Ready(String),
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormMode {
    None,
    // Target groups
    AddTarget,
    EditTarget(usize),
    DeleteTargetConfirm(usize),
    // Scan profiles
    AddProfile,
    EditProfile(usize),
    DeleteProfileConfirm(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormField {
    Name,
    Description,
    Targets,
}

impl FormField {
    pub fn next(self) -> Self {
        match self {
            Self::Name => Self::Description,
            Self::Description => Self::Targets,
            Self::Targets => Self::Name,
        }
    }
    pub fn prev(self) -> Self {
        match self {
            Self::Name => Self::Targets,
            Self::Description => Self::Name,
            Self::Targets => Self::Description,
        }
    }
    #[allow(dead_code)]
    pub fn label(self) -> &'static str {
        match self {
            Self::Name => "Name",
            Self::Description => "Description",
            Self::Targets => "Targets",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TargetForm {
    pub field: FormField,
    pub name: String,
    pub description: String,
    /// Each entry is one target line. The last entry is the one being typed.
    pub targets: Vec<String>,
    pub error: Option<String>,
}

impl TargetForm {
    pub fn empty() -> Self {
        Self {
            field: FormField::Name,
            name: String::new(),
            description: String::new(),
            targets: vec![String::new()],
            error: None,
        }
    }

    pub fn from_group(g: &TargetGroup) -> Self {
        let mut targets = g.targets.clone();
        if targets.is_empty() {
            targets.push(String::new());
        }
        Self {
            field: FormField::Name,
            name: g.name.clone(),
            description: g.description.clone(),
            targets,
            error: None,
        }
    }

    /// Produce the final validated TargetGroup, or an error string.
    pub fn to_group(&self) -> Result<TargetGroup, String> {
        let name = self.name.trim().to_string();
        if name.is_empty() {
            return Err("name is required".to_string());
        }
        let cleaned: Vec<String> = self
            .targets
            .iter()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect();
        if cleaned.is_empty() {
            return Err("add at least one target (IP, hostname, or CIDR)".to_string());
        }
        Ok(TargetGroup {
            name,
            description: self.description.trim().to_string(),
            targets: cleaned,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileFormField {
    Name,
    Description,
    Flags,
}

impl ProfileFormField {
    pub fn next(self) -> Self {
        match self {
            Self::Name => Self::Description,
            Self::Description => Self::Flags,
            Self::Flags => Self::Name,
        }
    }
    pub fn prev(self) -> Self {
        match self {
            Self::Name => Self::Flags,
            Self::Description => Self::Name,
            Self::Flags => Self::Description,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProfileForm {
    pub field: ProfileFormField,
    pub name: String,
    pub description: String,
    pub flags: String,
    pub error: Option<String>,
}

impl ProfileForm {
    pub fn empty() -> Self {
        Self {
            field: ProfileFormField::Name,
            name: String::new(),
            description: String::new(),
            flags: String::new(),
            error: None,
        }
    }

    pub fn from_profile(p: &Profile) -> Self {
        Self {
            field: ProfileFormField::Name,
            name: p.name.clone(),
            description: p.description.clone(),
            flags: p.flags.clone(),
            error: None,
        }
    }

    pub fn to_profile(&self) -> Result<Profile, String> {
        let name = self.name.trim().to_string();
        if name.is_empty() {
            return Err("name is required".to_string());
        }
        let flags = self.flags.trim().to_string();
        if flags.is_empty() {
            return Err("flags are required (e.g. \"-T4 --top-ports 100\")".to_string());
        }
        // Simple sanity check: flags must not include output flags or target args.
        if flags.contains(" -oX") || flags.starts_with("-oX") {
            return Err(
                "do not include -oX — netscan always appends -oX - automatically".to_string(),
            );
        }
        Ok(Profile {
            name,
            description: self.description.trim().to_string(),
            flags,
        })
    }
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
    pub history_marked_id: Option<String>,
    pub history_diff_view: Option<ScanDiff>,

    // AI triage
    pub ai_state: AiState,
    ai_rx: Option<Receiver<AiResult>>,

    // Target / profile CRUD forms
    pub form_mode: FormMode,
    pub form: TargetForm,
    pub profile_form: ProfileForm,

    // Active theme
    pub theme: crate::theme::Theme,

    store: Store,
    paths: Paths,
    config: AppConfig,
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
        config: AppConfig,
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
            history_marked_id: None,
            history_diff_view: None,
            ai_state: AiState::Off,
            ai_rx: None,
            form_mode: FormMode::None,
            form: TargetForm::empty(),
            profile_form: ProfileForm::empty(),
            theme: crate::theme::by_name(&config.ui.theme),
            store,
            paths,
            config,
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
            self.drain_ai_events();

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
            self.maybe_spawn_ai_triage();
        }
    }

    fn drain_ai_events(&mut self) {
        let done = if let Some(rx) = self.ai_rx.as_ref() {
            match rx.try_recv() {
                Ok(AiResult::Ok(text)) => {
                    self.ai_state = AiState::Ready(text);
                    true
                }
                Ok(AiResult::Err(e)) => {
                    self.ai_state = AiState::Failed(e);
                    true
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => false,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    if matches!(self.ai_state, AiState::Pending) {
                        self.ai_state = AiState::Failed("ai worker disconnected".to_string());
                    }
                    true
                }
            }
        } else {
            false
        };
        if done {
            self.ai_rx = None;
        }
    }

    fn maybe_spawn_ai_triage(&mut self) {
        if !self.config.ai.enabled {
            self.ai_state = AiState::Off;
            self.ai_rx = None;
            return;
        }
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
        let rx = ai::spawn_summary(self.config.ai.clone(), record, self.last_diff.clone());
        self.ai_state = AiState::Pending;
        self.ai_rx = Some(rx);
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

        // Form overlays intercept everything except Ctrl+C.
        if !matches!(self.form_mode, FormMode::None) {
            if let (KeyCode::Char('c'), KeyModifiers::CONTROL) = (key.code, key.modifiers) {
                self.should_quit = true;
                return;
            }
            self.on_key_form(key);
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
            (KeyCode::Char('t'), _) => {
                self.cycle_theme();
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
            KeyCode::Esc => {
                if self.history_diff_view.is_some() {
                    self.history_diff_view = None;
                    return;
                }
                if self.history_marked_id.is_some() {
                    self.history_marked_id = None;
                    self.toast = Some(("mark cleared".to_string(), Instant::now()));
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if self.history_index > 0 {
                    self.history_index -= 1;
                    self.history_diff_view = None;
                    self.load_history_detail();
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.history_index + 1 < self.history_entries.len() {
                    self.history_index += 1;
                    self.history_diff_view = None;
                    self.load_history_detail();
                }
            }
            KeyCode::Char('r') => {
                self.reload_history();
            }
            KeyCode::Char('e') | KeyCode::Char('E') => {
                self.export_selected();
            }
            KeyCode::Char('m') => {
                self.toggle_mark_current();
            }
            KeyCode::Char('d') | KeyCode::Char('D') => {
                self.run_marked_diff();
            }
            _ => {}
        }
    }

    fn toggle_mark_current(&mut self) {
        let Some(entry) = self.history_entries.get(self.history_index) else {
            return;
        };
        if self.history_marked_id.as_deref() == Some(&entry.id) {
            self.history_marked_id = None;
            self.toast = Some(("mark cleared".to_string(), Instant::now()));
            return;
        }
        self.history_marked_id = Some(entry.id.clone());
        self.toast = Some((
            format!("marked {} — select another and press [d] to diff", &entry.id[..entry.id.len().min(8)]),
            Instant::now(),
        ));
    }

    fn run_marked_diff(&mut self) {
        let Some(marked_id) = self.history_marked_id.clone() else {
            self.toast = Some((
                "press [m] to mark a scan first".to_string(),
                Instant::now(),
            ));
            return;
        };
        let Some(current) = self.history_selected.as_ref() else {
            return;
        };
        if current.id == marked_id {
            self.toast = Some((
                "mark and current are the same scan".to_string(),
                Instant::now(),
            ));
            return;
        }
        let marked_rec = match self.store.get_scan(&marked_id) {
            Ok(Some(r)) => r,
            Ok(None) => {
                self.toast = Some(("marked scan no longer exists".to_string(), Instant::now()));
                self.history_marked_id = None;
                return;
            }
            Err(e) => {
                self.scan_error = Some(format!("diff load failed: {e}"));
                return;
            }
        };
        // Order matters: older scan is "prev", newer is "curr".
        let (prev, curr) = if marked_rec.started_at <= current.started_at {
            (marked_rec, current.clone())
        } else {
            (current.clone(), marked_rec)
        };
        let d = diff::compute(&prev, &curr);
        self.history_diff_view = Some(d);
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
            KeyCode::Char('a') => {
                self.open_add_form();
            }
            KeyCode::Char('e') => {
                self.open_edit_form();
            }
            KeyCode::Char('d') => {
                self.open_delete_confirm();
            }
            _ => {}
        }
    }

    fn open_add_form(&mut self) {
        self.form = TargetForm::empty();
        self.form_mode = FormMode::AddTarget;
    }

    fn open_edit_form(&mut self) {
        let Some(g) = self.targets.get(self.target_index) else {
            return;
        };
        self.form = TargetForm::from_group(g);
        self.form_mode = FormMode::EditTarget(self.target_index);
    }

    fn open_delete_confirm(&mut self) {
        if self.targets.get(self.target_index).is_none() {
            return;
        }
        self.form_mode = FormMode::DeleteTargetConfirm(self.target_index);
    }

    fn on_key_form(&mut self, key: KeyEvent) {
        // Delete confirmations: y/Y confirms, anything else cancels.
        match self.form_mode {
            FormMode::DeleteTargetConfirm(idx) => {
                match key.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') => self.delete_group(idx),
                    _ => self.form_mode = FormMode::None,
                }
                return;
            }
            FormMode::DeleteProfileConfirm(idx) => {
                match key.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') => self.delete_profile(idx),
                    _ => self.form_mode = FormMode::None,
                }
                return;
            }
            _ => {}
        }

        let is_profile_form =
            matches!(self.form_mode, FormMode::AddProfile | FormMode::EditProfile(_));

        match (key.code, key.modifiers) {
            (KeyCode::Esc, _) => {
                self.form_mode = FormMode::None;
                self.form.error = None;
                self.profile_form.error = None;
            }
            (KeyCode::Char('s'), KeyModifiers::CONTROL) => {
                if is_profile_form {
                    self.submit_profile_form();
                } else {
                    self.submit_form();
                }
            }
            (KeyCode::Tab, _) => {
                if is_profile_form {
                    self.profile_form.field = self.profile_form.field.next();
                } else {
                    self.form.field = self.form.field.next();
                }
            }
            (KeyCode::BackTab, _) => {
                if is_profile_form {
                    self.profile_form.field = self.profile_form.field.prev();
                } else {
                    self.form.field = self.form.field.prev();
                }
            }
            (KeyCode::Enter, _) => {
                if is_profile_form {
                    self.profile_form.field = match self.profile_form.field {
                        ProfileFormField::Name => ProfileFormField::Description,
                        ProfileFormField::Description => ProfileFormField::Flags,
                        ProfileFormField::Flags => ProfileFormField::Name,
                    };
                } else {
                    match self.form.field {
                        FormField::Name => self.form.field = FormField::Description,
                        FormField::Description => self.form.field = FormField::Targets,
                        FormField::Targets => self.form.targets.push(String::new()),
                    }
                }
            }
            (KeyCode::Backspace, _) => {
                if is_profile_form {
                    self.profile_form_backspace();
                } else {
                    self.form_backspace();
                }
            }
            (KeyCode::Char(c), m) if !m.contains(KeyModifiers::CONTROL) => {
                if is_profile_form {
                    self.profile_form_insert_char(c);
                } else {
                    self.form_insert_char(c);
                }
            }
            _ => {}
        }
    }

    fn profile_form_insert_char(&mut self, c: char) {
        match self.profile_form.field {
            ProfileFormField::Name => self.profile_form.name.push(c),
            ProfileFormField::Description => self.profile_form.description.push(c),
            ProfileFormField::Flags => self.profile_form.flags.push(c),
        }
    }

    fn profile_form_backspace(&mut self) {
        match self.profile_form.field {
            ProfileFormField::Name => {
                self.profile_form.name.pop();
            }
            ProfileFormField::Description => {
                self.profile_form.description.pop();
            }
            ProfileFormField::Flags => {
                self.profile_form.flags.pop();
            }
        }
    }

    fn submit_profile_form(&mut self) {
        let profile = match self.profile_form.to_profile() {
            Ok(p) => p,
            Err(e) => {
                self.profile_form.error = Some(e);
                return;
            }
        };

        let edit_idx = if let FormMode::EditProfile(i) = self.form_mode {
            Some(i)
        } else {
            None
        };
        if self
            .profiles
            .iter()
            .enumerate()
            .any(|(i, p)| p.name == profile.name && Some(i) != edit_idx)
        {
            self.profile_form.error =
                Some(format!("a profile named \"{}\" already exists", profile.name));
            return;
        }

        match self.form_mode {
            FormMode::AddProfile => {
                self.profiles.push(profile);
                self.profile_index = self.profiles.len() - 1;
            }
            FormMode::EditProfile(i) => {
                if let Some(slot) = self.profiles.get_mut(i) {
                    *slot = profile;
                }
            }
            _ => {}
        }

        if let Err(e) = crate::config::save_profiles(&self.paths.profiles_file, &self.profiles) {
            self.profile_form.error = Some(format!("save failed: {e}"));
            return;
        }

        let msg = match self.form_mode {
            FormMode::AddProfile => "profile added",
            FormMode::EditProfile(_) => "profile updated",
            _ => "saved",
        };
        self.toast = Some((msg.to_string(), Instant::now()));
        self.form_mode = FormMode::None;
        self.profile_form.error = None;
    }

    fn delete_profile(&mut self, idx: usize) {
        if idx >= self.profiles.len() {
            self.form_mode = FormMode::None;
            return;
        }
        let removed = self.profiles.remove(idx);
        if self.profile_index >= self.profiles.len() && !self.profiles.is_empty() {
            self.profile_index = self.profiles.len() - 1;
        } else if self.profiles.is_empty() {
            self.profile_index = 0;
        }
        if let Err(e) = crate::config::save_profiles(&self.paths.profiles_file, &self.profiles) {
            self.scan_error = Some(format!("save failed: {e}"));
        } else {
            self.toast = Some((
                format!("deleted \"{}\"", removed.name),
                Instant::now(),
            ));
        }
        self.form_mode = FormMode::None;
    }

    fn form_insert_char(&mut self, c: char) {
        match self.form.field {
            FormField::Name => self.form.name.push(c),
            FormField::Description => self.form.description.push(c),
            FormField::Targets => {
                if self.form.targets.is_empty() {
                    self.form.targets.push(String::new());
                }
                let idx = self.form.targets.len() - 1;
                self.form.targets[idx].push(c);
            }
        }
    }

    fn form_backspace(&mut self) {
        match self.form.field {
            FormField::Name => {
                self.form.name.pop();
            }
            FormField::Description => {
                self.form.description.pop();
            }
            FormField::Targets => {
                if self.form.targets.is_empty() {
                    self.form.targets.push(String::new());
                    return;
                }
                let idx = self.form.targets.len() - 1;
                if self.form.targets[idx].is_empty() {
                    if self.form.targets.len() > 1 {
                        self.form.targets.pop();
                    }
                } else {
                    self.form.targets[idx].pop();
                }
            }
        }
    }

    fn submit_form(&mut self) {
        let group = match self.form.to_group() {
            Ok(g) => g,
            Err(e) => {
                self.form.error = Some(e);
                return;
            }
        };

        // Uniqueness check — name must not collide with another group.
        let edit_idx = if let FormMode::EditTarget(i) = self.form_mode {
            Some(i)
        } else {
            None
        };
        if self.targets.iter().enumerate().any(|(i, g)| {
            g.name == group.name && Some(i) != edit_idx
        }) {
            self.form.error =
                Some(format!("a group named \"{}\" already exists", group.name));
            return;
        }

        match self.form_mode {
            FormMode::AddTarget => {
                self.targets.push(group);
                self.target_index = self.targets.len() - 1;
            }
            FormMode::EditTarget(i) => {
                if let Some(slot) = self.targets.get_mut(i) {
                    *slot = group;
                }
            }
            _ => {}
        }

        if let Err(e) = crate::config::save_targets(&self.paths.targets_file, &self.targets) {
            self.form.error = Some(format!("save failed: {e}"));
            return;
        }

        let msg = match self.form_mode {
            FormMode::AddTarget => "target group added",
            FormMode::EditTarget(_) => "target group updated",
            _ => "saved",
        };
        self.toast = Some((msg.to_string(), Instant::now()));
        self.form_mode = FormMode::None;
        self.form.error = None;
    }

    fn delete_group(&mut self, idx: usize) {
        if idx >= self.targets.len() {
            self.form_mode = FormMode::None;
            return;
        }
        let removed = self.targets.remove(idx);
        if self.target_index >= self.targets.len() && !self.targets.is_empty() {
            self.target_index = self.targets.len() - 1;
        } else if self.targets.is_empty() {
            self.target_index = 0;
        }
        if let Err(e) = crate::config::save_targets(&self.paths.targets_file, &self.targets) {
            self.scan_error = Some(format!("save failed: {e}"));
        } else {
            self.toast = Some((
                format!("deleted \"{}\"", removed.name),
                Instant::now(),
            ));
        }
        self.form_mode = FormMode::None;
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
            KeyCode::Char('a') => {
                self.open_add_profile_form();
            }
            KeyCode::Char('e') => {
                self.open_edit_profile_form();
            }
            KeyCode::Char('d') => {
                self.open_delete_profile_confirm();
            }
            _ => {}
        }
    }

    fn open_add_profile_form(&mut self) {
        self.profile_form = ProfileForm::empty();
        self.form_mode = FormMode::AddProfile;
    }

    fn open_edit_profile_form(&mut self) {
        let Some(p) = self.profiles.get(self.profile_index) else {
            return;
        };
        self.profile_form = ProfileForm::from_profile(p);
        self.form_mode = FormMode::EditProfile(self.profile_index);
    }

    fn open_delete_profile_confirm(&mut self) {
        if self.profiles.get(self.profile_index).is_none() {
            return;
        }
        self.form_mode = FormMode::DeleteProfileConfirm(self.profile_index);
    }

    fn cycle_theme(&mut self) {
        let next = crate::theme::next(self.theme.name);
        self.theme = next;
        self.config.ui.theme = next.name.to_string();
        if let Err(e) = crate::config::save_app_config(&self.paths.config_file, &self.config) {
            self.scan_error = Some(format!("save theme: {e}"));
            return;
        }
        self.toast = Some((format!("theme: {}", next.name), Instant::now()));
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
                self.ai_state = if self.config.ai.enabled {
                    AiState::Pending
                } else {
                    AiState::Off
                };
                self.ai_rx = None;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_form_requires_name() {
        let f = TargetForm::empty();
        assert!(f.to_group().is_err());
    }

    #[test]
    fn form_requires_at_least_one_target() {
        let mut f = TargetForm::empty();
        f.name = "test".to_string();
        assert!(f.to_group().is_err());
        f.targets = vec!["  ".to_string(), "".to_string()];
        assert!(f.to_group().is_err());
    }

    #[test]
    fn form_trims_and_filters_targets() {
        let mut f = TargetForm::empty();
        f.name = "  home-lan  ".to_string();
        f.description = "  desc  ".to_string();
        f.targets = vec![
            "  192.168.1.0/24  ".to_string(),
            "".to_string(),
            " 10.0.0.5 ".to_string(),
            "   ".to_string(),
        ];
        let g = f.to_group().unwrap();
        assert_eq!(g.name, "home-lan");
        assert_eq!(g.description, "desc");
        assert_eq!(g.targets, vec!["192.168.1.0/24", "10.0.0.5"]);
    }

    #[test]
    fn form_from_group_roundtrips() {
        let g = TargetGroup {
            name: "prod".to_string(),
            description: "edge".to_string(),
            targets: vec!["a.example.com".to_string(), "b.example.com".to_string()],
        };
        let f = TargetForm::from_group(&g);
        let g2 = f.to_group().unwrap();
        assert_eq!(g2.name, g.name);
        assert_eq!(g2.description, g.description);
        assert_eq!(g2.targets, g.targets);
    }

    #[test]
    fn profile_form_requires_name_and_flags() {
        let f = ProfileForm::empty();
        assert!(f.to_profile().is_err());
        let mut f = ProfileForm::empty();
        f.name = "quick".to_string();
        assert!(f.to_profile().is_err()); // missing flags
        f.flags = "-T4 --top-ports 100".to_string();
        let p = f.to_profile().unwrap();
        assert_eq!(p.name, "quick");
        assert_eq!(p.flags, "-T4 --top-ports 100");
    }

    #[test]
    fn profile_form_rejects_explicit_output_flag() {
        let mut f = ProfileForm::empty();
        f.name = "bad".to_string();
        f.flags = "-T4 -oX out.xml".to_string();
        assert!(f.to_profile().is_err());
    }

    #[test]
    fn profile_form_from_profile_roundtrips() {
        let p = Profile {
            name: "ssl-audit".to_string(),
            description: "TLS checks".to_string(),
            flags: "-p 443 --script ssl-enum-ciphers".to_string(),
        };
        let f = ProfileForm::from_profile(&p);
        let p2 = f.to_profile().unwrap();
        assert_eq!(p2.name, p.name);
        assert_eq!(p2.description, p.description);
        assert_eq!(p2.flags, p.flags);
    }

    #[test]
    fn save_and_load_profiles_roundtrip() {
        let tmp = std::env::temp_dir().join(format!(
            "netscan-profiles-{}.toml",
            crate::history::short_id()
        ));
        let profiles = vec![
            Profile {
                name: "quick".to_string(),
                description: "fast".to_string(),
                flags: "-T4 --top-ports 100".to_string(),
            },
            Profile {
                name: "full".to_string(),
                description: "".to_string(),
                flags: "-T4 -p- -sV".to_string(),
            },
        ];
        crate::config::save_profiles(&tmp, &profiles).unwrap();
        let loaded = crate::config::load_profiles(&tmp).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].name, "quick");
        assert_eq!(loaded[1].flags, "-T4 -p- -sV");
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn save_and_load_targets_roundtrip() {
        let tmp = std::env::temp_dir().join(format!(
            "netscan-targets-{}.toml",
            crate::history::short_id()
        ));
        let groups = vec![
            TargetGroup {
                name: "lan".to_string(),
                description: "local".to_string(),
                targets: vec!["192.168.0.0/16".to_string()],
            },
            TargetGroup {
                name: "vps".to_string(),
                description: "cloud".to_string(),
                targets: vec!["a.example.com".to_string(), "b.example.com".to_string()],
            },
        ];
        crate::config::save_targets(&tmp, &groups).unwrap();
        let loaded = crate::config::load_targets(&tmp).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].name, "lan");
        assert_eq!(loaded[1].targets.len(), 2);
        std::fs::remove_file(&tmp).ok();
    }
}
