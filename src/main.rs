mod ai;
mod app;
mod config;
mod diff;
mod history;
mod nmap;
mod scheduler;
mod theme;
mod topology;
mod types;
mod ui;

use anyhow::{Context, Result};
use clap::Parser;
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io;

#[derive(Parser)]
#[command(
    name = "netscan",
    version,
    about = "Continuous attack surface monitor — a TUI workflow for nmap"
)]
struct Cli {
    /// Print the resolved config paths and exit
    #[arg(long)]
    config_paths: bool,

    /// Run in headless daemon mode — execute scheduled scans without the TUI
    #[arg(long)]
    daemon: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.config_paths {
        let paths = config::Paths::new()?;
        println!("config dir : {}", paths.config_dir.display());
        println!("targets    : {}", paths.targets_file.display());
        println!("profiles   : {}", paths.profiles_file.display());
        println!("data dir   : {}", paths.data_dir.display());
        return Ok(());
    }

    if which_nmap().is_none() {
        eprintln!("netscan: `nmap` was not found on PATH.");
        eprintln!("         Install it first:  brew install nmap   or   apt install nmap");
        std::process::exit(2);
    }

    let paths = config::Paths::new()?;
    paths.ensure_dirs().context("creating config/data dirs")?;
    let targets = config::load_targets(&paths.targets_file)?;
    let profiles = config::load_profiles(&paths.profiles_file)?;
    let app_config = config::load_app_config(&paths.config_file)?;
    let store = history::Store::open(&paths.data_dir.join("history.db"))
        .context("opening history store")?;

    if cli.daemon {
        return run_daemon(targets, profiles, store, paths, app_config);
    }

    let mut terminal = init_terminal()?;
    let res = app::App::new(targets, profiles, store, paths, app_config).run(&mut terminal);
    restore_terminal(&mut terminal)?;
    res
}

fn run_daemon(
    targets: Vec<types::TargetGroup>,
    profiles: Vec<types::Profile>,
    mut store: history::Store,
    _paths: config::Paths,
    app_config: config::AppConfig,
) -> Result<()> {
    if app_config.schedules.is_empty() {
        eprintln!("netscan: no schedules configured in config.toml");
        eprintln!("         add [[schedules]] entries and try again");
        std::process::exit(1);
    }

    let mut sched = scheduler::Scheduler::new(&app_config.schedules, &store);
    let active = app_config.schedules.iter().filter(|s| s.enabled).count();
    eprintln!("netscan daemon: {active} schedule(s) active, Ctrl+C to stop");

    loop {
        let now = history::now_secs();
        if let Some(req) = sched.tick(now) {
            let group = targets.iter().find(|g| g.name == req.target_name);
            let profile = profiles.iter().find(|p| p.name == req.profile_name);
            let (Some(group), Some(profile)) = (group, profile) else {
                eprintln!(
                    "  skip: target '{}' or profile '{}' not found",
                    req.target_name, req.profile_name
                );
                continue;
            };

            eprintln!("  scanning {}/{} ...", group.name, profile.name);
            match nmap::spawn(profile, group) {
                Ok(handle) => {
                    let scan_id = history::short_id();
                    let started_at = history::now_secs();
                    let mut hosts = Vec::new();
                    let mut summary = String::new();
                    let mut hosts_up = 0usize;
                    let mut hosts_down = 0usize;
                    let mut success = false;

                    for ev in handle.rx.iter() {
                        match ev {
                            nmap::ScanEvent::HostComplete(h) => hosts.push(h),
                            nmap::ScanEvent::RunFinished {
                                summary: s,
                                hosts_up: u,
                                hosts_down: d,
                            } => {
                                summary = s;
                                hosts_up = u;
                                hosts_down = d;
                            }
                            nmap::ScanEvent::Exited { success: s } => {
                                success = s;
                                break;
                            }
                            nmap::ScanEvent::Error(e) => {
                                eprintln!("  error: {e}");
                            }
                            _ => {}
                        }
                    }

                    if success {
                        let record = history::ScanRecord {
                            id: scan_id,
                            group_name: group.name.clone(),
                            profile_name: profile.name.clone(),
                            flags: profile.flags.clone(),
                            command: nmap::build_command(profile, group).join(" "),
                            started_at,
                            ended_at: Some(history::now_secs()),
                            status: "finished".to_string(),
                            summary: summary.clone(),
                            hosts_up,
                            hosts_down,
                            hosts,
                        };
                        if let Err(e) = store.insert_scan(&record) {
                            eprintln!("  history save failed: {e}");
                        }
                        if let Ok(Some(prev)) = store.previous_scan(
                            &record.group_name,
                            &record.profile_name,
                            record.started_at,
                        ) {
                            let d = diff::compute(&prev, &record);
                            if !d.host_changes.is_empty() {
                                eprintln!(
                                    "  changes detected: {} host(s) changed",
                                    d.host_changes.len()
                                );
                            }
                        }
                        sched.notify_complete(
                            &record.group_name,
                            &record.profile_name,
                            history::now_secs(),
                        );
                        eprintln!("  done: {summary}");
                    } else {
                        eprintln!("  scan failed");
                    }
                }
                Err(e) => {
                    eprintln!("  spawn failed: {e}");
                }
            }
        } else {
            std::thread::sleep(std::time::Duration::from_secs(10));
        }
    }
}

fn which_nmap() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let full = dir.join("nmap");
        if full.is_file() {
            return Some(full);
        }
    }
    None
}

type Tui = Terminal<CrosstermBackend<io::Stdout>>;

fn init_terminal() -> Result<Tui> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    Ok(Terminal::new(CrosstermBackend::new(stdout))?)
}

fn restore_terminal(terminal: &mut Tui) -> Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}
