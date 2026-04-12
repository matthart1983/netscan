mod ai;
mod app;
mod config;
mod diff;
mod history;
mod nmap;
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

    let mut terminal = init_terminal()?;
    let res = app::App::new(targets, profiles, store, paths, app_config).run(&mut terminal);
    restore_terminal(&mut terminal)?;
    res
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
