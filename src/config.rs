use crate::types::{Profile, TargetGroup};
use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Clone)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub targets_file: PathBuf,
    pub profiles_file: PathBuf,
    pub config_file: PathBuf,
}

impl Paths {
    pub fn new() -> Result<Self> {
        let dirs = ProjectDirs::from("com", "netscan", "netscan")
            .context("could not resolve platform config directories")?;
        let config_dir = dirs.config_dir().to_path_buf();
        let data_dir = dirs.data_dir().to_path_buf();
        let targets_file = config_dir.join("targets.toml");
        let profiles_file = config_dir.join("profiles.toml");
        let config_file = config_dir.join("config.toml");
        Ok(Self {
            config_dir,
            data_dir,
            targets_file,
            profiles_file,
            config_file,
        })
    }

    pub fn ensure_dirs(&self) -> Result<()> {
        fs::create_dir_all(&self.config_dir)?;
        fs::create_dir_all(&self.data_dir)?;
        fs::create_dir_all(self.data_dir.join("scans"))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleConfig {
    pub target: String,
    pub profile: String,
    pub interval_secs: u64,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub ai: AiConfig,
    #[serde(default)]
    pub ui: UiConfig,
    #[serde(default)]
    pub schedules: Vec<ScheduleConfig>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            ai: AiConfig::default(),
            ui: UiConfig::default(),
            schedules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfig {
    #[serde(default = "default_theme")]
    pub theme: String,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            theme: default_theme(),
        }
    }
}

fn default_theme() -> String {
    "dark".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    /// When true, netscan will send a scan summary to the configured endpoint
    /// after every completed scan and render the response in the Scan tab.
    #[serde(default)]
    pub enabled: bool,
    /// Ollama endpoint. "local" resolves to http://localhost:11434.
    /// Any value starting with "http" is used verbatim.
    #[serde(default = "default_ai_endpoint")]
    pub endpoint: String,
    /// Model name to use with /api/generate (e.g. "llama3.2", "qwen2.5:7b").
    #[serde(default = "default_ai_model")]
    pub model: String,
    /// Request timeout in seconds.
    #[serde(default = "default_ai_timeout")]
    pub timeout_secs: u64,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_ai_endpoint(),
            model: default_ai_model(),
            timeout_secs: default_ai_timeout(),
        }
    }
}

fn default_ai_endpoint() -> String {
    "local".to_string()
}

fn default_ai_model() -> String {
    "llama3.2".to_string()
}

fn default_ai_timeout() -> u64 {
    60
}

pub fn load_app_config(path: &std::path::Path) -> Result<AppConfig> {
    if !path.exists() {
        let default = AppConfig::default();
        let text = format!(
            r#"# netscan config
#
# AI Insights — opt-in. When enabled, netscan sends a structured summary of
# each completed scan (and its diff vs the previous scan) to an Ollama endpoint
# and renders the response in the Scan tab.
#
# Endpoint options:
#   "local"                      — http://localhost:11434 (default Ollama daemon)
#   "http://host:11434"          — remote Ollama on another machine
#   "https://ollama.com"         — Ollama Cloud (you must be logged in locally)
#
# Nothing happens unless ai.enabled = true.

[ai]
enabled = false
endpoint = "{}"
model = "{}"
timeout_secs = {}

# UI — theme cycles with [t] at runtime and is persisted here.
# Options: dark, solarized, dracula, nord, gruvbox
[ui]
theme = "{}"
"#,
            default.ai.endpoint, default.ai.model, default.ai.timeout_secs, default.ui.theme
        );
        fs::write(path, text)?;
        return Ok(default);
    }
    let text = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let cfg: AppConfig = toml::from_str(&text)
        .with_context(|| format!("parsing {}", path.display()))?;
    Ok(cfg)
}

pub fn save_app_config(path: &std::path::Path, cfg: &AppConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok();
    }
    let text = toml::to_string_pretty(cfg).context("serializing config.toml")?;
    let tmp = path.with_extension("toml.tmp");
    fs::write(&tmp, text)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

pub fn save_profiles(path: &std::path::Path, profiles: &[Profile]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok();
    }
    let file = ProfilesFile {
        profiles: profiles.to_vec(),
    };
    let text = toml::to_string_pretty(&file).context("serializing profiles.toml")?;
    let tmp = path.with_extension("toml.tmp");
    fs::write(&tmp, text)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

#[derive(Serialize, Deserialize, Default)]
struct TargetsFile {
    #[serde(default)]
    groups: Vec<TargetGroup>,
}

#[derive(Serialize, Deserialize, Default)]
struct ProfilesFile {
    #[serde(default)]
    profiles: Vec<Profile>,
}

pub fn load_targets(path: &std::path::Path) -> Result<Vec<TargetGroup>> {
    if !path.exists() {
        let defaults = default_targets();
        let file = TargetsFile {
            groups: defaults.clone(),
        };
        fs::write(path, toml::to_string_pretty(&file)?)?;
        return Ok(defaults);
    }
    let text = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let file: TargetsFile = toml::from_str(&text)
        .with_context(|| format!("parsing {}", path.display()))?;
    Ok(file.groups)
}

pub fn save_targets(path: &std::path::Path, groups: &[TargetGroup]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok();
    }
    let file = TargetsFile {
        groups: groups.to_vec(),
    };
    let text = toml::to_string_pretty(&file)
        .context("serializing targets.toml")?;
    // Write atomically via a temp file in the same directory, then rename.
    let tmp = path.with_extension("toml.tmp");
    fs::write(&tmp, text).with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} → {}", tmp.display(), path.display()))?;
    Ok(())
}

pub fn load_profiles(path: &std::path::Path) -> Result<Vec<Profile>> {
    if !path.exists() {
        let defaults = default_profiles();
        let file = ProfilesFile {
            profiles: defaults.clone(),
        };
        fs::write(path, toml::to_string_pretty(&file)?)?;
        return Ok(defaults);
    }
    let text = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let file: ProfilesFile = toml::from_str(&text)
        .with_context(|| format!("parsing {}", path.display()))?;
    Ok(file.profiles)
}

pub fn default_targets() -> Vec<TargetGroup> {
    vec![
        TargetGroup {
            name: "localhost".to_string(),
            description: "The box netscan is running on".to_string(),
            targets: vec!["127.0.0.1".to_string()],
        },
        TargetGroup {
            name: "home-lan".to_string(),
            description: "Home LAN sweep (edit before running)".to_string(),
            targets: vec!["192.168.1.0/24".to_string()],
        },
    ]
}

pub fn default_profiles() -> Vec<Profile> {
    vec![
        Profile {
            name: "quick".to_string(),
            description: "Quick TCP sweep — top 100 ports, no privileges required".to_string(),
            flags: "-T4 --top-ports 100".to_string(),
        },
        Profile {
            name: "full-tcp".to_string(),
            description: "Full TCP, service detection, default NSE".to_string(),
            flags: "-T4 -p- -sV -sC".to_string(),
        },
        Profile {
            name: "udp-top".to_string(),
            description: "UDP top-100 (requires root)".to_string(),
            flags: "-T4 -sU --top-ports 100 -sV".to_string(),
        },
        Profile {
            name: "ssl-audit".to_string(),
            description: "SSL/TLS configuration audit".to_string(),
            flags: "-T4 -p 443,8443,993,995,465,587 --script ssl-enum-ciphers,ssl-cert".to_string(),
        },
        Profile {
            name: "discovery".to_string(),
            description: "Host discovery only — no port scan".to_string(),
            flags: "-sn".to_string(),
        },
    ]
}
