use crate::types::{Profile, TargetGroup};
use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

pub struct Paths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub targets_file: PathBuf,
    pub profiles_file: PathBuf,
}

impl Paths {
    pub fn new() -> Result<Self> {
        let dirs = ProjectDirs::from("com", "netscan", "netscan")
            .context("could not resolve platform config directories")?;
        let config_dir = dirs.config_dir().to_path_buf();
        let data_dir = dirs.data_dir().to_path_buf();
        let targets_file = config_dir.join("targets.toml");
        let profiles_file = config_dir.join("profiles.toml");
        Ok(Self {
            config_dir,
            data_dir,
            targets_file,
            profiles_file,
        })
    }

    pub fn ensure_dirs(&self) -> Result<()> {
        fs::create_dir_all(&self.config_dir)?;
        fs::create_dir_all(&self.data_dir)?;
        fs::create_dir_all(self.data_dir.join("scans"))?;
        Ok(())
    }
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
