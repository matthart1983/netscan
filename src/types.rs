use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetGroup {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub targets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub flags: String,
}

#[derive(Debug, Clone)]
pub struct Host {
    pub address: String,
    pub hostname: Option<String>,
    pub status: HostStatus,
    pub ports: Vec<Port>,
    pub os_guess: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostStatus {
    Up,
    Down,
    Unknown,
}

impl HostStatus {
    #[allow(dead_code)]
    pub fn label(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Down => "down",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Port {
    pub protocol: String,
    pub port: u16,
    pub state: PortState,
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub scripts: Vec<ScriptOutput>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Other,
}

impl PortState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
            Self::Filtered => "filtered",
            Self::Other => "other",
        }
    }
}

impl From<&str> for PortState {
    fn from(s: &str) -> Self {
        match s {
            "open" => Self::Open,
            "closed" => Self::Closed,
            "filtered" => Self::Filtered,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScriptOutput {
    pub id: String,
    pub output: String,
}
