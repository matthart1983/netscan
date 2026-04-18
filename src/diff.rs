use crate::history::ScanRecord;
use crate::types::{Host, HostStatus, Port, PortState};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Default)]
pub struct ScanDiff {
    pub prev_id: String,
    pub curr_id: String,
    pub prev_started: i64,
    #[allow(dead_code)]
    pub curr_started: i64,
    pub host_changes: Vec<HostChange>,
}

#[derive(Debug, Clone)]
pub struct HostChange {
    pub address: String,
    pub hostname: Option<String>,
    pub kind: HostChangeKind,
    pub port_changes: Vec<PortChange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostChangeKind {
    New,           // host present only in curr
    Removed,       // host present only in prev
    StatusChanged, // was down, now up, or vice versa
    Modified,      // same host, ports or services changed
    Unchanged,     // included only if we ever want to surface a full list
}

#[derive(Debug, Clone)]
pub struct PortChange {
    pub protocol: String,
    pub port: u16,
    pub kind: PortChangeKind,
    pub prev_state: Option<PortState>,
    pub curr_state: Option<PortState>,
    pub prev_service: Option<String>,
    pub curr_service: Option<String>,
    pub prev_version: Option<String>,
    pub curr_version: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortChangeKind {
    NewlyOpen,      // wasn't seen before, now open
    NewlyClosed,    // was open, now closed/filtered/missing
    StateChanged,   // e.g. filtered → open
    ServiceChanged, // same state, different service name
    VersionChanged, // same service, different product/version
}

impl ScanDiff {
    pub fn is_empty(&self) -> bool {
        self.host_changes.is_empty()
    }

    pub fn summary(&self) -> String {
        if self.is_empty() {
            return "no changes".to_string();
        }
        let mut new_hosts = 0;
        let mut removed_hosts = 0;
        let mut new_ports = 0;
        let mut closed_ports = 0;
        let mut service_changes = 0;
        let mut version_changes = 0;

        for hc in &self.host_changes {
            match hc.kind {
                HostChangeKind::New => new_hosts += 1,
                HostChangeKind::Removed => removed_hosts += 1,
                _ => {}
            }
            for pc in &hc.port_changes {
                match pc.kind {
                    PortChangeKind::NewlyOpen => new_ports += 1,
                    PortChangeKind::NewlyClosed => closed_ports += 1,
                    PortChangeKind::StateChanged => {}
                    PortChangeKind::ServiceChanged => service_changes += 1,
                    PortChangeKind::VersionChanged => version_changes += 1,
                }
            }
        }

        let mut parts = Vec::new();
        if new_hosts > 0 {
            parts.push(format!("{} new host{}", new_hosts, plural(new_hosts)));
        }
        if removed_hosts > 0 {
            parts.push(format!(
                "{} removed host{}",
                removed_hosts,
                plural(removed_hosts)
            ));
        }
        if new_ports > 0 {
            parts.push(format!("{} new port{}", new_ports, plural(new_ports)));
        }
        if closed_ports > 0 {
            parts.push(format!(
                "{} closed port{}",
                closed_ports,
                plural(closed_ports)
            ));
        }
        if service_changes > 0 {
            parts.push(format!(
                "{} service change{}",
                service_changes,
                plural(service_changes)
            ));
        }
        if version_changes > 0 {
            parts.push(format!(
                "{} version change{}",
                version_changes,
                plural(version_changes)
            ));
        }
        parts.join(", ")
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

pub fn compute(prev: &ScanRecord, curr: &ScanRecord) -> ScanDiff {
    let mut changes: Vec<HostChange> = Vec::new();

    let mut prev_by_addr: BTreeMap<&str, &Host> =
        prev.hosts.iter().map(|h| (h.address.as_str(), h)).collect();
    let curr_by_addr: BTreeMap<&str, &Host> =
        curr.hosts.iter().map(|h| (h.address.as_str(), h)).collect();

    let mut all_addrs: BTreeSet<&str> = BTreeSet::new();
    all_addrs.extend(prev_by_addr.keys().copied());
    all_addrs.extend(curr_by_addr.keys().copied());

    for addr in all_addrs {
        let p = prev_by_addr.remove(addr);
        let c = curr_by_addr.get(&addr).copied();

        match (p, c) {
            (None, Some(ch)) => {
                // New host — report as New, plus every open port is a "newly open" event.
                let port_changes: Vec<PortChange> = ch
                    .ports
                    .iter()
                    .filter(|p| p.state == PortState::Open)
                    .map(|p| PortChange {
                        protocol: p.protocol.clone(),
                        port: p.port,
                        kind: PortChangeKind::NewlyOpen,
                        prev_state: None,
                        curr_state: Some(p.state),
                        prev_service: None,
                        curr_service: p.service.clone(),
                        prev_version: None,
                        curr_version: version_string(p),
                    })
                    .collect();
                changes.push(HostChange {
                    address: ch.address.clone(),
                    hostname: ch.hostname.clone(),
                    kind: HostChangeKind::New,
                    port_changes,
                });
            }
            (Some(ph), None) => {
                changes.push(HostChange {
                    address: ph.address.clone(),
                    hostname: ph.hostname.clone(),
                    kind: HostChangeKind::Removed,
                    port_changes: Vec::new(),
                });
            }
            (Some(ph), Some(ch)) => {
                let mut host_change = HostChange {
                    address: ch.address.clone(),
                    hostname: ch.hostname.clone(),
                    kind: HostChangeKind::Unchanged,
                    port_changes: diff_ports(ph, ch),
                };

                if ph.status != ch.status {
                    host_change.kind = HostChangeKind::StatusChanged;
                } else if !host_change.port_changes.is_empty() {
                    host_change.kind = HostChangeKind::Modified;
                }

                if host_change.kind != HostChangeKind::Unchanged {
                    changes.push(host_change);
                }
            }
            (None, None) => unreachable!(),
        }
    }

    // Sort: new → removed → status → modified, then by address.
    changes.sort_by_key(|c| (kind_order(c.kind), c.address.clone()));

    ScanDiff {
        prev_id: prev.id.clone(),
        curr_id: curr.id.clone(),
        prev_started: prev.started_at,
        curr_started: curr.started_at,
        host_changes: changes,
    }
}

fn kind_order(k: HostChangeKind) -> u8 {
    match k {
        HostChangeKind::New => 0,
        HostChangeKind::Removed => 1,
        HostChangeKind::StatusChanged => 2,
        HostChangeKind::Modified => 3,
        HostChangeKind::Unchanged => 4,
    }
}

fn diff_ports(prev: &Host, curr: &Host) -> Vec<PortChange> {
    let key = |p: &Port| (p.protocol.clone(), p.port);
    let prev_map: BTreeMap<(String, u16), &Port> = prev.ports.iter().map(|p| (key(p), p)).collect();
    let curr_map: BTreeMap<(String, u16), &Port> = curr.ports.iter().map(|p| (key(p), p)).collect();

    let mut all_keys: BTreeSet<(String, u16)> = BTreeSet::new();
    for k in prev_map.keys() {
        all_keys.insert(k.clone());
    }
    for k in curr_map.keys() {
        all_keys.insert(k.clone());
    }

    let mut out = Vec::new();
    for k in all_keys {
        let p = prev_map.get(&k);
        let c = curr_map.get(&k);

        match (p, c) {
            (None, Some(cp)) => {
                if cp.state == PortState::Open {
                    out.push(PortChange {
                        protocol: cp.protocol.clone(),
                        port: cp.port,
                        kind: PortChangeKind::NewlyOpen,
                        prev_state: None,
                        curr_state: Some(cp.state),
                        prev_service: None,
                        curr_service: cp.service.clone(),
                        prev_version: None,
                        curr_version: version_string(cp),
                    });
                }
            }
            (Some(pp), None) => {
                if pp.state == PortState::Open {
                    out.push(PortChange {
                        protocol: pp.protocol.clone(),
                        port: pp.port,
                        kind: PortChangeKind::NewlyClosed,
                        prev_state: Some(pp.state),
                        curr_state: None,
                        prev_service: pp.service.clone(),
                        curr_service: None,
                        prev_version: version_string(pp),
                        curr_version: None,
                    });
                }
            }
            (Some(pp), Some(cp)) => {
                if pp.state != cp.state {
                    let kind = match (pp.state, cp.state) {
                        (PortState::Open, PortState::Closed)
                        | (PortState::Open, PortState::Filtered)
                        | (PortState::Open, PortState::Other) => PortChangeKind::NewlyClosed,
                        (_, PortState::Open) => PortChangeKind::NewlyOpen,
                        _ => PortChangeKind::StateChanged,
                    };
                    out.push(PortChange {
                        protocol: cp.protocol.clone(),
                        port: cp.port,
                        kind,
                        prev_state: Some(pp.state),
                        curr_state: Some(cp.state),
                        prev_service: pp.service.clone(),
                        curr_service: cp.service.clone(),
                        prev_version: version_string(pp),
                        curr_version: version_string(cp),
                    });
                } else if pp.service != cp.service {
                    out.push(PortChange {
                        protocol: cp.protocol.clone(),
                        port: cp.port,
                        kind: PortChangeKind::ServiceChanged,
                        prev_state: Some(pp.state),
                        curr_state: Some(cp.state),
                        prev_service: pp.service.clone(),
                        curr_service: cp.service.clone(),
                        prev_version: version_string(pp),
                        curr_version: version_string(cp),
                    });
                } else if version_string(pp) != version_string(cp)
                    && (pp.version.is_some()
                        || cp.version.is_some()
                        || pp.product.is_some()
                        || cp.product.is_some())
                {
                    out.push(PortChange {
                        protocol: cp.protocol.clone(),
                        port: cp.port,
                        kind: PortChangeKind::VersionChanged,
                        prev_state: Some(pp.state),
                        curr_state: Some(cp.state),
                        prev_service: pp.service.clone(),
                        curr_service: cp.service.clone(),
                        prev_version: version_string(pp),
                        curr_version: version_string(cp),
                    });
                }
            }
            (None, None) => {}
        }
    }
    out
}

fn version_string(p: &Port) -> Option<String> {
    match (p.product.as_deref(), p.version.as_deref()) {
        (Some(pr), Some(v)) => Some(format!("{pr} {v}")),
        (Some(pr), None) => Some(pr.to_string()),
        (None, Some(v)) => Some(v.to_string()),
        (None, None) => None,
    }
}

#[allow(dead_code)]
pub fn render_markdown(diff: &ScanDiff) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let _ = writeln!(s, "# Diff: {} → {}\n", diff.prev_id, diff.curr_id);
    let _ = writeln!(s, "{}\n", diff.summary());

    if diff.is_empty() {
        return s;
    }

    for hc in &diff.host_changes {
        let label = match hc.kind {
            HostChangeKind::New => "NEW",
            HostChangeKind::Removed => "REMOVED",
            HostChangeKind::StatusChanged => "STATUS",
            HostChangeKind::Modified => "MOD",
            HostChangeKind::Unchanged => continue,
        };
        let host_label = match &hc.hostname {
            Some(h) => format!("{} ({})", hc.address, h),
            None => hc.address.clone(),
        };
        let _ = writeln!(s, "## [{}] {}", label, host_label);
        for pc in &hc.port_changes {
            let (prefix, detail) = match pc.kind {
                PortChangeKind::NewlyOpen => (
                    "+",
                    format!(
                        "{}/{}  {} {}",
                        pc.port,
                        pc.protocol,
                        pc.curr_service.clone().unwrap_or_default(),
                        pc.curr_version.clone().unwrap_or_default()
                    ),
                ),
                PortChangeKind::NewlyClosed => (
                    "-",
                    format!(
                        "{}/{}  {} {}",
                        pc.port,
                        pc.protocol,
                        pc.prev_service.clone().unwrap_or_default(),
                        pc.prev_version.clone().unwrap_or_default()
                    ),
                ),
                PortChangeKind::StateChanged => (
                    "~",
                    format!(
                        "{}/{}  {:?} → {:?}",
                        pc.port, pc.protocol, pc.prev_state, pc.curr_state
                    ),
                ),
                PortChangeKind::ServiceChanged => (
                    "~",
                    format!(
                        "{}/{}  service {:?} → {:?}",
                        pc.port, pc.protocol, pc.prev_service, pc.curr_service
                    ),
                ),
                PortChangeKind::VersionChanged => (
                    "~",
                    format!(
                        "{}/{}  version {:?} → {:?}",
                        pc.port, pc.protocol, pc.prev_version, pc.curr_version
                    ),
                ),
            };
            let _ = writeln!(s, "  {} {}", prefix, detail);
        }
        s.push('\n');
    }

    s
}

#[allow(dead_code)]
pub fn _mark(_s: HostStatus) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Host, HostStatus, Port, PortState};

    fn port(
        proto: &str,
        p: u16,
        state: PortState,
        service: Option<&str>,
        version: Option<&str>,
    ) -> Port {
        Port {
            protocol: proto.to_string(),
            port: p,
            state,
            service: service.map(|s| s.to_string()),
            product: None,
            version: version.map(|s| s.to_string()),
            scripts: Vec::new(),
        }
    }

    fn host(addr: &str, status: HostStatus, ports: Vec<Port>) -> Host {
        Host {
            address: addr.to_string(),
            hostname: None,
            status,
            ports,
            os_guess: None,
            hops: Vec::new(),
        }
    }

    fn record(id: &str, hosts: Vec<Host>) -> ScanRecord {
        ScanRecord {
            id: id.to_string(),
            group_name: "test".to_string(),
            profile_name: "test".to_string(),
            flags: "-T4".to_string(),
            command: "nmap -T4".to_string(),
            started_at: 0,
            ended_at: Some(1),
            status: "finished".to_string(),
            summary: String::new(),
            hosts_up: hosts.len(),
            hosts_down: 0,
            hosts,
        }
    }

    #[test]
    fn detects_new_host() {
        let prev = record("a", vec![]);
        let curr = record(
            "b",
            vec![host(
                "10.0.0.1",
                HostStatus::Up,
                vec![port("tcp", 22, PortState::Open, Some("ssh"), None)],
            )],
        );
        let d = compute(&prev, &curr);
        assert_eq!(d.host_changes.len(), 1);
        assert_eq!(d.host_changes[0].kind, HostChangeKind::New);
        assert_eq!(d.host_changes[0].port_changes.len(), 1);
        assert_eq!(
            d.host_changes[0].port_changes[0].kind,
            PortChangeKind::NewlyOpen
        );
        assert!(d.summary().contains("1 new host"));
        assert!(d.summary().contains("1 new port"));
    }

    #[test]
    fn detects_removed_host() {
        let prev = record("a", vec![host("10.0.0.2", HostStatus::Up, vec![])]);
        let curr = record("b", vec![]);
        let d = compute(&prev, &curr);
        assert_eq!(d.host_changes.len(), 1);
        assert_eq!(d.host_changes[0].kind, HostChangeKind::Removed);
    }

    #[test]
    fn detects_new_open_port_on_existing_host() {
        let prev = record(
            "a",
            vec![host(
                "10.0.0.3",
                HostStatus::Up,
                vec![port("tcp", 22, PortState::Open, Some("ssh"), None)],
            )],
        );
        let curr = record(
            "b",
            vec![host(
                "10.0.0.3",
                HostStatus::Up,
                vec![
                    port("tcp", 22, PortState::Open, Some("ssh"), None),
                    port("tcp", 443, PortState::Open, Some("https"), None),
                ],
            )],
        );
        let d = compute(&prev, &curr);
        assert_eq!(d.host_changes.len(), 1);
        assert_eq!(d.host_changes[0].kind, HostChangeKind::Modified);
        assert_eq!(d.host_changes[0].port_changes.len(), 1);
        assert_eq!(d.host_changes[0].port_changes[0].port, 443);
        assert_eq!(
            d.host_changes[0].port_changes[0].kind,
            PortChangeKind::NewlyOpen
        );
    }

    #[test]
    fn detects_closed_port() {
        let prev = record(
            "a",
            vec![host(
                "10.0.0.4",
                HostStatus::Up,
                vec![port("tcp", 8080, PortState::Open, Some("http-proxy"), None)],
            )],
        );
        let curr = record(
            "b",
            vec![host(
                "10.0.0.4",
                HostStatus::Up,
                vec![port(
                    "tcp",
                    8080,
                    PortState::Closed,
                    Some("http-proxy"),
                    None,
                )],
            )],
        );
        let d = compute(&prev, &curr);
        assert_eq!(d.host_changes.len(), 1);
        assert_eq!(
            d.host_changes[0].port_changes[0].kind,
            PortChangeKind::NewlyClosed
        );
    }

    #[test]
    fn detects_version_change() {
        let prev = record(
            "a",
            vec![host(
                "10.0.0.5",
                HostStatus::Up,
                vec![port("tcp", 22, PortState::Open, Some("ssh"), Some("9.2"))],
            )],
        );
        let curr = record(
            "b",
            vec![host(
                "10.0.0.5",
                HostStatus::Up,
                vec![port("tcp", 22, PortState::Open, Some("ssh"), Some("9.3"))],
            )],
        );
        let d = compute(&prev, &curr);
        assert_eq!(d.host_changes.len(), 1);
        assert_eq!(
            d.host_changes[0].port_changes[0].kind,
            PortChangeKind::VersionChanged
        );
    }

    #[test]
    fn identical_scans_produce_empty_diff() {
        let h = host(
            "10.0.0.6",
            HostStatus::Up,
            vec![port("tcp", 22, PortState::Open, Some("ssh"), None)],
        );
        let prev = record("a", vec![h.clone()]);
        let curr = record("b", vec![h]);
        let d = compute(&prev, &curr);
        assert!(d.is_empty());
        assert_eq!(d.summary(), "no changes");
    }
}
