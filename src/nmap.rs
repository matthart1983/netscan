use crate::types::{Hop, Host, HostStatus, Port, PortState, Profile, ScriptOutput, TargetGroup};
use anyhow::{Context, Result};
use quick_xml::events::Event;
use quick_xml::Reader;
use std::io::{BufRead, BufReader};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

#[derive(Debug, Clone)]
pub enum ScanEvent {
    Started {
        command: String,
    },
    HostComplete(Host),
    Progress {
        percent: f32,
        eta_secs: Option<u64>,
    },
    RunFinished {
        summary: String,
        hosts_up: usize,
        hosts_down: usize,
    },
    Error(String),
    Exited {
        success: bool,
    },
}

pub struct ScanHandle {
    #[allow(dead_code)]
    pub command: String,
    pub rx: Receiver<ScanEvent>,
    pub child: Child,
}

impl ScanHandle {
    pub fn try_kill(&mut self) {
        let _ = self.child.kill();
    }

    #[cfg(unix)]
    pub fn pause(&self) -> Result<()> {
        let pid = self.child.id() as i32;
        let rc = unsafe { libc::kill(pid, libc::SIGSTOP) };
        if rc == 0 {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "kill(SIGSTOP) failed: {}",
                std::io::Error::last_os_error()
            ))
        }
    }

    #[cfg(unix)]
    pub fn resume(&self) -> Result<()> {
        let pid = self.child.id() as i32;
        let rc = unsafe { libc::kill(pid, libc::SIGCONT) };
        if rc == 0 {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "kill(SIGCONT) failed: {}",
                std::io::Error::last_os_error()
            ))
        }
    }

    #[cfg(not(unix))]
    pub fn pause(&self) -> Result<()> {
        Err(anyhow::anyhow!("pause is only supported on Unix platforms"))
    }

    #[cfg(not(unix))]
    pub fn resume(&self) -> Result<()> {
        Err(anyhow::anyhow!(
            "resume is only supported on Unix platforms"
        ))
    }
}

pub fn build_command(profile: &Profile, group: &TargetGroup) -> Vec<String> {
    // Always ask nmap for per-second progress updates on stderr.
    let mut args: Vec<String> = vec!["--stats-every".to_string(), "1s".to_string()];
    let user_args = shell_split(&profile.flags);
    let has_traceroute = user_args.iter().any(|a| a == "--traceroute");
    let is_ping_only = user_args.iter().any(|a| a == "-sn");
    args.extend(user_args);
    // Traceroute feeds the topology view. nmap's --traceroute uses raw sockets
    // and requires root — without it nmap aborts the whole scan ("Traceroute
    // has to be run as root"). Only add the flag when we're actually root, so
    // non-privileged scans keep working (just without traceroute hops).
    // Skip for ping-only scans where it produces no useful trace.
    if !has_traceroute && !is_ping_only && is_root() {
        args.push("--traceroute".to_string());
    }
    // Always request XML on stdout.
    args.push("-oX".to_string());
    args.push("-".to_string());
    // Append all targets.
    for t in &group.targets {
        args.push(t.clone());
    }
    args
}

#[cfg(unix)]
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
fn is_root() -> bool {
    false
}

/// Very small shell-ish split. Handles quoted args; no escaping beyond that.
fn shell_split(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut in_quote: Option<char> = None;
    for c in s.chars() {
        match (c, in_quote) {
            ('"' | '\'', None) => in_quote = Some(c),
            (c, Some(q)) if c == q => in_quote = None,
            (c, Some(_)) => buf.push(c),
            (c, None) if c.is_whitespace() => {
                if !buf.is_empty() {
                    out.push(std::mem::take(&mut buf));
                }
            }
            (c, None) => buf.push(c),
        }
    }
    if !buf.is_empty() {
        out.push(buf);
    }
    out
}

pub fn spawn(profile: &Profile, group: &TargetGroup) -> Result<ScanHandle> {
    let args = build_command(profile, group);
    let command_line = format!("nmap {}", args.join(" "));
    let mut child = Command::new("nmap")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn nmap")?;

    let stdout = child.stdout.take().context("nmap stdout pipe missing")?;
    let stderr = child.stderr.take().context("nmap stderr pipe missing")?;

    let (tx, rx) = mpsc::channel::<ScanEvent>();

    let started_cmd = command_line.clone();
    let _ = tx.send(ScanEvent::Started {
        command: started_cmd,
    });

    let tx_out = tx.clone();
    thread::spawn(move || {
        let reader = BufReader::new(stdout);
        if let Err(e) = parse_stream(reader, &tx_out) {
            let _ = tx_out.send(ScanEvent::Error(format!("parse error: {e}")));
        }
    });

    // Stats parser reads nmap's --stats-every output from stderr.
    thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines().flatten() {
            if let Some(progress) = parse_stats_line(&line) {
                let _ = tx.send(progress);
            }
        }
    });

    Ok(ScanHandle {
        command: command_line,
        rx,
        child,
    })
}

/// Parse a single line from nmap's stderr for progress information.
///
/// The relevant lines look like:
///   `Connect Scan Timing: About 12.34% done; ETC: 11:30 (0:00:07 remaining)`
/// We don't care which scan type (Connect / SYN / UDP) — just the percent
/// and remaining-time fields.
pub fn parse_stats_line(line: &str) -> Option<ScanEvent> {
    if !line.contains("% done") {
        return None;
    }
    let about_start = line.find("About ")? + "About ".len();
    let pct_end = line[about_start..].find('%')?;
    let pct_str = line[about_start..about_start + pct_end].trim();
    let percent: f32 = pct_str.parse().ok()?;

    // "remaining)" may or may not be present — early reports sometimes omit ETC.
    let eta_secs = if let Some(rem_pos) = line.find(" remaining)") {
        line[..rem_pos]
            .rfind('(')
            .and_then(|lp| parse_hms(&line[lp + 1..rem_pos]))
    } else {
        None
    };

    Some(ScanEvent::Progress { percent, eta_secs })
}

fn parse_hms(s: &str) -> Option<u64> {
    let parts: Vec<&str> = s.split(':').collect();
    match parts.len() {
        3 => {
            let h: u64 = parts[0].parse().ok()?;
            let m: u64 = parts[1].parse().ok()?;
            let sec: u64 = parts[2].parse().ok()?;
            Some(h * 3600 + m * 60 + sec)
        }
        2 => {
            let m: u64 = parts[0].parse().ok()?;
            let sec: u64 = parts[1].parse().ok()?;
            Some(m * 60 + sec)
        }
        _ => None,
    }
}

fn parse_stream<R: BufRead>(reader: R, tx: &Sender<ScanEvent>) -> Result<()> {
    let mut xml = Reader::from_reader(reader);
    xml.config_mut().trim_text(false);

    let mut buf = Vec::new();

    // Per-host accumulator
    let mut current: Option<HostBuilder> = None;
    let mut current_port: Option<PortBuilder> = None;
    let mut runstats_finished: Option<FinishedStats> = None;
    let mut host_level_scripts: Vec<ScriptOutput> = Vec::new();

    loop {
        match xml.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = tag_name(&e);
                match name.as_str() {
                    "host" => {
                        current = Some(HostBuilder::default());
                        current_port = None;
                        host_level_scripts.clear();
                    }
                    "status" => {
                        if let Some(h) = current.as_mut() {
                            if let Some(s) = attr(&e, "state") {
                                h.status = Some(status_from(&s));
                            }
                        }
                    }
                    "address" => {
                        if let Some(h) = current.as_mut() {
                            if attr(&e, "addrtype").as_deref() != Some("mac") {
                                if let Some(a) = attr(&e, "addr") {
                                    h.address = Some(a);
                                }
                            }
                        }
                    }
                    "hostname" => {
                        if let Some(h) = current.as_mut() {
                            if let Some(n) = attr(&e, "name") {
                                if h.hostname.is_none() {
                                    h.hostname = Some(n);
                                }
                            }
                        }
                    }
                    "port" => {
                        let proto = attr(&e, "protocol").unwrap_or_default();
                        let port = attr(&e, "portid")
                            .and_then(|p| p.parse().ok())
                            .unwrap_or(0_u16);
                        current_port = Some(PortBuilder {
                            protocol: proto,
                            port,
                            ..Default::default()
                        });
                    }
                    "state" => {
                        if let Some(p) = current_port.as_mut() {
                            if let Some(s) = attr(&e, "state") {
                                p.state = Some(PortState::from(s.as_str()));
                            }
                        }
                    }
                    "service" => {
                        if let Some(p) = current_port.as_mut() {
                            p.service = attr(&e, "name");
                            p.product = attr(&e, "product");
                            p.version = attr(&e, "version");
                        }
                    }
                    "script" => {
                        let id = attr(&e, "id").unwrap_or_default();
                        let output = attr(&e, "output").unwrap_or_default();
                        if let Some(p) = current_port.as_mut() {
                            p.scripts.push(ScriptOutput { id, output });
                        } else if current.is_some() {
                            host_level_scripts.push(ScriptOutput { id, output });
                        }
                    }
                    "osmatch" => {
                        if let Some(h) = current.as_mut() {
                            if h.os_guess.is_none() {
                                h.os_guess = attr(&e, "name");
                            }
                        }
                    }
                    "hop" => {
                        if let Some(h) = current.as_mut() {
                            if let Some(hop) = parse_hop(&e) {
                                h.hops.push(hop);
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Empty(e)) => {
                let name = tag_name(&e);
                match name.as_str() {
                    "status" => {
                        if let Some(h) = current.as_mut() {
                            if let Some(s) = attr(&e, "state") {
                                h.status = Some(status_from(&s));
                            }
                        }
                    }
                    "address" => {
                        if let Some(h) = current.as_mut() {
                            if attr(&e, "addrtype").as_deref() != Some("mac") {
                                if let Some(a) = attr(&e, "addr") {
                                    h.address = Some(a);
                                }
                            }
                        }
                    }
                    "hostname" => {
                        if let Some(h) = current.as_mut() {
                            if let Some(n) = attr(&e, "name") {
                                if h.hostname.is_none() {
                                    h.hostname = Some(n);
                                }
                            }
                        }
                    }
                    "state" => {
                        if let Some(p) = current_port.as_mut() {
                            if let Some(s) = attr(&e, "state") {
                                p.state = Some(PortState::from(s.as_str()));
                            }
                        }
                    }
                    "service" => {
                        if let Some(p) = current_port.as_mut() {
                            p.service = attr(&e, "name");
                            p.product = attr(&e, "product");
                            p.version = attr(&e, "version");
                        }
                    }
                    "script" => {
                        let id = attr(&e, "id").unwrap_or_default();
                        let output = attr(&e, "output").unwrap_or_default();
                        if let Some(p) = current_port.as_mut() {
                            p.scripts.push(ScriptOutput { id, output });
                        } else if current.is_some() {
                            host_level_scripts.push(ScriptOutput { id, output });
                        }
                    }
                    "osmatch" => {
                        if let Some(h) = current.as_mut() {
                            if h.os_guess.is_none() {
                                h.os_guess = attr(&e, "name");
                            }
                        }
                    }
                    "hop" => {
                        if let Some(h) = current.as_mut() {
                            if let Some(hop) = parse_hop(&e) {
                                h.hops.push(hop);
                            }
                        }
                    }
                    "finished" => {
                        runstats_finished = Some(FinishedStats {
                            summary: attr(&e, "summary").unwrap_or_default(),
                            hosts_up: 0,
                            hosts_down: 0,
                        });
                    }
                    "hosts" => {
                        if let Some(fs) = runstats_finished.as_mut() {
                            fs.hosts_up = attr(&e, "up").and_then(|s| s.parse().ok()).unwrap_or(0);
                            fs.hosts_down =
                                attr(&e, "down").and_then(|s| s.parse().ok()).unwrap_or(0);
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::End(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                match name.as_str() {
                    "port" => {
                        if let (Some(h), Some(p)) = (current.as_mut(), current_port.take()) {
                            h.ports.push(p.into_port());
                        }
                    }
                    "host" => {
                        if let Some(mut h) = current.take() {
                            if !host_level_scripts.is_empty() && !h.ports.is_empty() {
                                // Attach host-level scripts to first port as a display anchor.
                                if let Some(first) = h.ports.first_mut() {
                                    first.scripts.extend(host_level_scripts.drain(..));
                                }
                            }
                            host_level_scripts.clear();
                            let host = h.finish();
                            let _ = tx.send(ScanEvent::HostComplete(host));
                        }
                    }
                    "nmaprun" => {
                        if let Some(fs) = runstats_finished.take() {
                            let _ = tx.send(ScanEvent::RunFinished {
                                summary: fs.summary,
                                hosts_up: fs.hosts_up,
                                hosts_down: fs.hosts_down,
                            });
                        }
                        let _ = tx.send(ScanEvent::Exited { success: true });
                        return Ok(());
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => {
                let _ = tx.send(ScanEvent::Exited { success: true });
                return Ok(());
            }
            Err(e) => {
                let _ = tx.send(ScanEvent::Error(format!("xml: {e}")));
                return Ok(());
            }
            _ => {}
        }
        buf.clear();
    }
}

fn tag_name(e: &quick_xml::events::BytesStart) -> String {
    String::from_utf8_lossy(e.name().as_ref()).to_string()
}

fn attr(e: &quick_xml::events::BytesStart, key: &str) -> Option<String> {
    for a in e.attributes().flatten() {
        if a.key.as_ref() == key.as_bytes() {
            return Some(String::from_utf8_lossy(&a.value).to_string());
        }
    }
    None
}

fn status_from(s: &str) -> HostStatus {
    match s {
        "up" => HostStatus::Up,
        "down" => HostStatus::Down,
        _ => HostStatus::Unknown,
    }
}

fn parse_hop(e: &quick_xml::events::BytesStart) -> Option<Hop> {
    let ttl: u8 = attr(e, "ttl").and_then(|s| s.parse().ok())?;
    let ipaddr = attr(e, "ipaddr")?;
    let host_name = attr(e, "host").filter(|s| !s.is_empty());
    let rtt_ms = attr(e, "rtt").and_then(|s| s.parse::<f32>().ok());
    Some(Hop {
        ttl,
        ipaddr,
        host: host_name,
        rtt_ms,
    })
}

#[derive(Default)]
struct HostBuilder {
    address: Option<String>,
    hostname: Option<String>,
    status: Option<HostStatus>,
    os_guess: Option<String>,
    ports: Vec<Port>,
    hops: Vec<Hop>,
}

impl HostBuilder {
    fn finish(self) -> Host {
        let mut hops = self.hops;
        hops.sort_by_key(|h| h.ttl);
        Host {
            address: self.address.unwrap_or_else(|| "unknown".to_string()),
            hostname: self.hostname,
            status: self.status.unwrap_or(HostStatus::Unknown),
            os_guess: self.os_guess,
            ports: self.ports,
            hops,
        }
    }
}

#[derive(Default)]
struct PortBuilder {
    protocol: String,
    port: u16,
    state: Option<PortState>,
    service: Option<String>,
    product: Option<String>,
    version: Option<String>,
    scripts: Vec<ScriptOutput>,
}

impl PortBuilder {
    fn into_port(self) -> Port {
        Port {
            protocol: self.protocol,
            port: self.port,
            state: self.state.unwrap_or(PortState::Other),
            service: self.service,
            product: self.product,
            version: self.version,
            scripts: self.scripts,
        }
    }
}

struct FinishedStats {
    summary: String,
    hosts_up: usize,
    hosts_down: usize,
}

#[allow(dead_code)]
fn _unused_marker(_s: &ChildStdout) {}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -T4 --top-ports 20 -oX - 127.0.0.1" start="1" version="7.95">
<scaninfo type="connect" protocol="tcp" numservices="20" services="21-23"/>
<verbose level="0"/>
<debugging level="0"/>
<hosthint><status state="up" reason="unknown-response" reason_ttl="0"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames></hostnames>
</hosthint>
<host starttime="1" endtime="1"><status state="up" reason="conn-refused" reason_ttl="0"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames>
<hostname name="localhost" type="PTR"/>
</hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="ssh" product="OpenSSH" version="9.3" method="probed" conf="10"/></port>
<port protocol="tcp" portid="80"><state state="closed" reason="conn-refused" reason_ttl="0"/><service name="http" method="table" conf="3"/></port>
</ports>
<times srtt="79" rttvar="46" to="100000"/>
</host>
<runstats><finished time="1" timestr="x" summary="Nmap done; 1 IP address (1 host up) scanned in 0.02s" elapsed="0.02" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>"#;

    #[test]
    fn parses_sample_nmap_xml() {
        let (tx, rx) = mpsc::channel::<ScanEvent>();
        parse_stream(SAMPLE_XML.as_bytes(), &tx).unwrap();
        drop(tx);

        let events: Vec<ScanEvent> = rx.into_iter().collect();

        // We should have at least: HostComplete, RunFinished, Exited
        let host_events: Vec<&Host> = events
            .iter()
            .filter_map(|e| match e {
                ScanEvent::HostComplete(h) => Some(h),
                _ => None,
            })
            .collect();
        assert_eq!(host_events.len(), 1, "expected exactly one host");
        let h = host_events[0];
        assert_eq!(h.address, "127.0.0.1");
        assert_eq!(h.hostname.as_deref(), Some("localhost"));
        assert_eq!(h.status, HostStatus::Up);
        assert_eq!(h.ports.len(), 2);

        let ssh = h.ports.iter().find(|p| p.port == 22).unwrap();
        assert_eq!(ssh.state, PortState::Open);
        assert_eq!(ssh.service.as_deref(), Some("ssh"));
        assert_eq!(ssh.product.as_deref(), Some("OpenSSH"));
        assert_eq!(ssh.version.as_deref(), Some("9.3"));

        let http = h.ports.iter().find(|p| p.port == 80).unwrap();
        assert_eq!(http.state, PortState::Closed);
        assert_eq!(http.service.as_deref(), Some("http"));

        assert!(matches!(
            events
                .iter()
                .find(|e| matches!(e, ScanEvent::RunFinished { .. })),
            Some(_)
        ));
    }

    #[test]
    fn parses_progress_line_with_eta() {
        let line = "Connect Scan Timing: About 42.5% done; ETC: 11:45 (0:01:23 remaining)";
        let ev = parse_stats_line(line).unwrap();
        match ev {
            ScanEvent::Progress { percent, eta_secs } => {
                assert!((percent - 42.5).abs() < 0.001);
                assert_eq!(eta_secs, Some(83));
            }
            _ => panic!("expected Progress event"),
        }
    }

    #[test]
    fn parses_progress_line_mmss_remaining() {
        let line = "SYN Stealth Scan Timing: About 8.12% done; ETC: 11:30 (02:45 remaining)";
        let ev = parse_stats_line(line).unwrap();
        match ev {
            ScanEvent::Progress { percent, eta_secs } => {
                assert!((percent - 8.12).abs() < 0.001);
                assert_eq!(eta_secs, Some(165));
            }
            _ => panic!("expected Progress event"),
        }
    }

    #[test]
    fn parses_progress_line_without_eta() {
        let line = "Service scan Timing: About 15.00% done";
        let ev = parse_stats_line(line).unwrap();
        match ev {
            ScanEvent::Progress { percent, eta_secs } => {
                assert!((percent - 15.0).abs() < 0.001);
                assert_eq!(eta_secs, None);
            }
            _ => panic!("expected Progress event"),
        }
    }

    #[test]
    fn ignores_non_progress_lines() {
        assert!(parse_stats_line("Starting Nmap 7.95").is_none());
        assert!(parse_stats_line("Stats: 0:00:05 elapsed; 0 hosts completed").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn live_pause_and_resume_roundtrip() {
        if std::process::Command::new("nmap")
            .arg("--version")
            .output()
            .is_err()
        {
            return;
        }
        // Use a long-running scan so we have time to pause mid-flight.
        let profile = Profile {
            name: "test".into(),
            description: "".into(),
            flags: "-T4 -p 1-200".into(),
        };
        let group = TargetGroup {
            name: "test".into(),
            description: "".into(),
            targets: vec!["127.0.0.1".into()],
        };
        let mut handle = spawn(&profile, &group).unwrap();
        // Give nmap a moment to start actually producing work.
        std::thread::sleep(std::time::Duration::from_millis(500));

        handle.pause().expect("pause (SIGSTOP) failed");

        // After SIGSTOP, the child's /proc/<pid>/stat state should flip to T on Linux.
        // On macOS there's no /proc; simply ensure the process is still reachable and
        // exactly one pause→resume cycle completes without error, then let the scan
        // finish normally.
        std::thread::sleep(std::time::Duration::from_millis(300));

        handle.resume().expect("resume (SIGCONT) failed");

        // Drain until exit to avoid leaving a zombie around.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while std::time::Instant::now() < deadline {
            match handle
                .rx
                .recv_timeout(std::time::Duration::from_millis(200))
            {
                Ok(ScanEvent::Exited { .. }) => break,
                Ok(_) => {}
                Err(_) => {}
            }
        }
        let _ = handle.child.wait();
    }

    #[test]
    fn parses_live_nmap_run() {
        // Actually spawn nmap against localhost and make sure we get a HostComplete.
        // Skipped if nmap is not on PATH.
        if std::process::Command::new("nmap")
            .arg("--version")
            .output()
            .is_err()
        {
            return;
        }
        let profile = Profile {
            name: "test".into(),
            description: "".into(),
            flags: "-T4 --top-ports 5".into(),
        };
        let group = TargetGroup {
            name: "test".into(),
            description: "".into(),
            targets: vec!["127.0.0.1".into()],
        };
        let handle = spawn(&profile, &group).unwrap();
        let mut saw_host = false;
        let mut saw_finished = false;
        // Drain for up to 10 seconds.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            match handle
                .rx
                .recv_timeout(std::time::Duration::from_millis(200))
            {
                Ok(ScanEvent::HostComplete(_)) => saw_host = true,
                Ok(ScanEvent::RunFinished { .. }) => saw_finished = true,
                Ok(ScanEvent::Exited { .. }) => break,
                Ok(_) => {}
                Err(_) => {}
            }
        }
        assert!(saw_host, "expected HostComplete event");
        assert!(saw_finished, "expected RunFinished event");
    }
}
