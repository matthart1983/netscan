use crate::config::AiConfig;
use crate::diff::{HostChangeKind, PortChangeKind, ScanDiff};
use crate::history::ScanRecord;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

/// One-shot result of an AI summary request.
#[derive(Debug, Clone)]
pub enum AiResult {
    Ok(String),
    Err(String),
}

/// Spawn a background thread that calls the configured Ollama endpoint and
/// returns a receiver the caller can poll non-blockingly.
///
/// The thread exits after posting exactly one `AiResult`. If the endpoint
/// is `"local"`, it is resolved to `http://localhost:11434`. Anything that
/// starts with `http` is used verbatim; other values produce an error.
pub fn spawn_summary(
    cfg: AiConfig,
    record: ScanRecord,
    diff: Option<ScanDiff>,
) -> Receiver<AiResult> {
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let endpoint = match resolve_endpoint(&cfg.endpoint) {
            Ok(e) => e,
            Err(e) => {
                let _ = tx.send(AiResult::Err(e));
                return;
            }
        };

        let prompt = build_prompt(&record, diff.as_ref());
        let body = serde_json::json!({
            "model": cfg.model,
            "prompt": prompt,
            "stream": false,
            "options": {
                "temperature": 0.2,
            }
        });

        let url = format!("{}/api/generate", endpoint.trim_end_matches('/'));
        let result = ureq::post(&url)
            .timeout(Duration::from_secs(cfg.timeout_secs))
            .send_json(body);

        match result {
            Ok(resp) => match resp.into_json::<serde_json::Value>() {
                Ok(v) => {
                    let text = v
                        .get("response")
                        .and_then(|s| s.as_str())
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    if text.is_empty() {
                        let _ = tx.send(AiResult::Err(
                            "empty response from Ollama".to_string(),
                        ));
                    } else {
                        let _ = tx.send(AiResult::Ok(text));
                    }
                }
                Err(e) => {
                    let _ = tx.send(AiResult::Err(format!("decode json: {e}")));
                }
            },
            Err(ureq::Error::Status(code, resp)) => {
                let body = resp.into_string().unwrap_or_default();
                let snippet: String = body.chars().take(160).collect();
                let _ = tx.send(AiResult::Err(format!(
                    "HTTP {code}: {snippet}"
                )));
            }
            Err(e) => {
                let _ = tx.send(AiResult::Err(format!("request: {e}")));
            }
        }
    });

    rx
}

fn resolve_endpoint(raw: &str) -> Result<String, String> {
    let r = raw.trim();
    if r.eq_ignore_ascii_case("local") || r.is_empty() {
        return Ok("http://localhost:11434".to_string());
    }
    if r.starts_with("http://") || r.starts_with("https://") {
        return Ok(r.to_string());
    }
    Err(format!(
        "endpoint must be \"local\" or start with http:// or https:// (got: {r})"
    ))
}

pub fn build_prompt(record: &ScanRecord, diff: Option<&ScanDiff>) -> String {
    use std::fmt::Write;
    let mut s = String::new();

    let _ = writeln!(
        s,
        "You are a network security analyst. A user just ran an nmap scan and wants a concise triage."
    );
    let _ = writeln!(s);
    let _ = writeln!(s, "SCAN METADATA");
    let _ = writeln!(s, "  group:   {}", record.group_name);
    let _ = writeln!(s, "  profile: {}", record.profile_name);
    let _ = writeln!(s, "  command: {}", record.command);
    let _ = writeln!(
        s,
        "  hosts:   {} up / {} down",
        record.hosts_up, record.hosts_down
    );
    let _ = writeln!(s);

    let _ = writeln!(s, "HOSTS & OPEN SERVICES");
    for host in record.hosts.iter().take(12) {
        let name = match &host.hostname {
            Some(h) => format!("{} ({h})", host.address),
            None => host.address.clone(),
        };
        let _ = writeln!(s, "  - {name} [{}]", host.status.label());
        let open: Vec<_> = host
            .ports
            .iter()
            .filter(|p| p.state == crate::types::PortState::Open)
            .collect();
        for p in open.iter().take(20) {
            let ver = match (p.product.as_deref(), p.version.as_deref()) {
                (Some(pr), Some(v)) => format!(" {pr} {v}"),
                (Some(pr), None) => format!(" {pr}"),
                (None, Some(v)) => format!(" {v}"),
                _ => String::new(),
            };
            let _ = writeln!(
                s,
                "      {}/{} {}{}",
                p.port,
                p.protocol,
                p.service.as_deref().unwrap_or(""),
                ver
            );
        }
    }
    if record.hosts.len() > 12 {
        let _ = writeln!(s, "  ... and {} more hosts", record.hosts.len() - 12);
    }
    let _ = writeln!(s);

    if let Some(d) = diff {
        if !d.is_empty() {
            let _ = writeln!(s, "CHANGES SINCE PREVIOUS SCAN");
            let _ = writeln!(s, "  summary: {}", d.summary());
            for hc in d.host_changes.iter().take(20) {
                let label = match hc.kind {
                    HostChangeKind::New => "NEW",
                    HostChangeKind::Removed => "REMOVED",
                    HostChangeKind::StatusChanged => "STATUS",
                    HostChangeKind::Modified => "MODIFIED",
                    HostChangeKind::Unchanged => continue,
                };
                let name = match &hc.hostname {
                    Some(n) => format!("{} ({n})", hc.address),
                    None => hc.address.clone(),
                };
                let _ = writeln!(s, "  [{label}] {name}");
                for pc in hc.port_changes.iter().take(15) {
                    let op = match pc.kind {
                        PortChangeKind::NewlyOpen => "+",
                        PortChangeKind::NewlyClosed => "-",
                        PortChangeKind::StateChanged => "~",
                        PortChangeKind::ServiceChanged => "~svc",
                        PortChangeKind::VersionChanged => "~ver",
                    };
                    let _ = writeln!(
                        s,
                        "      {op} {}/{}  {} {}",
                        pc.port,
                        pc.protocol,
                        pc.curr_service
                            .clone()
                            .or_else(|| pc.prev_service.clone())
                            .unwrap_or_default(),
                        pc.curr_version
                            .clone()
                            .or_else(|| pc.prev_version.clone())
                            .unwrap_or_default(),
                    );
                }
            }
            let _ = writeln!(s);
        }
    }

    let _ = writeln!(s, "TASK");
    let _ = writeln!(
        s,
        "Produce a tight bullet-list analysis (3-6 bullets). Cover:"
    );
    let _ = writeln!(
        s,
        "  1) The most important finding for a defender to act on."
    );
    let _ = writeln!(s, "  2) Any obvious security concerns (exposed services, outdated versions, unexpected open ports).");
    if diff.map(|d| !d.is_empty()).unwrap_or(false) {
        let _ = writeln!(
            s,
            "  3) Whether any of the changes since the last scan look suspicious."
        );
    }
    let _ = writeln!(
        s,
        "  4) What to investigate first and how (one specific command or next step)."
    );
    let _ = writeln!(s);
    let _ = writeln!(
        s,
        "Be concise and direct. No preamble, no apologies, no \"As an AI\". Use plain bullets (\"- ...\"). Stop after the last bullet."
    );
    let _ = writeln!(
        s,
        "If suggesting an ssh command, do NOT use `root` as the login user — modern distributions disable root ssh by default. Either omit the user (e.g. `ssh 192.0.2.1`) or pick a plausible non-root name like `admin`, `ubuntu`, `pi`, or `ec2-user` based on the context."
    );

    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_local() {
        assert_eq!(resolve_endpoint("local").unwrap(), "http://localhost:11434");
        assert_eq!(resolve_endpoint("LOCAL").unwrap(), "http://localhost:11434");
        assert_eq!(resolve_endpoint(" ").unwrap(), "http://localhost:11434");
    }

    #[test]
    fn resolve_http_passthrough() {
        assert_eq!(
            resolve_endpoint("http://example.com:11434").unwrap(),
            "http://example.com:11434"
        );
        assert_eq!(
            resolve_endpoint("https://ollama.com").unwrap(),
            "https://ollama.com"
        );
    }

    #[test]
    fn resolve_rejects_non_url() {
        assert!(resolve_endpoint("example.com").is_err());
    }

    #[test]
    fn live_ollama_roundtrip_if_available() {
        // Skip if local Ollama is not reachable. We don't want CI to fail on this.
        let reachable = ureq::get("http://localhost:11434/api/tags")
            .timeout(Duration::from_millis(500))
            .call()
            .is_ok();
        if !reachable {
            eprintln!("[skip] local Ollama not reachable");
            return;
        }

        let rec = ScanRecord {
            id: "livetest".into(),
            group_name: "localhost".into(),
            profile_name: "quick".into(),
            flags: "-T4 --top-ports 5".into(),
            command: "nmap -T4 --top-ports 5 127.0.0.1".into(),
            started_at: 0,
            ended_at: None,
            status: "finished".into(),
            summary: "ok".into(),
            hosts_up: 1,
            hosts_down: 0,
            hosts: vec![crate::types::Host {
                address: "127.0.0.1".into(),
                hostname: Some("localhost".into()),
                status: crate::types::HostStatus::Up,
                os_guess: None,
                ports: vec![crate::types::Port {
                    protocol: "tcp".into(),
                    port: 22,
                    state: crate::types::PortState::Open,
                    service: Some("ssh".into()),
                    product: None,
                    version: None,
                    scripts: vec![],
                }],
                hops: vec![],
            }],
        };
        let cfg = AiConfig {
            enabled: true,
            endpoint: "local".into(),
            model: "llama3.2".into(),
            timeout_secs: 120,
        };
        let rx = spawn_summary(cfg, rec, None);
        let result = rx.recv_timeout(Duration::from_secs(180)).unwrap();
        match result {
            AiResult::Ok(text) => {
                assert!(!text.is_empty(), "expected non-empty AI response");
                // We can't assert exact content (it's an LLM), but it should say *something*.
                eprintln!("[live-ai] {} chars returned", text.len());
            }
            AiResult::Err(e) => {
                panic!("live Ollama call failed: {e}");
            }
        }
    }

    #[test]
    fn prompt_includes_scan_metadata_and_hosts() {
        let rec = ScanRecord {
            id: "abc".into(),
            group_name: "lan".into(),
            profile_name: "quick".into(),
            flags: "-T4".into(),
            command: "nmap -T4".into(),
            started_at: 0,
            ended_at: None,
            status: "finished".into(),
            summary: "ok".into(),
            hosts_up: 1,
            hosts_down: 0,
            hosts: vec![crate::types::Host {
                address: "10.0.0.1".into(),
                hostname: Some("router".into()),
                status: crate::types::HostStatus::Up,
                os_guess: None,
                ports: vec![crate::types::Port {
                    protocol: "tcp".into(),
                    port: 22,
                    state: crate::types::PortState::Open,
                    service: Some("ssh".into()),
                    product: Some("OpenSSH".into()),
                    version: Some("9.3".into()),
                    scripts: vec![],
                }],
                hops: vec![],
            }],
        };
        let p = build_prompt(&rec, None);
        assert!(p.contains("group:   lan"));
        assert!(p.contains("10.0.0.1"));
        assert!(p.contains("OpenSSH 9.3"));
        assert!(p.contains("TASK"));
    }
}
