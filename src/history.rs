use crate::types::{Host, HostStatus, Port, PortState, ScriptOutput};
use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Store {
    conn: Connection,
}

#[derive(Debug, Clone)]
pub struct ScanRecord {
    pub id: String,
    pub group_name: String,
    pub profile_name: String,
    pub flags: String,
    pub command: String,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub status: String,
    pub summary: String,
    pub hosts_up: usize,
    pub hosts_down: usize,
    pub hosts: Vec<Host>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path)
            .with_context(|| format!("opening history db at {}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS scans (
                id             TEXT PRIMARY KEY,
                group_name     TEXT NOT NULL,
                profile_name   TEXT NOT NULL,
                flags          TEXT NOT NULL,
                command        TEXT NOT NULL,
                started_at     INTEGER NOT NULL,
                ended_at       INTEGER,
                status         TEXT NOT NULL,
                summary        TEXT NOT NULL DEFAULT '',
                hosts_up       INTEGER NOT NULL DEFAULT 0,
                hosts_down     INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_scans_gp ON scans(group_name, profile_name, started_at DESC);
            CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC);

            CREATE TABLE IF NOT EXISTS hosts (
                scan_id    TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                address    TEXT NOT NULL,
                hostname   TEXT,
                status     TEXT NOT NULL,
                os_guess   TEXT,
                PRIMARY KEY (scan_id, address)
            );

            CREATE TABLE IF NOT EXISTS ports (
                scan_id    TEXT NOT NULL,
                address    TEXT NOT NULL,
                protocol   TEXT NOT NULL,
                port       INTEGER NOT NULL,
                state      TEXT NOT NULL,
                service    TEXT,
                product    TEXT,
                version    TEXT,
                PRIMARY KEY (scan_id, address, protocol, port),
                FOREIGN KEY (scan_id, address) REFERENCES hosts(scan_id, address) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS scripts (
                scan_id    TEXT NOT NULL,
                address    TEXT NOT NULL,
                protocol   TEXT NOT NULL,
                port       INTEGER NOT NULL,
                script_id  TEXT NOT NULL,
                output     TEXT NOT NULL,
                FOREIGN KEY (scan_id, address, protocol, port)
                    REFERENCES ports(scan_id, address, protocol, port) ON DELETE CASCADE
            );
            "#,
        )?;
        Ok(())
    }

    pub fn insert_scan(&mut self, rec: &ScanRecord) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute(
            r#"INSERT OR REPLACE INTO scans
               (id, group_name, profile_name, flags, command, started_at, ended_at,
                status, summary, hosts_up, hosts_down)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"#,
            params![
                rec.id,
                rec.group_name,
                rec.profile_name,
                rec.flags,
                rec.command,
                rec.started_at,
                rec.ended_at,
                rec.status,
                rec.summary,
                rec.hosts_up as i64,
                rec.hosts_down as i64,
            ],
        )?;

        for host in &rec.hosts {
            tx.execute(
                r#"INSERT OR REPLACE INTO hosts
                   (scan_id, address, hostname, status, os_guess)
                   VALUES (?1, ?2, ?3, ?4, ?5)"#,
                params![
                    rec.id,
                    host.address,
                    host.hostname,
                    status_str(host.status),
                    host.os_guess,
                ],
            )?;

            for port in &host.ports {
                tx.execute(
                    r#"INSERT OR REPLACE INTO ports
                       (scan_id, address, protocol, port, state, service, product, version)
                       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"#,
                    params![
                        rec.id,
                        host.address,
                        port.protocol,
                        port.port as i64,
                        port_state_str(port.state),
                        port.service,
                        port.product,
                        port.version,
                    ],
                )?;

                for script in &port.scripts {
                    tx.execute(
                        r#"INSERT INTO scripts
                           (scan_id, address, protocol, port, script_id, output)
                           VALUES (?1, ?2, ?3, ?4, ?5, ?6)"#,
                        params![
                            rec.id,
                            host.address,
                            port.protocol,
                            port.port as i64,
                            script.id,
                            script.output,
                        ],
                    )?;
                }
            }
        }

        tx.commit()?;
        Ok(())
    }

    pub fn list_scans(&self, limit: usize) -> Result<Vec<ScanSummary>> {
        let mut stmt = self.conn.prepare(
            r#"SELECT id, group_name, profile_name, flags, started_at, ended_at, status,
                      summary, hosts_up, hosts_down
               FROM scans
               ORDER BY started_at DESC
               LIMIT ?1"#,
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(ScanSummary {
                id: row.get(0)?,
                group_name: row.get(1)?,
                profile_name: row.get(2)?,
                flags: row.get(3)?,
                started_at: row.get(4)?,
                ended_at: row.get(5)?,
                status: row.get(6)?,
                summary: row.get(7)?,
                hosts_up: row.get::<_, i64>(8)? as usize,
                hosts_down: row.get::<_, i64>(9)? as usize,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn previous_scan(
        &self,
        group_name: &str,
        profile_name: &str,
        before: i64,
    ) -> Result<Option<ScanRecord>> {
        let mut stmt = self.conn.prepare(
            r#"SELECT id FROM scans
               WHERE group_name = ?1 AND profile_name = ?2
                 AND started_at < ?3 AND status = 'finished'
               ORDER BY started_at DESC
               LIMIT 1"#,
        )?;
        let id: Option<String> = stmt
            .query_row(params![group_name, profile_name, before], |row| row.get(0))
            .ok();
        match id {
            Some(id) => self.get_scan(&id),
            None => Ok(None),
        }
    }

    pub fn get_scan(&self, id: &str) -> Result<Option<ScanRecord>> {
        let scan_row: Option<(
            String, String, String, String, String, i64, Option<i64>, String, String, i64, i64,
        )> = self
            .conn
            .query_row(
                r#"SELECT id, group_name, profile_name, flags, command, started_at, ended_at,
                          status, summary, hosts_up, hosts_down
                   FROM scans WHERE id = ?1"#,
                params![id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                        row.get(10)?,
                    ))
                },
            )
            .ok();
        let Some(scan_row) = scan_row else {
            return Ok(None);
        };

        let mut hosts: Vec<Host> = {
            let mut stmt = self.conn.prepare(
                r#"SELECT address, hostname, status, os_guess
                   FROM hosts WHERE scan_id = ?1
                   ORDER BY address"#,
            )?;
            let rows = stmt.query_map(params![id], |row| {
                Ok(Host {
                    address: row.get(0)?,
                    hostname: row.get(1)?,
                    status: status_from_str(&row.get::<_, String>(2)?),
                    os_guess: row.get(3)?,
                    ports: Vec::new(),
                })
            })?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            out
        };

        for host in &mut hosts {
            let mut stmt = self.conn.prepare(
                r#"SELECT protocol, port, state, service, product, version
                   FROM ports WHERE scan_id = ?1 AND address = ?2
                   ORDER BY protocol, port"#,
            )?;
            let rows = stmt.query_map(params![id, host.address], |row| {
                Ok(Port {
                    protocol: row.get(0)?,
                    port: row.get::<_, i64>(1)? as u16,
                    state: port_state_from_str(&row.get::<_, String>(2)?),
                    service: row.get(3)?,
                    product: row.get(4)?,
                    version: row.get(5)?,
                    scripts: Vec::new(),
                })
            })?;
            for r in rows {
                host.ports.push(r?);
            }

            for port in &mut host.ports {
                let mut sstmt = self.conn.prepare(
                    r#"SELECT script_id, output
                       FROM scripts
                       WHERE scan_id = ?1 AND address = ?2 AND protocol = ?3 AND port = ?4"#,
                )?;
                let rows = sstmt.query_map(
                    params![id, host.address, port.protocol, port.port as i64],
                    |row| {
                        Ok(ScriptOutput {
                            id: row.get(0)?,
                            output: row.get(1)?,
                        })
                    },
                )?;
                for r in rows {
                    port.scripts.push(r?);
                }
            }
        }

        Ok(Some(ScanRecord {
            id: scan_row.0,
            group_name: scan_row.1,
            profile_name: scan_row.2,
            flags: scan_row.3,
            command: scan_row.4,
            started_at: scan_row.5,
            ended_at: scan_row.6,
            status: scan_row.7,
            summary: scan_row.8,
            hosts_up: scan_row.9 as usize,
            hosts_down: scan_row.10 as usize,
            hosts,
        }))
    }

    #[allow(dead_code)]
    pub fn delete_scan(&self, id: &str) -> Result<()> {
        self.conn.execute("DELETE FROM scans WHERE id = ?1", params![id])?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ScanSummary {
    pub id: String,
    pub group_name: String,
    pub profile_name: String,
    pub flags: String,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub status: String,
    pub summary: String,
    pub hosts_up: usize,
    pub hosts_down: usize,
}

pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn short_id() -> String {
    // Non-crypto random short id — good enough for scan ids.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut h: u64 = 0xcbf29ce484222325;
    for b in now.to_le_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    // 8 hex chars
    format!("{:08x}", h & 0xffff_ffff)
}

fn status_str(s: HostStatus) -> &'static str {
    match s {
        HostStatus::Up => "up",
        HostStatus::Down => "down",
        HostStatus::Unknown => "unknown",
    }
}

fn status_from_str(s: &str) -> HostStatus {
    match s {
        "up" => HostStatus::Up,
        "down" => HostStatus::Down,
        _ => HostStatus::Unknown,
    }
}

fn port_state_str(s: PortState) -> &'static str {
    match s {
        PortState::Open => "open",
        PortState::Closed => "closed",
        PortState::Filtered => "filtered",
        PortState::Other => "other",
    }
}

fn port_state_from_str(s: &str) -> PortState {
    match s {
        "open" => PortState::Open,
        "closed" => PortState::Closed,
        "filtered" => PortState::Filtered,
        _ => PortState::Other,
    }
}

pub fn format_timestamp(secs: i64) -> String {
    // Minimal wall-clock format without pulling chrono. Convert to Y-m-d H:M:S in local offset.
    // We use SystemTime arithmetic. This intentionally drops DST nuance.
    let days_total = secs / 86400;
    let rem = secs - days_total * 86400;
    let hours = (rem / 3600) as u64;
    let mins = ((rem % 3600) / 60) as u64;
    let secs_disp = (rem % 60) as u64;

    // Epoch = 1970-01-01
    let (y, mo, d) = ymd_from_days(days_total);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        y, mo, d, hours, mins, secs_disp
    )
}

fn ymd_from_days(mut days: i64) -> (i64, u32, u32) {
    // Unix epoch → Gregorian. Ported Howard Hinnant's civil_from_days algorithm.
    days += 719468;
    let era = days.div_euclid(146097);
    let doe = days.rem_euclid(146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

pub fn human_ago(secs_ago: i64) -> String {
    if secs_ago < 60 {
        format!("{}s ago", secs_ago)
    } else if secs_ago < 3600 {
        format!("{}m ago", secs_ago / 60)
    } else if secs_ago < 86400 {
        format!("{}h ago", secs_ago / 3600)
    } else {
        format!("{}d ago", secs_ago / 86400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Host, HostStatus, Port, PortState};

    fn tmp_db() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("netscan-store-{}", short_id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("h.db")
    }

    fn sample_record(id: &str, group: &str, profile: &str, started: i64) -> ScanRecord {
        ScanRecord {
            id: id.to_string(),
            group_name: group.to_string(),
            profile_name: profile.to_string(),
            flags: "-T4".to_string(),
            command: "nmap -T4".to_string(),
            started_at: started,
            ended_at: Some(started + 1),
            status: "finished".to_string(),
            summary: "ok".to_string(),
            hosts_up: 1,
            hosts_down: 0,
            hosts: vec![Host {
                address: "127.0.0.1".to_string(),
                hostname: Some("localhost".to_string()),
                status: HostStatus::Up,
                os_guess: None,
                ports: vec![Port {
                    protocol: "tcp".to_string(),
                    port: 22,
                    state: PortState::Open,
                    service: Some("ssh".to_string()),
                    product: Some("OpenSSH".to_string()),
                    version: Some("9.3".to_string()),
                    scripts: vec![],
                }],
            }],
        }
    }

    #[test]
    fn roundtrip_insert_and_load() {
        let db = tmp_db();
        let mut store = Store::open(&db).unwrap();
        let rec = sample_record("abc123", "g1", "quick", 1000);
        store.insert_scan(&rec).unwrap();

        let got = store.get_scan("abc123").unwrap().unwrap();
        assert_eq!(got.id, "abc123");
        assert_eq!(got.group_name, "g1");
        assert_eq!(got.hosts.len(), 1);
        assert_eq!(got.hosts[0].address, "127.0.0.1");
        assert_eq!(got.hosts[0].ports.len(), 1);
        assert_eq!(got.hosts[0].ports[0].port, 22);
        assert_eq!(got.hosts[0].ports[0].service.as_deref(), Some("ssh"));
        assert_eq!(got.hosts[0].ports[0].version.as_deref(), Some("9.3"));
    }

    #[test]
    fn list_scans_orders_by_started_desc() {
        let db = tmp_db();
        let mut store = Store::open(&db).unwrap();
        store.insert_scan(&sample_record("a", "g", "p", 1000)).unwrap();
        store.insert_scan(&sample_record("b", "g", "p", 2000)).unwrap();
        store.insert_scan(&sample_record("c", "g", "p", 1500)).unwrap();
        let list = store.list_scans(10).unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].id, "b"); // newest first
        assert_eq!(list[1].id, "c");
        assert_eq!(list[2].id, "a");
    }

    #[test]
    fn previous_scan_picks_latest_before_cutoff() {
        let db = tmp_db();
        let mut store = Store::open(&db).unwrap();
        store.insert_scan(&sample_record("old", "g", "p", 100)).unwrap();
        store.insert_scan(&sample_record("mid", "g", "p", 200)).unwrap();
        store.insert_scan(&sample_record("new", "g", "p", 300)).unwrap();
        // other group shouldn't match
        store.insert_scan(&sample_record("other", "other", "p", 250)).unwrap();

        let prev = store.previous_scan("g", "p", 300).unwrap().unwrap();
        assert_eq!(prev.id, "mid");
    }
}
