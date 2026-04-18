#!/usr/bin/env bash
# Seeds a throwaway HOME with a sample scan record so the demo's topology
# view renders a non-trivial graph. Called from demo.tape before launching
# netscan. Idempotent — recreates HOME from scratch.
set -euo pipefail

H="${HOME_DEMO:-/tmp/netscan-demo-home}"
rm -rf "$H"

CFG="$H/Library/Application Support/com.netscan.netscan"
mkdir -p "$CFG" "$H/Library/Application Support/com.netscan.netscan/scans"

cat > "$CFG/targets.toml" <<'TOML'
[[groups]]
name = "demo-lan"
description = "Synthetic LAN for the demo"
targets = ["192.168.1.0/24"]
TOML

SCAN_ID="demo-scan-01"
NOW=$(date +%s)
DB="$CFG/history.db"

sqlite3 "$DB" <<SQL
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY, group_name TEXT, profile_name TEXT, flags TEXT,
    command TEXT, started_at INTEGER, ended_at INTEGER, status TEXT,
    summary TEXT DEFAULT '', hosts_up INTEGER DEFAULT 0, hosts_down INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS hosts (
    scan_id TEXT, address TEXT, hostname TEXT, status TEXT, os_guess TEXT,
    PRIMARY KEY (scan_id, address)
);
CREATE TABLE IF NOT EXISTS ports (
    scan_id TEXT, address TEXT, protocol TEXT, port INTEGER, state TEXT,
    service TEXT, product TEXT, version TEXT,
    PRIMARY KEY (scan_id, address, protocol, port)
);
CREATE TABLE IF NOT EXISTS scripts (
    scan_id TEXT, address TEXT, protocol TEXT, port INTEGER,
    script_id TEXT, output TEXT
);

INSERT INTO scans VALUES
  ('$SCAN_ID','demo-lan','quick','-T4 --top-ports 100',
   'nmap -T4 --top-ports 100 192.168.1.0/24', $((NOW - 120)), $((NOW - 90)),
   'finished','5 up / 0 down',5,0);

INSERT INTO hosts VALUES
  ('$SCAN_ID','192.168.1.1','gateway.lan','up','Linux 5.x'),
  ('$SCAN_ID','192.168.1.10','server.lan','up','Linux 6.x'),
  ('$SCAN_ID','192.168.1.23','printer.lan','up','HP embedded'),
  ('$SCAN_ID','192.168.1.42','laptop.lan','up','macOS 14'),
  ('$SCAN_ID','192.168.1.88','nas.lan','up','Synology DSM');

INSERT INTO ports VALUES
  ('$SCAN_ID','192.168.1.1','tcp',22,'open','ssh','OpenSSH','9.3'),
  ('$SCAN_ID','192.168.1.1','tcp',80,'open','http','nginx','1.25'),
  ('$SCAN_ID','192.168.1.10','tcp',22,'open','ssh','OpenSSH','9.3'),
  ('$SCAN_ID','192.168.1.10','tcp',443,'open','https','nginx','1.25'),
  ('$SCAN_ID','192.168.1.23','tcp',9100,'open','jetdirect',NULL,NULL),
  ('$SCAN_ID','192.168.1.42','tcp',22,'open','ssh','OpenSSH','9.3'),
  ('$SCAN_ID','192.168.1.88','tcp',5000,'open','http','Synology DSM','7.2'),
  ('$SCAN_ID','192.168.1.88','tcp',445,'open','microsoft-ds','Samba','4.17');
SQL
