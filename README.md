<h1 align="center">netscan</h1>
<p align="center">
  <strong>The continuous attack surface monitor — a TUI workflow for nmap.</strong>
</p>
<p align="center">
  <img src="https://img.shields.io/badge/status-early--development-orange" alt="status">
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux-blue" alt="platform">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="license">
</p>

netscan wraps the `nmap` engine with a real workflow: target inventory, saved scan profiles,
live streaming results as each host comes in, and (soon) scan history with differential
scanning. One binary. No config required on first run.

**Status:** v0.2. Target inventory, scan profiles, live streaming scan view,
SQLite-backed scan history, automatic differential scanning, and incident bundle
export are all working. NSE script picker, scheduled/daemon mode, and opt-in AI
triage are next.

---

## Why

nmap is the canonical network scanner, and its UX has been frozen since 1998. Zenmap is
decaying. Nobody loves typing `nmap -T4 -p- -sV -sC 192.168.1.0/24` from memory every
time they want to check their LAN. netscan keeps nmap as the engine and puts a modern TUI
in front of it.

The design principle: **the value is in the workflow, not the engine**. nmap has 25+
years of NSE scripts, OS fingerprinting, and protocol probes you can't match. netscan
doesn't try. It gives you:

- Named target groups you edit once
- Saved scan profiles so you never look up flags
- Live streaming results as nmap reports each host
- (Soon) scan history and differential scanning — the real killer feature

## Requirements

- `nmap` installed and on `PATH` — hard dependency. Install with `brew install nmap`
  or `apt install nmap`.
- Rust 1.70+ if you're building from source.

## Build & run

```bash
cd netscan
cargo run --release
```

Or build once and run the binary directly:

```bash
cargo build --release
./target/release/netscan
```

First run creates `~/.config/netscan/targets.toml` and `~/.config/netscan/profiles.toml`
(or the platform equivalent) with sensible defaults. Edit them to add your own groups.

```bash
netscan --config-paths   # show where config and data live
```

## Keyboard reference

| Key | Action |
|-----|--------|
| `1` / `2` / `3` / `4` | Switch tabs (Targets / Profiles / Scan / History) |
| `Tab` | Next tab |
| `↑↓` / `j` `k` | Navigate lists |
| `Enter` | Run scan with selected target group + profile |
| `x` | Stop a running scan |
| `Shift+E` | Export incident bundle (Scan or History tab) |
| `e` | Export selected history entry |
| `r` | Reload history list |
| `?` | Help overlay |
| `q` | Quit (or stop a running scan) |

## Scan history & differential scanning

Every completed scan is persisted to a local SQLite database at
`~/.local/share/netscan/history.db` (or the platform equivalent). When you finish a
scan, netscan automatically looks up the most recent prior scan with the same
target group + profile combination and renders a diff pane at the bottom of the
Scan tab showing:

- New hosts that came online
- Removed hosts that went dark
- Newly open ports (potential attack surface growth)
- Newly closed ports
- Service changes (e.g. `nginx` → `apache`)
- Version changes (e.g. `OpenSSH 9.2` → `OpenSSH 9.3`)

This is the core value loop: **run the same scan on a schedule, see only what
changed.** Press `4` to browse the full scan history.

## Incident bundle export

Press `Shift+E` on the Scan tab (or `e` in History) to export a self-contained
bundle into `~/.local/share/netscan/exports/`:

```
netscan_YYYY-MM-DD-HH-MM-SS_<group>_<scan-id>/
  manifest.json    scan metadata
  hosts.json       normalized host + port data
  summary.md       human-readable write-up
  diff.md          diff against previous scan (if present)
```

Hand this directory to a teammate, a client, or your future self.

## Config format

```toml
# ~/.config/netscan/targets.toml

[[groups]]
name = "home-lan"
description = "Home LAN sweep"
targets = ["192.168.1.0/24"]

[[groups]]
name = "prod-edge"
description = "Production edge hosts"
targets = [
  "api.example.com",
  "cdn.example.com",
]
```

```toml
# ~/.config/netscan/profiles.toml

[[profiles]]
name = "quick"
description = "Quick TCP sweep — top 100 ports"
flags = "-T4 --top-ports 100"

[[profiles]]
name = "full-tcp"
description = "Full TCP, service detection, default NSE"
flags = "-T4 -p- -sV -sC"
```

netscan always appends `-oX -` and the target list to whatever flags you specify, so you
never need to include those yourself.

## Roadmap

- [x] TUI shell with target/profile inventory
- [x] Live scan view with streaming XML parse
- [x] Default profiles (`quick`, `full-tcp`, `udp-top`, `ssl-audit`, `discovery`)
- [x] SQLite-backed scan history
- [x] Automatic diff on scan completion
- [x] History browser with detail view
- [x] Incident bundle export (`Shift+E`)
- [ ] Manual diff between any two historical scans (select two in History)
- [ ] NSE script picker
- [ ] Scheduled / daemon mode for background scans
- [ ] Webhook alerts on change
- [ ] Opt-in AI triage via local or remote Ollama

## License

MIT.

---

*Part of [NetWatch Labs](https://netwatchlabs.com) — the security-minded sysadmin's toolkit.*
