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

**Status:** Early MVP. Target inventory, profiles, live scan view, streaming XML parsing,
and the core TUI shell are working. Scan history, diffing, incident bundle export, and
AI triage are next.

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
| `1` / `2` / `3` | Switch tabs (Targets / Profiles / Scan) |
| `Tab` | Next tab |
| `↑↓` / `j` `k` | Navigate lists |
| `Enter` | Run scan with selected target group + profile |
| `x` | Stop a running scan |
| `?` | Help overlay |
| `q` | Quit (or stop a running scan) |

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
- [ ] SQLite-backed scan history
- [ ] Automatic diff on scan completion
- [ ] Manual diff between any two historical scans
- [ ] Incident bundle export (`Shift+E`)
- [ ] NSE script picker
- [ ] Scheduled / daemon mode for background scans
- [ ] Webhook alerts on change
- [ ] Opt-in AI triage via local or remote Ollama

## License

MIT.

---

*Part of [NetWatch Labs](https://netwatchlabs.com) — the security-minded sysadmin's toolkit.*
