# Vanguard-OOB Blue Team Detection Suite

**21 original tools · 13,000+ lines · Zero external detection-engine dependencies**

This is a from-scratch Blue Team / SOC platform. Every detection engine,
scoring model, and dashboard was designed and built specifically for this
project — nothing here is a wrapper around an existing open-source scanner.
The architecture is original so you can extend it freely for your own
follow-on projects.

---

## Why this is different from a typical open-source toolkit

| Typical approach | Vanguard-OOB approach |
|---|---|
| Wraps `nmap`/`masscan` | Pure-Python concurrent TCP/UDP scanner with its own CVE-surface mapper |
| Wraps `libyara` | Original `.vyr` rule engine + parser implemented in Python, zero C deps |
| Simple regex log grep | Statistical anomaly models (Z-score, circular time-of-day, robust MAD) |
| Single-tool alerting | Cross-tool **Alert Correlator** with entity resolution + kill-chain reconstruction |
| Static signature DGA list | Local n-gram language model trained on a built-in corpus — no API calls |
| Basic honeypot | 6 protocol-specific honeypots with attacker-intent classification |
| One-off scripts | Unified `vanguard` CLI + Master SOC Dashboard tying all 21 tools together |

---

## The 21 Tools

| # | Tool | Category | What it does |
|---|------|----------|---------------|
| 1 | `threat_intel` | Intel | IOC feed engine, Bloom-filter lookup, reputation scoring, REST API |
| 2 | `log_analyzer` | Detection | Multi-format log parser (syslog/nginx/apache/json/windows) + 25 detection rules |
| 3 | `vuln_scanner` | Scanning | Concurrent port scanner, service fingerprinting, CVE-surface mapping, TLS audit |
| 4 | `packet_inspector` | Network | Pure-Python PCAP decoder, DNS/HTTP/TLS-SNI parsing, beacon/port-scan/tunnel detection |
| 5 | `ioc_hunter` | Hunting | Filesystem + process memory + persistence-location IOC hunter |
| 6 | `yara_engine` | Detection | Original `.vyr` rule language + parser + matcher (no libyara) |
| 7 | `timeline_builder` | Forensics | Multi-source forensic timeline (FS, logs, processes, network, tool JSON) |
| 8 | `network_mapper` | Network | ARP/ICMP/TCP LAN discovery, OUI vendor lookup, OS fingerprinting, rogue detection |
| 9 | `file_integrity` | Integrity | Dual-hash (SHA256+BLAKE2b) FIM with HMAC-chained tamper-evident baselines |
| 10 | `lateral_movement_detector` | Detection | Auth-graph analysis: fan-out, fan-in, chain-hop, Kerberoasting, AS-REP roasting |
| 11 | `dns_analyzer` | Network | DGA (n-gram model), fast-flux, DNS tunneling, typosquat/homoglyph detection |
| 12 | `credential_monitor` | Identity | Password-spray detection, entropy-gated secret scanner, hash-strength auditor |
| 13 | `alert_correlator` | Correlation | **The integration spine** — unifies all 21 schemas, dedups, reconstructs kill chains |
| 14 | `behavioral_engine` | UEBA | 4 independent baseline models: circular time, peer-rarity, robust MAD, Markov chains |
| 15 | `config_auditor` | Hardening | 33+ CIS-inspired checks across SSH/PAM/kernel/filesystem/services/audit/cron |
| 16 | `deception_engine` | Deception | Canary files/credentials/DNS/processes with access + exfil-staging detection |
| 17 | `threat_hunter` | Hunting | 9 hypothesis-driven hunt playbooks (CONFIRMED/SUSPECT/NEGATIVE verdicts) |
| 18 | `reporting_engine` | Reporting | Executive/Technical/Compliance/Delta reports with inline SVG charts |
| 19 | `honeypot_manager` | Deception | 6 protocol honeypots (SSH/HTTP/FTP/MySQL/Telnet/raw) + intent classifier |
| 20 | `memory_forensics` | Forensics | Live `/proc` memory scanning + offline ELF core-dump analysis, zero Volatility dep |
| 21 | `soc_dashboard` | Dashboard | Real-time Flask dashboard unifying all 20 detection tools |

---

## Quick Start

```bash
cd blue_team
pip install -r requirements.txt

# See everything available
python3 vanguard.py tools

# Run one tool directly
python3 vanguard.py run vuln_scanner --target 192.168.1.1

# Run a full hardening + IOC + integrity audit
python3 vanguard.py audit --path /etc

# Run all 9 proactive threat-hunt playbooks
python3 vanguard.py hunt

# Network discovery + vulnerability scan
python3 vanguard.py sweep 192.168.1.0/24

# Unify every tool's findings into one risk picture
python3 vanguard.py correlate findings/

# Generate executive + technical HTML reports
python3 vanguard.py report findings/

# Launch the live Master SOC Dashboard
python3 vanguard.py dashboard --port 8080
# → open http://localhost:8080

# Run the entire pipeline end-to-end
python3 vanguard.py full-scan --target-dir /etc --network-target 192.168.1.0/24
```

---

## How the pieces connect

```
  21 detection tools
        │  (each writes JSON findings)
        ▼
  findings/*.json
        │
        ▼
  alert_correlator.py  ──► unified schema, dedup, kill-chain reconstruction
        │
        ├──► soc_dashboard.py     (live visual ops view)
        ├──► reporting_engine.py  (executive/technical/compliance reports)
        └──► control_center.py    (Vanguard-OOB OOB isolation trigger, ../host_control_plane/)
```

Every tool emits a finding with at minimum: `severity`, `description`,
`timestamp`. The correlator auto-detects each tool's schema (no manual
config) and converts it into the unified `UnifiedFinding` record, then:

1. **Deduplicates** repeat alerts (content-hash + time-bucket)
2. **Resolves entities** — all findings about one host/IP/user converge
3. **Reconstructs campaigns** — MITRE ATT&CK tactic-ordered chains spanning
   ≥3 tactics get a multiplied risk score, surfacing real attacks above noise

---

## False-positive engineering

Every detector in this suite was explicitly designed to minimize false
positives, not just maximize detection:

- **DGA detection** uses a trained linguistic plausibility model, not a flat
  entropy threshold — `cloudflare.com` scores high-plausibility while
  `qhxzkptbvmlfjg.biz` scores near zero.
- **UEBA time-of-day model** uses circular statistics so a night-shift
  worker's normal hours (e.g. 22:00–23:00) never false-positive on wraparound.
- **UEBA process model** uses peer-rarity — a tool used by 1/3 of your fleet
  is normal even if new to one user; a tool used by 0/50 is flagged.
- **Password-spray detector** requires BOTH high account fan-out AND
  abnormally regular timing OR overwhelming volume — a user mistyping their
  password 3 times never triggers it.
- **Secret scanner** entropy-gates generic patterns so UUIDs, version
  strings, and `"changeme"` placeholders are never flagged.
- **Config auditor** uses PASS/FAIL/WARN/**SKIP** — a missing subsystem
  (e.g. no auditd on a minimal container) is SKIP, not FAIL.

---

## Architecture notes

- **Zero required external detection dependencies.** Only `psutil`, `flask`,
  and `requests` (for hypervisor REST calls) are needed — no nmap, no
  libyara, no Volatility, no Suricata.
- **Every tool runs standalone** — you can use `log_analyzer.py` by itself
  with no other tool installed.
- **Every tool also speaks the unified finding schema** when run with
  `--json`/`--output`, so they compose automatically through the correlator.
- **Pure stdlib + small surface** — easy to audit, easy to extend, easy to
  fork into your next project.

---

## Extending this suite

The adapter pattern in `alert_correlator.py`'s `ToolAdapters` class makes it
straightforward to plug in a new tool: write your detector to emit a JSON
list of `{severity, description, ...}` objects, add one `detect_adapter`
signature function, and it flows into the dashboard and reports automatically.

---

## License

MIT. Built for defensive security research and operations on systems you own
or are authorized to monitor.
