# Changelog

## [Unreleased] — Resilience + modern-threat detection upgrade

### Fixed
- Resolved committed Git merge-conflict markers that made `secure_channel.py`,
  `sentry_agent.py`, and `control_center.py` unparseable on `main`.

### Added
- **Real host network containment** (`host_control_plane/containment.py`):
  iptables / nftables / netsh / pf backends, **dry-run by default**, reversible
  `lift()`, management-CIDR carve-out, and an auditable action log. Wired into
  the control plane's instant-block path.
- **10 new Sigma detection rules** (16 total) for current threats: LSASS dumping,
  encoded PowerShell, BYOVD, RMM abuse, cloud exfil, ESXi ransomware,
  Kerberoasting, LOLBin proxy exec, persistence (task/WMI/account), MFA fatigue.
- **14 new ATT&CK techniques** (25 total) with event→technique mappings and
  server-side score weights (kerberoast tuned separately from LSASS).
- Extended `attack_replay.py` matrix to 14 techniques (100% coverage, 0 FP).
- **CI conflict-marker gate** as the first build step (covers md/sh/yml/bat too).
- **Containment unit tests** proving dry-run safety and reversibility.

### Changed
- README rewritten: honest Real-vs-Simulated table, full 25-technique coverage
  table, cross-platform install (Linux/Windows/macOS), structure, roadmap.
- RTO badge now labelled `(simulated)` to reflect the `SimulatedBackend` source.


# Vanguard-OOB — Changelog

## v2.0 — Security, Ransomware Continuity, and Honesty Pass

Every item below was verified by running the code, not by inspection alone.
Run `python3 verify.py` (23 assertions) and `python3 demo.py` to confirm.

### 🔒 Security (the biggest gap in v1)

- **Replaced the static-XOR transport with a real authenticated channel**
  (`common/secure_channel.py`).
  - *Why:* v1 used one hard-coded 28-byte XOR key shared by the agent,
    controller, AND the public test harness. XOR with a repeating key is
    trivially broken, there was no authentication, and no replay protection.
  - *Now:* AES-256-GCM (or a stdlib-only HMAC-SHA256 encrypt-then-MAC AEAD if
    `cryptography` is absent), **per-agent keys** via HKDF, **replay protection**
    (random nonce + monotonic counter + timestamp-skew window), and **identity
    binding** so a frame's `vm_id` is forced to equal the authenticated agent.
- **Killed the vm_id-spoofing attack.** In v1, malware in VM-A could send
  telemetry tagged `vm_id: "VM-B"` and force-isolate an innocent VM. The
  receiver now rejects any frame whose payload `vm_id` ≠ authenticated identity.
- **Agent score deltas are no longer trusted.** v1 fell back to the agent's
  self-reported `score_delta` for unknown event types, so a compromised agent
  could send `score_delta: 0` to suppress its own score. The controller now
  computes every score from a single authoritative table.

### 🦠 Ransomware detection + response (the user's core idea)

- **New `CryptographicSpikeDetector`** in the agent — the "crypto map" the design
  called for. It tracks the *rate and variance* of high-entropy writes and fires
  a dedicated `crypto_spike` event (+50) the moment encryption behaviour deviates
  ≥3σ from the host's own baseline. Variance-aware, so steady encrypted-blob
  workloads don't false-positive.
- **Instant NIC kill-switch** on a crypto-spike (`hypervisor_api.block_network`),
  executed *before* the slower quarantine-VLAN move — containment in milliseconds.
- **Business-continuity failover** (`host_control_plane/failover_orchestrator.py`)
  — the missing half of v1. When the ACTIVE node of a service is compromised, a
  warm STANDBY is promoted, the service VIP is redirected, the workload keeps
  running (sub-second RTO measured + shown on the dashboard), the primary is cured
  in the background, and it rejoins as the new STANDBY. The pair self-heals.
- **Cross-platform backup-destruction detection.** v1 only caught Windows
  `vssadmin`/`wbadmin`. Now also detects Linux/macOS (`rm -rf /backup`,
  `btrfs subvolume delete`, `zfs destroy`, `shred`, snapshot deletion, etc.).

### 🐶 Always-active aggression

- **Agent-silence watchdog.** Malware's first move is to kill the agent; in v1
  that just made the VM go quiet and nothing happened. The controller now flags
  any agent that misses 3× its expected heartbeat interval (`silent=true` +
  synthetic `agent_silence` alert).
- **Heartbeat self-attestation** — monotonic `agent_seq` + declared interval, so
  the watchdog can distinguish "idle" from "killed".

### 🐛 Functional bug fixes

- **Velocity-spike scoring fixed.** v1 emitted the velocity spike as an `entropy`
  event, which the controller silently re-scored from 20 → 40. It now has its own
  `velocity` type scored at the intended +20.
- **Non-blocking incident response.** v1 ran the ~9s IR sequence (with
  `time.sleep` calls) synchronously inside the main loop, freezing the dashboard
  and leaving `isolated:true` with an empty IR log. IR now runs in a worker
  thread; the dashboard shows IR + failover progress live.
- **Score band consistency.** Score is no longer capped at exactly 100 (capped at
  200) so CRITICAL severity is meaningful; dashboard/threshold bands aligned.
- **Fixed `f"/tmp/{random.choices(...)}"`** in the test harness (was embedding a
  list object in the path instead of a joined string).
- **Fixed `yara_engine.py` invalid escape-sequence warning** (raw docstring).
- **Docs/requirements consistency.** `blue_team/__init__.py` said "Eight tools"
  while the suite has 21 — corrected. Requirements pinned consistently across all
  modules; `cryptography` added (optional, with graceful fallback).

### ✨ Shock-factor / presentation

- **`demo.py`** — one command runs the entire story (normal → crypto-spike →
  block → isolate → failover → self-heal) with narration and a final RTO readout.
- **Rebuilt SOC dashboard** (`host_control_plane/dashboard.html`) — live crypto
  map per VM, kill-chain event stream, **Service Continuity / failover panel**
  with node roles and RTO, watchdog "silent agent" indicator, failover counter.
- **`verify.py`** — 23-assertion self-test that proves security, scoring,
  crypto-spike, failover, and watchdog all work, with no hypervisor required.

### Deployment

- systemd units now read a shared master secret from
  `/etc/vanguard-oob/master.env`; `deploy.sh` generates one on the host and
  reminds you to copy it to each guest.
- `deploy.sh` copies the new `common/`, `failover_orchestrator.py`, and
  `dashboard.html` for the relevant roles.

### Known limitations (stated honestly)

- The failover orchestrator ships with a **simulated backend** so the full flow
  runs without real infrastructure. Wiring it to a real load balancer / hypervisor
  is a matter of implementing the 4-method `FailoverBackend` interface
  (`promote`, `redirect_traffic`, `health_check`, `rejoin_as_standby`).
- The hypervisor actions require real VirtualBox/Proxmox to actually execute; on
  a machine without them they log "would execute" and return failure — by design.
- The default master key is a **development** key. Production MUST set
  `VANGUARD_MASTER_KEY`.

## v2.1 — Detection Intelligence Layer (ATT&CK + Sigma + Validation)

Built as one coherent layer that makes detections speak the language real SOCs
use, and proves they work.

- **MITRE ATT&CK mapping** (`common/mitre_attack.py`) — every telemetry event is
  tagged with real published technique IDs (T1486 Data Encrypted for Impact,
  T1490 Inhibit System Recovery, T1505.003 Web Shell, T1036.005 Masquerading,
  T1571 Non-Standard Port, T1562.001 Impair Defenses). Events, the API, and the
  dashboard all carry ATT&CK context.
- **Live ATT&CK matrix** on the SOC dashboard — tactic columns light up as
  techniques are observed in real time.
- **Sigma-compatible detection engine** (`blue_team/sigma_engine/`) — loads
  industry-standard Sigma YAML rules (selections, conditions incl. `and/or/not`,
  `1 of them`, `all of them`, field modifiers `contains/startswith/endswith/re`),
  extracts ATT&CK tags, and matches Vanguard telemetry. Ships 6 rules. Now the
  22nd tool in the blue-team CLI.
- **Attack-replay validation** (`attack_replay.py`) — fires every technique in a
  test matrix and reports **ATT&CK coverage, MTTD, and false-positive rate**,
  cross-confirmed by the Sigma engine. Offline (in-process) and live modes.
- **Bug found BY the new validation harness and fixed:** `agent_silence`
  (T1562.001) was detected but scored 0, so killing the agent didn't raise the
  threat score. Now weighted at +25 and contributes to isolation. (This is the
  good kind of finding — the test suite caught a gap in the product.)
- `verify.py` expanded to **34 assertions** (added ATT&CK + Sigma coverage).
- `demo.py` now prints the detection-coverage report (ATT&CK + Sigma metrics) at
  the end, so one command shows both the attack story AND the proof.

## v2.2 — SOC Workflow, Enrichment & Defensibility

- **SOC alert queue** (`host_control_plane/alert_manager.py`) — scored events
  become alerts with a full lifecycle (OPEN → ACKNOWLEDGED → ESCALATED → CLOSED /
  FALSE_POSITIVE), analyst actions (ack/assign/escalate/close/false-positive/note),
  dedupe, and an audit trail. This is the "real SOC" workflow detection alone lacks.
- **Operational metrics** — mean detection latency (MTTD), false-positive rate,
  and an alert-volume trend, all from real data, surfaced on the dashboard.
- **Threat geography + intel enrichment** (`host_control_plane/geo_intel.py`) —
  outbound destination IPs are geo-located (offline approximation, honestly
  labelled) and given a local threat-intel verdict (malicious/suspicious/internal).
- **Dashboard upgraded** with three new panels: SOC alert queue with action
  buttons, alert-volume trend chart, and outbound-destination/threat-geo panel.
- **New API:** `/api/alerts/<id>/<action>` for analyst dispositions; alerts,
  metrics, and geo events added to `/api/status`.
- **`verify.py` now at 44 assertions** (added SOC workflow + enrichment checks).
- **`DEFENSE_GUIDE.md` added** — module-by-module rationale and an interview Q&A,
  so the project can be *defended*, not just demonstrated. Read it.

### Honest limitations (unchanged stance)
- Geo-IP is an **offline approximation** (built-in block table + deterministic
  placement for unknowns, flagged `approx`). Drop in MaxMind GeoLite2 for real
  accuracy — the dashboard contract is unchanged.
- Alerts are in-memory (reset on restart). A persistent store is the next step.

## v2.3 — Hardening Pass (bugs, security, tooling)

Addressed an external code-review. Every fix verified against the live system.

### Bug fixes
- **Telemetry re-queue (sentry_agent.py):** failed sends previously used
  `appendleft()` onto a `maxlen=500` deque, which silently dropped the newest
  events during a burst. Now uses a dedicated `_retry` buffer (maxlen=2000)
  drained oldest-first on the next flush — no event loss, order preserved.
- **OrderedSet eviction (secure_channel.py):** nonce-replay cache evicted with
  `list.pop(0)` (O(n)). Replaced the order list with `collections.deque` +
  `popleft()` (O(1)).
- **Packaging:** added `__init__.py` to all 21 blue-team tool directories — they
  are now importable Python packages (needed for pytest + clean imports).
- **Silent excepts:** replaced bare `except: pass` sites with logged versions.
  The agent logs to a local file (`sentry_agent.log`) and never to a TTY, so it
  stays invisible to an attacker on the box; the controller logs at debug/exception.

### Security
- **API authentication (critical):** `/api/isolate`, `/api/restore`, and all
  `/api/alerts/<id>/<action>` mutations now require a bearer token
  (`X-Vanguard-Token` or `Authorization: Bearer`). Read-only `/api/status` and the
  dashboard stay open so the UI loads. Token via `--api-token`,
  `VANGUARD_API_TOKEN`, or an auto-generated per-session token printed at startup.
  Constant-time comparison. Optional `--allow-ips` IP allowlist.
- **Dev-key warning:** the controller now detects the public development master
  key and prints a loud multi-line startup warning that telemetry can be forged
  until `VANGUARD_MASTER_KEY` is set.

### Tooling / repo hygiene
- Added **LICENSE** (MIT), **.gitignore** (caches, dumps, keys, findings),
  **.github/workflows/ci.yml** (compile + pytest + verify + replay on py3.10–3.12),
  **tests/test_vanguard.py** (19 pytest unit tests), and **pyproject.toml**
  (pytest + mypy config).

### Verified after this pass
- `pytest` → 19 passed   ·   `verify.py` → 44/44   ·   `attack_replay --offline` → 100% coverage, 0 FP
- API auth: unauth isolate → 401, wrong token → 401, correct token → 200, status → 200
- All 22 blue-team tools import; blue_team packages now importable.
