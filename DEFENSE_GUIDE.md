# Vanguard-OOB — Defense Guide (Own It, Don't Just Show It)

This document exists for one reason: so you can **defend every part of this
project under questioning**. A project you can't explain is a liability the
moment someone competent probes it. Read this until each answer is yours.

How to use it: read a section, close it, and explain that module out loud to an
empty room. If you stumble, re-read. Do this until you don't stumble.

---

## 1. The one-sentence pitch (memorise this)

> "Vanguard-OOB is an out-of-band security control plane: the detection and
> response logic runs **outside** the monitored VM, so malware inside the VM
> can't disable it — and when ransomware hits, it fails the workload over to a
> warm standby so the business keeps running while the infected machine is cured."

If you can only say one thing, say that. Everything else supports it.

---

## 2. Architecture in 60 seconds

Three planes, deliberately separated:

- **Guest VM (the thing being protected)** runs `sentry_agent.py` — a *sender-only*
  telemetry daemon. Zero listening ports. It watches files, processes, and sockets.
- **Host Control Plane (outside the guest)** runs `control_center.py` — receives
  authenticated telemetry, scores threats, and triggers response. Malware in the
  guest cannot reach it because it lives on a different trust boundary.
- **Hypervisor** executes the actual containment (isolate NIC, snapshot rollback)
  *below* the guest OS, so a compromised guest can't block it.

**Why this matters / why it's the core idea:** EDR that runs inside the OS can be
killed by malware that gains admin. Out-of-band monitoring can't be — the
attacker would have to escape the VM to the hypervisor, a much higher bar.

---

## 3. Module-by-module — what it does and WHY

### `common/secure_channel.py` — authenticated telemetry
- **What:** seals telemetry with AES-256-GCM (or a stdlib HMAC-AEAD fallback),
  per-agent keys via HKDF, replay protection, identity binding.
- **Why each piece:**
  - *AEAD (GCM):* gives confidentiality **and** integrity in one operation. If
    a byte is flipped, decryption fails — you can't tamper undetected.
  - *Per-agent keys (HKDF):* one master secret → a unique key per agent. If one
    agent's key leaks, the rest of the fleet is unaffected. HKDF is the standard
    way to derive multiple keys from one secret (RFC 5869).
  - *Replay protection (nonce + counter + timestamp):* a captured frame can't be
    re-sent to force a false isolation. The receiver remembers recent nonces and
    rejects counter regressions and stale timestamps.
  - *Identity binding:* the frame's `vm_id` is forced to equal the authenticated
    sender. This kills the attack where malware in VM-A sends events labelled
    "VM-B" to get an innocent machine isolated.
- **The fallback exists because** the framework must never be *weaker* than
  authenticated-encrypted, even with zero third-party libraries installed.

### `guest_production_vm/sentry_agent.py` — the sensor
- **What:** scans filesystem entropy, a rolling "crypto map", process lineage,
  backup-destruction commands, and sockets; sends events; emits heartbeats.
- **Key design choice — Shannon entropy for ransomware:** encrypted/compressed
  data is high-entropy (close to 8 bits/byte). A normal text file is ~4–5. A
  sudden run of files crossing ~7.2 is the signature of mass encryption.
- **The crypto-spike detector is variance-aware, not a flat threshold:** it
  compares the *recent* high-entropy write rate to the host's own baseline and
  fires only when it's ≥3σ above normal. This avoids false positives on servers
  that legitimately write some encrypted blobs.

### `host_control_plane/control_center.py` — the brain
- **What:** authenticated receiver → correlation/scoring → response orchestration.
- **Scoring is additive over a 60-second rolling window.** No single event
  isolates a machine; multiple corroborating signals must stack to 100.
  **Why a window:** point-in-time scores would either be too trigger-happy or
  forget context. A rolling window models "how bad is it *right now*".
- **The controller computes scores itself; it never trusts the agent's number.**
  *Why:* the agent runs inside the possibly-compromised VM. If malware owns it,
  it could send `score: 0` to stay quiet. The authoritative table lives on the
  trusted side.

### `host_control_plane/failover_orchestrator.py` — business continuity
- **What:** models each service as an HA pair (ACTIVE + STANDBY). On compromise
  of the active node it promotes the standby, redirects the service VIP, cures
  the primary in the background, and rejoins it as the new standby.
- **Why it's the whole point:** isolation alone stops the bleeding but also stops
  the *business*. Failover keeps the workload alive. "Hit at 10–20% beats 100%."
- **RTO (Recovery Time Objective):** the measured seconds from "active node down"
  to "service serving on the standby". The demo shows ~0.8s.

### `host_control_plane/alert_manager.py` — SOC workflow
- **What:** turns scored events into an alert queue with a lifecycle
  (OPEN → ACKNOWLEDGED → ESCALATED → CLOSED / FALSE_POSITIVE), analyst actions,
  notes, and metrics (MTTD, FP rate, volume trend).
- **Why:** detection is half the job; a real SOC *works* alerts. Dedupe collapses
  repeats so one storm doesn't bury the analyst.

### `common/mitre_attack.py` — the vocabulary
- **What:** maps every event to real ATT&CK technique IDs (T1486, T1490, …).
- **Why:** analysts think in ATT&CK. Speaking it makes the tool interoperable and
  the alerts intelligible to anyone in the field.

### `blue_team/sigma_engine/` — industry-standard detection rules
- **What:** loads Sigma YAML rules (the open SIEM rule standard) and matches them
  against telemetry; extracts ATT&CK tags from each rule.
- **Why:** hard-coded Python detections don't scale or share. Sigma is the format
  the whole industry uses; compatibility means community rules drop straight in.

### `attack_replay.py` — proof
- **What:** fires every technique and reports ATT&CK coverage, MTTD, and
  false-positive rate, cross-confirmed by the Sigma engine.
- **Why this is your strongest interview material:** it *found a real bug* — the
  agent-silence technique (T1562.001) was detected but scored 0, so killing the
  agent didn't raise the threat score. The harness caught it; I fixed it. That is
  exactly how a security engineer thinks: build the thing that proves your own
  detections work, and trust the result over your assumptions.

---

## 4. The questions you WILL be asked (with answers)

**Q: Isn't running an agent inside the VM the same problem as EDR — malware can kill it?**
A: It can, and we plan for that. The agent emits heartbeats with a monotonic
sequence number. If it goes silent past 3× its interval, the watchdog raises an
`agent_silence` alert (ATT&CK T1562.001, Impair Defenses) and adds to the threat
score. Killing the agent is itself a detection, not a blind spot. The *response*
(isolate, snapshot) runs out-of-band at the hypervisor, where the agent's death
doesn't matter.

**Q: Why XOR is— (they'll test if you know crypto):**
A: The first version used XOR with one static key — that's not encryption, it's
trivially broken with known plaintext, and it had no authentication or replay
protection. I replaced it with AES-256-GCM (authenticated encryption) with
per-agent keys and replay protection. I can walk you through the wire format.

**Q: How do you avoid false positives on a server that legitimately encrypts data?**
A: The crypto-spike detector is variance-based, not a fixed threshold. It learns
the host's own baseline rate of high-entropy writes and only fires when recent
activity is ≥3σ above that baseline. A steady encrypted workload sits in its
baseline and never trips; a ransomware burst is many sigma out.

**Q: What's your MTTD/MTTR?**
A: MTTD (detect) is ~110ms in the live attack-replay — telemetry arrival to score
flag. MTTR/RTO (respond) for full isolation+failover is sub-second in the demo,
measured and shown on the dashboard. Both are produced by the validation harness,
not estimated.

**Q: Why isolate before curing instead of just restoring?**
A: Containment first. An infected box on the network keeps spreading — lateral
movement, encrypting shares, beaconing to C2. You cut it off (NIC kill-switch in
milliseconds on a crypto-spike), *then* fail the workload over so the business
continues, *then* cure the box at leisure. Order matters: stop the bleeding,
preserve continuity, recover.

**Q: What are the limits / what would you do with more time? (Always asked — answer honestly)**
A: The failover backend is simulated so the flow runs without real infra; wiring
it to a real load balancer is the `FailoverBackend` 4-method interface. Geo-IP is
an offline approximation, not MaxMind-grade. The detection set is the slice we
can honestly claim, not the full ATT&CK matrix. None of it is tuned against
production data yet. I'd prioritise real GeoIP, a persistent alert store, and
tuning thresholds against real traffic.

---

## 5. Things NOT to say (they backfire)

- ❌ "It's the father of SOC / unbeatable / blocks 100% of attacks."
  → Nothing blocks 100%. Claiming it signals inexperience. Say "reduces blast
  radius and preserves continuity."
- ❌ "It uses AI." → It doesn't. There's no ML here. Don't claim it.
- ❌ Overstating the geo map's accuracy. → Call it an offline approximation.

Confidence comes from knowing the limits, not hiding them.

---

## 6. Your 5-step study plan

1. Run `python3 verify.py` and read each check — that's the feature list.
2. Read `secure_channel.py` top to bottom. Re-implement `_hkdf` from memory.
3. Trace one event from `sentry_agent` → `control_center.process_batch` →
   `alert_manager.raise_alert`. Narrate the path out loud.
4. Run `python3 attack_replay.py --offline` and explain each technique + its ID.
5. Run `python3 demo.py` and narrate the failover story as if presenting it.

When you can do all five without notes, the project is genuinely yours.
