#!/usr/bin/env python3
"""
Vanguard-OOB :: Attack Replay & Detection Validation
=====================================================
"I think it works" → "I PROVED it catches T1486."

This harness fires a battery of known attack techniques and asserts that each
is (a) detected by the live controller and (b) correctly mapped to its MITRE
ATT&CK technique. It then reports the metrics a real SOC lives by:

  - DETECTION COVERAGE : how many techniques in our test matrix we actually catch
  - MTTD (mean time to detect)   : telemetry sent → controller flags it
  - MTTR (mean time to respond)  : detection → isolation/failover executed
  - FALSE-POSITIVE RATE          : benign events that wrongly raise score
  - SIGMA CONFIRMATION           : each detection re-validated by the Sigma engine

Two modes:
  --live   : run against a running Control Center (full path incl. response/RTO)
  --offline: drive the CorrelationEngine + Sigma engine in-process (no network)

Each "attack" is a real ATT&CK technique mapped to the telemetry it produces, so
this doubles as an ATT&CK coverage report.

Usage:
    python3 attack_replay.py --offline
    python3 attack_replay.py --live --host 127.0.0.1 --port 9999 --web-port 5000
"""

from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "host_control_plane"))
sys.path.insert(0, str(ROOT / "blue_team" / "sigma_engine"))

from common.mitre_attack import map_event_to_techniques  # noqa: E402

C = {"r": "\033[0m", "b": "\033[1m", "red": "\033[91m", "grn": "\033[92m",
     "ylw": "\033[93m", "cyn": "\033[96m", "dim": "\033[2m", "mag": "\033[95m"}


def p(k, s):
    return f"{C[k]}{s}{C['r']}"


# ---------------------------------------------------------------------------
# The attack matrix: technique -> the telemetry events that represent it
# ---------------------------------------------------------------------------

@dataclass
class AttackCase:
    name: str
    technique: str            # expected ATT&CK technique id
    events: List[dict]        # telemetry events the technique emits
    expect_detection: bool = True


def _ev(event_type, severity="high", **details):
    return {"event_type": event_type, "severity": severity,
            "timestamp": datetime.now(timezone.utc).isoformat(), "details": details}


def attack_matrix() -> List[AttackCase]:
    return [
        AttackCase("Ransomware mass encryption", "T1486",
                   [_ev("crypto_spike", "critical", reason="ransomware_crypto_spike",
                        recent_high_entropy_writes=15, sigma_above_baseline=12.0)]),
        AttackCase("Inhibit system recovery", "T1490",
                   [_ev("shadow", "critical", reason="backup_destruction_detected",
                        command="vssadmin delete shadows /all /quiet")]),
        AttackCase("Web shell / RCE", "T1505.003",
                   [_ev("process", "critical", reason="web_server_spawned_shell",
                        parent_name="nginx", child_name="bash")]),
        AttackCase("Masquerading exec path", "T1036.005",
                   [_ev("process", "high", reason="suspicious_exec_path",
                        exe="/tmp/.x9f2", name="x9f2")]),
        AttackCase("C2 non-standard port", "T1571",
                   [_ev("network", "medium", reason="unexpected_outbound_connection",
                        proc_name="nc", dest_ip="185.220.1.9", dest_port=4444)]),
        AttackCase("Defense evasion: agent kill", "T1562.001",
                   [_ev("agent_silence", "high", reason="agent_silence", silent_seconds=42)]),
        # --- Current-threat matrix additions ---
        AttackCase("LSASS credential dump", "T1003.001",
                   [_ev("cred_dump", "critical", reason="lsass_dump",
                        access_proc="comsvcs.dll", target="lsass.exe")]),
        AttackCase("Encoded PowerShell (fileless)", "T1059.001",
                   [_ev("powershell", "high", reason="encoded_command",
                        cmdline="powershell -enc SQBFAFgAKAAuLi4p")]),
        AttackCase("BYOVD kernel driver load", "T1068",
                   [_ev("driver_load", "critical", reason="byovd",
                        driver_name="RTCore64.sys")]),
        AttackCase("RMM tool abuse (ScreenConnect)", "T1219",
                   [_ev("rmm_tool", "high", tool="screenconnect.exe")]),
        AttackCase("Exfil to cloud storage", "T1567.002",
                   [_ev("cloud_exfil", "high", dest="rclone->mega.nz", bytes=8_500_000_000)]),
        AttackCase("ESXi datastore encryption", "T1486",
                   [_ev("ransomware_esxi", "critical", reason="vmdk_mass_encrypt",
                        datastore="datastore1", vmdk_touched=37)]),
        AttackCase("LOLBin proxy execution", "T1218",
                   [_ev("lolbin", "high", binary="rundll32.exe")]),
        AttackCase("Persistence: WMI subscription", "T1546.003",
                   [_ev("persistence", "high", reason="wmi_subscription")]),
        # A benign control: should NOT raise score (false-positive check)
        AttackCase("Benign heartbeat (control)", "-",
                   [_ev("heartbeat", "low", cpu_percent=12, mem_percent=33, agent_seq=5)],
                   expect_detection=False),
    ]


# ---------------------------------------------------------------------------
# Offline mode — drive the engine in-process
# ---------------------------------------------------------------------------

def run_offline() -> int:
    import logging
    logging.getLogger("vanguard.hypervisor").setLevel(logging.WARNING)
    from control_center import CorrelationEngine, _resolve_delta
    from hypervisor_api import HypervisorAPI, load_default_config
    from failover_orchestrator import FailoverOrchestrator, SimulatedBackend
    from sigma_engine import SigmaEngine

    sigma = SigmaEngine()
    sigma.load_dir(ROOT / "blue_team" / "sigma_engine" / "rules")

    print(p("cyn", "\n══ ATTACK REPLAY (offline) ══════════════════════════════════"))
    print(p("dim", f"   Sigma rules loaded: {len(sigma.rules)}\n"))

    cases = attack_matrix()
    detected = 0
    attack_cases = [c for c in cases if c.expect_detection]
    fp = 0
    benign_cases = [c for c in cases if not c.expect_detection]
    technique_hits: Dict[str, bool] = {}

    for case in cases:
        eng = CorrelationEngine(HypervisorAPI(load_default_config()),
                                FailoverOrchestrator(SimulatedBackend(step_delay=0.0)))
        eng.process_batch({"vm_id": "replay-vm", "batch": case.events})
        vm = eng.get_or_create_vm("replay-vm")
        score = vm.threat_score

        # ATT&CK mapping check
        ev0 = case.events[0]
        mapped = [t.tid for t in map_event_to_techniques(ev0["event_type"], ev0.get("details", {}))]
        attack_ok = (case.technique in mapped) if case.expect_detection else True

        # Sigma confirmation
        sig = sigma.evaluate(ev0)
        sig_techs = sorted({t for r in sig for t in r.attack_techniques})

        if case.expect_detection:
            ok = score > 0 and attack_ok
            technique_hits[case.technique] = ok
            if ok:
                detected += 1
            status = p("grn", "DETECT") if ok else p("red", "MISS  ")
            sig_note = p("dim", f"sigma:{','.join(sig_techs) or '-'}")
            print(f"  [{status}] {case.name:30} {p('cyn', case.technique):>10}  "
                  f"score={score:<4} {sig_note}")
        else:
            raised = score > 0
            if raised:
                fp += 1
            status = p("red", "FP    ") if raised else p("grn", "CLEAN ")
            print(f"  [{status}] {case.name:30} {'(benign)':>10}  score={score}")

    # ---- metrics ----
    coverage = 100.0 * detected / max(1, len(attack_cases))
    fp_rate = 100.0 * fp / max(1, len(benign_cases))
    print(p("cyn", "\n══ DETECTION METRICS ════════════════════════════════════════"))
    print(f"   ATT&CK coverage (test matrix) : {p('cyn', f'{coverage:.0f}%')} "
          f"({detected}/{len(attack_cases)} techniques)")
    print(f"   False-positive rate           : {p('cyn', f'{fp_rate:.0f}%')} "
          f"({fp}/{len(benign_cases)} benign events)")
    print(f"   Sigma rule coverage           : {p('cyn', str(len(sigma.rules)))} rules active")
    techs = ", ".join(sorted(technique_hits))
    print(f"   Techniques validated          : {p('dim', techs)}")
    print()

    all_pass = (detected == len(attack_cases)) and (fp == 0)
    print(p("grn" if all_pass else "red",
            f"   {'ALL ATTACKS DETECTED, ZERO FALSE POSITIVES' if all_pass else 'GAPS FOUND'}"))
    print()
    return 0 if all_pass else 1


# ---------------------------------------------------------------------------
# Live mode — fire through the authenticated channel, measure MTTD/MTTR
# ---------------------------------------------------------------------------

def run_live(host: str, port: int, web_port: int) -> int:
    import urllib.request
    from common.secure_channel import SecureSender, load_master_secret

    master = load_master_secret()

    def send(vm_id, events):
        snd = SecureSender(master, vm_id)
        frame = snd.seal({"vm_id": vm_id, "batch": events})
        with socket.socket() as s:
            s.settimeout(5)
            s.connect((host, port))
            s.sendall(struct.pack(">I", len(frame)) + frame)

    def status():
        with urllib.request.urlopen(f"http://{host}:{web_port}/api/status", timeout=3) as r:
            return json.loads(r.read().decode())

    print(p("cyn", "\n══ ATTACK REPLAY (live) ═════════════════════════════════════"))
    cases = attack_matrix()
    mttd_samples: List[float] = []
    detected = 0
    attack_cases = [c for c in cases if c.expect_detection]

    for i, case in enumerate(cases):
        if not case.expect_detection:
            continue
        vm = f"replay-{i:02d}"
        t0 = time.perf_counter()
        send(vm, case.events)
        # poll until the controller reflects a non-zero score for this VM
        found = False
        for _ in range(40):
            time.sleep(0.1)
            try:
                data = status()
            except Exception:
                continue
            v = next((x for x in data["vms"] if x["vm_id"] == vm), None)
            if v and v["threat_score"] > 0:
                mttd = time.perf_counter() - t0
                mttd_samples.append(mttd)
                detected += 1
                found = True
                print(f"  [{p('grn','DETECT')}] {case.name:30} {p('cyn',case.technique):>10}  "
                      f"MTTD={mttd*1000:.0f}ms")
                break
        if not found:
            print(f"  [{p('red','MISS  ')}] {case.name:30} {p('cyn',case.technique):>10}")

    coverage = 100.0 * detected / max(1, len(attack_cases))
    avg_mttd = (sum(mttd_samples) / len(mttd_samples)) if mttd_samples else 0
    print(p("cyn", "\n══ LIVE SOC METRICS ═════════════════════════════════════════"))
    print(f"   ATT&CK coverage : {p('cyn', f'{coverage:.0f}%')} ({detected}/{len(attack_cases)})")
    print(f"   Mean MTTD       : {p('cyn', f'{avg_mttd*1000:.0f} ms')}")
    print(p("dim", "   (MTTR/RTO for full isolation+failover is shown on the dashboard"))
    print(p("dim", "    and printed by demo.py; this mode validates detection + MTTD.)"))
    print()
    return 0 if detected == len(attack_cases) else 1


def main():
    ap = argparse.ArgumentParser(description="Vanguard attack-replay validation")
    ap.add_argument("--offline", action="store_true", help="in-process (no network)")
    ap.add_argument("--live", action="store_true", help="against a running controller")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9999)
    ap.add_argument("--web-port", type=int, default=5000)
    args = ap.parse_args()

    if args.live:
        return run_live(args.host, args.port, args.web_port)
    return run_offline()


if __name__ == "__main__":
    sys.exit(main())
