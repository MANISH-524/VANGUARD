#!/usr/bin/env python3
"""
Vanguard-OOB :: Integration Test Harness
==========================================
Simulates adversarial activity (ransomware, process abuse, network anomalies)
by injecting synthetic telemetry events directly into the Control Center's
TCP listener — exactly as a real Sentry Agent would.

Run this on the same machine as the Control Center (or any host that can
reach CONTROLLER_HOST:CONTROLLER_PORT) to exercise the full pipeline:

  sentry_agent (simulated) → TCP → control_center → correlation engine
                                 → SOC dashboard  → hypervisor (mocked)

Usage:
    python3 test_harness.py [--host 127.0.0.1] [--port 9999] [--scenario all]

Scenarios:
    entropy   - High-entropy file modifications (ransomware-like)
    process   - Webserver spawning shell (RCE)
    shadow    - Shadow copy deletion (ransomware pre-encryption)
    network   - Unexpected outbound C2 connection
    combined  - Full kill-chain: entropy + shadow + process in rapid succession
    all       - Run all scenarios sequentially with delays
"""

import argparse
import json
import math
import random
import socket
import struct
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict

# Use the SAME authenticated secure channel the real agent uses, so the harness
# is a faithful adversary simulator (and proves the controller's auth works).
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common.secure_channel import SecureSender, load_master_secret  # noqa: E402

ANSI = {
    "reset":  "\033[0m",
    "bold":   "\033[1m",
    "red":    "\033[91m",
    "green":  "\033[92m",
    "yellow": "\033[93m",
    "cyan":   "\033[96m",
    "dim":    "\033[2m",
    "magenta":"\033[95m",
}

def c(color: str, text: str) -> str:
    return f"{ANSI.get(color,'')}{text}{ANSI['reset']}"

def banner():
    print(c("cyan", r"""
  ██╗   ██╗ █████╗ ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
  ██║   ██║██╔══██╗████╗  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ██║   ██║███████║██╔██╗ ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
  ╚██╗ ██╔╝██╔══██║██║╚██╗██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
   ╚████╔╝ ██║  ██║██║ ╚████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
    ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
"""))
    print(c("dim", "  Vanguard-OOB Integration Test Harness — Adversary Simulation Engine\n"))


# ---------------------------------------------------------------------------
# Crypto (identical to agent)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Authenticated transmission (per-VM SecureSender, like the real agent)
# ---------------------------------------------------------------------------

_SENDERS: Dict[str, SecureSender] = {}
_MASTER = load_master_secret()


def _sender_for(vm_id: str) -> SecureSender:
    if vm_id not in _SENDERS:
        _SENDERS[vm_id] = SecureSender(_MASTER, vm_id)
    return _SENDERS[vm_id]


def send_batch(host: str, port: int, vm_id: str, events: List[dict], verbose: bool = True):
    """Seal (AEAD) and transmit a batch of events to the control center."""
    payload = {"vm_id": vm_id, "batch": events}
    try:
        frame = _sender_for(vm_id).seal(payload)
        wire = struct.pack(">I", len(frame)) + frame
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5.0)
            s.connect((host, port))
            s.sendall(wire)
        if verbose:
            print(c("green", f"  ✓ Sent {len(events)} event(s) for VM '{vm_id}'"))
    except Exception as exc:
        print(c("red", f"  ✗ Transmission failed: {exc}"))


def make_event(event_type: str, severity: str, score_delta: int, details: dict) -> dict:
    return {
        "vm_id":       "",   # filled by send_batch
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "event_type":  event_type,
        "severity":    severity,
        "score_delta": score_delta,
        "details":     details,
    }


# ---------------------------------------------------------------------------
# Individual event constructors
# ---------------------------------------------------------------------------

def heartbeat_event() -> dict:
    return make_event("heartbeat", "low", 0, {
        "cpu_percent": round(random.uniform(5, 95), 1),
        "mem_percent": round(random.uniform(20, 80), 1),
        "uptime_s":    random.randint(3600, 86400),
        "agent_seq":   random.randint(1, 9999),
        "interval_s":  15.0,
    })


def high_entropy_event(path: str = None, entropy: float = None) -> dict:
    path    = path    or f"/home/user/Documents/{random.choice(['report','budget','contracts','photos','backup'])}_{''.join(random.choices('abcdef0123456789',k=6))}.enc"
    entropy = entropy or round(random.uniform(7.3, 7.98), 4)
    return make_event("entropy", "critical", 40, {
        "path":           path,
        "entropy":        entropy,
        "threshold":      7.2,
        "velocity":       random.randint(8, 25),
        "velocity_spike": True,
    })


def velocity_spike_event(velocity: int = 15) -> dict:
    return make_event("entropy", "high", 20, {
        "message":  f"Modification velocity spike: {velocity} files in 30s",
        "velocity": velocity,
    })


def shadow_deletion_event() -> dict:
    cmd = random.choice([
        "vssadmin delete shadows /all /quiet",
        "wmic shadowcopy delete",
        "bcdedit /set {default} recoveryenabled no",
        "wbadmin delete catalog -quiet",
    ])
    return make_event("shadow", "critical", 40, {
        "reason":  "shadow_deletion_detected",
        "command": cmd,
        "pid":     random.randint(1000, 9999),
        "name":    "cmd.exe",
    })


def web_shell_spawn_event() -> dict:
    parent = random.choice(["nginx", "apache2", "tomcat", "iis"])
    child  = random.choice(["bash", "sh", "cmd.exe", "powershell.exe"])
    return make_event("process", "critical", 30, {
        "reason":      "web_server_spawned_shell",
        "parent_name": parent,
        "parent_pid":  random.randint(800, 2000),
        "child_name":  child,
        "child_pid":   random.randint(3000, 9999),
        "exe":         f"/usr/sbin/{parent}",
    })


def suspicious_path_event() -> dict:
    name = random.choice(["python3", "bash", "nc", "wget", "curl", "perl"])
    path = random.choice(["/tmp/", "/dev/shm/", "/var/tmp/"]) + "".join(random.choices("abcdef0123456789", k=8))
    return make_event("process", "high", 40, {
        "reason":   "suspicious_exec_path",
        "pid":      random.randint(3000, 9999),
        "name":     name,
        "exe":      path,
        "sus_path": path,
    })


def c2_network_event() -> dict:
    return make_event("network", "medium", 15, {
        "reason":     "unexpected_outbound_connection",
        "proc_name":  random.choice(["python3", "nc", "socat", "bash"]),
        "exe":        f"/tmp/{''.join(random.choices('abcdef0123456789',k=6))}",
        "pid":        random.randint(3000, 9999),
        "dest_ip":    f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
        "dest_port":  random.choice([4444, 8080, 1337, 6666, 9001, 31337]),
        "laddr_port": random.randint(49152, 65535),
    })


def crypto_spike_event(count: int = 14, sigma: float = 11.0) -> dict:
    return make_event("crypto_spike", "critical", 50, {
        "reason": "ransomware_crypto_spike",
        "recent_high_entropy_writes": count,
        "window_seconds": 15,
        "baseline_rate_per_window": 0.5,
        "sigma_above_baseline": sigma,
        "avg_recent_entropy": round(random.uniform(7.7, 7.97), 3),
        "message": f"Cryptographic spike: {count} high-entropy writes in 15s ({sigma:.1f}sigma above baseline)",
    })


# ---------------------------------------------------------------------------
# Scenario: Entropy-only (slow ransomware)
# ---------------------------------------------------------------------------

def scenario_entropy(host: str, port: int, vm_id: str):
    print(c("yellow", "\n[SCENARIO] High-Entropy File Modification (Ransomware Encryption)"))
    print(c("dim",    "  Simulating mass file encryption — 3 high-entropy writes + velocity spike"))

    files = [
        "/home/alice/Documents/tax_2024.pdf",
        "/home/alice/Pictures/vacation_2023.jpg",
        "/home/alice/Desktop/passwords.kdbx",
    ]
    for fpath in files:
        events = [heartbeat_event(), high_entropy_event(fpath)]
        send_batch(host, port, vm_id, events)
        print(c("dim", f"    → Encrypted: {fpath}"))
        time.sleep(0.3)

    # Velocity spike
    send_batch(host, port, vm_id, [velocity_spike_event(velocity=22)])


# ---------------------------------------------------------------------------
# Scenario: Process abuse (webshell / RCE)
# ---------------------------------------------------------------------------

def scenario_process(host: str, port: int, vm_id: str):
    print(c("yellow", "\n[SCENARIO] Process Lineage Abuse (Webshell / RCE)"))
    print(c("dim",    "  Simulating web server spawning interactive shell + suspicious temp execution"))

    send_batch(host, port, vm_id, [web_shell_spawn_event()])
    time.sleep(0.4)
    send_batch(host, port, vm_id, [suspicious_path_event()])


# ---------------------------------------------------------------------------
# Scenario: Shadow copy deletion
# ---------------------------------------------------------------------------

def scenario_shadow(host: str, port: int, vm_id: str):
    print(c("yellow", "\n[SCENARIO] Shadow Copy Deletion (Backup Destruction)"))
    print(c("dim",    "  Simulating ransomware wiping VSS backups before encryption"))

    send_batch(host, port, vm_id, [shadow_deletion_event()])
    time.sleep(0.2)
    send_batch(host, port, vm_id, [shadow_deletion_event()])


# ---------------------------------------------------------------------------
# Scenario: C2 network beacon
# ---------------------------------------------------------------------------

def scenario_network(host: str, port: int, vm_id: str):
    print(c("yellow", "\n[SCENARIO] C2 Network Beacon (Outbound Anomaly)"))
    print(c("dim",    "  Simulating reverse shell / C2 callback from non-browser process"))

    for _ in range(3):
        send_batch(host, port, vm_id, [c2_network_event()])
        time.sleep(0.2)


# ---------------------------------------------------------------------------
# Scenario: Combined kill-chain (triggers isolation at score >= 100)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Scenario: Ransomware crypto-spike (instant block → isolation → failover)
# ---------------------------------------------------------------------------

def scenario_ransomware(host: str, port: int, vm_id: str):
    print(c("red", "\n[SCENARIO] RANSOMWARE CRYPTO-SPIKE → INSTANT BLOCK → FAILOVER"))
    print(c("dim", "  The crypto map spikes; controller hard-blocks the NIC, isolates,"))
    print(c("dim", "  and promotes a warm standby so the workload keeps running.\n"))
    send_batch(host, port, vm_id, [heartbeat_event()])
    time.sleep(0.4)
    print(c("dim", "  Crypto map spiking — mass encryption detected (+50, instant block)"))
    send_batch(host, port, vm_id, [crypto_spike_event(count=14, sigma=11.2)])
    time.sleep(0.4)
    print(c("dim", "  Backup destruction (+40)"))
    send_batch(host, port, vm_id, [shadow_deletion_event()])
    time.sleep(0.3)
    print(c("dim", "  High-entropy encryption continues (+40) → threshold breached"))
    for _ in range(2):
        send_batch(host, port, vm_id, [high_entropy_event()])
        time.sleep(0.2)
    print(c("red", c("bold", "\n  ► Watch the SOC dashboard: BLOCK → ISOLATE → FAILOVER → SELF-HEAL.")))


def scenario_combined(host: str, port: int, vm_id: str):
    print(c("red", "\n[SCENARIO] FULL RANSOMWARE KILL-CHAIN (score → 100 → AUTO ISOLATION)"))
    print(c("dim", "  Phase 1: Reconnaissance beacon"))
    send_batch(host, port, vm_id, [heartbeat_event(), c2_network_event()])
    time.sleep(0.5)

    print(c("dim", "  Phase 2: Shadow copy destruction (+40)"))
    send_batch(host, port, vm_id, [shadow_deletion_event()])
    time.sleep(0.5)

    print(c("dim", "  Phase 3: Webshell spawned (+30)"))
    send_batch(host, port, vm_id, [web_shell_spawn_event()])
    time.sleep(0.5)

    print(c("dim", "  Phase 4: High-entropy file encryption (+40) → total ≥ 100"))
    for i in range(3):
        send_batch(host, port, vm_id, [high_entropy_event()])
        time.sleep(0.2)

    print(c("red", c("bold", "\n  ► Threshold should be breached. Watch SOC Dashboard for ISOLATION trigger.")))


# ---------------------------------------------------------------------------
# Scenario: Heartbeat-only (baseline / keep-alive test)
# ---------------------------------------------------------------------------

def scenario_heartbeat(host: str, port: int, vm_id: str, count: int = 5):
    print(c("cyan", f"\n[SCENARIO] Heartbeat ({count} pulses)"))
    for i in range(count):
        send_batch(host, port, vm_id, [heartbeat_event()], verbose=(i == 0))
        if i > 0:
            print(c("dim", f"    Pulse {i+1}/{count}"), end="\r")
        time.sleep(1.0)
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

SCENARIOS = {
    "entropy":    scenario_entropy,
    "process":    scenario_process,
    "shadow":     scenario_shadow,
    "network":    scenario_network,
    "ransomware": scenario_ransomware,
    "combined":   scenario_combined,
    "heartbeat":  lambda h, p, v: scenario_heartbeat(h, p, v),
}

def main():
    banner()
    parser = argparse.ArgumentParser(
        description="Vanguard-OOB Integration Test Harness"
    )
    parser.add_argument("--host",     default="127.0.0.1",
                        help="Control Center host (default: 127.0.0.1)")
    parser.add_argument("--port",     type=int, default=9999,
                        help="Control Center telemetry port (default: 9999)")
    parser.add_argument("--vm-id",    default="test-vm-01",
                        help="Logical VM ID to impersonate (default: test-vm-01)")
    parser.add_argument("--scenario", default="all",
                        choices=list(SCENARIOS.keys()) + ["all"],
                        help="Scenario to run (default: all)")
    parser.add_argument("--delay",    type=float, default=2.0,
                        help="Seconds between scenarios when running 'all' (default: 2)")
    args = parser.parse_args()

    print(f"  Target  : {c('cyan', f'{args.host}:{args.port}')}")
    print(f"  VM ID   : {c('cyan', args.vm_id)}")
    print(f"  Scenario: {c('cyan', args.scenario)}")
    print(f"  Dashboard: {c('cyan', f'http://{args.host}:5000')}\n")

    # Connectivity check
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3.0)
            s.connect((args.host, args.port))
        print(c("green", "  ✓ Control Center reachable\n"))
    except Exception as e:
        print(c("red", f"  ✗ Cannot connect to {args.host}:{args.port} — {e}"))
        print(c("dim", "    Start control_center.py first, then re-run this test."))
        sys.exit(1)

    if args.scenario == "all":
        order = ["heartbeat", "entropy", "process", "shadow", "network", "ransomware", "combined"]
        for sc_name in order:
            fn = SCENARIOS[sc_name]
            fn(args.host, args.port, args.vm_id)
            print(c("dim", f"\n  Waiting {args.delay}s before next scenario…"))
            time.sleep(args.delay)
    else:
        SCENARIOS[args.scenario](args.host, args.port, args.vm_id)

    print(c("green", "\n  ✓ Test harness complete. Check the SOC Dashboard for results."))
    print(c("dim",   f"    http://{args.host}:5000\n"))


if __name__ == "__main__":
    main()
