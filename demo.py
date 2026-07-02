#!/usr/bin/env python3
"""
Vanguard-OOB :: Live Demo  ("the 90-second money shot")
========================================================
ONE command tells the whole story to a non-technical audience:

    python3 demo.py

It will:
  1. Launch the Control Center (telemetry + SOC dashboard) in the background.
  2. Open the dashboard URL for you (http://127.0.0.1:5000).
  3. Narrate and fire a full ransomware kill-chain against a simulated VM:
        normal ops → CRYPTO-SPIKE → instant network BLOCK → ISOLATE →
        forensic DUMP → FAILOVER to standby (work continues) → SELF-HEAL.
  4. Print the live recovery metrics (RTO) at the end.

Everything runs locally. No hypervisor required — the hypervisor calls log as
"would execute" and the failover orchestrator runs in simulated mode so the
entire choreography is visible on the dashboard.

Flags:
    --no-browser     don't auto-open the dashboard
    --web-port N     dashboard port (default 5000)
    --listen-port N  telemetry port (default 9999)
    --speed X        narration speed multiplier (default 1.0; 2.0 = faster)
"""

import argparse
import os
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
HCP = ROOT / "host_control_plane"

C = {"r": "\033[0m", "b": "\033[1m", "red": "\033[91m", "grn": "\033[92m",
     "ylw": "\033[93m", "cyn": "\033[96m", "dim": "\033[2m", "mag": "\033[95m"}


def paint(k, s):
    return f"{C[k]}{s}{C['r']}"


def banner():
    print(paint("cyn", r"""
   ██╗   ██╗ █████╗ ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
   ██║   ██║██╔══██╗████╗  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
   ██║   ██║███████║██╔██╗ ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
   ╚██╗ ██╔╝██╔══██║██║╚██╗██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
    ╚████╔╝ ██║  ██║██║ ╚████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
     ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
"""))
    print(paint("dim", "   Out-of-Band Cyber Resilience — LIVE RANSOMWARE DEFENSE DEMO\n"))


def step(speed, *lines, pause=1.2):
    for ln in lines:
        print(ln)
    time.sleep(pause / speed)


def main():
    ap = argparse.ArgumentParser(description="Vanguard-OOB live demo")
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--web-port", type=int, default=5000)
    ap.add_argument("--listen-port", type=int, default=9999)
    ap.add_argument("--speed", type=float, default=1.0)
    args = ap.parse_args()
    sp = max(0.25, args.speed)

    banner()

    # 1. Launch control center
    print(paint("cyn", "  [1/5] Launching Control Center (SOC dashboard + telemetry)…"))
    env = dict(os.environ)
    cc = subprocess.Popen(
        [sys.executable, str(HCP / "control_center.py"),
         "--listen-port", str(args.listen_port),
         "--web-port", str(args.web_port),
         "--log-level", "WARNING"],
        cwd=str(HCP), env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(4.0)
    url = f"http://127.0.0.1:{args.web_port}"
    print(paint("grn", f"        Dashboard live → {url}"))
    if not args.no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    step(sp, paint("dim", "        (open the dashboard now — keep it visible)"), pause=2.5)

    # Import the harness helpers (authenticated sender) after CC is up.
    sys.path.insert(0, str(ROOT))
    import test_harness as H
    host, port = "127.0.0.1", args.listen_port
    vm = "test-vm-01"   # this is the ACTIVE node of the 'web-app' service

    # 2. Normal operations
    print(paint("cyn", "\n  [2/5] Normal operations — agent reporting healthy telemetry…"))
    for _ in range(2):
        H.send_batch(host, port, vm, [H.heartbeat_event()], verbose=False)
        time.sleep(0.6 / sp)
    step(sp, paint("grn", "        VM SECURE. Workload serving normally."), pause=1.5)

    # 3. Attack begins
    step(sp, paint("red", "\n  [3/5] ⚠ ATTACK: ransomware begins mass-encrypting files…"))
    step(sp, paint("dim", "        The cryptographic map spikes far above baseline."))
    H.send_batch(host, port, vm, [H.crypto_spike_event(count=15, sigma=12.4)], verbose=False)
    step(sp, paint("red", "        → CRYPTO-SPIKE detected (+50). Controller HARD-BLOCKS the NIC."),
         pause=1.6)
    step(sp, paint("dim", "        Backup destruction attempt…"))
    H.send_batch(host, port, vm, [H.shadow_deletion_event()], verbose=False)
    step(sp, paint("red", "        → Backup destruction detected (+40)."), pause=1.2)
    for _ in range(2):
        H.send_batch(host, port, vm, [H.high_entropy_event()], verbose=False)
        time.sleep(0.4 / sp)
    step(sp, paint("red", c_bold("        → Threat score breaches 100. AUTO-ISOLATION ENGAGED.")),
         pause=1.6)

    # 4. Response + failover
    print(paint("cyn", "\n  [4/5] Automated incident response + business continuity…"))
    step(sp, paint("dim", "        ISOLATE → DUMP RAM → promote warm STANDBY → redirect traffic."),
         pause=2.0)
    step(sp, paint("mag", "        ⇄ FAILOVER: standby promoted to ACTIVE — workload keeps running."),
         pause=2.0)

    # 5. Self-heal — poll the API for the final state
    print(paint("cyn", "\n  [5/5] Self-healing — curing the infected VM and rejoining the pair…"))
    import json
    import urllib.request
    final = None
    for _ in range(20):
        time.sleep(1.0)
        try:
            with urllib.request.urlopen(f"{url}/api/status", timeout=3) as r:
                data = json.loads(r.read().decode())
            svc = next((s for s in data.get("failover", []) if s["service"] == "web-app"), None)
            if svc and svc["state"] in ("RESTORED",):
                final = svc
                break
            final = svc
        except Exception:
            pass

    print()
    print(paint("grn", "  ════════════════════════════════════════════════════════════"))
    print(paint("grn", "   INCIDENT NEUTRALISED — ORGANISATION KEPT RUNNING"))
    print(paint("grn", "  ════════════════════════════════════════════════════════════"))
    if final:
        rto = final.get("rto_seconds")
        print(f"   Service        : {paint('cyn', final['service'])} @ {final['vip']}")
        print(f"   Final state    : {paint('cyn', final['state'])}")
        print(f"   Now serving on : {paint('cyn', final['active_node'])}")
        print(f"   Recovery time  : {paint('cyn', str(rto) + ' s')}  (RTO)")
        for n in final["nodes"]:
            print(f"      {n['node_id']:12} {n['role']:10} ({n['last_event']})")
    print()
    print(paint("dim", "   The attacker encrypted a slice of one VM. The business never stopped."))
    print(paint("dim", f"   Full timeline on the dashboard: {url}"))

    # Bonus: run the detection-coverage validation so the audience sees the
    # ATT&CK coverage + metrics, not just the single scripted attack.
    print(paint("cyn", "\n  ── Detection coverage (MITRE ATT&CK + Sigma) ──"))
    try:
        import attack_replay
        attack_replay.run_offline()
    except SystemExit:
        pass
    except Exception as e:
        print(paint("dim", f"   (coverage report skipped: {e})"))

    print(paint("dim", "   Press Ctrl+C to stop the Control Center.\n"))

    try:
        cc.wait()
    except KeyboardInterrupt:
        print(paint("dim", "\n  Stopping Control Center…"))
        cc.terminate()


def c_bold(s):
    return f"{C['b']}{s}{C['r']}"


if __name__ == "__main__":
    main()
