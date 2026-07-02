#!/usr/bin/env python3
"""
Vanguard-OOB :: Verification Suite
====================================
Proves — with assertions, not claims — that the security, scoring, ransomware
crypto-spike, failover, and watchdog logic actually work. No hypervisor needed.

    python3 verify.py

Exit code 0 = all checks passed.
"""

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "host_control_plane"))

PASS, FAIL = "\033[92mPASS\033[0m", "\033[91mFAIL\033[0m"
_results = []


def check(name, cond, detail=""):
    _results.append(bool(cond))
    tag = PASS if cond else FAIL
    print(f"  [{tag}] {name}" + (f"  — {detail}" if detail else ""))


# ---------------------------------------------------------------------------
print("\n── 1. Secure channel: confidentiality, integrity, replay, identity ──")
from common.secure_channel import (SecureSender, SecureReceiver, AuthError,
                                    load_master_secret, _HAVE_AESGCM)
import os

master = load_master_secret()
print(f"     (crypto backend: {'AES-256-GCM' if _HAVE_AESGCM else 'HMAC-AEAD (stdlib)'})")
snd = SecureSender(master, "vm-a")
rcv = SecureReceiver(master)

frame = snd.seal({"vm_id": "vm-a", "batch": [{"event_type": "heartbeat"}]})
aid, payload = rcv.open(frame)
check("legit frame accepted", aid == "vm-a" and payload["batch"][0]["event_type"] == "heartbeat")

try:
    rcv.open(frame); check("replay rejected", False)
except AuthError:
    check("replay rejected", True)

spoof = SecureSender(master, "vm-a").seal({"vm_id": "vm-evil", "batch": []})
try:
    rcv.open(spoof); check("vm_id spoof rejected", False)
except AuthError as e:
    check("vm_id spoof rejected", True, str(e)[:40])

wrong = SecureSender(os.urandom(32), "vm-a").seal({"vm_id": "vm-a", "batch": []})
try:
    rcv.open(wrong); check("forged (wrong-key) frame rejected", False)
except AuthError:
    check("forged (wrong-key) frame rejected", True)

tam = bytearray(SecureSender(master, "vm-b").seal({"vm_id": "vm-b", "batch": []}))
tam[-1] ^= 0xFF
try:
    rcv.open(bytes(tam)); check("tampered frame rejected", False)
except AuthError:
    check("tampered frame rejected", True)

# stdlib fallback must also be authenticated
import common.secure_channel as sc
saved = sc._HAVE_AESGCM
sc._HAVE_AESGCM = False
s2 = SecureSender(master, "vm-c", prefer_aesgcm=False)
r2 = SecureReceiver(master)
f2 = s2.seal({"vm_id": "vm-c", "batch": [{"x": 1}]})
_, p2 = r2.open(f2)
check("HMAC-AEAD fallback round-trips", p2["batch"][0]["x"] == 1)
sc._HAVE_AESGCM = saved

# ---------------------------------------------------------------------------
print("\n── 2. Scoring: authoritative, agent deltas never trusted ──")
from control_center import _resolve_delta, SCORE_WEIGHTS

check("crypto_spike scores 50", _resolve_delta("crypto_spike", {}) == 50)
check("velocity scores 20 (was wrongly 40 in v1)", _resolve_delta("velocity", {}) == 20)
check("webshell process scores 30 (shell)",
      _resolve_delta("process", {"reason": "web_server_spawned_shell"}) == 30)
check("suspicious-path process scores 40",
      _resolve_delta("process", {"reason": "suspicious_exec_path"}) == 40)
# Malicious agent trying to suppress its own score must be ignored:
check("agent-claimed score_delta is ignored",
      _resolve_delta("entropy", {"score_delta": 0}) == 40)

# ---------------------------------------------------------------------------
print("\n── 3. Ransomware crypto-spike detector ──")
import importlib.util
spec = importlib.util.spec_from_file_location(
    "sentry", ROOT / "guest_production_vm" / "sentry_agent.py")
sentry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sentry)


class _FakeTunnel:
    vm_id = "t"
    def __init__(self): self.fired = []
    def enqueue(self, e): self.fired.append(e)


ft = _FakeTunnel()
det = sentry.CryptographicSpikeDetector(ft)
now = time.time()
for i in range(3):
    det._events.append((now - 200 + i, 7.1))   # sparse baseline
for i in range(12):
    det._events.append((now - 2, 7.9))          # sudden burst
det.evaluate()
check("crypto_spike fires on sudden variance", len(ft.fired) == 1)
if ft.fired:
    check("crypto_spike event_type correct", ft.fired[0].event_type == "crypto_spike")

# No false positive on steady low-rate activity
ft2 = _FakeTunnel()
det2 = sentry.CryptographicSpikeDetector(ft2)
for i in range(8):
    det2._events.append((now - 250 + i * 30, 7.3))  # spread out, no burst
det2.evaluate()
check("no false-positive on steady baseline", len(ft2.fired) == 0)

# ---------------------------------------------------------------------------
print("\n── 4. Failover orchestrator: continuity + self-heal ──")
from failover_orchestrator import FailoverOrchestrator, SimulatedBackend, ServiceState

orch = FailoverOrchestrator(SimulatedBackend(step_delay=0.02))
orch.register_service("web", "10.0.0.100", "vm-1", ["vm-2"])
res = orch.handle_compromise("vm-1")          # active node down
check("failover promotes standby", res["active_node"] == "vm-2")
check("failover measures RTO", res["rto_seconds"] is not None)
check("service DEGRADED during failover", res["state"] == "DEGRADED")
time.sleep(1.6)                               # let self-heal run
final = orch.get_service("web")
check("primary self-heals & rejoins as standby",
      any(n["node_id"] == "vm-1" and n["role"] == "STANDBY" for n in final["nodes"]))
check("service RESTORED after self-heal", final["state"] == "RESTORED")

# Compromising a STANDBY must NOT disrupt the active node
orch.register_service("db", "10.0.0.110", "vm-3", ["vm-4"])
r = orch.handle_compromise("vm-4")
check("standby compromise keeps service alive", r["active_node"] == "vm-3")

# ---------------------------------------------------------------------------
print("\n── 5. Engine integration: instant-block + isolation queueing ──")
from control_center import CorrelationEngine, ISOLATION_THRESHOLD
from hypervisor_api import HypervisorAPI, load_default_config

eng = CorrelationEngine(HypervisorAPI(load_default_config()),
                        FailoverOrchestrator(SimulatedBackend(step_delay=0.0)))
eng.process_batch({"vm_id": "vm-x", "batch": [
    {"event_type": "crypto_spike", "severity": "critical", "details": {"reason": "ransomware_crypto_spike"}}]})
check("crypto_spike queues an instant block", len(eng._block_queue) == 1)
eng.process_batch({"vm_id": "vm-x", "batch": [
    {"event_type": "shadow", "details": {}},
    {"event_type": "entropy", "details": {}},
]})
state = eng.get_or_create_vm("vm-x")
check("score accumulates across events", state.threat_score >= 100,
      f"score={state.threat_score}")
check("isolation queued at threshold", len(eng._isolation_queue) >= 1)

# ---------------------------------------------------------------------------
print("\n── 6. MITRE ATT&CK mapping ──")
from common.mitre_attack import map_event_to_techniques, annotate_event, TECHNIQUES

def tids(et, d=None):
    return [t.tid for t in map_event_to_techniques(et, d or {})]

check("ransomware → T1486", "T1486" in tids("crypto_spike"))
check("backup destruction → T1490", "T1490" in tids("shadow"))
check("webshell → T1505.003", "T1505.003" in tids("process", {"reason": "web_server_spawned_shell"}))
check("suspicious path → T1036.005", "T1036.005" in tids("process", {"reason": "suspicious_exec_path"}))
check("agent kill → T1562.001", "T1562.001" in tids("agent_silence"))
check("annotation carries tactics", len(annotate_event("crypto_spike")["tactics"]) >= 1)

# ---------------------------------------------------------------------------
print("\n── 7. Sigma-compatible detection engine ──")
import importlib.util as _ilu
_sp = _ilu.spec_from_file_location("sigma_engine",
        ROOT / "blue_team" / "sigma_engine" / "sigma_engine.py")
sigma_mod = _ilu.module_from_spec(_sp)
sys.modules["sigma_engine"] = sigma_mod          # needed for @dataclass resolution
_sp.loader.exec_module(sigma_mod)
eng_s = sigma_mod.SigmaEngine()
n_rules = eng_s.load_dir(ROOT / "blue_team" / "sigma_engine" / "rules")
check("Sigma rules load", n_rules >= 6, f"{n_rules} rules")
fired = eng_s.evaluate({"event_type": "crypto_spike", "details": {"reason": "x"}})
check("Sigma fires on ransomware", len(fired) >= 1)
check("Sigma rule exposes ATT&CK id", any("T1486" in r.attack_techniques for r in fired))
fired_c2 = eng_s.evaluate({"event_type": "network", "details": {"dest_port": 4444}})
check("Sigma compound condition works (C2 port)", len(fired_c2) >= 1)
check("Sigma ignores benign heartbeat",
      len(eng_s.evaluate({"event_type": "heartbeat", "details": {}})) == 0)

# ---------------------------------------------------------------------------
print("\n── 8. SOC alert workflow + enrichment ──")
from alert_manager import AlertManager, AlertStatus
am = AlertManager(dedupe_window_s=0)
al = am.raise_alert("vm-1", "crypto_spike", "critical", 50,
                    {"attack": [{"id": "T1486", "name": "Data Encrypted for Impact"}]},
                    event_ts_iso=__import__("datetime").datetime.now(
                        __import__("datetime").timezone.utc).isoformat())
check("alert raised for high-signal event", al is not None and al.alert_id.startswith("ALRT"))
check("low-signal event raises no alert",
      am.raise_alert("vm-1", "heartbeat", "low", 0, {}) is None)
check("acknowledge works", am.acknowledge(al.alert_id)["ok"])
check("escalate works", am.escalate(al.alert_id)["ok"])
check("false-positive disposition works", am.mark_false_positive(al.alert_id)["ok"])
mm = am.metrics()
check("metrics compute FP rate", mm["false_positive_rate"] == 100.0, f"{mm['false_positive_rate']}%")
check("trend volume series present", len(mm["volume_series"]) == 12)

from geo_intel import enrich_ip
e = enrich_ip("185.220.1.9")
check("malicious IP flagged by intel", e["intel"]["verdict"] == "malicious")
check("internal IP recognised", enrich_ip("10.0.0.5")["intel"]["verdict"] == "internal")
check("unknown IP marked approx", enrich_ip("221.244.55.89")["geo"]["approx"] is True)

# ---------------------------------------------------------------------------
total = len(_results)
passed = sum(_results)
print("\n" + "═" * 52)
if passed == total:
    print(f"  \033[92mALL {total} CHECKS PASSED\033[0m")
    print("═" * 52 + "\n")
    sys.exit(0)
else:
    print(f"  \033[91m{passed}/{total} passed — {total - passed} FAILED\033[0m")
    print("═" * 52 + "\n")
    sys.exit(1)
