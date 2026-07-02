#!/usr/bin/env python3
"""
Vanguard-OOB :: Control Center  (v2)
======================================
Host Control Plane (VLAN 20). Always-active, aggressive auto-response.

Threads:
  T1  Telemetry server   — receives AUTHENTICATED agent frames (SecureReceiver),
                            rejects replays / spoofed identities, feeds the engine.
  T2  Flask SOC Dashboard — real-time command view + control API (port 5000).
  T3  Watchdog           — "always active aggression": flags agents that go
                            silent (malware's first move is to kill the agent)
                            and escalates score for unexplained silence.
  Main IR worker         — drains the isolation queue and runs the response
                            sequence ASYNCHRONOUSLY so the engine never blocks.

Response on threat (auto or manual):
  1. BLOCK   instant NIC kill-switch (stops C2/exfil in ms)
  2. ISOLATE move to quarantine VLAN
  3. DUMP    capture RAM for forensics
  4. FAILOVER promote a warm standby so the WORKLOAD KEEPS RUNNING
  5. RESTORE rollback the infected VM to a clean golden snapshot
  6. REJOIN  cured VM comes back as the new standby (self-healing)

Key fixes vs v1:
  - Authenticated transport (no more forgeable XOR / vm_id spoofing).
  - Correct scoring: crypto_spike=50, velocity=20 (was silently 40), shell vs
    process split honoured; agent score_delta is NEVER trusted as a fallback.
  - IR runs in a worker thread, so the dashboard shows IR-log progress live
    instead of freezing for ~9s.
  - Per-VM lock discipline avoids holding the global lock during slow hypervisor
    calls.
"""

import argparse
import hmac
import json
import logging
import os
import secrets
import socketserver
import struct
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from flask import Flask, jsonify, render_template_string

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from hypervisor_api import HypervisorAPI, load_default_config  # noqa: E402
from failover_orchestrator import FailoverOrchestrator, SimulatedBackend  # noqa: E402
from common.secure_channel import SecureReceiver, AuthError, load_master_secret  # noqa: E402
from common.mitre_attack import annotate_event, map_event_to_techniques, matrix_state  # noqa: E402
from alert_manager import AlertManager  # noqa: E402
from geo_intel import geolocate, enrich_ip  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("vanguard.control")

# ---------------------------------------------------------------------------
# Scoring — single source of truth (agent-supplied deltas are NEVER trusted)
# ---------------------------------------------------------------------------
SCORE_WEIGHTS = {
    "crypto_spike": 50,   # ransomware mass-encryption signature (highest signal)
    "entropy":      40,   # single high-entropy file write
    "shadow":       40,   # backup / shadow-copy destruction
    "process":      40,   # execution from suspicious path
    "shell":        30,   # web server spawning a shell (RCE / webshell)
    "agent_silence": 25,  # agent went dark — possible defense evasion (T1562.001)
    "velocity":     20,   # file-modification velocity spike
    "network":      15,   # unexpected outbound connection (C2 / beacon)
    "heartbeat":     0,
    # --- current-threat event types ---
    "cred_dump":    50,   # LSASS credential dumping (T1003.001) — pre-ransomware staple
    "driver_load":  45,   # BYOVD: vulnerable signed driver loaded (T1068)
    "cloud_exfil":  45,   # bulk exfil to cloud storage (T1567.002)
    "ransomware_esxi": 50, # hypervisor/ESXi datastore encryption (T1486)
    "kerberoast":   35,   # SPN ticket harvesting (T1558.003)
    "rmm_tool":     30,   # unsanctioned remote-access tool (T1219)
    "powershell":   30,   # encoded/obfuscated PowerShell (T1059.001 / T1027)
    "lolbin":       30,   # signed-binary proxy execution (T1218)
    "staging":      25,   # data archived for exfil (T1560)
    "persistence":  25,   # scheduled task / WMI / new account (T1053/T1546.003/T1136)
    "mfa_fatigue":  25,   # MFA push-bombing (T1621)
    "cloud_auth":   20,   # anomalous cloud logon / impossible travel (T1078.004)
}
ISOLATION_THRESHOLD = 100
# Unambiguous, high-confidence signals that justify an immediate NIC hard-block
# before the full score even accrues (cut C2/exfil in milliseconds).
INSTANT_BLOCK_TYPES = {"crypto_spike", "cred_dump", "ransomware_esxi"}
ROLLING_WINDOW_SECS = 60
MAX_EVENTS_PER_VM = 500
# Watchdog: an agent that misses this many expected heartbeats is "silent".
SILENCE_GRACE_MULTIPLIER = 3.0   # missed beats = (now - last_seen) / interval


def _resolve_delta(event_type: str, details: dict) -> int:
    """Authoritative score for an event. Ignores any agent-claimed delta."""
    if event_type == "process":
        if details.get("reason") == "web_server_spawned_shell":
            return SCORE_WEIGHTS["shell"]
        return SCORE_WEIGHTS["process"]
    # Credential-access events share one event_type; reason tunes the weight.
    if event_type == "cred_dump" and details.get("reason") == "kerberoast":
        return SCORE_WEIGHTS["kerberoast"]
    return SCORE_WEIGHTS.get(event_type, 0)


# ---------------------------------------------------------------------------
# Per-VM state
# ---------------------------------------------------------------------------

@dataclass
class ScoredEvent:
    timestamp:   float
    event_type:  str
    severity:    str
    score_delta: int
    details:     dict
    raw_event:   dict


@dataclass
class VMState:
    vm_id:           str
    threat_score:    int = 0
    status:          str = "SECURE"          # SECURE|WARNING|CRITICAL|ISOLATED
    isolated:        bool = False
    silent:          bool = False            # watchdog: agent went quiet
    last_seen:       float = 0.0
    last_hb_interval: float = 15.0
    last_agent_seq:  int = 0
    events:          deque = field(default_factory=lambda: deque(maxlen=MAX_EVENTS_PER_VM))
    scored_events:   deque = field(default_factory=lambda: deque(maxlen=MAX_EVENTS_PER_VM))
    ir_log:          List[dict] = field(default_factory=list)
    heartbeat_count: int = 0

    def purge_expired(self, now: float):
        cutoff = now - ROLLING_WINDOW_SECS
        while self.scored_events and self.scored_events[0].timestamp < cutoff:
            self.scored_events.popleft()

    def recalculate_score(self) -> int:
        now = time.time()
        self.purge_expired(now)
        total = sum(e.score_delta for e in self.scored_events)
        self.threat_score = min(total, 200)   # allow >100 so severity is meaningful
        if self.isolated:
            self.status = "ISOLATED"
        elif self.threat_score >= ISOLATION_THRESHOLD:
            self.status = "CRITICAL"
        elif self.threat_score >= 50:
            self.status = "WARNING"
        else:
            self.status = "SECURE"
        return self.threat_score

    def to_dict(self) -> dict:
        return {
            "vm_id": self.vm_id,
            "threat_score": self.threat_score,
            "status": self.status,
            "isolated": self.isolated,
            "silent": self.silent,
            "last_seen": self.last_seen,
            "heartbeat_count": self.heartbeat_count,
            "event_count": len(self.events),
            "recent_events": [
                {"timestamp": e.raw_event.get("timestamp"), "event_type": e.event_type,
                 "severity": e.severity, "score_delta": e.score_delta, "details": e.details}
                for e in list(self.events)[-20:]
            ],
            "ir_log": self.ir_log[-12:],
        }


# ---------------------------------------------------------------------------
# Correlation Engine
# ---------------------------------------------------------------------------

class CorrelationEngine:
    def __init__(self, hypervisor: HypervisorAPI, failover: FailoverOrchestrator,
                 containment=None):
        self.hypervisor = hypervisor
        self.failover = failover
        # Optional host-network containment backend (dry-run by default). This is
        # the OS-level NIC block that runs *alongside* the hypervisor isolation —
        # it cuts C2/exfil even before the hypervisor path completes. If None, we
        # lazily build a dry-run backend so the control plane is always safe.
        if containment is None:
            try:
                from containment import build_backend
                containment = build_backend(dry_run=True)
            except Exception:
                containment = None
        self.containment = containment
        self._lock = threading.Lock()
        self._vms: Dict[str, VMState] = {}
        self._isolation_queue: deque = deque()
        self._block_queue: deque = deque()       # instant hard-blocks (crypto spike)
        self._failover_count = 0
        self._seen_techniques: set = set()        # MITRE ATT&CK technique IDs observed
        self.alerts = AlertManager()              # SOC triage workflow
        self._geo_events: deque = deque(maxlen=200)  # enriched destination IPs for the map

    def get_or_create_vm(self, vm_id: str) -> VMState:
        with self._lock:
            if vm_id not in self._vms:
                self._vms[vm_id] = VMState(vm_id=vm_id)
            return self._vms[vm_id]

    def process_batch(self, payload: dict):
        vm_id = payload.get("vm_id", "unknown")
        events = payload.get("batch", [])
        vm = self.get_or_create_vm(vm_id)
        with self._lock:
            vm.last_seen = time.time()
            vm.silent = False
            for raw in events:
                et = raw.get("event_type", "unknown")
                sev = raw.get("severity", "low")
                details = raw.get("details", {})
                if et == "heartbeat":
                    vm.heartbeat_count += 1
                    vm.last_hb_interval = float(details.get("interval_s", vm.last_hb_interval))
                    vm.last_agent_seq = int(details.get("agent_seq", vm.last_agent_seq))
                    continue
                delta = _resolve_delta(et, details)   # authoritative, not agent-supplied
                # Tag the event with its MITRE ATT&CK technique(s).
                techs = map_event_to_techniques(et, details)
                if techs:
                    details = dict(details)
                    details["attack"] = [{"id": t.tid, "name": t.name} for t in techs]
                    for t in techs:
                        self._seen_techniques.add(t.tid)
                se = ScoredEvent(time.time(), et, sev, delta, details, raw)
                vm.scored_events.append(se)
                vm.events.append(se)
                # Raise a triage alert for meaningful events.
                self.alerts.raise_alert(vm_id, et, sev, delta, details,
                                        event_ts_iso=raw.get("timestamp"))
                # Enrich destination IPs for the live attack map + intel panel.
                if et == "network":
                    dip = details.get("dest_ip")
                    if dip:
                        enriched = enrich_ip(dip)
                        enriched.update({"vm_id": vm_id, "dest_port": details.get("dest_port"),
                                         "ts": time.time()})
                        self._geo_events.append(enriched)
                if et in INSTANT_BLOCK_TYPES and not vm.isolated:
                    self._block_queue.append(vm_id)
            score = vm.recalculate_score()
            if score >= ISOLATION_THRESHOLD and not vm.isolated:
                logger.critical("[ALERT] VM %s reached threat score %d - queuing isolation", vm_id, score)
                self._isolation_queue.append(vm_id)

    # ---- queue draining (called from worker thread) ----------------------

    def drain_queues(self):
        while self._block_queue:
            vm_id = self._block_queue.popleft()
            self._instant_block(vm_id)
        while self._isolation_queue:
            vm_id = self._isolation_queue.popleft()
            self._trigger_isolation(vm_id, reason="auto")

    def _instant_block(self, vm_id: str):
        """Immediate NIC kill-switch on a ransomware crypto-spike, ahead of full IR."""
        vm = self.get_or_create_vm(vm_id)
        with self._lock:
            if vm.isolated:
                return
        logger.critical("[CRYPTO-SPIKE] Hard-blocking network for %s before full IR", vm_id)
        r = self.hypervisor.block_network(vm_id)
        with self._lock:
            vm.ir_log.append({"timestamp": r.timestamp, "operation": "block_network",
                              "success": r.success, "message": r.message})
        # Host-level containment (iptables/nftables/netsh/pf) in parallel with the
        # hypervisor block. Dry-run by default; records the exact rules it would apply.
        if self.containment is not None:
            try:
                actions = self.containment.isolate_host()
                applied = "applied" if not self.containment.dry_run else "dry-run"
                with self._lock:
                    vm.ir_log.append({
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "operation": f"host_containment ({self.containment.name}, {applied})",
                        "success": True,
                        "message": f"{len(actions)} firewall rule(s) staged to cut C2/exfil"})
            except Exception as exc:
                logger.error("host containment failed: %s", exc)

    def _trigger_isolation(self, vm_id: str, reason: str = "auto"):
        vm = self.get_or_create_vm(vm_id)
        with self._lock:
            if vm.isolated:
                return
            vm.isolated = True
            vm.status = "ISOLATED"
        logger.critical("[ISOLATION] Full IR + continuity failover for %s (reason=%s)", vm_id, reason)

        # 1-3 + 5-6: hypervisor incident response (isolate, dump, restore, boot).
        results = self.hypervisor.full_incident_response(vm_id)
        with self._lock:
            for r in results:
                vm.ir_log.append({"timestamp": r.timestamp, "operation": r.operation,
                                  "success": r.success, "message": r.message})

        # 4: business-continuity failover so the workload keeps running.
        fo = self.failover.handle_compromise(vm_id)
        with self._lock:
            if fo is not None:
                self._failover_count += 1
                vm.ir_log.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "operation": "failover",
                    "success": fo["state"] in ("DEGRADED", "RESTORED", "HEALTHY"),
                    "message": (f"Service '{fo['service']}' -> {fo['state']} "
                                f"(active={fo['active_node']}, RTO={fo.get('rto_seconds')}s)"),
                })

    def manual_isolate(self, vm_id: str) -> dict:
        threading.Thread(target=self._trigger_isolation, args=(vm_id, "manual"),
                         daemon=True).start()
        return {"status": "ok", "message": f"Isolation + failover triggered for {vm_id}"}

    def abort_and_restore(self, vm_id: str) -> dict:
        vm = self.get_or_create_vm(vm_id)
        with self._lock:
            vm.scored_events.clear()
            vm.events.clear()
            vm.threat_score = 0
            vm.isolated = False
            vm.silent = False
            vm.status = "SECURE"
            vm.ir_log.append({"timestamp": datetime.now(timezone.utc).isoformat(),
                              "operation": "abort_and_restore", "success": True,
                              "message": "Threat score reset by operator"})
        svc = self.failover.service_for_vm(vm_id)
        if svc:
            self.failover.reset_service(svc)
        logger.info("[MANUAL] Abort & restore executed for VM: %s", vm_id)
        return {"status": "ok", "message": f"Threat score cleared for {vm_id}"}

    # ---- watchdog --------------------------------------------------------

    def watchdog_sweep(self):
        """Flag agents that went silent past their grace window. Aggressive posture:
        unexplained silence on a non-isolated VM raises a synthetic alert."""
        now = time.time()
        with self._lock:
            for vm in self._vms.values():
                if vm.last_seen == 0 or vm.isolated:
                    continue
                gap = now - vm.last_seen
                grace = vm.last_hb_interval * SILENCE_GRACE_MULTIPLIER
                if gap > grace and not vm.silent:
                    vm.silent = True
                    logger.warning("[WATCHDOG] Agent on %s silent for %.0fs (>%.0fs grace) "
                                   "- possible agent kill", vm.vm_id, gap, grace)
                    se = ScoredEvent(now, "agent_silence", "high",
                                     SCORE_WEIGHTS["agent_silence"],
                                     {"reason": "agent_silence",
                                      "silent_seconds": round(gap, 1),
                                      "message": f"Agent silent {gap:.0f}s — possible tamper"},
                                     {"timestamp": datetime.now(timezone.utc).isoformat(),
                                      "event_type": "agent_silence"})
                    vm.scored_events.append(se)   # contributes to threat score
                    vm.events.append(se)
                    self._seen_techniques.add("T1562.001")  # Impair Defenses
                    if vm.recalculate_score() >= ISOLATION_THRESHOLD and not vm.isolated:
                        self._isolation_queue.append(vm.vm_id)

    def get_all_vm_states(self) -> List[dict]:
        with self._lock:
            for vm in self._vms.values():
                vm.recalculate_score()
            return [vm.to_dict() for vm in self._vms.values()]

    def stats(self) -> dict:
        with self._lock:
            return {"failover_count": self._failover_count}

    def get_geo_events(self) -> List[dict]:
        with self._lock:
            return list(self._geo_events)[-60:]


# ---------------------------------------------------------------------------
# Telemetry server (authenticated)
# ---------------------------------------------------------------------------

def recv_framed(conn) -> Optional[bytes]:
    try:
        header = _recv_exact(conn, 4)
        if not header:
            return None
        length = struct.unpack(">I", header)[0]
        if length > 10 * 1024 * 1024:
            logger.warning("Frame too large (%d bytes), dropping", length)
            return None
        return _recv_exact(conn, length)
    except Exception as exc:
        logger.debug("recv_framed dropped a frame: %s: %s", exc.__class__.__name__, exc)
        return None


def _recv_exact(conn, n: int) -> Optional[bytes]:
    buf = b""
    while len(buf) < n:
        try:
            chunk = conn.recv(n - len(buf))
        except Exception:
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


class TelemetryHandler(socketserver.BaseRequestHandler):
    def handle(self):
        conn = self.request
        peer = self.client_address
        engine: CorrelationEngine = self.server.engine
        receiver: SecureReceiver = self.server.receiver
        raw = recv_framed(conn)
        if raw is None:
            return
        try:
            agent_id, payload = receiver.open(raw)   # auth + replay + identity binding
        except AuthError as e:
            logger.warning("[SECURITY] Rejected frame from %s: %s", peer[0], e)
            return
        except Exception as e:
            logger.warning("Failed to parse frame from %s: %s", peer[0], e)
            return
        engine.process_batch(payload)
        logger.debug("Accepted %d events from authenticated agent '%s' (%s)",
                     len(payload.get("batch", [])), agent_id, peer[0])


class TelemetryServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, host, port, engine, receiver):
        self.engine = engine
        self.receiver = receiver
        super().__init__((host, port), TelemetryHandler)


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

_DASHBOARD_HTML = (Path(__file__).parent / "dashboard.html").read_text(encoding="utf-8")


def _const_eq(a: str, b: str) -> bool:
    """Constant-time string comparison to avoid token timing leaks."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _is_dev_master_key(master: bytes) -> bool:
    """True if the loaded master secret is the public development fallback."""
    import hashlib
    dev = hashlib.sha256(b"vanguard-oob-development-master-key-CHANGE-ME").digest()
    return hmac.compare_digest(master, dev)


def create_flask_app(engine: CorrelationEngine, api_token: str,
                     allowed_ips: Optional[set] = None) -> Flask:
    from flask import request, abort

    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.urandom(32)

    # Endpoints that change state require the API token. Read-only status and the
    # dashboard HTML stay open so the UI loads, but every mutation is gated.
    _PROTECTED_PREFIXES = ("/api/isolate", "/api/restore")

    def _is_protected(path: str, method: str) -> bool:
        if method not in ("POST", "PUT", "DELETE", "PATCH"):
            return False
        if path.startswith(_PROTECTED_PREFIXES):
            return True
        if path.startswith("/api/alerts/"):
            return True
        return False

    @app.before_request
    def _guard():
        # 1) Optional IP allowlist (applies to everything).
        if allowed_ips is not None and request.remote_addr not in allowed_ips:
            logger.warning("[SECURITY] Blocked request from %s (not in allowlist)",
                           request.remote_addr)
            abort(403)
        # 2) Token required for state-changing endpoints.
        if _is_protected(request.path, request.method):
            supplied = (request.headers.get("X-Vanguard-Token")
                        or request.headers.get("Authorization", "").replace("Bearer ", "").strip())
            if not supplied or not _const_eq(supplied, api_token):
                logger.warning("[SECURITY] Rejected unauthenticated %s %s from %s",
                               request.method, request.path, request.remote_addr)
                abort(401)

    # Make the token available to the dashboard JS (same-origin) so its action
    # buttons can call the protected endpoints. This is the page the operator
    # already loaded; the token is only exposed to whoever can load the dashboard.
    @app.route("/")
    def dashboard():
        html = _DASHBOARD_HTML.replace("__VANGUARD_API_TOKEN__", api_token)
        return render_template_string(html)

    @app.route("/api/status")
    def api_status():
        return jsonify({
            "vms": engine.get_all_vm_states(),
            "failover": engine.failover.get_all(),
            "attack_matrix": matrix_state(engine._seen_techniques),
            "alerts": engine.alerts.get_alerts(50),
            "alert_metrics": engine.alerts.metrics(),
            "geo_events": engine.get_geo_events(),
            "stats": engine.stats(),
            "server_time": datetime.now(timezone.utc).isoformat(),
        })

    @app.route("/api/alerts/<alert_id>/<action>", methods=["POST"])
    def api_alert_action(alert_id, action):
        body = request.get_json(silent=True) or {}
        by = body.get("by", "analyst")
        if action == "ack":
            return jsonify(engine.alerts.acknowledge(alert_id, by))
        if action == "assign":
            return jsonify(engine.alerts.assign(alert_id, body.get("assignee", "tier1"), by))
        if action == "escalate":
            return jsonify(engine.alerts.escalate(alert_id, by))
        if action == "close":
            return jsonify(engine.alerts.close(alert_id, by, body.get("note", "")))
        if action == "false_positive":
            return jsonify(engine.alerts.mark_false_positive(alert_id, by, body.get("note", "")))
        if action == "note":
            return jsonify(engine.alerts.add_note(alert_id, body.get("text", ""), by))
        return jsonify({"ok": False, "message": f"unknown action '{action}'"}), 400

    @app.route("/api/isolate/<vm_id>", methods=["POST"])
    def api_isolate(vm_id):
        return jsonify(engine.manual_isolate(vm_id))

    @app.route("/api/restore/<vm_id>", methods=["POST"])
    def api_restore(vm_id):
        return jsonify(engine.abort_and_restore(vm_id))

    @app.route("/healthz")
    def healthz():
        return jsonify({"status": "ok", "service": "vanguard-oob-control-center"})

    return app


# ---------------------------------------------------------------------------
# Demo topology (registers HA service pairs so failover has something to do)
# ---------------------------------------------------------------------------

def register_demo_topology(failover: FailoverOrchestrator):
    """Register sensible defaults so the failover panel is populated out-of-box.
    In production, drive this from hypervisor_config.json instead."""
    failover.register_service("web-app", "10.0.0.100", "test-vm-01", ["test-vm-02"])
    failover.register_service("db", "10.0.0.110", "prod-vm-01", ["prod-vm-02"])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="Vanguard-OOB Control Center v2")
    p.add_argument("--listen-host", default="0.0.0.0")
    p.add_argument("--listen-port", type=int, default=9999)
    p.add_argument("--web-host", default="0.0.0.0")
    p.add_argument("--web-port", type=int, default=5000)
    p.add_argument("--hypervisor-config", default=None)
    p.add_argument("--key-file", default=None, help="Master key file (else env VANGUARD_MASTER_KEY or dev key)")
    p.add_argument("--max-skew", type=float, default=120.0, help="Max telemetry timestamp skew (s)")
    p.add_argument("--api-token", default=None,
                   help="Bearer token required for state-changing API calls "
                        "(default: env VANGUARD_API_TOKEN, else an auto-generated token printed at startup)")
    p.add_argument("--allow-ips", default=None,
                   help="Comma-separated IP allowlist for the dashboard/API (default: allow any)")
    p.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = p.parse_args()

    logging.getLogger().setLevel(getattr(logging, args.log_level))

    hyp = HypervisorAPI(load_default_config(args.hypervisor_config))
    failover = FailoverOrchestrator(SimulatedBackend())
    register_demo_topology(failover)
    engine = CorrelationEngine(hyp, failover)
    master = load_master_secret(fallback_file=args.key_file)
    receiver = SecureReceiver(master, max_skew=args.max_skew)

    # --- Security: loud warning if the public development key is in use ---
    if _is_dev_master_key(master):
        logger.warning("=" * 70)
        logger.warning("[SECURITY] Using the PUBLIC development master key.")
        logger.warning("[SECURITY] Telemetry can be FORGED by anyone who has read the source.")
        logger.warning("[SECURITY] Set VANGUARD_MASTER_KEY (hex) before any real deployment.")
        logger.warning("=" * 70)

    # --- Security: API token for state-changing endpoints ---
    api_token = args.api_token or os.environ.get("VANGUARD_API_TOKEN")
    if not api_token:
        api_token = secrets.token_urlsafe(24)
        logger.warning("[SECURITY] No --api-token / VANGUARD_API_TOKEN set; generated one for this session:")
        logger.warning("[SECURITY]   API token: %s", api_token)
        logger.warning("[SECURITY]   (the dashboard injects it automatically; external callers must send it)")

    allowed_ips = None
    if args.allow_ips:
        allowed_ips = {ip.strip() for ip in args.allow_ips.split(",") if ip.strip()}
        logger.info("[SECURITY] Dashboard/API restricted to IPs: %s", sorted(allowed_ips))

    app = create_flask_app(engine, api_token=api_token, allowed_ips=allowed_ips)

    tcp = TelemetryServer(args.listen_host, args.listen_port, engine, receiver)
    threading.Thread(target=tcp.serve_forever, name="TelemetryServer", daemon=True).start()
    logger.info("Telemetry listener (authenticated) on %s:%d", args.listen_host, args.listen_port)

    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    threading.Thread(target=lambda: app.run(host=args.web_host, port=args.web_port,
                                            debug=False, use_reloader=False, threaded=True),
                     name="FlaskSOC", daemon=True).start()
    logger.info("SOC Dashboard on http://%s:%d", args.web_host, args.web_port)
    logger.info("Vanguard-OOB Control Center v2 running. Threshold=%d / %ds window.",
                ISOLATION_THRESHOLD, ROLLING_WINDOW_SECS)

    last_watchdog = 0.0
    try:
        while True:
            engine.drain_queues()
            now = time.time()
            if now - last_watchdog > 5.0:
                engine.watchdog_sweep()
                last_watchdog = now
            time.sleep(0.3)
    except KeyboardInterrupt:
        logger.info("Shutting down Control Center.")
        tcp.shutdown()


if __name__ == "__main__":
    main()
