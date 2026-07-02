#!/usr/bin/env python3
"""
Vanguard-OOB :: Sentry Agent  (v2 — secured + crypto-spike aware)
=================================================================
Runs silently inside the Guest Production VM (VLAN 10).
Monitors filesystem entropy, a rolling CRYPTOGRAPHIC SPIKE MAP (ransomware),
process lineage, backup-destruction commands, and network sockets.

Transmits AUTHENTICATED, replay-resistant telemetry to the Host Control Plane
via egress-only TCP. ZERO listening ports. Read-only observability posture.

What changed from v1 (and why):
  - Transport upgraded from static-key XOR to the shared SecureChannel
    (AES-256-GCM or HMAC-AEAD, per-agent keys, replay + identity binding).
  - Added CryptographicSpikeDetector: the "crypto map" the design called for —
    it tracks the RATE and VARIANCE of high-entropy writes and fires a dedicated
    `crypto_spike` event the moment encryption behaviour deviates from baseline.
  - Backup-destruction detection now also covers Linux/macOS, not just Windows.
  - Heartbeat carries an agent self-attestation (monotonic seq) so the
    controller's watchdog can tell "VM quiet because idle" from "agent was
    killed" (malware's first move).

Usage:
    python3 sentry_agent.py --target-dir /home --controller-host 192.168.20.1
"""

import argparse
import math
import os
import platform
import socket
import struct
import sys
import threading
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import psutil

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common.secure_channel import SecureSender, load_master_secret  # noqa: E402

# ---------------------------------------------------------------------------
# Silent diagnostics: the agent must NEVER print to a TTY an attacker can see,
# but swallowing errors with no record makes debugging impossible. Compromise:
# log to a local rotating-ish file only. Failures here are themselves ignored
# (logging must never crash or expose the agent).
# ---------------------------------------------------------------------------
_AGENT_LOG_PATH = os.environ.get("VANGUARD_AGENT_LOG",
                                 os.path.join(os.path.dirname(__file__), "sentry_agent.log"))


def _agent_log(message: str) -> None:
    try:
        from datetime import datetime, timezone
        line = f"{datetime.now(timezone.utc).isoformat()} {message}\n"
        with open(_AGENT_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(line)
    except Exception:
        pass  # logging must never break the agent

# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------
DEFAULT_CONTROLLER_HOST = "192.168.20.1"
DEFAULT_CONTROLLER_PORT = 9999
DEFAULT_TARGET_DIR = "/home"
DEFAULT_ENTROPY_THRESHOLD = 7.2
DEFAULT_POLL_INTERVAL = 2.0
DEFAULT_ENTROPY_WINDOW = 30
DEFAULT_VELOCITY_THRESHOLD = 10

CRYPTO_BASELINE_WINDOW = 300      # seconds of history that forms the baseline
CRYPTO_SPIKE_WINDOW = 15          # recent window compared against baseline
CRYPTO_SPIKE_MIN_FILES = 6        # min recent high-entropy writes to consider
CRYPTO_SPIKE_SIGMA = 3.0          # std-devs above baseline that counts as a spike

SUSPICIOUS_LINEAGE: Dict[str, Set[str]] = {
    "nginx":    {"bash", "sh", "cmd.exe", "powershell.exe", "python", "python3", "perl", "ruby"},
    "apache2":  {"bash", "sh", "cmd.exe", "powershell.exe", "python", "python3"},
    "httpd":    {"bash", "sh", "cmd.exe", "powershell.exe", "python", "python3"},
    "iis":      {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"},
    "tomcat":   {"bash", "sh", "cmd.exe", "powershell.exe"},
    "php-fpm":  {"bash", "sh", "cmd.exe"},
    "node":     {"bash", "sh", "cmd.exe", "powershell.exe"},
    "java":     {"bash", "sh", "cmd.exe", "powershell.exe"},
    "svchost":  {"cmd.exe", "powershell.exe", "wscript.exe"},
}

SUSPICIOUS_PATHS_LINUX = {"/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"}
SUSPICIOUS_PATHS_WIN = {"\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\users\\public\\"}

KNOWN_BROWSER_NAMES = {"chrome", "chromium", "firefox", "brave", "edge", "msedge",
                       "opera", "safari", "vivaldi", "iridium"}

SHADOW_COMMANDS = {
    "vssadmin delete shadows", "wmic shadowcopy delete",
    "bcdedit /set {default} recoveryenabled no", "wbadmin delete catalog",
    "diskshadow /s",
}
UNIX_BACKUP_DESTRUCTION = {
    "rm -rf /var/backups", "rm -rf /backup", "rm -rf /snap",
    "btrfs subvolume delete", "zfs destroy", "tmutil deletelocalsnapshots",
    "rm -rf .snapshots", "shred ",
}


@dataclass
class TelemetryEvent:
    vm_id:       str
    timestamp:   str
    event_type:  str
    severity:    str
    score_delta: int
    details:     dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Authenticated telemetry transmitter
# ---------------------------------------------------------------------------

class TelemetryTunnel:
    def __init__(self, host: str, port: int, sender: SecureSender, vm_id: str):
        self.host = host
        self.port = port
        self.sender = sender
        self.vm_id = vm_id
        self._queue: deque = deque(maxlen=500)
        # Separate retry buffer for events that failed to send. Kept distinct from
        # the live queue so a controller outage can NEVER push newer events off the
        # end of the main queue (the old appendleft() bug). Retries are drained
        # first on the next flush so ordering is preserved.
        self._retry: deque = deque(maxlen=2000)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._sender_loop, daemon=True, name="TelemetryTunnel")

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()

    def enqueue(self, event: TelemetryEvent):
        with self._lock:
            self._queue.append(asdict(event))

    def _sender_loop(self):
        while not self._stop.is_set():
            batch = []
            with self._lock:
                # Drain retries first (oldest unsent), then live events.
                while self._retry:
                    batch.append(self._retry.popleft())
                while self._queue:
                    batch.append(self._queue.popleft())
            if batch:
                self._transmit(batch)
            time.sleep(1.0)

    def _transmit(self, events: list):
        payload = {"vm_id": self.vm_id, "batch": events}
        try:
            frame = self.sender.seal(payload)
            wire = struct.pack(">I", len(frame)) + frame
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5.0)
                s.connect((self.host, self.port))
                s.sendall(wire)
        except Exception as exc:
            # Re-queue into the dedicated retry buffer (append=keep chronological
            # order; it is drained left-first next cycle). The agent stays silent
            # to any attacker on the box — failures go only to a local file.
            with self._lock:
                for e in events:
                    self._retry.append(e)
            _agent_log(f"telemetry send failed ({exc.__class__.__name__}: {exc}); "
                       f"{len(events)} event(s) buffered for retry")


# ---------------------------------------------------------------------------
# Shannon entropy
# ---------------------------------------------------------------------------

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: Dict[int, int] = defaultdict(int)
    for byte in data:
        freq[byte] += 1
    n = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / n
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def file_entropy(path: str, sample_bytes: int = 65536) -> Optional[float]:
    try:
        with open(path, "rb") as f:
            data = f.read(sample_bytes)
        return shannon_entropy(data)
    except (OSError, PermissionError):
        return None


# ---------------------------------------------------------------------------
# Cryptographic Spike Detector  ("the crypto map")
# ---------------------------------------------------------------------------

class CryptographicSpikeDetector:
    """Fires a `crypto_spike` event when the recent high-entropy write rate
    deviates sharply (sigma-based) from this host's own baseline."""

    def __init__(self, tunnel: "TelemetryTunnel"):
        self.tunnel = tunnel
        self._events: deque = deque()
        self._fired_at = 0.0

    def record(self, entropy: float):
        self._events.append((time.time(), entropy))

    def evaluate(self):
        now = time.time()
        while self._events and self._events[0][0] < now - CRYPTO_BASELINE_WINDOW:
            self._events.popleft()
        if len(self._events) < CRYPTO_SPIKE_MIN_FILES:
            return
        recent = [e for e in self._events if e[0] >= now - CRYPTO_SPIKE_WINDOW]
        recent_count = len(recent)
        if recent_count < CRYPTO_SPIKE_MIN_FILES:
            return
        baseline_events = [e for e in self._events if e[0] < now - CRYPTO_SPIKE_WINDOW]
        baseline_span = max(1.0, CRYPTO_BASELINE_WINDOW - CRYPTO_SPIKE_WINDOW)
        n_windows = baseline_span / CRYPTO_SPIKE_WINDOW
        baseline_rate = len(baseline_events) / n_windows
        std = max(1.0, math.sqrt(max(baseline_rate, 1.0)))
        z = (recent_count - baseline_rate) / std
        recent_entropy = sum(e[1] for e in recent) / recent_count
        spike = (z >= CRYPTO_SPIKE_SIGMA) and (recent_entropy >= 7.0)
        if spike and (now - self._fired_at) > CRYPTO_SPIKE_WINDOW:
            self._fired_at = now
            self.tunnel.enqueue(TelemetryEvent(
                vm_id=self.tunnel.vm_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                event_type="crypto_spike", severity="critical", score_delta=50,
                details={
                    "reason": "ransomware_crypto_spike",
                    "recent_high_entropy_writes": recent_count,
                    "window_seconds": CRYPTO_SPIKE_WINDOW,
                    "baseline_rate_per_window": round(baseline_rate, 2),
                    "sigma_above_baseline": round(z, 2),
                    "avg_recent_entropy": round(recent_entropy, 3),
                    "message": (f"Cryptographic spike: {recent_count} high-entropy writes "
                                f"in {CRYPTO_SPIKE_WINDOW}s ({z:.1f}sigma above baseline)"),
                }))


# ---------------------------------------------------------------------------
# Filesystem Monitor
# ---------------------------------------------------------------------------

class FilesystemMonitor:
    def __init__(self, target_dir, entropy_threshold, velocity_window,
                 velocity_threshold, tunnel, crypto_detector):
        self.target_dir = Path(target_dir)
        self.entropy_threshold = entropy_threshold
        self.velocity_window = velocity_window
        self.velocity_threshold = velocity_threshold
        self.tunnel = tunnel
        self.crypto = crypto_detector
        self._seen_mtimes: Dict[str, float] = {}
        self._modification_times: deque = deque()
        self._alerted_files: Set[str] = set()

    def scan(self):
        now = time.time()
        modified: List[Tuple[str, float]] = []
        try:
            for entry in self.target_dir.rglob("*"):
                if not entry.is_file():
                    continue
                try:
                    mtime = entry.stat().st_mtime
                except OSError:
                    continue
                path_str = str(entry)
                prev = self._seen_mtimes.get(path_str)
                self._seen_mtimes[path_str] = mtime
                if prev is not None and mtime != prev:
                    ent = file_entropy(path_str)
                    if ent is not None:
                        modified.append((path_str, ent))
                        self._modification_times.append(now)
                        if ent >= self.entropy_threshold:
                            self.crypto.record(ent)
        except Exception as exc:
            _agent_log(f"fs_monitor.scan error: {exc.__class__.__name__}: {exc}")

        cutoff = now - self.velocity_window
        while self._modification_times and self._modification_times[0] < cutoff:
            self._modification_times.popleft()
        velocity = len(self._modification_times)
        velocity_spike = velocity >= self.velocity_threshold

        for path_str, ent in modified:
            if ent >= self.entropy_threshold and path_str not in self._alerted_files:
                self._alerted_files.add(path_str)
                self.tunnel.enqueue(TelemetryEvent(
                    vm_id=self.tunnel.vm_id,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    event_type="entropy", severity="critical", score_delta=40,
                    details={"path": path_str, "entropy": round(ent, 4),
                             "threshold": self.entropy_threshold,
                             "velocity": velocity, "velocity_spike": velocity_spike}))

        if velocity_spike and modified:
            # distinct 'velocity' type so the controller scores it as +20, not +40
            self.tunnel.enqueue(TelemetryEvent(
                vm_id=self.tunnel.vm_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                event_type="velocity", severity="high", score_delta=20,
                details={"message": f"Modification velocity spike: {velocity} files in {self.velocity_window}s",
                         "velocity": velocity}))

        self.crypto.evaluate()


# ---------------------------------------------------------------------------
# Process Lineage Monitor
# ---------------------------------------------------------------------------

class ProcessLineageMonitor:
    def __init__(self, tunnel):
        self.tunnel = tunnel
        self._alerted_pids: Set[int] = set()
        self._is_windows = platform.system() == "Windows"

    def scan(self):
        suspicious_paths = SUSPICIOUS_PATHS_WIN if self._is_windows else SUSPICIOUS_PATHS_LINUX
        try:
            procs = {p.pid: p for p in psutil.process_iter(
                ["pid", "name", "exe", "ppid", "cmdline", "username"])}
        except Exception:
            return
        pid_to_name = {pid: (p.info.get("name") or "").lower() for pid, p in procs.items()}

        for pid, proc in procs.items():
            if pid in self._alerted_pids:
                continue
            try:
                info = proc.info
                name = (info.get("name") or "").lower()
                exe = (info.get("exe") or "").lower()
                ppid = info.get("ppid") or 0
                cmdline = " ".join(info.get("cmdline") or []).lower()

                for sus in suspicious_paths:
                    if sus in exe:
                        self._alerted_pids.add(pid)
                        self.tunnel.enqueue(TelemetryEvent(
                            vm_id=self.tunnel.vm_id,
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            event_type="process", severity="high", score_delta=40,
                            details={"reason": "suspicious_exec_path", "pid": pid,
                                     "name": name, "exe": exe, "sus_path": sus}))
                        break

                parent_name = pid_to_name.get(ppid, "")
                if name in SUSPICIOUS_LINEAGE.get(parent_name, set()) and pid not in self._alerted_pids:
                    self._alerted_pids.add(pid)
                    self.tunnel.enqueue(TelemetryEvent(
                        vm_id=self.tunnel.vm_id,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        event_type="process", severity="critical", score_delta=30,
                        details={"reason": "web_server_spawned_shell",
                                 "parent_name": parent_name, "parent_pid": ppid,
                                 "child_name": name, "child_pid": pid, "exe": exe}))

                backup_kill = SHADOW_COMMANDS if self._is_windows else UNIX_BACKUP_DESTRUCTION
                for cmd in backup_kill:
                    if cmd in cmdline and pid not in self._alerted_pids:
                        self._alerted_pids.add(pid)
                        self.tunnel.enqueue(TelemetryEvent(
                            vm_id=self.tunnel.vm_id,
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            event_type="shadow", severity="critical", score_delta=40,
                            details={"reason": "backup_destruction_detected",
                                     "command": cmdline[:256], "pid": pid, "name": name}))
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue


# ---------------------------------------------------------------------------
# Socket / Network Monitor
# ---------------------------------------------------------------------------

class SocketMonitor:
    def __init__(self, tunnel):
        self.tunnel = tunnel
        self._alerted_conns: Set[Tuple] = set()

    def scan(self):
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            return
        benign_system = {"svchost", "system", "systemd", "networkmanager", "dhclient",
                         "ntpd", "chronyd", "resolvd", "apt", "dpkg", "yum", "dnf", "pip"}
        for conn in connections:
            if conn.status != "ESTABLISHED" or conn.raddr is None or conn.pid is None:
                continue
            key = (conn.pid, conn.raddr.ip, conn.raddr.port)
            if key in self._alerted_conns:
                continue
            try:
                proc = psutil.Process(conn.pid)
                proc_name = (proc.name() or "").lower()
                exe = (proc.exe() or "").lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            if any(b in proc_name for b in KNOWN_BROWSER_NAMES):
                continue
            if any(b in proc_name for b in benign_system):
                continue
            dest_ip, dest_port = conn.raddr.ip, conn.raddr.port
            is_suspicious = (dest_port not in {80, 443, 53, 123}
                             or any(s in exe for s in ["/tmp/", "/var/tmp/", "/dev/shm/"]))
            if is_suspicious:
                self._alerted_conns.add(key)
                self.tunnel.enqueue(TelemetryEvent(
                    vm_id=self.tunnel.vm_id,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    event_type="network", severity="medium", score_delta=15,
                    details={"reason": "unexpected_outbound_connection",
                             "proc_name": proc_name, "exe": exe, "pid": conn.pid,
                             "dest_ip": dest_ip, "dest_port": dest_port,
                             "laddr_port": conn.laddr.port if conn.laddr else None}))


# ---------------------------------------------------------------------------
# Heartbeat (self-attestation)
# ---------------------------------------------------------------------------

class HeartbeatEmitter:
    def __init__(self, tunnel, interval: float = 15.0):
        self.tunnel = tunnel
        self.interval = interval
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="Heartbeat")
        self._seq = 0

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.is_set():
            self._seq += 1
            self.tunnel.enqueue(TelemetryEvent(
                vm_id=self.tunnel.vm_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                event_type="heartbeat", severity="low", score_delta=0,
                details={"cpu_percent": psutil.cpu_percent(interval=None),
                         "mem_percent": psutil.virtual_memory().percent,
                         "uptime_s": int(time.time() - psutil.boot_time()),
                         "agent_seq": self._seq, "interval_s": self.interval}))
            self._stop.wait(self.interval)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class SentryAgent:
    def __init__(self, config: argparse.Namespace):
        self.config = config
        vm_id = config.vm_id or socket.gethostname()
        master = load_master_secret(fallback_file=config.key_file)
        sender = SecureSender(master, vm_id, prefer_aesgcm=not config.force_hmac)
        self.tunnel = TelemetryTunnel(config.controller_host, config.controller_port, sender, vm_id)
        self.crypto = CryptographicSpikeDetector(self.tunnel)
        self.fs_monitor = FilesystemMonitor(
            config.target_dir, config.entropy_threshold, DEFAULT_ENTROPY_WINDOW,
            DEFAULT_VELOCITY_THRESHOLD, self.tunnel, self.crypto)
        self.proc_monitor = ProcessLineageMonitor(self.tunnel)
        self.sock_monitor = SocketMonitor(self.tunnel)
        self.heartbeat = HeartbeatEmitter(self.tunnel, interval=config.heartbeat_interval)

    def run(self):
        backend = "HMAC-AEAD" if self.config.force_hmac else "AES-256-GCM (fallback HMAC-AEAD)"
        print(f"[*] Vanguard Sentry Agent v2 starting. VM: {self.tunnel.vm_id}")
        print(f"[*] Controller: {self.config.controller_host}:{self.config.controller_port}")
        print(f"[*] Target dir: {self.config.target_dir}")
        print(f"[*] Secure channel: {backend}")
        self.tunnel.start()
        self.heartbeat.start()
        try:
            while True:
                try:
                    self.fs_monitor.scan()
                    self.proc_monitor.scan()
                    self.sock_monitor.scan()
                except Exception as exc:
                    _agent_log(f"monitor loop error: {exc.__class__.__name__}: {exc}")
                time.sleep(self.config.poll_interval)
        except KeyboardInterrupt:
            print("\n[*] Agent shutting down.")
        finally:
            self.tunnel.stop()
            self.heartbeat.stop()


def main():
    parser = argparse.ArgumentParser(description="Vanguard-OOB Sentry Agent v2")
    parser.add_argument("--controller-host", default=DEFAULT_CONTROLLER_HOST)
    parser.add_argument("--controller-port", type=int, default=DEFAULT_CONTROLLER_PORT)
    parser.add_argument("--target-dir", default=DEFAULT_TARGET_DIR)
    parser.add_argument("--entropy-threshold", type=float, default=DEFAULT_ENTROPY_THRESHOLD)
    parser.add_argument("--poll-interval", type=float, default=DEFAULT_POLL_INTERVAL)
    parser.add_argument("--heartbeat-interval", type=float, default=15.0)
    parser.add_argument("--vm-id", default=None)
    parser.add_argument("--key-file", default=None)
    parser.add_argument("--force-hmac", action="store_true")
    args = parser.parse_args()
    SentryAgent(args).run()


if __name__ == "__main__":
    main()
