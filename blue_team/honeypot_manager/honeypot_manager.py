#!/usr/bin/env python3
"""
Vanguard-OOB :: Blue Team Tool 19 — Honeypot Manager
=====================================================
Original architecture. Lightweight, zero-dependency service honeypots
that mimic real services just enough to attract and log attacker activity.

Philosophy: every connection to a honeypot is 100% malicious.
No legitimate user or system process should ever connect to these ports.
This gives near-zero false-positive alerting.

Honeypot types:
  SSH-FAKE     — Presents an SSH banner, captures auth attempts
                 (username/password combinations from brute-forcers)
  HTTP-FAKE    — Returns a believable Nginx/Apache response, logs all
                 requests including headers, bodies, user-agents, paths
  FTP-FAKE     — Issues a 220 banner, captures login attempts
  TELNET-FAKE  — Issues a VT100 login prompt, captures credentials
  MYSQL-FAKE   — Issues MySQL handshake, captures connection attempts
  RAW-TCP      — Listens on any port, captures raw bytes (catch-all for
                 scanners, worms, novel exploits)

Each honeypot runs in its own thread. All captured interactions are:
  - Written to a structured JSON interaction log
  - Emitted as Vanguard findings (severity=CRITICAL — no exceptions)
  - Enriched with: source IP, port, timestamp, raw payload, inferred intent

Attack classification engine: infers attacker intent from captured data:
  - BRUTE_FORCE   (repeated auth with different creds)
  - SCANNER       (rapid connection, no data, quick disconnect)
  - EXPLOIT_PROBE (payload matches known vulnerability patterns)
  - C2_CALLBACK   (unusual payload structure suggesting C2 beacon)
  - WORM          (automated payload suggesting self-propagating malware)

Usage:
    python3 honeypot_manager.py --start --ports ssh:2222,http:8888,mysql:3307
    python3 honeypot_manager.py --start --all-types --log interactions.jsonl
    python3 honeypot_manager.py --status
"""

import argparse
import json
import logging
import re
import socket
import threading
import time
import uuid
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("vanguard.honeypot")

# ── Interaction model ─────────────────────────────────────────────────────

@dataclass
class Interaction:
    interaction_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    honeypot_type:  str = ""
    listen_port:    int = 0
    src_ip:         str = ""
    src_port:       int = 0
    timestamp:      str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    duration_ms:    float = 0.0
    bytes_received: int   = 0
    bytes_sent:     int   = 0
    payload_hex:    str   = ""
    payload_text:   str   = ""
    captured_user:  str   = ""
    captured_pass:  str   = ""
    intent:         str   = "UNKNOWN"   # BRUTE_FORCE / SCANNER / EXPLOIT_PROBE / WORM / C2_CALLBACK
    finding_type:   str   = "honeypot_interaction"
    severity:       str   = "critical"
    mitre:          str   = "T1046"
    score:          int   = 60
    evidence:       dict  = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


# ── Intent classifier ─────────────────────────────────────────────────────

EXPLOIT_PATTERNS = [
    re.compile(rb"(?:\/bin\/sh|\/bin\/bash|cmd\.exe|powershell)", re.I),
    re.compile(rb"(?:eval\(|base64_decode|gzinflate)", re.I),
    re.compile(rb"(?:union\s+select|information_schema)", re.I),
    re.compile(rb"(?:\x90{4,}|\xcc{4,})", re.I),        # NOP sleds / breakpoints
    re.compile(rb"(?:jndi:|ldap://|rmi://)", re.I),       # Log4Shell pattern
    re.compile(rb"(?:\.\.\/|\.\.\\|%2e%2e)", re.I),       # Path traversal
    re.compile(rb"(?:wget|curl)\s+http", re.I),
]

WORM_PATTERNS = [
    re.compile(rb"(?:mirai|gafgyt|tsunami|botnet)", re.I),
    re.compile(rb"(?:tftp|busybox)", re.I),
    re.compile(rb"(?:/proc/mounts|/etc/shadow|/var/tmp/)", re.I),
]

def classify_intent(payload: bytes, duration_ms: float,
                     bytes_rx: int, captured_user: str,
                     captured_pass: str) -> Tuple[str, str, int]:
    """Returns (intent, mitre_technique, score)."""
    if bytes_rx < 10 and duration_ms < 500:
        return "SCANNER", "T1046", 30

    if captured_user or captured_pass:
        return "BRUTE_FORCE", "T1110", 50

    for pat in WORM_PATTERNS:
        if pat.search(payload):
            return "WORM", "T1584", 70

    for pat in EXPLOIT_PATTERNS:
        if pat.search(payload):
            return "EXPLOIT_PROBE", "T1203", 65

    if len(payload) > 200 and len(set(payload)) > 100:
        return "C2_CALLBACK", "T1071", 55

    return "UNKNOWN", "T1046", 40


# ── Base honeypot ─────────────────────────────────────────────────────────

class BaseHoneypot:
    def __init__(self, port: int, hp_type: str, callback: Callable,
                 max_recv: int = 4096):
        self.port     = port
        self.hp_type  = hp_type
        self.callback = callback
        self.max_recv = max_recv
        self._stop    = threading.Event()
        self._thread  = threading.Thread(target=self._listen_loop,
                                          name=f"HP-{hp_type}-{port}", daemon=True)
        self._conn_count = 0
        self._ip_counter: Counter = Counter()

    def start(self):
        self._thread.start()
        logger.info("Honeypot started: %s on port %d", self.hp_type, self.port)

    def stop(self):
        self._stop.set()

    def stats(self) -> dict:
        return {"type": self.hp_type, "port": self.port,
                "connections": self._conn_count,
                "top_ips": self._ip_counter.most_common(5)}

    def _listen_loop(self):
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.settimeout(1.0)
            srv.bind(("0.0.0.0", self.port))
            srv.listen(10)
        except OSError as e:
            logger.error("Honeypot %s port %d failed: %s", self.hp_type, self.port, e)
            return

        while not self._stop.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except Exception:
                break
            self._conn_count += 1
            self._ip_counter[addr[0]] += 1
            t = threading.Thread(target=self._handle, args=(conn, addr), daemon=True)
            t.start()
        srv.close()

    def _handle(self, conn: socket.socket, addr: Tuple[str, int]):
        src_ip, src_port = addr
        t0 = time.perf_counter()
        payload = b""
        sent    = 0

        try:
            conn.settimeout(5.0)
            banner, payload, user, pwd = self._interact(conn, src_ip)
            sent = len(banner)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

        duration_ms = (time.perf_counter() - t0) * 1000
        intent, mitre, score = classify_intent(payload, duration_ms,
                                                len(payload), user, pwd)

        iact = Interaction(
            honeypot_type  = self.hp_type,
            listen_port    = self.port,
            src_ip         = src_ip,
            src_port       = src_port,
            duration_ms    = round(duration_ms, 2),
            bytes_received = len(payload),
            bytes_sent     = sent,
            payload_hex    = payload[:64].hex(),
            payload_text   = payload[:256].decode("utf-8", errors="replace").replace("\n"," "),
            captured_user  = user,
            captured_pass  = pwd[:3] + "***" if pwd else "",
            intent         = intent,
            mitre          = mitre,
            score          = score,
            evidence       = {"src": f"{src_ip}:{src_port}", "duration_ms": round(duration_ms,1)},
        )
        self.callback(iact)

    def _interact(self, conn: socket.socket, src_ip: str) -> Tuple[bytes, bytes, str, str]:
        """Override per honeypot type. Returns (banner_sent, payload_rx, user, password)."""
        data = conn.recv(self.max_recv)
        return b"", data, "", ""


# ── SSH Honeypot ──────────────────────────────────────────────────────────

class SSHHoneypot(BaseHoneypot):
    BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"

    def _interact(self, conn, src_ip):
        conn.sendall(self.BANNER)
        data = b""
        user = pwd = ""
        try:
            # SSH auth is binary, but we capture the raw bytes for analysis
            data = conn.recv(self.max_recv)
            # Try to extract username from SSH_MSG_USERAUTH_REQUEST if plaintext readable
            text = data.decode("utf-8", errors="replace")
            m = re.search(r"([a-z_][a-z0-9_\-]{0,30})\x00+([^\x00]{4,64})", text)
            if m:
                user = m.group(1)
                pwd  = m.group(2)[:64]
        except Exception:
            pass
        return self.BANNER, data, user, pwd


# ── HTTP Honeypot ─────────────────────────────────────────────────────────

class HTTPHoneypot(BaseHoneypot):
    def _interact(self, conn, src_ip):
        data = b""
        try:
            data = conn.recv(self.max_recv)
        except Exception:
            pass

        # Parse basic request info
        lines  = data.decode("utf-8", errors="replace").splitlines()
        method = path = ua = ""
        if lines:
            parts = lines[0].split(" ")
            if len(parts) >= 2:
                method, path = parts[0], parts[1]
        for l in lines[1:]:
            if l.lower().startswith("user-agent:"):
                ua = l.split(":", 1)[1].strip()[:200]

        # Craft convincing fake response
        body = (
            "<!DOCTYPE html><html><head><title>401 Authorization Required</title></head>"
            "<body><h1>Authorization Required</h1>"
            "<p>This server could not verify that you are authorized to access the "
            "document requested.</p><hr><address>Apache/2.4.57 (Ubuntu)</address>"
            "</body></html>"
        )
        resp = (
            "HTTP/1.1 401 Unauthorized\r\n"
            "Server: Apache/2.4.57 (Ubuntu)\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            "WWW-Authenticate: Basic realm=\"Restricted\"\r\n"
            "Connection: close\r\n\r\n" + body
        )
        banner = resp.encode()
        try:
            conn.sendall(banner)
        except Exception:
            pass
        return banner, data, "", ""


# ── FTP Honeypot ──────────────────────────────────────────────────────────

class FTPHoneypot(BaseHoneypot):
    BANNER = b"220 ProFTPD 1.3.8 Server (ProFTPD) [127.0.0.1]\r\n"

    def _interact(self, conn, src_ip):
        conn.sendall(self.BANNER)
        user = pwd = ""
        raw  = b""
        try:
            for _ in range(4):
                chunk = conn.recv(512)
                if not chunk:
                    break
                raw += chunk
                line = chunk.decode("utf-8", errors="replace").strip().upper()
                if line.startswith("USER "):
                    user = line[5:].strip()
                    conn.sendall(b"331 Password required for " + user.encode() + b"\r\n")
                elif line.startswith("PASS "):
                    pwd  = chunk.decode("utf-8", errors="replace")[5:].strip()
                    conn.sendall(b"530 Login incorrect.\r\n")
                    break
        except Exception:
            pass
        return self.BANNER, raw, user, pwd


# ── MySQL Honeypot ────────────────────────────────────────────────────────

class MySQLHoneypot(BaseHoneypot):
    # MySQL 8.0 greeting packet (simplified — enough to fool scanners/tools)
    @staticmethod
    def _mysql_greeting() -> bytes:
        server_version = b"8.0.36\x00"
        greeting = (
            b"\x0a"             # protocol version
            + server_version
            + b"\x01\x00\x00\x00"   # connection id
            + b"\x52\x42\x33\x4a\x59\x4c\x37\x53\x00"  # auth-plugin-data-1
            + b"\xff\xf7"       # capability flags low
            + b"\x21"           # character set: utf8mb4
            + b"\x02\x00"       # status flags
            + b"\xff\x81"       # capability flags high
            + b"\x15"           # auth-plugin-data-len
            + b"\x00" * 10      # reserved
            + b"\x7a\x69\x55\x6e\x6e\x6d\x4e\x51\x6d\x73\x62\x00"  # auth-plugin-data-2
            + b"mysql_native_password\x00"
        )
        length  = len(greeting)
        packet  = length.to_bytes(3, "little") + b"\x00" + greeting
        return packet

    def _interact(self, conn, src_ip):
        greeting = self._mysql_greeting()
        try:
            conn.sendall(greeting)
            data = conn.recv(self.max_recv)
            # Send error response
            err_msg = b"Access denied for user"
            err_pkt = (
                (len(err_msg) + 9).to_bytes(3,"little") + b"\x02"
                + b"\xff"           # error packet
                + b"\x28\x04"       # error code 1040
                + b"#28000"
                + err_msg
            )
            conn.sendall(err_pkt)
        except Exception:
            data = b""
        return greeting, data, "", ""


# ── Raw TCP Honeypot ──────────────────────────────────────────────────────

class RawTCPHoneypot(BaseHoneypot):
    def _interact(self, conn, src_ip):
        data = b""
        try:
            data = conn.recv(self.max_recv)
        except Exception:
            pass
        return b"", data, "", ""


# ── Telnet Honeypot ───────────────────────────────────────────────────────

class TelnetHoneypot(BaseHoneypot):
    PROMPT_SEQ = (
        b"\xff\xfb\x01"   # WILL ECHO
        b"\xff\xfb\x03"   # WILL SUPPRESS-GO-AHEAD
        b"\xff\xfd\x03"   # DO SUPPRESS-GO-AHEAD
        b"\r\nUbuntu 22.04.3 LTS\r\nlocalhost login: "
    )

    def _interact(self, conn, src_ip):
        try:
            conn.sendall(self.PROMPT_SEQ)
        except Exception:
            return self.PROMPT_SEQ, b"", "", ""

        user = pwd = ""
        raw  = b""
        try:
            chunk = conn.recv(256)
            raw  += chunk
            user  = chunk.replace(b"\xff\xfd\x00", b"").decode("utf-8", errors="replace").strip()
            user  = re.sub(r"[^\x20-\x7e]", "", user)[:32]
            if user:
                conn.sendall(b"\r\nPassword: ")
                chunk2 = conn.recv(256)
                raw   += chunk2
                pwd    = chunk2.decode("utf-8", errors="replace").strip()
                pwd    = re.sub(r"[^\x20-\x7e]", "", pwd)[:64]
                conn.sendall(b"\r\nLogin incorrect\r\n")
        except Exception:
            pass
        return self.PROMPT_SEQ, raw, user, pwd


# ── Honeypot factory ──────────────────────────────────────────────────────

HONEYPOT_CLASSES = {
    "ssh":     SSHHoneypot,
    "http":    HTTPHoneypot,
    "ftp":     FTPHoneypot,
    "mysql":   MySQLHoneypot,
    "telnet":  TelnetHoneypot,
    "raw":     RawTCPHoneypot,
}

DEFAULT_PORTS = {
    "ssh":    2222,
    "http":   8888,
    "ftp":    2121,
    "mysql":  3307,
    "telnet": 2323,
}


# ── Honeypot Manager ──────────────────────────────────────────────────────

class HoneypotManager:
    def __init__(self, log_path: Optional[str] = None):
        self.log_path      = log_path
        self._honeypots:   List[BaseHoneypot] = []
        self._interactions: List[Interaction] = []
        self._lock         = threading.Lock()
        self._ip_repeat: Counter = Counter()

    def _on_interaction(self, iact: Interaction):
        with self._lock:
            self._interactions.append(iact)
            self._ip_repeat[iact.src_ip] += 1

            # Escalate repeat attackers
            if self._ip_repeat[iact.src_ip] >= 5:
                iact.intent = "BRUTE_FORCE"
                iact.score  = min(80, iact.score + 20)

        # Log to file
        if self.log_path:
            try:
                with open(self.log_path, "a") as f:
                    f.write(json.dumps(iact.to_dict()) + "\n")
            except OSError:
                pass

        sev_c = "\033[95m"  # always critical
        R     = "\033[0m"
        print(f"  {sev_c}[HONEYPOT ⚠]{R}  {iact.src_ip}:{iact.src_port} → "
              f"{iact.honeypot_type}:{iact.listen_port}  "
              f"intent={iact.intent}  creds={iact.captured_user or '—'}/"
              f"{iact.captured_pass or '—'}  "
              f"payload={iact.bytes_received}B  score={iact.score}")

    def add(self, hp_type: str, port: int):
        cls = HONEYPOT_CLASSES.get(hp_type.lower())
        if not cls:
            logger.warning("Unknown honeypot type: %s", hp_type)
            return
        hp = cls(port=port, hp_type=hp_type, callback=self._on_interaction)
        self._honeypots.append(hp)

    def start_all(self):
        for hp in self._honeypots:
            hp.start()

    def stop_all(self):
        for hp in self._honeypots:
            hp.stop()

    def stats(self) -> dict:
        with self._lock:
            intent_counts = Counter(i.intent for i in self._interactions)
            top_ips = Counter(i.src_ip for i in self._interactions).most_common(10)
        return {
            "total_interactions": len(self._interactions),
            "by_intent":          dict(intent_counts),
            "top_attacker_ips":   top_ips,
            "honeypots":          [hp.stats() for hp in self._honeypots],
        }

    def export_findings(self) -> List[dict]:
        """Export interactions as Vanguard-OOB unified finding format."""
        with self._lock:
            return [
                {
                    "tool":         "honeypot_manager",
                    "finding_type": f"honeypot_{iact.intent.lower()}",
                    "severity":     "critical",
                    "mitre":        iact.mitre,
                    "tactic":       "Reconnaissance" if iact.intent=="SCANNER"
                                    else ("Credential Access" if iact.intent=="BRUTE_FORCE"
                                    else "Initial Access"),
                    "entity":       iact.src_ip,
                    "description":  f"Honeypot {iact.honeypot_type}:{iact.listen_port} "
                                    f"interaction from {iact.src_ip} — intent={iact.intent}",
                    "evidence":     {"port": iact.listen_port, "type": iact.honeypot_type,
                                     "bytes_rx": iact.bytes_received,
                                     "user": iact.captured_user,
                                     "payload_preview": iact.payload_text[:80]},
                    "score":        iact.score,
                    "timestamp":    iact.timestamp,
                }
                for iact in self._interactions
            ]


# ── CLI ────────────────────────────────────────────────────────────────────

def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Vanguard-OOB Honeypot Manager")
    parser.add_argument("--start",     action="store_true")
    parser.add_argument("--status",    action="store_true")
    parser.add_argument("--ports",     help="type:port,... e.g. ssh:2222,http:8888")
    parser.add_argument("--all-types", action="store_true",
                        help="Start all honeypot types on default ports")
    parser.add_argument("--log",       default="honeypot_interactions.jsonl",
                        help="Interaction log file (.jsonl)")
    parser.add_argument("--export-json", help="Export findings as unified JSON")
    parser.add_argument("--duration",  type=int, default=0,
                        help="Run for N seconds then exit (0=forever)")
    args = parser.parse_args()

    C = "\033[96m"; R = "\033[0m"; B = "\033[1m"
    print(f"\n{B}  ── Vanguard-OOB Honeypot Manager ──{R}\n")

    manager = HoneypotManager(log_path=args.log)

    if args.all_types:
        for hp_type, port in DEFAULT_PORTS.items():
            manager.add(hp_type, port)

    if args.ports:
        for spec in args.ports.split(","):
            parts = spec.strip().split(":")
            if len(parts) == 2:
                manager.add(parts[0].strip(), int(parts[1].strip()))

    if args.start or args.all_types:
        if not manager._honeypots:
            print("  No honeypots configured. Use --ports or --all-types")
            return

        manager.start_all()
        print(f"  Active honeypots:")
        for hp in manager._honeypots:
            print(f"    {hp.hp_type:10} → port {hp.port}")
        print(f"\n  Logging to {C}{args.log}{R}")
        print(f"  Waiting for attacker connections... (Ctrl+C to stop)\n")

        try:
            elapsed = 0
            while True:
                time.sleep(5)
                elapsed += 5
                if args.duration and elapsed >= args.duration:
                    break
        except KeyboardInterrupt:
            pass
        finally:
            manager.stop_all()
            s = manager.stats()
            print(f"\n  Total interactions: {s['total_interactions']}")
            print(f"  By intent:          {s['by_intent']}")
            print(f"  Top attacker IPs:   {s['top_attacker_ips'][:5]}")

            if args.export_json:
                findings = manager.export_findings()
                with open(args.export_json, "w") as f:
                    json.dump(findings, f, indent=2)
                print(f"  Findings exported to {C}{args.export_json}{R}")

    elif args.status:
        print("  Use --start to launch honeypots.")


if __name__ == "__main__":
    main()
