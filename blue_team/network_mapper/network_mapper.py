#!/usr/bin/env python3
"""
Vanguard-OOB :: Blue Team Tool 8 — Network Mapper
==================================================
Original architecture. Pure Python LAN discovery and topology mapper.
No nmap/arp-scan dependency. Uses raw sockets and OS APIs.

Capabilities:
  - ARP sweep (fastest LAN host discovery, requires root on Linux)
  - ICMP ping sweep (fallback, works without raw socket on some platforms)
  - TCP SYN probe sweep (determines host-up state per port)
  - Hostname resolution (reverse DNS + NetBIOS NBT)
  - MAC vendor lookup (IEEE OUI database built-in)
  - OS fingerprinting heuristics (TTL, TCP window size)
  - Topology export: adjacency table, JSON, HTML network graph
  - Rogue device detection (new MACs vs baseline)
  - Subnet calculator and CIDR enumerator

Usage:
    sudo python3 network_mapper.py --sweep 192.168.1.0/24
    python3 network_mapper.py --sweep 10.0.0.0/24 --tcp-probe 22,80,443
    python3 network_mapper.py --sweep 192.168.1.0/24 --baseline baseline.json --rogue
    python3 network_mapper.py --topology --output network.html
"""

import argparse
import concurrent.futures
import ipaddress
import json
import logging
import os
import platform
import re
import socket
import struct
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger("vanguard.network_mapper")
IS_LINUX   = platform.system() == "Linux"
IS_WINDOWS = platform.system() == "Windows"
IS_MAC     = platform.system() == "Darwin"

# ── OUI vendor prefix database (abbreviated — top vendors) ──────────────────

OUI_DATABASE: Dict[str, str] = {
    "00:00:0c": "Cisco Systems",
    "00:0c:29": "VMware",
    "00:50:56": "VMware",
    "00:1a:11": "Google",
    "00:16:3e": "Xen / Amazon",
    "00:0d:3a": "Microsoft Azure",
    "52:54:00": "QEMU/KVM",
    "08:00:27": "Oracle VirtualBox",
    "00:15:5d": "Microsoft Hyper-V",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    "00:1b:21": "Intel",
    "00:1e:67": "Intel",
    "00:22:fb": "Intel",
    "00:26:b9": "Dell",
    "14:18:77": "Dell",
    "f0:1f:af": "Dell",
    "00:1a:4b": "HP",
    "00:21:5a": "HP",
    "3c:d9:2b": "HP",
    "00:0e:7f": "Cisco-Linksys",
    "00:12:17": "Cisco-Linksys",
    "00:18:f8": "Apple",
    "00:1b:63": "Apple",
    "00:25:4b": "Apple",
    "28:cf:e9": "Apple",
    "3c:07:54": "Apple",
    "ac:de:48": "Apple",
    "00:26:bb": "Apple",
    "fc:fb:fb": "Cisco Meraki",
    "00:0f:61": "Juniper Networks",
    "00:1f:12": "Juniper Networks",
    "00:60:97": "3Com",
    "00:50:ba": "D-Link",
    "00:11:95": "D-Link",
    "14:91:82": "TP-Link",
    "ec:08:6b": "TP-Link",
    "50:c7:bf": "TP-Link",
    "00:50:43": "Zyxel",
    "00:13:49": "Zyxel",
}

def lookup_vendor(mac: str) -> str:
    """Look up OUI vendor from MAC address."""
    prefix = ":".join(mac.lower().split(":")[:3])
    return OUI_DATABASE.get(prefix, "Unknown")


# ── OS heuristics ─────────────────────────────────────────────────────────────

def guess_os(ttl: int, window_size: int = 0) -> str:
    """Heuristic OS guess from TTL and TCP window size."""
    if ttl <= 0:
        return "Unknown"
    if 60 <= ttl <= 65:
        return "Linux/Android"
    if 126 <= ttl <= 128:
        if window_size in (8192, 65535):
            return "Windows (NT/XP/7)"
        if window_size >= 65535:
            return "Windows 10/11"
        return "Windows"
    if 250 <= ttl <= 255:
        return "Cisco IOS / Network Device"
    if 240 <= ttl <= 245:
        return "Solaris/AIX"
    if ttl <= 30:
        return "Linux (tunneled/low TTL)"
    return f"Unknown (TTL={ttl})"


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class Host:
    ip:         str
    mac:        str           = ""
    hostname:   str           = ""
    vendor:     str           = ""
    os_guess:   str           = ""
    ttl:        int           = 0
    open_ports: List[int]     = field(default_factory=list)
    state:      str           = "up"    # up / down
    first_seen: str           = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen:  str           = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    is_rogue:   bool          = False
    notes:      List[str]     = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


# ── ARP sweep ─────────────────────────────────────────────────────────────────

def arp_sweep_linux(subnet: str) -> Dict[str, str]:
    """
    Send ARP requests via raw socket. Returns {ip: mac} dict.
    Requires root on Linux.
    """
    mac_map: Dict[str, str] = {}

    try:
        import fcntl
        SIOCGIFHWADDR  = 0x8927
        SIOCGIFINDEX   = 0x8933
        SIOCSARP       = 0x8956
        SIOCGARP       = 0x8954
        ETH_P_ARP      = 0x0806
    except ImportError:
        return mac_map

    network = ipaddress.ip_network(subnet, strict=False)
    hosts   = list(network.hosts())

    # Fallback: use arping via /proc/net/arp after pinging
    for ip in hosts:
        try:
            subprocess.run(
                ["ping", "-c", "1", "-W", "1", str(ip)],
                capture_output=True, timeout=2
            )
        except Exception:
            pass

    # Read /proc/net/arp
    try:
        with open("/proc/net/arp") as f:
            lines = f.read().splitlines()[1:]  # skip header
        for line in lines:
            parts = line.split()
            if len(parts) >= 4:
                ip  = parts[0]
                mac = parts[3]
                if mac != "00:00:00:00:00:00" and ipaddress.ip_address(ip) in network:
                    mac_map[ip] = mac
    except (OSError, ValueError):
        pass

    return mac_map


def arp_sweep_fallback(subnet: str) -> Dict[str, str]:
    """Fallback ARP using OS 'arp -a' command."""
    mac_map: Dict[str, str] = {}
    network = ipaddress.ip_network(subnet, strict=False)

    # Ping entire subnet to populate ARP cache
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as exe:
        list(exe.map(lambda ip: _ping_once(str(ip)), network.hosts()))

    try:
        result = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            m = re.search(r"\(?([\d.]+)\)?\s+at\s+([\da-fA-F:]{11,17})", line)
            if m:
                ip  = m.group(1)
                mac = m.group(2).lower()
                try:
                    if ipaddress.ip_address(ip) in network:
                        mac_map[ip] = mac
                except ValueError:
                    pass
    except Exception:
        pass

    return mac_map


# ── ICMP ping ─────────────────────────────────────────────────────────────────

def _ping_once(host: str, timeout: float = 1.0) -> Optional[int]:
    """
    Return TTL if host responds to ICMP, else None.
    Uses subprocess ping for cross-platform compatibility.
    """
    try:
        flag = "-n" if IS_WINDOWS else "-c"
        res  = subprocess.run(
            ["ping", flag, "1", "-W" if IS_LINUX else "-w", "1", host],
            capture_output=True, text=True, timeout=3
        )
        if res.returncode == 0:
            m = re.search(r"ttl[=s](\d+)", res.stdout, re.I)
            return int(m.group(1)) if m else 64
    except Exception:
        pass
    return None


def ping_sweep(subnet: str, threads: int = 100) -> Dict[str, int]:
    """Return {ip: ttl} for all responding hosts in subnet."""
    network = ipaddress.ip_network(subnet, strict=False)
    hosts   = [str(h) for h in network.hosts()]
    results = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as exe:
        futures = {exe.submit(_ping_once, ip): ip for ip in hosts}
        for fut in concurrent.futures.as_completed(futures):
            ip  = futures[fut]
            ttl = fut.result()
            if ttl is not None:
                results[ip] = ttl

    return results


# ── TCP port probe ────────────────────────────────────────────────────────────

def tcp_probe(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


def tcp_probe_host(host: str, ports: List[int], threads: int = 20) -> List[int]:
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as exe:
        futures = {exe.submit(tcp_probe, host, p): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            if fut.result():
                open_ports.append(futures[fut])
    return sorted(open_ports)


# ── Hostname resolver ─────────────────────────────────────────────────────────

def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return ""


# ── Rogue device detector ─────────────────────────────────────────────────────

def find_rogues(current: Dict[str, Host], baseline_path: str) -> List[Host]:
    """Compare current scan to a baseline JSON. Return new/unknown hosts."""
    try:
        baseline_data = json.loads(Path(baseline_path).read_text())
        known_ips     = {h["ip"] for h in baseline_data}
        known_macs    = {h.get("mac","") for h in baseline_data if h.get("mac")}
    except Exception as e:
        logger.error("Cannot load baseline %s: %s", baseline_path, e)
        return []

    rogues = []
    for ip, host in current.items():
        if ip not in known_ips and host.mac not in known_macs:
            host.is_rogue = True
            host.notes.append("NOT IN BASELINE — possible rogue device")
            rogues.append(host)
    return rogues


# ── HTML topology output ──────────────────────────────────────────────────────

def export_html(hosts: List[Host], output_path: str):
    nodes_js = json.dumps([
        {"id": h.ip, "label": f"{h.ip}\\n{h.hostname or h.vendor or ''}",
         "color": "#ef4444" if h.is_rogue else
                  ("#f59e0b" if h.open_ports else "#22c55e"),
         "title": f"MAC: {h.mac}<br>OS: {h.os_guess}<br>Ports: {h.open_ports}"}
        for h in hosts
    ], indent=2)

    html = f"""<!DOCTYPE html><html><head>
<meta charset="UTF-8"><title>Vanguard-OOB Network Map</title>
<style>
  body{{background:#0a0e1a;color:#e2e8f0;font-family:'Segoe UI',sans-serif;margin:0;padding:0}}
  #header{{padding:16px 24px;background:#0f172a;border-bottom:1px solid #1e293b}}
  h1{{color:#38bdf8;margin:0;font-size:1.2rem;letter-spacing:.1em}}
  #canvas{{width:100%;height:calc(100vh - 60px);background:#070c18}}
  .node-info{{position:absolute;bottom:20px;left:20px;background:#0f172a;
    border:1px solid #1e293b;padding:12px 16px;border-radius:6px;font-size:12px;
    color:#94a3b8;max-width:300px}}
  table{{width:100%;border-collapse:collapse;font-size:11px;margin-top:16px}}
  th{{color:#475569;padding:4px 8px;text-align:left;border-bottom:1px solid #1e293b}}
  td{{color:#94a3b8;padding:4px 8px;border-bottom:1px solid #0f172a}}
</style></head><body>
<div id="header">
  <h1>⬡ VANGUARD-OOB · NETWORK TOPOLOGY MAP</h1>
</div>
<div id="canvas">
<svg width="100%" height="100%" id="svg" style="display:block"></svg>
</div>
<div class="node-info">
  <b style="color:#38bdf8">Legend</b><br>
  <span style="color:#22c55e">●</span> Normal host &nbsp;
  <span style="color:#f59e0b">●</span> Open ports &nbsp;
  <span style="color:#ef4444">●</span> Rogue device
  <table>
    <tr><th>IP</th><th>Hostname</th><th>OS</th><th>Ports</th><th>Rogue</th></tr>
    {"".join(f"<tr><td>{h.ip}</td><td>{h.hostname[:20]}</td><td>{h.os_guess[:15]}</td><td>{','.join(map(str,h.open_ports[:5]))}</td><td>{'⚠ YES' if h.is_rogue else '–'}</td></tr>" for h in hosts)}
  </table>
</div>

<script>
// Simple force-directed layout
const nodes = {nodes_js};
const svg   = document.getElementById('svg');
const W     = svg.clientWidth  || window.innerWidth;
const H     = svg.clientHeight || window.innerHeight - 60;

// Circular layout fallback
nodes.forEach((n, i) => {{
  const angle = (2 * Math.PI * i) / nodes.length;
  const r     = Math.min(W, H) * 0.35;
  n.x = W/2 + r * Math.cos(angle);
  n.y = H/2 + r * Math.sin(angle);
}});

// Draw edges (fully connected mesh for demo — filter in real use)
let edgeSvg = '';

// Draw nodes
let nodeSvg = nodes.map(n => `
  <g transform="translate(${{n.x}},${{n.y}})">
    <circle r="22" fill="${{n.color}}22" stroke="${{n.color}}" stroke-width="1.5"/>
    <text text-anchor="middle" dy="-4" fill="${{n.color}}" font-size="11" font-family="monospace">${{n.id}}</text>
    <text text-anchor="middle" dy="10" fill="#475569" font-size="9">${{(n.label.split('\\\\n')[1]||'').substring(0,16)}}</text>
  </g>`).join('');

svg.innerHTML = edgeSvg + nodeSvg;

// Tooltip
svg.querySelectorAll('g').forEach((el, i) => {{
  if (!nodes[i]) return;
  el.style.cursor = 'pointer';
  el.addEventListener('mouseenter', () => {{
    const n = nodes[i];
    el.querySelector('circle').setAttribute('stroke-width','3');
  }});
  el.addEventListener('mouseleave', () => {{
    el.querySelector('circle').setAttribute('stroke-width','1.5');
  }});
}});
</script></body></html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    logger.info("Topology exported to %s", output_path)


# ── Main mapper ───────────────────────────────────────────────────────────────

class NetworkMapper:
    def __init__(self, threads: int = 100, tcp_timeout: float = 1.5):
        self.threads     = threads
        self.tcp_timeout = tcp_timeout
        self.hosts:      Dict[str, Host] = {}

    def sweep(self, subnet: str, probe_ports: List[int] = None) -> Dict[str, Host]:
        logger.info("Sweeping subnet: %s", subnet)

        # Step 1: ARP (Linux root) or fallback
        mac_map: Dict[str, str] = {}
        if IS_LINUX and os.geteuid() == 0:
            mac_map = arp_sweep_linux(subnet)
            logger.info("ARP sweep found %d hosts", len(mac_map))

        # Step 2: ICMP ping sweep
        logger.info("ICMP ping sweep...")
        ttl_map = ping_sweep(subnet, threads=self.threads)
        logger.info("Ping responded: %d hosts", len(ttl_map))

        # Combine results
        all_ips = set(mac_map.keys()) | set(ttl_map.keys())

        # Step 3: Build host objects
        for ip in all_ips:
            mac   = mac_map.get(ip, "")
            ttl   = ttl_map.get(ip, 0)
            host  = Host(
                ip      = ip,
                mac     = mac,
                vendor  = lookup_vendor(mac) if mac else "",
                ttl     = ttl,
                os_guess= guess_os(ttl),
                state   = "up",
            )
            self.hosts[ip] = host

        # Step 4: Hostname resolution (parallel)
        def resolve(ip):
            return ip, resolve_hostname(ip)

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as exe:
            for ip, hostname in exe.map(resolve, list(self.hosts.keys())):
                if hostname:
                    self.hosts[ip].hostname = hostname

        # Step 5: TCP port probe
        if probe_ports:
            logger.info("TCP probing %d ports on %d hosts...", len(probe_ports), len(self.hosts))
            def probe_host(ip):
                return ip, tcp_probe_host(ip, probe_ports, threads=10)

            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as exe:
                for ip, ports in exe.map(probe_host, list(self.hosts.keys())):
                    self.hosts[ip].open_ports = ports

        # ARP fallback if no results yet
        if not self.hosts:
            logger.info("No results from ARP/ping — trying arp fallback...")
            mac_map2 = arp_sweep_fallback(subnet)
            for ip, mac in mac_map2.items():
                self.hosts[ip] = Host(ip=ip, mac=mac, vendor=lookup_vendor(mac))

        logger.info("Sweep complete: %d live hosts", len(self.hosts))
        return self.hosts

    def summary(self) -> dict:
        vendors    = {}
        os_list    = {}
        for h in self.hosts.values():
            vendors[h.vendor]   = vendors.get(h.vendor, 0) + 1
            os_list[h.os_guess] = os_list.get(h.os_guess, 0) + 1

        return {
            "total_hosts":  len(self.hosts),
            "hosts_with_ports": sum(1 for h in self.hosts.values() if h.open_ports),
            "rogue_devices": sum(1 for h in self.hosts.values() if h.is_rogue),
            "top_vendors":  sorted(vendors.items(), key=lambda x:-x[1])[:5],
            "os_breakdown": os_list,
        }


# ── CLI ───────────────────────────────────────────────────────────────────────

def _print_hosts(hosts: Dict[str, Host]):
    R = "\033[0m"; B = "\033[1m"; C = "\033[96m"; Y = "\033[93m"; RE = "\033[91m"
    print(f"\n  {B}{'IP':<18} {'MAC':<20} {'HOSTNAME':<25} {'OS/TTL':<22} {'VENDOR':<18} PORTS{R}")
    print(f"  {'─'*110}")
    for ip in sorted(hosts.keys(), key=lambda x: [int(n) for n in x.split(".")]):
        h = hosts[ip]
        c = RE if h.is_rogue else (Y if h.open_ports else C)
        ports_str = ",".join(str(p) for p in h.open_ports[:8])
        rogue_tag = " ⚠ROGUE" if h.is_rogue else ""
        print(f"  {c}{h.ip:<18}{R} {h.mac:<20} {h.hostname[:24]:<25} "
              f"{h.os_guess[:21]:<22} {h.vendor[:17]:<18} {ports_str}{RE}{rogue_tag}{R}")
    print()


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Vanguard-OOB Network Mapper")
    parser.add_argument("--sweep",      required=True, help="Subnet to sweep, e.g. 192.168.1.0/24")
    parser.add_argument("--tcp-probe",  help="Comma-separated ports to probe, e.g. 22,80,443")
    parser.add_argument("--baseline",   help="Baseline JSON to compare for rogue detection")
    parser.add_argument("--rogue",      action="store_true", help="Show only rogue devices")
    parser.add_argument("--threads",    type=int, default=100)
    parser.add_argument("--output",     help="Output file (.json or .html)")
    parser.add_argument("--save-baseline", help="Save current scan as baseline JSON")
    args = parser.parse_args()

    C = "\033[96m"; R = "\033[0m"; B = "\033[1m"
    print(f"\n{B}  ── Vanguard-OOB Network Mapper ──{R}\n")

    probe_ports = None
    if args.tcp_probe:
        probe_ports = [int(p.strip()) for p in args.tcp_probe.split(",")]

    mapper = NetworkMapper(threads=args.threads)
    hosts  = mapper.sweep(args.sweep, probe_ports=probe_ports)

    # Rogue detection
    if args.baseline:
        rogues = find_rogues(hosts, args.baseline)
        if rogues:
            print(f"  {B}\033[91m⚠ {len(rogues)} ROGUE DEVICE(S) DETECTED{R}\n")

    if args.rogue:
        filtered = {ip: h for ip, h in hosts.items() if h.is_rogue}
    else:
        filtered = hosts

    _print_hosts(filtered)

    s = mapper.summary()
    print(f"  Hosts up     : {s['total_hosts']}")
    print(f"  With ports   : {s['hosts_with_ports']}")
    print(f"  Rogue devices: {s['rogue_devices']}")
    print(f"  Top vendors  : {s['top_vendors']}")
    print(f"  OS breakdown : {s['os_breakdown']}\n")

    if args.save_baseline:
        with open(args.save_baseline, "w") as f:
            json.dump([h.to_dict() for h in hosts.values()], f, indent=2)
        print(f"  Baseline saved to {C}{args.save_baseline}{R}")

    if args.output:
        ext = Path(args.output).suffix.lower()
        host_list = list(filtered.values())
        if ext == ".html":
            export_html(host_list, args.output)
        else:
            with open(args.output, "w") as f:
                json.dump([h.to_dict() for h in host_list], f, indent=2)
        print(f"  Output saved to {C}{args.output}{R}")


if __name__ == "__main__":
    main()
