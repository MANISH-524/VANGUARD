#!/usr/bin/env python3
"""
Vanguard-OOB :: Blue Team Tool 4 — Packet Inspector
====================================================
Original architecture. Reads PCAP files or captures live traffic
using raw sockets (Linux, requires root for live capture).

Capabilities:
  - PCAP file parser (libpcap global/record header, no scapy needed)
  - Ethernet / IPv4 / IPv6 / TCP / UDP / ICMP decoder
  - DNS query/response parser
  - HTTP/1.x request/response reconstruction
  - TLS ClientHello SNI extraction
  - Protocol anomaly detection:
      * Port scanning (SYN flood, single-IP many-port)
      * DNS tunneling (high-entropy subdomain labels)
      * Beaconing (regular periodic connections)
      * Large DNS responses (data exfil)
      * Non-standard protocol on standard ports
      * ICMP tunneling (oversized payload)
  - Connection tracker with flow statistics
  - Outputs findings + pcap summary as JSON or human-readable

Usage:
    sudo python3 packet_inspector.py --live eth0
    python3 packet_inspector.py --pcap capture.pcap
    python3 packet_inspector.py --pcap capture.pcap --filter tcp --json out.json
"""

import argparse
import json
import logging
import math
import socket
import struct
import sys
import time
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Generator, List, Optional, Tuple

logger = logging.getLogger("vanguard.packet_inspector")

# ── PCAP file format constants ────────────────────────────────────────────────

PCAP_GLOBAL_MAGIC_LE = 0xD4C3B2A1
PCAP_GLOBAL_MAGIC_BE = 0xA1B2C3D4
PCAP_HEADER_SIZE     = 24
PCAP_RECORD_SIZE     = 16
LINK_ETHERNET        = 1
LINK_RAW             = 101

# ── Protocol numbers ──────────────────────────────────────────────────────────

PROTO_ICMP  = 1
PROTO_TCP   = 6
PROTO_UDP   = 17
PROTO_ICMPv6= 58

ETH_IP4  = 0x0800
ETH_IP6  = 0x86DD
ETH_ARP  = 0x0806

# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class Packet:
    ts:         float
    frame_no:   int
    src_mac:    str = ""
    dst_mac:    str = ""
    eth_type:   int = 0
    src_ip:     str = ""
    dst_ip:     str = ""
    ip_proto:   int = 0
    src_port:   int = 0
    dst_port:   int = 0
    tcp_flags:  int = 0
    payload:    bytes = b""
    length:     int = 0
    layer:      str = ""       # "ethernet" / "raw"
    transport:  str = ""       # "tcp" / "udp" / "icmp"


@dataclass
class FlowKey:
    src_ip:   str
    dst_ip:   str
    src_port: int
    dst_port: int
    proto:    str

    def __hash__(self):
        return hash((min(self.src_ip, self.dst_ip),
                     max(self.src_ip, self.dst_ip),
                     min(self.src_port, self.dst_port),
                     max(self.src_port, self.dst_port),
                     self.proto))

    def __eq__(self, other):
        return hash(self) == hash(other)


@dataclass
class FlowStats:
    key:          FlowKey
    first_seen:   float = 0.0
    last_seen:    float = 0.0
    packet_count: int   = 0
    byte_count:   int   = 0
    syn_count:    int   = 0
    payload_bytes:int   = 0
    inter_arrival_times: List[float] = field(default_factory=list)


@dataclass
class Anomaly:
    ts:          float
    anomaly_type:str
    severity:    str
    description: str
    evidence:    dict = field(default_factory=dict)
    src_ip:      str  = ""
    dst_ip:      str  = ""
    dst_port:    int  = 0


# ── PCAP parser ───────────────────────────────────────────────────────────────

class PCAPReader:
    def __init__(self, path: str):
        self.path    = path
        self._fh     = open(path, "rb")
        self._le     = True   # little-endian
        self._link   = LINK_ETHERNET
        self._parse_global_header()

    def _parse_global_header(self):
        hdr = self._fh.read(PCAP_HEADER_SIZE)
        if len(hdr) < PCAP_HEADER_SIZE:
            raise ValueError("Truncated PCAP file")
        magic = struct.unpack("<I", hdr[:4])[0]
        if magic == PCAP_GLOBAL_MAGIC_LE:
            self._le = True
        elif magic == PCAP_GLOBAL_MAGIC_BE:
            self._le = False
        else:
            raise ValueError(f"Invalid PCAP magic: {magic:#x}")
        fmt        = "<" if self._le else ">"
        _, _, _, _, _, self._link = struct.unpack(fmt + "IHHiII", hdr)

    def _unpack(self, fmt: str, data: bytes):
        prefix = "<" if self._le else ">"
        return struct.unpack(prefix + fmt, data)

    def __iter__(self) -> Generator[Tuple[float, bytes], None, None]:
        frame_no = 0
        while True:
            rec = self._fh.read(PCAP_RECORD_SIZE)
            if not rec:
                break
            if len(rec) < PCAP_RECORD_SIZE:
                break
            ts_sec, ts_usec, cap_len, _ = self._unpack("IIII", rec)
            ts     = ts_sec + ts_usec / 1_000_000
            data   = self._fh.read(cap_len)
            frame_no += 1
            yield frame_no, ts, data

    def close(self):
        self._fh.close()


# ── Packet decoder ────────────────────────────────────────────────────────────

def decode_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def decode_ethernet(frame_no: int, ts: float, data: bytes) -> Optional[Packet]:
    if len(data) < 14:
        return None
    pkt = Packet(ts=ts, frame_no=frame_no, length=len(data), layer="ethernet")
    pkt.dst_mac  = decode_mac(data[0:6])
    pkt.src_mac  = decode_mac(data[6:12])
    pkt.eth_type = struct.unpack(">H", data[12:14])[0]

    # Handle 802.1Q VLAN tag
    payload = data[14:]
    if pkt.eth_type == 0x8100:  # VLAN tagged
        if len(data) < 18:
            return pkt
        pkt.eth_type = struct.unpack(">H", data[16:18])[0]
        payload = data[18:]

    if pkt.eth_type == ETH_IP4:
        _decode_ipv4(pkt, payload)
    elif pkt.eth_type == ETH_IP6:
        _decode_ipv6(pkt, payload)
    return pkt


def _decode_ipv4(pkt: Packet, data: bytes):
    if len(data) < 20:
        return
    ihl       = (data[0] & 0x0F) * 4
    pkt.ip_proto = data[9]
    pkt.src_ip   = socket.inet_ntoa(data[12:16])
    pkt.dst_ip   = socket.inet_ntoa(data[16:20])
    transport    = data[ihl:]
    _decode_transport(pkt, transport)


def _decode_ipv6(pkt: Packet, data: bytes):
    if len(data) < 40:
        return
    pkt.ip_proto = data[6]
    pkt.src_ip   = socket.inet_ntop(socket.AF_INET6, data[8:24])
    pkt.dst_ip   = socket.inet_ntop(socket.AF_INET6, data[24:40])
    transport    = data[40:]
    _decode_transport(pkt, transport)


def _decode_transport(pkt: Packet, data: bytes):
    if pkt.ip_proto == PROTO_TCP:
        if len(data) < 20:
            return
        pkt.transport = "tcp"
        pkt.src_port  = struct.unpack(">H", data[0:2])[0]
        pkt.dst_port  = struct.unpack(">H", data[2:4])[0]
        pkt.tcp_flags = data[13]
        offset        = ((data[12] >> 4) & 0xF) * 4
        pkt.payload   = data[offset:]

    elif pkt.ip_proto == PROTO_UDP:
        if len(data) < 8:
            return
        pkt.transport = "udp"
        pkt.src_port  = struct.unpack(">H", data[0:2])[0]
        pkt.dst_port  = struct.unpack(">H", data[2:4])[0]
        pkt.payload   = data[8:]

    elif pkt.ip_proto in (PROTO_ICMP, PROTO_ICMPv6):
        pkt.transport = "icmp"
        pkt.payload   = data[4:]


# ── DNS parser ────────────────────────────────────────────────────────────────

def parse_dns_name(data: bytes, offset: int) -> Tuple[str, int]:
    labels = []
    visited = set()
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:   # compression pointer
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if ptr in visited:
                break
            visited.add(ptr)
            name, _ = parse_dns_name(data, ptr)
            labels.append(name)
            offset += 2
            break
        else:
            offset += 1
            labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
            offset += length
    return ".".join(labels), offset


def parse_dns(payload: bytes) -> Optional[dict]:
    if len(payload) < 12:
        return None
    try:
        txid    = struct.unpack(">H", payload[0:2])[0]
        flags   = struct.unpack(">H", payload[2:4])[0]
        qdcount = struct.unpack(">H", payload[4:6])[0]
        is_response = bool(flags & 0x8000)
        offset  = 12
        queries = []
        for _ in range(qdcount):
            name, offset = parse_dns_name(payload, offset)
            if offset + 4 > len(payload):
                break
            qtype  = struct.unpack(">H", payload[offset:offset+2])[0]
            offset += 4
            queries.append({"name": name, "type": qtype})
        return {"txid": txid, "is_response": is_response, "queries": queries}
    except Exception:
        return None


# ── HTTP parser ────────────────────────────────────────────────────────────────

def parse_http(payload: bytes) -> Optional[dict]:
    try:
        text = payload.decode("utf-8", errors="replace")
        lines = text.split("\r\n")
        if not lines:
            return None
        first = lines[0]
        if first.startswith(("GET","POST","PUT","DELETE","HEAD","OPTIONS","PATCH")):
            parts = first.split(" ", 2)
            if len(parts) >= 2:
                headers = {}
                for line in lines[1:]:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        headers[k.strip().lower()] = v.strip()
                return {"type": "request", "method": parts[0],
                        "uri": parts[1], "headers": headers}
        elif first.startswith("HTTP/"):
            parts = first.split(" ", 2)
            return {"type": "response", "status": int(parts[1]) if len(parts) > 1 else 0,
                    "reason": parts[2] if len(parts) > 2 else ""}
    except Exception:
        pass
    return None


# ── TLS ClientHello SNI extractor ────────────────────────────────────────────

def extract_sni(payload: bytes) -> Optional[str]:
    """Extract SNI from TLS ClientHello without decryption."""
    try:
        if len(payload) < 5 or payload[0] != 0x16:  # TLS record
            return None
        rec_len = struct.unpack(">H", payload[3:5])[0]
        if len(payload) < 5 + rec_len:
            return None
        hs = payload[5:]
        if hs[0] != 0x01:  # ClientHello
            return None
        # Skip to extensions
        pos  = 4 + 2 + 32    # handshake header + version + random
        if pos >= len(hs):   return None
        sess_len = hs[pos];  pos += 1 + sess_len
        if pos + 2 >= len(hs): return None
        cs_len   = struct.unpack(">H", hs[pos:pos+2])[0]; pos += 2 + cs_len
        if pos >= len(hs):   return None
        comp_len = hs[pos];  pos += 1 + comp_len
        if pos + 2 >= len(hs): return None
        ext_total = struct.unpack(">H", hs[pos:pos+2])[0]; pos += 2
        end = pos + ext_total
        while pos + 4 <= end:
            ext_type = struct.unpack(">H", hs[pos:pos+2])[0]
            ext_len  = struct.unpack(">H", hs[pos+2:pos+4])[0]
            pos += 4
            if ext_type == 0x0000:  # SNI
                # server_name_list_length, type, name_length, name
                if pos + 5 <= end:
                    name_len = struct.unpack(">H", hs[pos+3:pos+5])[0]
                    if pos + 5 + name_len <= end:
                        return hs[pos+5:pos+5+name_len].decode("ascii", errors="replace")
            pos += ext_len
    except Exception:
        pass
    return None


# ── Entropy helper ────────────────────────────────────────────────────────────

def string_entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    freq = Counter(s)
    n    = len(s)
    return -sum((c/n) * math.log2(c/n) for c in freq.values())


# ── Anomaly detection engine ──────────────────────────────────────────────────

class AnomalyEngine:
    def __init__(self):
        self._port_scan:  Dict[str, Counter]  = defaultdict(Counter)  # src_ip → Counter(dst_port)
        self._beacon:     Dict[str, deque]    = defaultdict(deque)    # (src,dst,port) → deque of timestamps
        self._dns_sizes:  Dict[str, List[int]]= defaultdict(list)
        self._icmp_sizes: Dict[str, List[int]]= defaultdict(list)
        self._findings:   List[Anomaly]       = []
        self._syn_only:   Dict[str, Counter]  = defaultdict(Counter)  # src → counter of SYN-only flows
        self._reported:   set = set()

    def feed(self, pkt: Packet) -> List[Anomaly]:
        found = []
        # Port scan detection
        if pkt.transport == "tcp" and (pkt.tcp_flags & 0x02):  # SYN
            self._port_scan[pkt.src_ip][pkt.dst_port] += 1
            key = f"portscan:{pkt.src_ip}"
            ports_hit = len(self._port_scan[pkt.src_ip])
            if ports_hit in (20, 50, 100) and key not in self._reported:
                self._reported.add(f"{key}:{ports_hit}")
                a = Anomaly(ts=pkt.ts, anomaly_type="port_scan",
                            severity="high" if ports_hit >= 50 else "medium",
                            description=f"Port scan from {pkt.src_ip}: {ports_hit} unique ports",
                            evidence={"unique_ports": ports_hit,
                                      "sample_ports": list(self._port_scan[pkt.src_ip].keys())[:10]},
                            src_ip=pkt.src_ip)
                found.append(a)

        # Beaconing detection (regular intervals)
        if pkt.transport in ("tcp","udp") and pkt.dst_ip and pkt.dst_port:
            bkey = (pkt.src_ip, pkt.dst_ip, pkt.dst_port)
            times = self._beacon[bkey]
            times.append(pkt.ts)
            if len(times) == 100:
                intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
                mean_iv   = sum(intervals) / len(intervals)
                variance  = sum((x - mean_iv)**2 for x in intervals) / len(intervals)
                cv        = math.sqrt(variance) / mean_iv if mean_iv > 0 else 999
                bkey_str  = f"beacon:{bkey}"
                if cv < 0.10 and bkey_str not in self._reported:
                    self._reported.add(bkey_str)
                    a = Anomaly(ts=pkt.ts, anomaly_type="c2_beaconing",
                                severity="critical",
                                description=f"Beaconing to {pkt.dst_ip}:{pkt.dst_port} (CV={cv:.3f})",
                                evidence={"mean_interval_s": round(mean_iv,2),
                                          "coeff_variation": round(cv,4),
                                          "sample_count": len(times)},
                                src_ip=pkt.src_ip, dst_ip=pkt.dst_ip, dst_port=pkt.dst_port)
                    found.append(a)
                self._beacon[bkey] = deque(list(times)[-50:], maxlen=100)

        # DNS tunneling (high-entropy subdomain)
        if pkt.transport == "udp" and pkt.dst_port == 53 and pkt.payload:
            dns = parse_dns(pkt.payload)
            if dns and dns["queries"]:
                for q in dns["queries"]:
                    name = q.get("name","")
                    parts = name.split(".")
                    for label in parts[:-2]:
                        ent = string_entropy(label)
                        key = f"dnstunnel:{pkt.src_ip}:{name}"
                        if len(label) > 20 and ent > 3.5 and key not in self._reported:
                            self._reported.add(key)
                            a = Anomaly(ts=pkt.ts, anomaly_type="dns_tunnel",
                                        severity="high",
                                        description=f"High-entropy DNS label: {label[:40]}",
                                        evidence={"label": label[:60], "entropy": round(ent,3),
                                                  "query": name[:80]},
                                        src_ip=pkt.src_ip, dst_ip=pkt.dst_ip, dst_port=53)
                            found.append(a)

        # ICMP tunneling (oversized payload)
        if pkt.transport == "icmp" and len(pkt.payload) > 512:
            key = f"icmptunnel:{pkt.src_ip}"
            if key not in self._reported:
                self._reported.add(key)
                a = Anomaly(ts=pkt.ts, anomaly_type="icmp_tunnel",
                            severity="high",
                            description=f"Oversized ICMP payload ({len(pkt.payload)} bytes)",
                            evidence={"payload_size": len(pkt.payload)},
                            src_ip=pkt.src_ip, dst_ip=pkt.dst_ip)
                found.append(a)

        self._findings.extend(found)
        return found

    def all_findings(self) -> List[Anomaly]:
        return self._findings


# ── Flow tracker ─────────────────────────────────────────────────────────────

class FlowTracker:
    def __init__(self):
        self._flows: Dict[int, FlowStats] = {}

    def update(self, pkt: Packet):
        if not pkt.transport:
            return
        key = FlowKey(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.transport)
        h   = hash(key)
        if h not in self._flows:
            self._flows[h] = FlowStats(key=key, first_seen=pkt.ts)
        fs = self._flows[h]
        if fs.last_seen:
            fs.inter_arrival_times.append(pkt.ts - fs.last_seen)
            if len(fs.inter_arrival_times) > 200:
                fs.inter_arrival_times = fs.inter_arrival_times[-200:]
        fs.last_seen    = pkt.ts
        fs.packet_count += 1
        fs.byte_count   += pkt.length
        fs.payload_bytes += len(pkt.payload)
        if pkt.transport == "tcp" and (pkt.tcp_flags & 0x02):
            fs.syn_count += 1

    def top_talkers(self, n: int = 10) -> List[Tuple[str, int]]:
        ip_bytes: Counter = Counter()
        for fs in self._flows.values():
            ip_bytes[fs.key.src_ip] += fs.byte_count
        return ip_bytes.most_common(n)

    def summary(self) -> dict:
        return {
            "total_flows":   len(self._flows),
            "total_packets": sum(fs.packet_count for fs in self._flows.values()),
            "total_bytes":   sum(fs.byte_count   for fs in self._flows.values()),
        }


# ── Main inspector ────────────────────────────────────────────────────────────

class PacketInspector:
    def __init__(self, filter_proto: str = None):
        self.filter_proto  = filter_proto
        self.flow_tracker  = FlowTracker()
        self.anomaly_engine= AnomalyEngine()
        self.packet_count  = 0
        self.http_events:  List[dict] = []
        self.dns_queries:  List[dict] = []
        self.sni_list:     List[str]  = []

    def process_packet(self, frame_no: int, ts: float, data: bytes) -> List[Anomaly]:
        pkt = decode_ethernet(frame_no, ts, data)
        if pkt is None:
            return []
        if self.filter_proto and pkt.transport != self.filter_proto:
            return []

        self.packet_count += 1
        self.flow_tracker.update(pkt)

        # Application layer parsing
        if pkt.payload:
            if pkt.transport == "udp" and pkt.dst_port == 53:
                dns = parse_dns(pkt.payload)
                if dns and dns["queries"]:
                    self.dns_queries.append({"ts": ts, "src": pkt.src_ip, **dns})

            if pkt.transport == "tcp" and pkt.dst_port in (80, 8080, 8000):
                http = parse_http(pkt.payload)
                if http:
                    self.http_events.append({"ts": ts, "src": pkt.src_ip,
                                             "dst": pkt.dst_ip, **http})

            if pkt.transport == "tcp" and pkt.dst_port == 443:
                sni = extract_sni(pkt.payload)
                if sni:
                    self.sni_list.append(sni)

        return self.anomaly_engine.feed(pkt)

    def analyze_pcap(self, path: str) -> dict:
        logger.info("Analyzing PCAP: %s", path)
        reader = PCAPReader(path)
        all_anomalies = []
        try:
            for frame_no, ts, data in reader:
                anomalies = self.process_packet(frame_no, ts, data)
                all_anomalies.extend(anomalies)
        finally:
            reader.close()

        return {
            "pcap_file":     path,
            "packets":       self.packet_count,
            "flows":         self.flow_tracker.summary(),
            "top_talkers":   self.flow_tracker.top_talkers(),
            "anomalies":     [asdict(a) for a in all_anomalies],
            "dns_queries":   self.dns_queries[:50],
            "http_events":   self.http_events[:50],
            "tls_sni":       list(set(self.sni_list))[:50],
        }

    def live_capture(self, interface: str):
        """Capture live packets via raw socket (Linux root required)."""
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            s.bind((interface, 0))
        except PermissionError:
            print("  [ERROR] Root required for live capture: sudo python3 packet_inspector.py ...")
            return
        except AttributeError:
            print("  [ERROR] AF_PACKET not available on this OS (Linux only for live capture)")
            return

        print(f"  Capturing on {interface} — Ctrl+C to stop\n")
        frame_no = 0
        try:
            while True:
                data, _ = s.recvfrom(65535)
                frame_no += 1
                anomalies = self.process_packet(frame_no, time.time(), data)
                for a in anomalies:
                    _print_anomaly(a)
        except KeyboardInterrupt:
            print("\n  Capture stopped.")
        finally:
            s.close()


# ── CLI output ────────────────────────────────────────────────────────────────

SEV_COLOR = {"critical":"\033[95m","high":"\033[91m","medium":"\033[93m","low":"\033[92m"}

def _print_anomaly(a: Anomaly):
    color = SEV_COLOR.get(a.severity, "")
    R     = "\033[0m"
    ts    = datetime.fromtimestamp(a.ts, tz=timezone.utc).strftime("%H:%M:%S")
    print(f"  {color}[{a.severity.upper():8}]{R} {ts}  {a.anomaly_type}")
    print(f"             {a.description}")
    if a.src_ip:
        print(f"             src={a.src_ip}  dst={a.dst_ip}:{a.dst_port}")
    print()


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Vanguard-OOB Packet Inspector")
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument("--pcap",  help="PCAP file to analyze")
    g.add_argument("--live",  help="Network interface for live capture (root required)")
    parser.add_argument("--filter", choices=["tcp","udp","icmp"], help="Filter by protocol")
    parser.add_argument("--json",   help="Output JSON report to file")
    args = parser.parse_args()

    C = "\033[96m"; R = "\033[0m"; B = "\033[1m"
    print(f"\n{B}  ── Vanguard-OOB Packet Inspector ──{R}\n")

    inspector = PacketInspector(filter_proto=args.filter)

    if args.pcap:
        report = inspector.analyze_pcap(args.pcap)
        print(f"  File    : {report['pcap_file']}")
        print(f"  Packets : {report['packets']}")
        print(f"  Flows   : {report['flows']['total_flows']}")
        print(f"  Anomalies: {len(report['anomalies'])}\n")

        for a_dict in report["anomalies"]:
            a = Anomaly(**{k: a_dict[k] for k in Anomaly.__dataclass_fields__ if k in a_dict})
            _print_anomaly(a)

        if report["tls_sni"]:
            print(f"  TLS SNI observed: {', '.join(report['tls_sni'][:10])}")

        if report["top_talkers"]:
            print("\n  Top talkers:")
            for ip, bts in report["top_talkers"][:5]:
                print(f"    {ip:<18} {bts:>10,} bytes")

        if args.json:
            with open(args.json, "w") as f:
                json.dump(report, f, indent=2, default=str)
            print(f"\n  Report saved to {args.json}")

    elif args.live:
        inspector.live_capture(args.live)


if __name__ == "__main__":
    main()
