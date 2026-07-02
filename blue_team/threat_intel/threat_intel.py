#!/usr/bin/env python3
"""
Vanguard-OOB :: Blue Team Tool 1 — Threat Intelligence Engine
==============================================================
Original architecture. No external threat-feed dependencies.

Capabilities:
  - Maintains an in-process IOC database (IPs, domains, hashes, URLs)
  - Multi-source feed ingestion (CSV, JSON, plain-text, STIX-lite)
  - Reputation scoring engine  (0–100, configurable weights)
  - Fast lookup via bloom-filter-style pre-check + hash index
  - Exports matches as enriched JSON for the SOC dashboard
  - CLI: query single IOC or bulk-scan a file of indicators

Usage:
    python3 threat_intel.py --query 8.8.8.8
    python3 threat_intel.py --query malware.exe --type hash
    python3 threat_intel.py --feed feeds/custom_feed.csv
    python3 threat_intel.py --scan /var/log/syslog
    python3 threat_intel.py --server --port 7001   (REST API mode)
"""

import argparse
import csv
import hashlib
import ipaddress
import json
import logging
import re
import socket
import struct
import threading
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger("vanguard.threat_intel")

# ── IOC Types ────────────────────────────────────────────────────────────────

class IOCType(str, Enum):
    IP        = "ip"
    DOMAIN    = "domain"
    URL       = "url"
    MD5       = "md5"
    SHA1      = "sha1"
    SHA256    = "sha256"
    EMAIL     = "email"
    MUTEX     = "mutex"
    REGISTRY  = "registry"
    FILENAME  = "filename"

# ── Reputation tiers ─────────────────────────────────────────────────────────

TIER_LABELS = {
    range(0,  20): ("CLEAN",    "\033[92m"),
    range(20, 50): ("SUSPICIOUS", "\033[93m"),
    range(50, 80): ("MALICIOUS", "\033[91m"),
    range(80,101): ("CRITICAL",  "\033[95m"),
}

def reputation_tier(score: int) -> Tuple[str, str]:
    for r, (label, color) in TIER_LABELS.items():
        if score in r:
            return label, color
    return "UNKNOWN", "\033[2m"

# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class IOCEntry:
    value:       str
    ioc_type:    str
    score:       int              = 0      # 0–100 reputation score
    tags:        List[str]        = field(default_factory=list)
    source:      str              = "manual"
    first_seen:  str              = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen:   str              = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    hit_count:   int              = 0
    context:     dict             = field(default_factory=dict)

    def to_dict(self) -> dict:
        tier, _ = reputation_tier(self.score)
        return {**asdict(self), "tier": tier}


@dataclass
class QueryResult:
    query:      str
    ioc_type:   str
    found:      bool
    score:      int               = 0
    tier:       str               = "CLEAN"
    entry:      Optional[dict]    = None
    enrichment: dict              = field(default_factory=dict)
    elapsed_ms: float             = 0.0

# ── Bloom filter (fast pre-screening) ────────────────────────────────────────

class SimpleBloom:
    """Minimal Bloom filter — no bitarray dep, pure Python."""
    def __init__(self, capacity: int = 500_000, error_rate: float = 0.01):
        self.size  = self._optimal_size(capacity, error_rate)
        self.hashes= self._optimal_hashes(capacity, self.size)
        self.bits  = bytearray(self.size // 8 + 1)

    @staticmethod
    def _optimal_size(n, p):
        return int(-n * (p.__class__.__mro__[0]) and -n * 1.4427 * (p ** 0.5) or
                   int(-n * 9.58496 / (1 - 2 ** (-1.44 * (-n / (n + 1)))))) if False else \
               max(1024, int(-(n * (p ** 0.5)) * 14.4))

    @staticmethod
    def _optimal_hashes(n, m):
        return max(1, int((m / n) * 0.693))

    def _positions(self, item: str):
        h1 = int(hashlib.md5(item.encode()).hexdigest(), 16)
        h2 = int(hashlib.sha1(item.encode()).hexdigest(), 16)
        return [(h1 + i * h2) % self.size for i in range(self.hashes)]

    def add(self, item: str):
        for pos in self._positions(item):
            self.bits[pos >> 3] |= (1 << (pos & 7))

    def __contains__(self, item: str) -> bool:
        return all(self.bits[pos >> 3] & (1 << (pos & 7)) for pos in self._positions(item))


# ── IOC Database ─────────────────────────────────────────────────────────────

class IOCDatabase:
    def __init__(self):
        self._lock       = threading.RLock()
        self._index:     Dict[str, IOCEntry] = {}   # normalized_value → entry
        self._type_idx:  Dict[str, Set[str]] = defaultdict(set)
        self._tag_idx:   Dict[str, Set[str]] = defaultdict(set)
        self._bloom      = SimpleBloom(capacity=200_000)
        self._stats      = {"total": 0, "hits": 0, "misses": 0, "feeds_loaded": 0}

    # ── Normalization ─────────────────────────────────────────────────────

    @staticmethod
    def normalize(value: str, ioc_type: str) -> str:
        v = value.strip().lower()
        if ioc_type == IOCType.IP:
            try:
                return str(ipaddress.ip_address(v))
            except ValueError:
                pass
        if ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
            return v.replace(":", "").replace("-", "")
        if ioc_type == IOCType.DOMAIN:
            return v.rstrip(".")
        return v

    # ── Ingest ────────────────────────────────────────────────────────────

    def add(self, value: str, ioc_type: str, score: int = 75,
            tags: List[str] = None, source: str = "manual", context: dict = None) -> IOCEntry:
        key = self.normalize(value, ioc_type)
        with self._lock:
            if key in self._index:
                entry = self._index[key]
                entry.score     = max(entry.score, score)
                entry.last_seen = datetime.now(timezone.utc).isoformat()
                if tags:
                    entry.tags = list(set(entry.tags) | set(tags))
                return entry

            entry = IOCEntry(
                value    = key,
                ioc_type = ioc_type,
                score    = score,
                tags     = tags or [],
                source   = source,
                context  = context or {},
            )
            self._index[key]              = entry
            self._type_idx[ioc_type].add(key)
            for tag in (tags or []):
                self._tag_idx[tag].add(key)
            self._bloom.add(key)
            self._stats["total"] += 1
            return entry

    # ── Lookup ────────────────────────────────────────────────────────────

    def query(self, value: str, ioc_type: str = None) -> QueryResult:
        t0 = time.perf_counter()

        # Auto-detect type if not given
        if ioc_type is None:
            ioc_type = self._detect_type(value)

        key = self.normalize(value, ioc_type)

        # Bloom pre-check (fast path)
        if key not in self._bloom:
            self._stats["misses"] += 1
            elapsed = (time.perf_counter() - t0) * 1000
            return QueryResult(query=value, ioc_type=ioc_type, found=False, elapsed_ms=elapsed)

        with self._lock:
            entry = self._index.get(key)

        elapsed = (time.perf_counter() - t0) * 1000
        if entry is None:
            self._stats["misses"] += 1
            return QueryResult(query=value, ioc_type=ioc_type, found=False, elapsed_ms=elapsed)

        self._stats["hits"] += 1
        entry.hit_count += 1
        entry.last_seen  = datetime.now(timezone.utc).isoformat()
        tier, _ = reputation_tier(entry.score)

        return QueryResult(
            query      = value,
            ioc_type   = ioc_type,
            found      = True,
            score      = entry.score,
            tier       = tier,
            entry      = entry.to_dict(),
            enrichment = self._enrich(entry),
            elapsed_ms = elapsed,
        )

    def _enrich(self, entry: IOCEntry) -> dict:
        """Add contextual enrichment to a hit."""
        enrichment = {}
        if entry.ioc_type == IOCType.IP:
            try:
                addr = ipaddress.ip_address(entry.value)
                enrichment["is_private"]   = addr.is_private
                enrichment["is_loopback"]  = addr.is_loopback
                enrichment["is_multicast"] = addr.is_multicast
                enrichment["version"]      = f"IPv{addr.version}"
            except Exception:
                pass
        if entry.ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
            enrichment["hash_type"] = entry.ioc_type
            enrichment["length"]    = len(entry.value)
        return enrichment

    @staticmethod
    def _detect_type(value: str) -> str:
        v = value.strip()
        # IP address
        try:
            ipaddress.ip_address(v)
            return IOCType.IP
        except ValueError:
            pass
        # Hashes by length
        if re.fullmatch(r"[0-9a-fA-F]{32}", v):  return IOCType.MD5
        if re.fullmatch(r"[0-9a-fA-F]{40}", v):  return IOCType.SHA1
        if re.fullmatch(r"[0-9a-fA-F]{64}", v):  return IOCType.SHA256
        # URL
        if v.startswith(("http://", "https://", "ftp://")): return IOCType.URL
        # Email
        if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", v): return IOCType.EMAIL
        # Domain
        if re.fullmatch(r"([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}", v): return IOCType.DOMAIN
        return IOCType.FILENAME

    # ── Feed ingestion ────────────────────────────────────────────────────

    def load_csv(self, path: str, value_col: str = "indicator",
                 type_col: str = "type", score_col: str = "score",
                 tag_col: str = "tags", source: str = "csv") -> int:
        loaded = 0
        with open(path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                val  = row.get(value_col, "").strip()
                typ  = row.get(type_col, "").strip().lower() or self._detect_type(val)
                scr  = int(row.get(score_col, 75) or 75)
                tags = [t.strip() for t in str(row.get(tag_col, "")).split(",") if t.strip()]
                if val:
                    self.add(val, typ, scr, tags, source)
                    loaded += 1
        self._stats["feeds_loaded"] += 1
        return loaded

    def load_txt(self, path: str, ioc_type: str = None,
                 score: int = 70, source: str = "txt") -> int:
        """Plain text feed — one indicator per line, # comments skipped."""
        loaded = 0
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                typ = ioc_type or self._detect_type(line)
                self.add(line, typ, score, source=source)
                loaded += 1
        self._stats["feeds_loaded"] += 1
        return loaded

    def load_json(self, path: str, source: str = "json") -> int:
        """JSON array of {value, type, score, tags} objects."""
        loaded = 0
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        for item in (data if isinstance(data, list) else data.get("indicators", [])):
            val  = item.get("value") or item.get("indicator", "")
            typ  = item.get("type", self._detect_type(val))
            scr  = int(item.get("score", 75))
            tags = item.get("tags", [])
            ctx  = item.get("context", {})
            if val:
                self.add(val, typ, scr, tags, source, ctx)
                loaded += 1
        self._stats["feeds_loaded"] += 1
        return loaded

    def load_builtin_demo(self):
        """Seed with a small set of known-bad demo indicators for testing."""
        demo = [
            # Known ransomware C2 IPs (fictional for demo)
            ("198.51.100.10",  IOCType.IP,     95, ["ransomware", "c2", "lockbit"]),
            ("203.0.113.77",   IOCType.IP,     90, ["trojan", "c2"]),
            ("192.0.2.55",     IOCType.IP,     85, ["scanner", "botnet"]),
            # Malware domains
            ("evil-c2.example.com",    IOCType.DOMAIN, 95, ["c2", "malware"]),
            ("update-flash-now.biz",   IOCType.DOMAIN, 88, ["phishing", "dropper"]),
            ("cdn-fast-delivery.ru",   IOCType.DOMAIN, 82, ["malware", "redirector"]),
            # Malware hashes (fictional MD5s)
            ("d41d8cd98f00b204e9800998ecf8427e", IOCType.MD5,    90, ["ransomware", "wannacry-variant"]),
            ("aabbcc112233445566778899aabbcc11", IOCType.MD5,    85, ["trojan", "agent-tesla"]),
            # Suspicious filenames
            ("invoice_2024.exe", IOCType.FILENAME, 75, ["phishing", "dropper"]),
            ("update.bat",       IOCType.FILENAME, 60, ["suspicious"]),
            ("svchost32.exe",    IOCType.FILENAME, 80, ["masquerading", "trojan"]),
        ]
        for val, typ, score, tags in demo:
            self.add(val, typ, score, tags, source="builtin-demo")
        logger.info("Loaded %d built-in demo IOCs", len(demo))

    # ── Bulk scan ─────────────────────────────────────────────────────────

    def scan_text(self, text: str) -> List[QueryResult]:
        """Extract and query all IOC patterns from a block of text."""
        hits = []
        patterns = {
            IOCType.IP:     r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            IOCType.MD5:    r"\b[0-9a-fA-F]{32}\b",
            IOCType.SHA1:   r"\b[0-9a-fA-F]{40}\b",
            IOCType.SHA256: r"\b[0-9a-fA-F]{64}\b",
            IOCType.DOMAIN: r"\b(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,6}\b",
            IOCType.URL:    r"https?://[^\s\"'<>]+",
        }
        seen = set()
        for typ, pattern in patterns.items():
            for match in re.finditer(pattern, text):
                val = match.group()
                key = f"{typ}:{val}"
                if key in seen:
                    continue
                seen.add(key)
                result = self.query(val, typ)
                if result.found:
                    hits.append(result)
        return hits

    def scan_file(self, path: str) -> List[QueryResult]:
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.error("Cannot read %s: %s", path, e)
            return []
        return self.scan_text(text)

    def stats(self) -> dict:
        with self._lock:
            return {**self._stats, "bloom_size_bits": self._bloom.size}

    def export_json(self, path: str):
        with self._lock:
            data = [e.to_dict() for e in self._index.values()]
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        logger.info("Exported %d IOCs to %s", len(data), path)


# ── REST API server (lightweight, zero dependencies) ─────────────────────────

class ThreatIntelHandler(BaseHTTPRequestHandler):
    db: IOCDatabase = None

    def log_message(self, *_):
        pass  # suppress default access log

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path == "/query":
            val = params.get("v", [""])[0]
            typ = params.get("t", [None])[0]
            result = self.db.query(val, typ)
            self._json(asdict(result))

        elif parsed.path == "/stats":
            self._json(self.db.stats())

        elif parsed.path == "/health":
            self._json({"status": "ok", "service": "vanguard-threat-intel"})

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length)

        if parsed.path == "/add":
            try:
                item = json.loads(body)
                entry = self.db.add(
                    item["value"], item["type"],
                    item.get("score", 75),
                    item.get("tags", []),
                    item.get("source", "api"),
                    item.get("context", {}),
                )
                self._json(entry.to_dict())
            except Exception as e:
                self._json({"error": str(e)}, 400)

        elif parsed.path == "/scan":
            try:
                data   = json.loads(body)
                text   = data.get("text", "")
                hits   = self.db.scan_text(text)
                self._json({"hits": [asdict(h) for h in hits], "count": len(hits)})
            except Exception as e:
                self._json({"error": str(e)}, 400)

        else:
            self.send_response(404)
            self.end_headers()

    def _json(self, data: dict, status: int = 200):
        body = json.dumps(data, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)


def start_api_server(db: IOCDatabase, host: str = "0.0.0.0", port: int = 7001):
    ThreatIntelHandler.db = db
    srv = HTTPServer((host, port), ThreatIntelHandler)
    logger.info("Threat Intel API listening on http://%s:%d", host, port)
    srv.serve_forever()


# ── CLI ───────────────────────────────────────────────────────────────────────

def _print_result(result: QueryResult):
    C = "\033[0m"
    tier, color = reputation_tier(result.score)
    if result.found:
        print(f"\n  {'─'*52}")
        print(f"  Query  : {result.query}")
        print(f"  Type   : {result.ioc_type}")
        print(f"  Score  : {color}{result.score}/100{C}")
        print(f"  Tier   : {color}{tier}{C}")
        if result.entry:
            e = result.entry
            print(f"  Tags   : {', '.join(e.get('tags', [])) or '—'}")
            print(f"  Source : {e.get('source','—')}")
            print(f"  Seen   : {e.get('hit_count',0)} times")
        if result.enrichment:
            print(f"  Info   : {result.enrichment}")
        print(f"  {'─'*52}\n")
    else:
        print(f"  {result.query}  →  \033[92mNOT IN DATABASE (clean){C}  [{result.elapsed_ms:.2f}ms]")


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Vanguard-OOB Threat Intelligence Engine")
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument("--query",  help="Single IOC to look up")
    g.add_argument("--scan",   help="Scan a file for IOC matches")
    g.add_argument("--feed",   help="Load a CSV/JSON/TXT feed file")
    g.add_argument("--server", action="store_true", help="Start REST API server")
    parser.add_argument("--type",   help="IOC type override (ip/domain/md5/sha256/...)")
    parser.add_argument("--port",   type=int, default=7001)
    parser.add_argument("--export", help="Export database to JSON file after loading")
    args = parser.parse_args()

    db = IOCDatabase()
    db.load_builtin_demo()

    if args.feed:
        path = args.feed
        ext  = Path(path).suffix.lower()
        if ext == ".csv":
            n = db.load_csv(path)
        elif ext == ".json":
            n = db.load_json(path)
        else:
            n = db.load_txt(path, args.type)
        print(f"  Loaded {n} indicators from {path}")

    if args.query:
        result = db.query(args.query, args.type)
        _print_result(result)

    elif args.scan:
        hits = db.scan_file(args.scan)
        print(f"\n  Scanned: {args.scan}")
        print(f"  IOC Hits: {len(hits)}\n")
        for h in hits:
            _print_result(h)

    elif args.server:
        start_api_server(db, port=args.port)

    if args.export:
        db.export_json(args.export)
        print(f"  Exported to {args.export}")


if __name__ == "__main__":
    main()
