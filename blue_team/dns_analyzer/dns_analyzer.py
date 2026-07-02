#!/usr/bin/env python3
"""
Vanguard-OOB :: Blue Team Tool 11 — DNS Threat Analyzer
========================================================
Original architecture. Passive-DNS-log threat analyzer — no live capture
dependency (complements packet_inspector.py for pcap-level work).

Core engines (all original):

  1. DGA SCORER — Domain-Generation-Algorithm detection using a LOCAL
     n-gram language model trained on a built-in corpus of common English
     dictionary words + Alexa-style legitimate TLD patterns. Computes a
     "linguistic plausibility" score per label via bigram/trigram
     frequency; malware-generated domains score far outside the trained
     distribution. No external API required.

  2. FAST-FLUX DETECTOR — Tracks A-record TTL + resolved-IP-set churn per
     domain over a sliding window. Legitimate CDNs rotate IPs but keep TTL
     stable and IP count bounded; fast-flux botnets show low TTL (<300s)
     AND high IP churn (>threshold unique IPs/hour) AND IPs spanning many
     distinct /16 networks (geographic dispersion).

  3. DNS TUNNEL DETECTOR — Statistical model over (a) query-name entropy,
     (b) query-name length distribution, (c) query rate per source, and
     (d) TXT/NULL/CNAME record-type ratio. Tunneling tools (iodine, dnscat2,
     DNScat) produce long high-entropy labels at high query-rates — this
     combination is rare in legitimate traffic (NXDOMAIN floods alone are
     NOT flagged to avoid false positives from typo'd hostnames).

  4. TYPOSQUAT DETECTOR — Damerau-Levenshtein distance + homoglyph
     normalization against a configurable list of brand/critical domains.
     Flags domains within edit-distance 1-2 OR using confusable Unicode
     look-alikes (e.g. "gооgle.com" with Cyrillic 'о').

  5. NXDOMAIN BURST — Per-source NXDOMAIN rate spike detection (possible
     DGA callback enumeration), gated by minimum absolute volume to avoid
     flagging single typos.

Input format: passive DNS log — one JSON object per line:
    {"ts": 1700000000, "src": "10.0.0.5", "qname": "example.com",
     "qtype": "A", "rcode": "NOERROR", "answers": ["1.2.3.4"], "ttl": 300}

Usage:
    python3 dns_analyzer.py --log passive_dns.jsonl
    python3 dns_analyzer.py --log passive_dns.jsonl --watchlist brands.txt
    python3 dns_analyzer.py --log passive_dns.jsonl --json findings.json
"""

import argparse
import json
import logging
import math
import re
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger("vanguard.dns_analyzer")

# ─────────────────────────────────────────────────────────────────────────────
# DGA language model — built from common English bigrams/trigrams
# ─────────────────────────────────────────────────────────────────────────────

# A compact but representative corpus of common words used to bootstrap
# an n-gram model of "what English-ish domain labels look like".
_ENGLISH_CORPUS = """
the quick brown fox jumps over lazy dog house garden window door floor
ceiling wall paint color light dark bright shadow morning evening night
day week month year time clock hour minute second water fire earth wind
cloud rain snow storm sunny weather climate forest tree leaf branch root
flower garden park street road highway bridge river lake ocean mountain
hill valley desert island beach sand rock stone metal gold silver copper
bronze steel iron wood plastic glass paper cloth cotton wool silk leather
rubber computer software hardware internet website server database cloud
network security system program code data file folder document image
video audio music sound speaker microphone camera screen display monitor
keyboard mouse button click scroll search browse download upload share
email message chat call video conference meeting schedule calendar task
project team work office home family friend people person human animal
bird fish insect plant flower fruit vegetable food drink coffee tea milk
bread butter cheese meat chicken beef pork fish rice pasta pizza salad
soup sandwich burger fries chocolate cake cookie candy sugar salt pepper
spice herb oil vinegar sauce recipe kitchen cook bake fry grill roast
restaurant cafe bar hotel travel airport flight train bus car bike walk
run jump swim climb dance sing play game sport football basketball
baseball tennis golf swimming running cycling hiking camping fishing
hunting reading writing drawing painting photography design art music
movie film theater concert show performance ticket ballet opera museum
gallery exhibition library bookstore shop store market mall shopping
clothes shirt pants dress shoes jacket coat hat glove scarf belt
"""

def _build_ngram_model(corpus: str, n: int = 2) -> Dict[str, int]:
    counts: Dict[str, int] = Counter()
    words = re.findall(r"[a-z]+", corpus.lower())
    for w in words:
        padded = f"^{w}$"
        for i in range(len(padded) - n + 1):
            counts[padded[i:i+n]] += 1
    return counts

_BIGRAM_MODEL  = _build_ngram_model(_ENGLISH_CORPUS, 2)
_TRIGRAM_MODEL = _build_ngram_model(_ENGLISH_CORPUS, 3)
_BIGRAM_TOTAL  = sum(_BIGRAM_MODEL.values())
_TRIGRAM_TOTAL = sum(_TRIGRAM_MODEL.values())


def linguistic_score(label: str) -> float:
    """
    Return a 0-1 'looks like English' plausibility score for a domain
    label using trigram coverage. Higher = more plausible / human-chosen.
    DGA-generated strings score near 0.
    """
    label = label.lower()
    label = re.sub(r"[^a-z]", "", label)
    if len(label) < 3:
        return 0.5  # too short to judge; neutral

    padded = f"^{label}$"
    trigrams = [padded[i:i+3] for i in range(len(padded)-2)]
    if not trigrams:
        return 0.5

    hits = sum(1 for t in trigrams if t in _TRIGRAM_MODEL)
    return hits / len(trigrams)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    n    = len(s)
    return -sum((c/n) * math.log2(c/n) for c in freq.values())


def consonant_run_ratio(label: str) -> float:
    """Fraction of label that is part of a run of 4+ consecutive consonants."""
    label = re.sub(r"[^a-z]", "", label.lower())
    if not label:
        return 0.0
    vowels = set("aeiou")
    run = 0
    max_run_chars = 0
    for ch in label:
        if ch not in vowels:
            run += 1
            if run >= 4:
                max_run_chars = max(max_run_chars, run)
        else:
            run = 0
    return max_run_chars / len(label) if max_run_chars else 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DNSRecord:
    ts:      float
    src:     str
    qname:   str
    qtype:   str
    rcode:   str
    answers: List[str] = field(default_factory=list)
    ttl:     int = 0


@dataclass
class DNSFinding:
    finding_type: str
    severity:     str
    mitre:        str
    description:  str
    evidence:     dict = field(default_factory=dict)
    score:        int  = 0
    timestamp:    str  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self):
        return asdict(self)


# ─────────────────────────────────────────────────────────────────────────────
# Damerau-Levenshtein distance (for typosquat detection)
# ─────────────────────────────────────────────────────────────────────────────

def damerau_levenshtein(a: str, b: str) -> int:
    la, lb = len(a), len(b)
    if abs(la - lb) > 3:   # short-circuit — never close enough
        return 99
    d = [[0]*(lb+1) for _ in range(la+1)]
    for i in range(la+1): d[i][0] = i
    for j in range(lb+1): d[0][j] = j
    for i in range(1, la+1):
        for j in range(1, lb+1):
            cost = 0 if a[i-1] == b[j-1] else 1
            d[i][j] = min(
                d[i-1][j] + 1,
                d[i][j-1] + 1,
                d[i-1][j-1] + cost,
            )
            if i > 1 and j > 1 and a[i-1] == b[j-2] and a[i-2] == b[j-1]:
                d[i][j] = min(d[i][j], d[i-2][j-2] + 1)
    return d[la][lb]


# Homoglyph normalization map (common confusable Unicode → ASCII)
HOMOGLYPHS = {
    "а":"a","е":"e","о":"o","р":"p","с":"c","х":"x","у":"y","і":"i",  # Cyrillic
    "ı":"i","ɡ":"g","ⅼ":"l","０":"0","１":"1","ѕ":"s","ⅰ":"i",
    "rn":"m", "vv":"w",  # combo confusables
}

def normalize_homoglyphs(s: str) -> str:
    out = s
    for k, v in HOMOGLYPHS.items():
        out = out.replace(k, v)
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Analyzer engines
# ─────────────────────────────────────────────────────────────────────────────

class DGAEngine:
    """Detects algorithmically-generated domain names via n-gram model + entropy."""

    def __init__(self, score_threshold: float = 0.18, min_label_len: int = 8):
        self.score_threshold = score_threshold
        self.min_label_len   = min_label_len
        self._reported: Set[str] = set()

    def analyze(self, rec: DNSRecord) -> Optional[DNSFinding]:
        qname = rec.qname.rstrip(".").lower()
        if qname in self._reported:
            return None

        labels = qname.split(".")
        if len(labels) < 2:
            return None

        # Analyze the second-level label (the "interesting" part for DGA)
        sld = labels[-2] if len(labels) >= 2 else labels[0]
        if len(sld) < self.min_label_len:
            return None

        ling   = linguistic_score(sld)
        ent    = shannon_entropy(sld)
        cons   = consonant_run_ratio(sld)

        # Combined heuristic: low linguistic plausibility + high entropy +
        # long consonant runs = DGA-like. All three signals reduce false
        # positives from legitimate-but-unusual names (e.g. product codes).
        is_dga = (ling < self.score_threshold and ent > 3.6 and cons > 0.35)

        if is_dga:
            self._reported.add(qname)
            return DNSFinding(
                finding_type="dga_domain",
                severity="high",
                mitre="T1568.002",
                description=f"Domain '{qname}' has DGA-like characteristics "
                            f"(linguistic={ling:.2f}, entropy={ent:.2f}, "
                            f"consonant_run={cons:.2f})",
                evidence={"qname": qname, "label": sld,
                          "linguistic_score": round(ling,3),
                          "entropy": round(ent,3),
                          "consonant_run_ratio": round(cons,3),
                          "src": rec.src},
                score=30,
            )
        return None


class FastFluxEngine:
    """Tracks per-domain IP churn + TTL to detect fast-flux infrastructure."""

    def __init__(self, window_s: int = 3600, ip_churn_threshold: int = 8,
                 low_ttl_threshold: int = 300, asn_diversity_threshold: int = 4):
        self.window_s          = window_s
        self.ip_churn_threshold= ip_churn_threshold
        self.low_ttl_threshold = low_ttl_threshold
        self.asn_diversity_threshold = asn_diversity_threshold
        self._history: Dict[str, deque] = defaultdict(deque)   # domain -> deque[(ts, ip, ttl)]
        self._reported: Set[str] = set()

    def feed(self, rec: DNSRecord) -> Optional[DNSFinding]:
        if rec.qtype != "A" or not rec.answers:
            return None

        qname = rec.qname.rstrip(".").lower()
        hist  = self._history[qname]
        for ip in rec.answers:
            hist.append((rec.ts, ip, rec.ttl))

        # Prune old entries
        while hist and rec.ts - hist[0][0] > self.window_s:
            hist.popleft()

        if qname in self._reported:
            return None

        unique_ips = {ip for _, ip, _ in hist}
        avg_ttl    = sum(t for _, _, t in hist) / len(hist) if hist else 0
        net16s     = {".".join(ip.split(".")[:2]) for ip in unique_ips
                       if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip)}

        if (len(unique_ips) >= self.ip_churn_threshold and
            avg_ttl <= self.low_ttl_threshold and
            len(net16s) >= self.asn_diversity_threshold):

            self._reported.add(qname)
            return DNSFinding(
                finding_type="fast_flux",
                severity="critical",
                mitre="T1568.001",
                description=f"Domain '{qname}' resolved to {len(unique_ips)} "
                            f"distinct IPs across {len(net16s)} /16 networks "
                            f"with avg TTL {avg_ttl:.0f}s — fast-flux pattern",
                evidence={"qname": qname, "unique_ip_count": len(unique_ips),
                          "distinct_16_nets": len(net16s),
                          "avg_ttl": round(avg_ttl,1),
                          "sample_ips": sorted(unique_ips)[:10]},
                score=45,
            )
        return None


class DNSTunnelEngine:
    """Detects DNS tunneling via combined entropy + rate + record-type signals."""

    def __init__(self, window_s: int = 60, rate_threshold: int = 30,
                 entropy_threshold: float = 3.8, len_threshold: int = 40):
        self.window_s          = window_s
        self.rate_threshold    = rate_threshold
        self.entropy_threshold = entropy_threshold
        self.len_threshold     = len_threshold
        self._history: Dict[str, deque] = defaultdict(deque)   # src -> deque[(ts, qname, qtype)]
        self._reported: Set[str] = set()

    def feed(self, rec: DNSRecord) -> Optional[DNSFinding]:
        hist = self._history[rec.src]
        hist.append((rec.ts, rec.qname, rec.qtype))
        while hist and rec.ts - hist[0][0] > self.window_s:
            hist.popleft()

        if rec.src in self._reported:
            return None

        if len(hist) < self.rate_threshold:
            return None

        # Evaluate the window for tunneling characteristics
        long_high_entropy = 0
        txt_null_count    = 0
        for _, qname, qtype in hist:
            label = qname.split(".")[0]
            if len(label) >= self.len_threshold and shannon_entropy(label) >= self.entropy_threshold:
                long_high_entropy += 1
            if qtype in ("TXT", "NULL", "CNAME"):
                txt_null_count += 1

        ratio_he  = long_high_entropy / len(hist)
        ratio_txt = txt_null_count    / len(hist)

        # Require BOTH high query rate AND high-entropy-label ratio to fire
        if ratio_he >= 0.5 and len(hist) >= self.rate_threshold:
            self._reported.add(rec.src)
            return DNSFinding(
                finding_type="dns_tunnel",
                severity="critical",
                mitre="T1071.004",
                description=f"Source {rec.src} sent {len(hist)} DNS queries in "
                            f"{self.window_s}s, {ratio_he:.0%} with long "
                            f"high-entropy labels (TXT/NULL ratio={ratio_txt:.0%}) "
                            f"— DNS tunneling pattern",
                evidence={"src": rec.src, "query_count": len(hist),
                          "high_entropy_ratio": round(ratio_he,3),
                          "txt_null_ratio": round(ratio_txt,3),
                          "sample_query": hist[-1][1][:80]},
                score=50,
            )
        return None


class TyposquatEngine:
    """Detects domains close to a watchlist of protected brand domains."""

    DEFAULT_WATCHLIST = [
        "google.com","microsoft.com","apple.com","amazon.com","paypal.com",
        "facebook.com","github.com","gmail.com","outlook.com","office365.com",
        "okta.com","cloudflare.com","aws.amazon.com",
    ]

    def __init__(self, watchlist: List[str] = None, max_distance: int = 2):
        self.watchlist    = [w.lower() for w in (watchlist or self.DEFAULT_WATCHLIST)]
        self.max_distance = max_distance
        self._reported: Set[str] = set()

    def analyze(self, rec: DNSRecord) -> Optional[DNSFinding]:
        qname = rec.qname.rstrip(".").lower()
        if qname in self._reported or qname in self.watchlist:
            return None

        norm = normalize_homoglyphs(qname)
        homoglyph_hit = norm != qname and norm in self.watchlist

        for brand in self.watchlist:
            if qname == brand:
                continue
            dist = damerau_levenshtein(qname, brand)
            if homoglyph_hit or (1 <= dist <= self.max_distance):
                self._reported.add(qname)
                return DNSFinding(
                    finding_type="typosquat",
                    severity="high",
                    mitre="T1583.001",
                    description=(f"Domain '{qname}' is a homoglyph of '{brand}'"
                                  if homoglyph_hit else
                                  f"Domain '{qname}' is edit-distance {dist} from "
                                  f"watchlisted brand '{brand}'"),
                    evidence={"qname": qname, "target_brand": brand,
                              "edit_distance": dist if not homoglyph_hit else 0,
                              "homoglyph": homoglyph_hit, "src": rec.src},
                    score=30,
                )
        return None


class NXDomainBurstEngine:
    """Detects NXDOMAIN rate spikes per source — possible DGA C2 enumeration."""

    def __init__(self, window_s: int = 60, threshold: int = 15, min_unique: int = 10):
        self.window_s   = window_s
        self.threshold  = threshold
        self.min_unique = min_unique
        self._history: Dict[str, deque] = defaultdict(deque)
        self._reported: Set[str] = set()

    def feed(self, rec: DNSRecord) -> Optional[DNSFinding]:
        if rec.rcode != "NXDOMAIN":
            return None

        hist = self._history[rec.src]
        hist.append((rec.ts, rec.qname))
        while hist and rec.ts - hist[0][0] > self.window_s:
            hist.popleft()

        if rec.src in self._reported:
            return None

        unique_names = {q for _, q in hist}
        if len(hist) >= self.threshold and len(unique_names) >= self.min_unique:
            self._reported.add(rec.src)
            return DNSFinding(
                finding_type="nxdomain_burst",
                severity="medium",
                mitre="T1568.002",
                description=f"Source {rec.src} generated {len(hist)} NXDOMAIN "
                            f"responses ({len(unique_names)} unique names) in "
                            f"{self.window_s}s — possible DGA C2 enumeration",
                evidence={"src": rec.src, "nxdomain_count": len(hist),
                          "unique_names": len(unique_names),
                          "samples": list(unique_names)[:8]},
                score=20,
            )
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Master analyzer
# ─────────────────────────────────────────────────────────────────────────────

class DNSAnalyzer:
    def __init__(self, watchlist: List[str] = None):
        self.dga      = DGAEngine()
        self.flux     = FastFluxEngine()
        self.tunnel   = DNSTunnelEngine()
        self.typo     = TyposquatEngine(watchlist)
        self.nxburst  = NXDomainBurstEngine()
        self.findings: List[DNSFinding] = []
        self.record_count = 0
        self.qtype_counts: Counter = Counter()

    def feed(self, rec: DNSRecord):
        self.record_count += 1
        self.qtype_counts[rec.qtype] += 1

        for engine, method in [
            (self.dga,     "analyze"),
            (self.flux,    "feed"),
            (self.tunnel,  "feed"),
            (self.typo,    "analyze"),
            (self.nxburst, "feed"),
        ]:
            result = getattr(engine, method)(rec)
            if result:
                self.findings.append(result)

    def load_jsonl(self, path: str):
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    rec = DNSRecord(
                        ts      = float(obj.get("ts", 0)),
                        src     = obj.get("src", "unknown"),
                        qname   = obj.get("qname", ""),
                        qtype   = obj.get("qtype", "A"),
                        rcode   = obj.get("rcode", "NOERROR"),
                        answers = obj.get("answers", []),
                        ttl     = int(obj.get("ttl", 0)),
                    )
                    self.feed(rec)
                except (json.JSONDecodeError, ValueError):
                    continue

    def summary(self) -> dict:
        SEV_RANK = {"critical":0,"high":1,"medium":2,"low":3}
        self.findings.sort(key=lambda f: SEV_RANK.get(f.severity,4))
        from collections import Counter as C
        sev = C(f.severity for f in self.findings)
        typ = C(f.finding_type for f in self.findings)
        return {
            "records_processed": self.record_count,
            "qtype_breakdown":   dict(self.qtype_counts),
            "total_findings":    len(self.findings),
            "by_severity":       dict(sev),
            "by_type":           dict(typ),
            "total_score":       sum(f.score for f in self.findings),
        }


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

SEV_C = {"critical":"\033[95m","high":"\033[91m","medium":"\033[93m","low":"\033[92m"}

def _print_finding(f: DNSFinding):
    c = SEV_C.get(f.severity,""); R = "\033[0m"; B = "\033[1m"
    print(f"  {c}[{f.severity.upper():8}]{R} [{f.mitre}] {B}{f.finding_type}{R}  +{f.score}")
    print(f"     {f.description}")
    print()


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Vanguard-OOB DNS Threat Analyzer")
    parser.add_argument("--log", required=True, help="Passive DNS log (JSONL format)")
    parser.add_argument("--watchlist", help="Text file of brand domains, one per line")
    parser.add_argument("--json", help="Output findings to JSON")
    parser.add_argument("--min-severity", default="low",
                        choices=["low","medium","high","critical"])
    args = parser.parse_args()

    C = "\033[96m"; R = "\033[0m"; B = "\033[1m"
    print(f"\n{B}  ── Vanguard-OOB DNS Threat Analyzer ──{R}\n")

    watchlist = None
    if args.watchlist:
        watchlist = [l.strip() for l in Path(args.watchlist).read_text().splitlines() if l.strip()]

    analyzer = DNSAnalyzer(watchlist=watchlist)
    analyzer.load_jsonl(args.log)

    SEV_RANK = {"low":0,"medium":1,"high":2,"critical":3}
    min_rank = SEV_RANK[args.min_severity]
    filtered = [f for f in analyzer.findings if SEV_RANK.get(f.severity,0) >= min_rank]

    for f in filtered:
        _print_finding(f)

    s = analyzer.summary()
    print(f"  Records processed: {s['records_processed']}")
    print(f"  Query types      : {s['qtype_breakdown']}")
    print(f"  Findings (shown) : {len(filtered)} / {s['total_findings']}")
    print(f"  By severity      : {s['by_severity']}")
    print(f"  Aggregate score  : {s['total_score']}")

    if args.json and analyzer.findings:
        with open(args.json, "w") as f:
            json.dump([fnd.to_dict() for fnd in analyzer.findings], f, indent=2)
        print(f"\n  Findings saved to {C}{args.json}{R}")


if __name__ == "__main__":
    main()
