#!/usr/bin/env python3
"""
Vanguard-OOB :: Geo + Threat-Intel Enrichment
===============================================
Enriches destination IPs seen in `network` telemetry with:
  - an approximate geographic location (for the live attack map), and
  - a local threat-intelligence verdict.

HONESTY NOTE (important — say this in interviews):
This module does NOT call any external GeoIP API or download MaxMind data
(the framework is deliberately self-contained and offline). It uses a small,
built-in table of well-known network blocks plus a deterministic placement for
unknown IPs so the attack map is populated for demos. For production accuracy,
drop in a MaxMind GeoLite2 database and replace `geolocate()` — the dashboard
contract (lat, lon, country) stays the same. Unknown IPs are clearly flagged
`approx: true` so nothing is presented as more precise than it is.

The threat-intel verdict reuses the same idea as the blue_team `threat_intel`
tool: a local IOC set. Private/reserved ranges are always "internal/clean".
"""

from __future__ import annotations

import hashlib
import ipaddress
from typing import Dict, Optional

# A few real, well-known anchors so common demo IPs land somewhere sensible.
# (city-level centroids; country codes are ISO-3166-alpha2)
_KNOWN_BLOCKS = [
    ("8.8.8.0/24",      "US", "Mountain View",  37.4, -122.1),
    ("1.1.1.0/24",      "AU", "Sydney",         -33.9,  151.2),
    ("185.220.0.0/16",  "DE", "Frankfurt",       50.1,    8.7),   # common Tor exit space
    ("45.135.0.0/16",   "RU", "Moscow",          55.8,   37.6),
    ("103.0.0.0/8",     "CN", "Beijing",         39.9,  116.4),
    ("196.0.0.0/8",     "ZA", "Johannesburg",   -26.2,   28.0),
    ("191.0.0.0/8",     "BR", "Sao Paulo",      -23.5,  -46.6),
    ("80.0.0.0/8",      "GB", "London",          51.5,   -0.1),
]

# Tiny local IOC set (mirrors the threat_intel tool's idea).
_MALICIOUS_IPS = {
    "185.220.1.9", "45.135.232.4", "103.224.182.250", "194.147.78.11",
}
_MALICIOUS_BLOCKS = ["185.220.0.0/16", "45.135.0.0/16"]


def _is_internal(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
    except ValueError:
        return False


def geolocate(ip: str) -> Dict:
    """Return {lat, lon, country, city, approx} for an IP (offline)."""
    if _is_internal(ip):
        return {"lat": 0.0, "lon": 0.0, "country": "INTERNAL",
                "city": "internal", "approx": False}
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"lat": 0.0, "lon": 0.0, "country": "??", "city": "invalid", "approx": True}

    for cidr, cc, city, lat, lon in _KNOWN_BLOCKS:
        if addr in ipaddress.ip_network(cidr):
            return {"lat": lat, "lon": lon, "country": cc, "city": city, "approx": False}

    # Unknown IP: deterministic, clearly-approximate placement so the map isn't empty.
    h = hashlib.sha256(ip.encode()).digest()
    lat = (h[0] / 255.0) * 140.0 - 70.0      # -70..70
    lon = (h[1] / 255.0) * 360.0 - 180.0     # -180..180
    return {"lat": round(lat, 2), "lon": round(lon, 2),
            "country": "??", "city": "unknown", "approx": True}


def ti_verdict(ip: str) -> Dict:
    """Local threat-intel verdict for an IP."""
    if _is_internal(ip):
        return {"verdict": "internal", "score": 0, "source": "rfc1918"}
    if ip in _MALICIOUS_IPS:
        return {"verdict": "malicious", "score": 95, "source": "local-ioc"}
    try:
        addr = ipaddress.ip_address(ip)
        for cidr in _MALICIOUS_BLOCKS:
            if addr in ipaddress.ip_network(cidr):
                return {"verdict": "suspicious", "score": 70, "source": "local-block"}
    except ValueError:
        return {"verdict": "invalid", "score": 0, "source": "-"}
    return {"verdict": "unknown", "score": 30, "source": "no-data"}


def enrich_ip(ip: str) -> Dict:
    """Full enrichment for one IP: geo + threat-intel."""
    geo = geolocate(ip)
    ti = ti_verdict(ip)
    return {"ip": ip, **{"geo": geo, "intel": ti}}


if __name__ == "__main__":
    for ip in ["8.8.8.8", "185.220.1.9", "45.135.232.4", "10.0.0.5", "203.0.113.7", "garbage"]:
        e = enrich_ip(ip)
        g, t = e["geo"], e["intel"]
        print(f"  {ip:18} {g['country']:8} ({g['city']:12}) approx={g['approx']!s:5} "
              f"-> {t['verdict']:10} score={t['score']}")
