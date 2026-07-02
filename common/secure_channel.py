#!/usr/bin/env python3
"""
Vanguard-OOB :: Secure Channel
================================
Authenticated, replay-resistant transport shared by the Sentry Agent (sender)
and the Control Center (receiver).

WHY THIS EXISTS
---------------
The previous build used a single hard-coded XOR key. That is not encryption:
- XOR with a repeating key is trivially broken (known-plaintext recovers the key).
- The same key lived in the agent, controller AND the public test harness.
- There was no authentication, so anyone on the network could forge telemetry
  and force-isolate a healthy VM, and no replay protection, so a captured frame
  could be replayed forever.

THIS MODULE FIXES ALL OF THAT, with zero hard dependencies:

  1. AEAD encryption
       - AES-256-GCM when the `cryptography` package is present (preferred).
       - A stdlib-only HMAC-SHA256 "encrypt-then-MAC" AEAD otherwise, so the
         system is NEVER weaker than authenticated-and-encrypted, even with no
         third-party packages installed.
  2. Per-agent keys
       - Every agent identity derives its OWN key from a master secret via
         HKDF-SHA256. Compromising one agent's key does not expose the fleet,
         and the controller can pin/expect a specific agent identity.
  3. Replay protection
       - Every frame carries a random 96-bit nonce + a monotonic counter +
         a wall-clock timestamp. The receiver rejects: stale frames (outside a
         skew window), counter regressions, and any nonce it has already seen.
  4. Identity binding
       - The agent identity and timestamp are bound into the authenticated
         associated-data, so an attacker cannot relabel a frame to a different
         vm_id (the old "send events tagged as another VM" attack is dead).

WIRE FORMAT  (all big-endian, length-prefixed by the caller's framing layer)
----------------------------------------------------------------------------
    magic(4) = b"VG02"
    version(1)
    mode(1)            0x01 = AES-256-GCM,  0x02 = HMAC-AEAD
    id_len(1) | agent_id(id_len)
    counter(8)
    timestamp(8)       IEEE-754 double, unix seconds
    nonce(12)
    ct_len(4) | ciphertext(ct_len)        (AEAD: includes the auth tag)

The associated data authenticated (but not encrypted) is:
    magic | version | mode | agent_id | counter | timestamp | nonce
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import struct
import threading
import time
from collections import deque
from typing import Dict, Optional, Tuple

MAGIC = b"VG02"
VERSION = 2

MODE_AESGCM = 0x01
MODE_HMAC = 0x02

# How far a frame's timestamp may drift from the receiver's clock (seconds).
DEFAULT_MAX_SKEW = 120.0
# How many recent nonces the receiver remembers per agent (replay window).
REPLAY_CACHE_SIZE = 4096

# ---------------------------------------------------------------------------
# Optional AES-GCM backend
# ---------------------------------------------------------------------------
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore

    _HAVE_AESGCM = True
except Exception:  # pragma: no cover - exercised only when lib missing
    _HAVE_AESGCM = False


# ---------------------------------------------------------------------------
# Key derivation (HKDF-SHA256, RFC 5869) — stdlib only
# ---------------------------------------------------------------------------

def _hkdf(master: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """Derive `length` bytes from `master` using HKDF-SHA256."""
    if not salt:
        salt = b"\x00" * hashlib.sha256().digest_size
    prk = hmac.new(salt, master, hashlib.sha256).digest()
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def derive_agent_keys(master_secret: bytes, agent_id: str) -> Tuple[bytes, bytes]:
    """
    Derive (enc_key, mac_key) unique to this agent identity.
    Two independent keys so confidentiality and integrity never share material.
    """
    info = b"vanguard-oob|agent|" + agent_id.encode("utf-8")
    enc_key = _hkdf(master_secret, b"vanguard-enc", info, 32)
    mac_key = _hkdf(master_secret, b"vanguard-mac", info, 32)
    return enc_key, mac_key


def load_master_secret(env_var: str = "VANGUARD_MASTER_KEY",
                       fallback_file: Optional[str] = None) -> bytes:
    """
    Resolve the master secret in priority order:
      1. environment variable (hex or raw)
      2. a key file on disk
      3. a generated dev key (printed once, NOT for production)
    """
    val = os.environ.get(env_var)
    if val:
        try:
            return bytes.fromhex(val.strip())
        except ValueError:
            return val.encode("utf-8")
    if fallback_file and os.path.exists(fallback_file):
        with open(fallback_file, "rb") as f:
            data = f.read().strip()
        try:
            return bytes.fromhex(data.decode().strip())
        except Exception:
            return data
    # Deterministic dev key so agent + controller match out-of-the-box for demos.
    # Production deployments MUST set VANGUARD_MASTER_KEY.
    return hashlib.sha256(b"vanguard-oob-development-master-key-CHANGE-ME").digest()


# ---------------------------------------------------------------------------
# HMAC-based AEAD fallback (stdlib only) — encrypt-then-MAC, CTR-style keystream
# ---------------------------------------------------------------------------

def _keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    """A PRF-based keystream: HMAC-SHA256(enc_key, nonce || block_counter)."""
    out = bytearray()
    block = 0
    while len(out) < length:
        out += hmac.new(enc_key, nonce + struct.pack(">I", block), hashlib.sha256).digest()
        block += 1
    return bytes(out[:length])


def _hmac_seal(enc_key: bytes, mac_key: bytes, nonce: bytes,
               plaintext: bytes, aad: bytes) -> bytes:
    ks = _keystream(enc_key, nonce, len(plaintext))
    ct = bytes(p ^ k for p, k in zip(plaintext, ks))
    tag = hmac.new(mac_key, aad + ct, hashlib.sha256).digest()
    return ct + tag


def _hmac_open(enc_key: bytes, mac_key: bytes, nonce: bytes,
               blob: bytes, aad: bytes) -> Optional[bytes]:
    if len(blob) < 32:
        return None
    ct, tag = blob[:-32], blob[-32:]
    expected = hmac.new(mac_key, aad + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, tag):
        return None  # authentication failure
    ks = _keystream(enc_key, nonce, len(ct))
    return bytes(c ^ k for c, k in zip(ct, ks))


# ---------------------------------------------------------------------------
# Sender side
# ---------------------------------------------------------------------------

class SecureSender:
    """Seals JSON payloads for one agent identity. Thread-safe."""

    def __init__(self, master_secret: bytes, agent_id: str, prefer_aesgcm: bool = True):
        self.agent_id = agent_id
        self.enc_key, self.mac_key = derive_agent_keys(master_secret, agent_id)
        self.mode = MODE_AESGCM if (prefer_aesgcm and _HAVE_AESGCM) else MODE_HMAC
        self._counter = int(time.time() * 1000) & ((1 << 63) - 1)  # monotonic-ish start
        self._lock = threading.Lock()

    def seal(self, payload: dict) -> bytes:
        plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        with self._lock:
            self._counter += 1
            counter = self._counter
        nonce = os.urandom(12)
        ts = time.time()
        aid = self.agent_id.encode("utf-8")
        header = (
            MAGIC
            + bytes([VERSION, self.mode, len(aid)])
            + aid
            + struct.pack(">Q", counter)
            + struct.pack(">d", ts)
            + nonce
        )
        aad = header  # everything before the ciphertext is authenticated

        if self.mode == MODE_AESGCM:
            ct = AESGCM(self.enc_key).encrypt(nonce, plaintext, aad)
        else:
            ct = _hmac_seal(self.enc_key, self.mac_key, nonce, plaintext, aad)

        return header + struct.pack(">I", len(ct)) + ct


# ---------------------------------------------------------------------------
# Receiver side
# ---------------------------------------------------------------------------

class AuthError(Exception):
    """Raised when a frame fails authentication, replay, or skew checks."""


class SecureReceiver:
    """
    Opens frames from any number of agents, enforcing authentication,
    monotonic counters, timestamp skew, and nonce-replay rejection.
    Thread-safe.
    """

    def __init__(self, master_secret: bytes, max_skew: float = DEFAULT_MAX_SKEW,
                 allowed_agents: Optional[set] = None):
        self.master = master_secret
        self.max_skew = max_skew
        self.allowed_agents = allowed_agents  # None = accept any identity
        self._lock = threading.Lock()
        self._keys: Dict[str, Tuple[bytes, bytes]] = {}
        self._last_counter: Dict[str, int] = {}
        self._nonce_cache: Dict[str, "OrderedSet"] = {}

    def _keys_for(self, agent_id: str) -> Tuple[bytes, bytes]:
        if agent_id not in self._keys:
            self._keys[agent_id] = derive_agent_keys(self.master, agent_id)
        return self._keys[agent_id]

    def open(self, frame: bytes) -> Tuple[str, dict]:
        """Return (agent_id, payload) or raise AuthError."""
        try:
            if frame[:4] != MAGIC:
                raise AuthError("bad magic")
            version, mode, id_len = frame[4], frame[5], frame[6]
            off = 7
            aid_b = frame[off:off + id_len]; off += id_len
            agent_id = aid_b.decode("utf-8")
            counter = struct.unpack(">Q", frame[off:off + 8])[0]; off += 8
            ts = struct.unpack(">d", frame[off:off + 8])[0]; off += 8
            nonce = frame[off:off + 12]; off += 12
            header_end = off               # AAD = everything up to (not incl.) ct_len
            ct_len = struct.unpack(">I", frame[off:off + 4])[0]; off += 4
            ct = frame[off:off + ct_len]
        except (IndexError, struct.error, UnicodeDecodeError) as e:
            raise AuthError(f"malformed frame: {e}")

        if version != VERSION:
            raise AuthError(f"unsupported version {version}")
        if self.allowed_agents is not None and agent_id not in self.allowed_agents:
            raise AuthError(f"unknown agent identity '{agent_id}'")

        # Timestamp skew check (anti-replay, part 1)
        now = time.time()
        if abs(now - ts) > self.max_skew:
            raise AuthError(f"timestamp skew too large ({now - ts:+.1f}s)")

        enc_key, mac_key = self._keys_for(agent_id)
        aad = frame[:header_end]  # magic..nonce — exactly what the sender authenticated

        if mode == MODE_AESGCM:
            if not _HAVE_AESGCM:
                raise AuthError("AES-GCM frame received but library unavailable")
            try:
                plaintext = AESGCM(enc_key).decrypt(nonce, ct, aad)
            except Exception:
                raise AuthError("AEAD authentication failed")
        elif mode == MODE_HMAC:
            plaintext = _hmac_open(enc_key, mac_key, nonce, ct, aad)
            if plaintext is None:
                raise AuthError("HMAC authentication failed")
        else:
            raise AuthError(f"unknown mode {mode}")

        # Replay protection (part 2): counter monotonicity + nonce uniqueness
        with self._lock:
            last = self._last_counter.get(agent_id, -1)
            cache = self._nonce_cache.setdefault(agent_id, OrderedSet(REPLAY_CACHE_SIZE))
            if nonce in cache:
                raise AuthError("replayed nonce")
            if counter <= last:
                raise AuthError(f"counter regression ({counter} <= {last})")
            self._last_counter[agent_id] = counter
            cache.add(nonce)

        try:
            payload = json.loads(plaintext.decode("utf-8"))
        except Exception as e:
            raise AuthError(f"payload not valid JSON: {e}")

        # Identity binding: the payload's vm_id MUST equal the authenticated agent_id.
        claimed = payload.get("vm_id")
        if claimed is not None and claimed != agent_id:
            raise AuthError(
                f"vm_id spoof attempt: payload claims '{claimed}' "
                f"but authenticated as '{agent_id}'"
            )
        payload["vm_id"] = agent_id  # force-bind to the authenticated identity
        return agent_id, payload


class OrderedSet:
    """Bounded FIFO set for nonce-replay caching (small, dependency-free).

    Uses a deque for the eviction order so removing the oldest entry is O(1)
    (deque.popleft) instead of O(n) (list.pop(0), which shifts every element).
    """

    def __init__(self, maxlen: int):
        self.maxlen = maxlen
        self._set: set = set()
        self._order: "deque" = deque()

    def __contains__(self, item) -> bool:
        return item in self._set

    def add(self, item):
        if item in self._set:
            return
        self._set.add(item)
        self._order.append(item)
        if len(self._order) > self.maxlen:
            old = self._order.popleft()
            self._set.discard(old)


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    master = load_master_secret()
    print(f"AES-GCM backend available: {_HAVE_AESGCM}")

    sender = SecureSender(master, "prod-vm-01")
    receiver = SecureReceiver(master)

    frame = sender.seal({"vm_id": "prod-vm-01", "batch": [{"event_type": "heartbeat"}]})
    aid, payload = receiver.open(frame)
    print(f"[OK] round-trip: agent={aid} payload={payload}")

    # Replay must be rejected
    try:
        receiver.open(frame)
        print("[FAIL] replay was accepted!")
    except AuthError as e:
        print(f"[OK] replay rejected: {e}")

    # vm_id spoof must be rejected
    spoof = SecureSender(master, "prod-vm-01")
    bad = spoof.seal({"vm_id": "prod-vm-99", "batch": []})
    try:
        receiver.open(bad)
        print("[FAIL] vm_id spoof accepted!")
    except AuthError as e:
        print(f"[OK] vm_id spoof rejected: {e}")

    # Tamper must be rejected
    sender2 = SecureSender(master, "prod-vm-02")
    f2 = bytearray(sender2.seal({"vm_id": "prod-vm-02", "batch": []}))
    f2[-1] ^= 0xFF
    try:
        receiver.open(bytes(f2))
        print("[FAIL] tampered frame accepted!")
    except AuthError as e:
        print(f"[OK] tamper rejected: {e}")
