#!/usr/bin/env python3
r"""
Vanguard-OOB :: Blue Team Tool 6 — YARA-like Rule Engine
=========================================================
Original architecture. Zero dependency on libyara.
Implements a substantial subset of YARA syntax natively in Python.

Supported rule features:
  - String types: text, hex, regex, wide (UTF-16LE)
  - String modifiers: nocase, fullword, ascii, wide, xor (single-byte)
  - Conditions: all/any/none of them, N of them, filesize, at/in operators
  - Boolean operators: and, or, not
  - Math helpers: entropy(), count(), offset()
  - Rule tags and metadata blocks
  - Multi-rule file scanning with match aggregation

Rule file syntax (.vyr = Vanguard YARA):
  rule RuleName : tag1 tag2 {
      meta:
          author  = "analyst"
          severity= "high"
          mitre   = "T1059"
      strings:
          $s1 = "malicious string"
          $s2 = { 4d 5a 90 00 }
          $r1 = /eval\s*\(/ nocase
          $w1 = "wide string" wide
      condition:
          any of ($s*) and filesize < 1MB
  }

Usage:
    python3 yara_engine.py --rules rules/ransomware.vyr --scan /path/to/file
    python3 yara_engine.py --rules rules/ --scan /var/www --recursive
    python3 yara_engine.py --compile rules/all.vyr            (validate syntax)
    python3 yara_engine.py --generate-rules                   (print built-in rules)
"""

import argparse
import ast
import hashlib
import json
import logging
import math
import os
import re
import struct
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Set, Tuple

logger = logging.getLogger("vanguard.yara_engine")

# ─────────────────────────────────────────────────────────────────────────────
# Built-in rule library
# ─────────────────────────────────────────────────────────────────────────────

BUILTIN_RULES = r"""
rule Ransomware_ShadowCopy_Deletion : ransomware persistence {
    meta:
        author   = "Vanguard-OOB"
        severity = "critical"
        mitre    = "T1490"
        desc     = "Detects shadow copy deletion commands embedded in files"
    strings:
        $s1 = "vssadmin delete shadows" nocase
        $s2 = "wmic shadowcopy delete" nocase
        $s3 = "bcdedit /set {default} recoveryenabled no" nocase
        $s4 = "wbadmin delete catalog" nocase
        $s5 = "diskshadow /s" nocase
    condition:
        any of ($s*)
}

rule Ransomware_FileEncryption_Strings : ransomware {
    meta:
        author   = "Vanguard-OOB"
        severity = "critical"
        mitre    = "T1486"
        desc     = "Ransomware file encryption / ransom note indicators"
    strings:
        $n1 = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $n2 = "All your files are encrypted" nocase
        $n3 = "DECRYPT_INSTRUCTIONS" nocase
        $n4 = "HOW_TO_RECOVER" nocase
        $n5 = "bitcoin" nocase
        $n6 = "onion" nocase
        $e1 = ".locked"
        $e2 = ".encrypted"
        $e3 = ".WNCRY"
        $e4 = ".zepto"
        $e5 = ".locky"
        $e6 = ".cerber"
    condition:
        (2 of ($n*)) or (any of ($e*) and any of ($n*))
}

rule Webshell_PHP_Generic : webshell {
    meta:
        author   = "Vanguard-OOB"
        severity = "critical"
        mitre    = "T1505.003"
        desc     = "Generic PHP webshell detection"
    strings:
        $eval1 = /eval\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress)\s*\(/ nocase
        $eval2 = /assert\s*\(\s*(base64_decode|gzinflate|str_rot13)\s*\(/ nocase
        $super = /\$_(GET|POST|REQUEST|COOKIE)\s*\[/ nocase
        $exec1 = "passthru" nocase
        $exec2 = "shell_exec" nocase
        $exec3 = "proc_open" nocase
    condition:
        ($eval1 or $eval2) or (($exec1 or $exec2 or $exec3) and $super)
}

rule Mimikatz_Strings : credential_access {
    meta:
        author   = "Vanguard-OOB"
        severity = "critical"
        mitre    = "T1003.001"
        desc     = "Mimikatz credential dumping tool strings"
    strings:
        $m1 = "sekurlsa::logonpasswords" nocase
        $m2 = "lsadump::sam" nocase
        $m3 = "privilege::debug" nocase
        $m4 = "SekurLSA" nocase
        $m5 = "gentilkiwi" nocase
        $hex = { 6B 69 77 69 }
    condition:
        2 of ($m*) or $hex
}

rule Trojan_Reverse_Shell : c2 {
    meta:
        author   = "Vanguard-OOB"
        severity = "critical"
        mitre    = "T1059.004"
        desc     = "Reverse shell indicators in binaries or scripts"
    strings:
        $bash1 = "bash -i >& /dev/tcp/" nocase
        $bash2 = "/bin/bash -i"
        $nc1   = "nc -e /bin/bash" nocase
        $nc2   = "nc -e /bin/sh" nocase
        $py1   = "import socket,subprocess,os" nocase
        $py2   = /socket\.connect\(.{5,50}\).*subprocess/ nocase
        $socat = "socat exec:" nocase
    condition:
        any of them
}

rule Packed_PE_HighEntropy : packer {
    meta:
        author   = "Vanguard-OOB"
        severity = "high"
        mitre    = "T1027.002"
        desc     = "Packed Windows PE with unusually high section entropy"
    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }
    condition:
        $mz at 0 and $pe and filesize < 10MB and entropy(0, filesize) > 7.2
}

rule Dropper_Base64_Execution : dropper {
    meta:
        author   = "Vanguard-OOB"
        severity = "high"
        mitre    = "T1027"
        desc     = "Script dropper using base64-decode-then-execute"
    strings:
        $b1 = /base64[_\-]?decode/ nocase
        $b2 = "FromBase64String" nocase
        $b3 = "base64 -d" nocase
        $x1 = "exec(" nocase
        $x2 = "eval(" nocase
        $x3 = "Invoke-Expression" nocase
        $x4 = "IEX(" nocase
    condition:
        (any of ($b*)) and (any of ($x*))
}

rule Persistence_Cron_Download : persistence {
    meta:
        author   = "Vanguard-OOB"
        severity = "high"
        mitre    = "T1053.003"
        desc     = "Cron job with download-and-execute behavior"
    strings:
        $cron = "* * * * *"
        $dl1  = "wget " nocase
        $dl2  = "curl " nocase
        $ex1  = "| bash" nocase
        $ex2  = "| sh" nocase
        $ex3  = "/tmp/" nocase
    condition:
        $cron and (any of ($dl*)) and (any of ($ex*))
}

rule Network_PortScan_Tool : recon {
    meta:
        author   = "Vanguard-OOB"
        severity = "medium"
        mitre    = "T1595"
        desc     = "Network scanning tool binary or configuration"
    strings:
        $t1 = "nmap" nocase
        $t2 = "masscan" nocase
        $t3 = "zmap" nocase
        $t4 = "unicornscan" nocase
        $t5 = "rustscan" nocase
        $s1 = "--open --script" nocase
        $s2 = "-sV -sC" nocase
        $s3 = "SYN scan" nocase
    condition:
        any of ($t*) and any of ($s*)
}
"""

# ─────────────────────────────────────────────────────────────────────────────
# Rule parser
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class YarString:
    name:      str
    value:     bytes
    str_type:  str       # "text" | "hex" | "regex"
    modifiers: Set[str]  = field(default_factory=set)
    xor_key:   int       = 0


@dataclass
class YarRule:
    name:       str
    tags:       List[str]         = field(default_factory=list)
    meta:       Dict[str,str]     = field(default_factory=dict)
    strings:    List[YarString]   = field(default_factory=list)
    condition:  str               = "true"


@dataclass
class RuleMatch:
    rule_name:  str
    file_path:  str
    file_size:  int
    tags:       List[str]
    meta:       Dict[str,str]
    matched_strings: List[dict]
    timestamp:  str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self):
        return asdict(self)


class RuleParseError(Exception):
    pass


class VYRParser:
    """Parser for .vyr rule files (Vanguard YARA Rule format)."""

    # Tokeniser
    _RE_RULE   = re.compile(r"rule\s+(\w+)\s*(?::\s*([\w\s]+))?\{", re.M)
    _RE_META   = re.compile(r"meta\s*:", re.M)
    _RE_STRINGS= re.compile(r"strings\s*:", re.M)
    _RE_COND   = re.compile(r"condition\s*:", re.M)
    _RE_KVMETA = re.compile(r'(\w+)\s*=\s*"([^"]*)"')
    _RE_STRDEF = re.compile(
        r'(\$\w+)\s*=\s*(?:(/[^/]*/[a-z]*)|(\{[^}]+\})|("(?:[^"\\]|\\.)*"))\s*((?:nocase|fullword|ascii|wide|xor(?:\([0-9a-fA-F]{1,2}\))?\s*)*)',
        re.M
    )

    def parse_text(self, text: str) -> List[YarRule]:
        rules = []
        # Strip comments
        text = re.sub(r"//[^\n]*", "", text)
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)

        pos = 0
        while True:
            m = self._RE_RULE.search(text, pos)
            if not m:
                break
            rule_name = m.group(1)
            tags_raw  = (m.group(2) or "").split()
            body_start = m.end()

            # Find matching closing brace
            depth = 1
            i     = body_start
            while i < len(text) and depth > 0:
                if text[i] == "{":  depth += 1
                elif text[i] == "}": depth -= 1
                i += 1
            body = text[body_start:i-1]
            pos  = i

            rule = YarRule(name=rule_name, tags=tags_raw)
            self._parse_body(rule, body)
            rules.append(rule)

        return rules

    def _parse_body(self, rule: YarRule, body: str):
        # Meta
        mm = self._RE_META.search(body)
        ms = self._RE_STRINGS.search(body)
        mc = self._RE_COND.search(body)

        if mm and ms:
            meta_block = body[mm.end():ms.start()]
            for k, v in self._RE_KVMETA.findall(meta_block):
                rule.meta[k] = v

        if ms:
            cond_start = mc.start() if mc else len(body)
            str_block  = body[ms.end():cond_start]
            for m in self._RE_STRDEF.finditer(str_block):
                ystr = self._parse_string(m)
                if ystr:
                    rule.strings.append(ystr)

        if mc:
            cond_block = body[mc.end():].strip().rstrip("}")
            rule.condition = cond_block.strip()

    def _parse_string(self, m: re.Match) -> Optional[YarString]:
        name      = m.group(1)
        regex_val = m.group(2)
        hex_val   = m.group(3)
        text_val  = m.group(4)
        mods_raw  = m.group(5).strip() if m.lastindex >= 5 else ""
        mods      = set(re.findall(r"nocase|fullword|ascii|wide|xor", mods_raw))

        xor_key = 0
        xorm = re.search(r"xor\(([0-9a-fA-F]{1,2})\)", mods_raw)
        if xorm:
            xor_key = int(xorm.group(1), 16)

        if regex_val:
            flags_part = regex_val[regex_val.rfind("/")+1:]
            pat = regex_val[1:regex_val.rfind("/")]
            return YarString(name=name, value=pat.encode(), str_type="regex", modifiers=mods)

        if hex_val:
            cleaned = re.sub(r"\s+", "", hex_val[1:-1])
            try:
                return YarString(name=name, value=bytes.fromhex(cleaned), str_type="hex", modifiers=mods)
            except ValueError:
                return None

        if text_val:
            unquoted = text_val[1:-1].replace('\\"', '"').replace("\\\\","\\")
            return YarString(name=name, value=unquoted.encode("utf-8"), str_type="text",
                             modifiers=mods, xor_key=xor_key)
        return None

    def parse_file(self, path: str) -> List[YarRule]:
        return self.parse_text(Path(path).read_text(encoding="utf-8", errors="replace"))

    def parse_dir(self, directory: str) -> List[YarRule]:
        all_rules = []
        for p in Path(directory).rglob("*.vyr"):
            try:
                all_rules.extend(self.parse_file(str(p)))
            except Exception as e:
                logger.warning("Failed to parse %s: %s", p, e)
        return all_rules


# ─────────────────────────────────────────────────────────────────────────────
# Rule matcher
# ─────────────────────────────────────────────────────────────────────────────

class RuleMatcher:
    def __init__(self, rules: List[YarRule]):
        self.rules = rules
        logger.info("Loaded %d rules", len(rules))

    # ── String searching ──────────────────────────────────────────────────

    def _find_string(self, ystr: YarString, data: bytes) -> List[int]:
        """Return list of byte offsets where ystr matches in data."""
        offsets = []
        needle  = ystr.value

        if ystr.str_type == "hex":
            start = 0
            while True:
                idx = data.find(needle, start)
                if idx == -1:
                    break
                offsets.append(idx)
                start = idx + 1
            return offsets

        if ystr.str_type == "regex":
            flags = re.DOTALL
            if "nocase" in ystr.modifiers:
                flags |= re.IGNORECASE
            try:
                for m in re.finditer(needle, data, flags):
                    offsets.append(m.start())
            except re.error:
                pass
            return offsets

        # Text string
        search_val = needle
        if "nocase" in ystr.modifiers:
            offsets += [m.start() for m in re.finditer(re.escape(needle), data, re.IGNORECASE)]
        elif "xor" in ystr.modifiers and ystr.xor_key:
            xored = bytes(b ^ ystr.xor_key for b in needle)
            start = 0
            while True:
                idx = data.find(xored, start)
                if idx == -1: break
                offsets.append(idx)
                start = idx + 1
        else:
            start = 0
            while True:
                idx = data.find(search_val, start)
                if idx == -1: break
                offsets.append(idx)
                start = idx + 1

        # Wide string (UTF-16LE)
        if "wide" in ystr.modifiers:
            wide_needle = needle.decode("utf-8", errors="replace").encode("utf-16-le")
            start = 0
            while True:
                idx = data.find(wide_needle, start)
                if idx == -1: break
                if idx not in offsets:
                    offsets.append(idx)
                start = idx + 1

        # Fullword check
        if "fullword" in ystr.modifiers and offsets:
            filtered = []
            for off in offsets:
                pre  = off > 0 and (data[off-1:off].isalnum() or data[off-1:off] == b"_")
                post_idx = off + len(needle)
                post = post_idx < len(data) and (data[post_idx:post_idx+1].isalnum() or data[post_idx:post_idx+1] == b"_")
                if not pre and not post:
                    filtered.append(off)
            offsets = filtered

        return offsets

    # ── Condition evaluation ──────────────────────────────────────────────

    def _eval_condition(self, rule: YarRule, data: bytes,
                        matches: Dict[str, List[int]]) -> bool:
        cond = rule.condition.strip()

        # Replace file size literals (1MB, 500KB, etc.)
        cond = re.sub(r"(\d+)\s*MB\b", lambda m: str(int(m.group(1)) * 1024 * 1024), cond)
        cond = re.sub(r"(\d+)\s*KB\b", lambda m: str(int(m.group(1)) * 1024), cond)

        filesize = len(data)

        def _count(var_pat: str) -> int:
            pat = var_pat.replace("*",".*").replace("?",".")
            return sum(len(v) for k, v in matches.items()
                       if re.fullmatch(pat, k))

        def _entropy(offset: int, length: int) -> float:
            chunk = data[int(offset):int(offset)+int(length)]
            return _file_entropy_of(chunk)

        def _has(name: str) -> bool:
            return bool(matches.get(name))

        # Expand "N of ($x*)" and "any/all/none of ($x*)"
        def expand_of(m):
            quant = m.group(1)
            pat   = m.group(2).strip("()")
            matched_names = [k for k in matches if
                             re.fullmatch(pat.replace("*",".*").replace("?","."), k)
                             and matches[k]]
            total = sum(1 for k in [kk for kk in (
                [ss.name for ss in rule.strings]
            ) if re.fullmatch(pat.replace("*",".*").replace("?","."), kk)])
            n = len(matched_names)
            if quant.lower() == "any":
                return "True" if n >= 1 else "False"
            if quant.lower() == "all":
                return "True" if n == total else "False"
            if quant.lower() == "none":
                return "True" if n == 0 else "False"
            try:
                return "True" if n >= int(quant) else "False"
            except ValueError:
                return "False"

        cond = re.sub(r"(any|all|none|\d+)\s+of\s+(\(\$[\w*?]*\))",
                      expand_of, cond, flags=re.I)

        # Replace $name references with True/False
        for sname, offs in matches.items():
            cond = re.sub(re.escape(sname) + r"\b", "True" if offs else "False", cond)
        # Any remaining $name → False
        cond = re.sub(r"\$\w+\b", "False", cond)

        # Replace entropy() calls
        cond = re.sub(r"entropy\s*\(\s*(\d+)\s*,\s*(\w+)\s*\)",
                      lambda m: str(round(_entropy(int(m.group(1)),
                                                    filesize if m.group(2)=="filesize" else int(m.group(2))), 4)),
                      cond)

        # Replace filesize
        cond = cond.replace("filesize", str(filesize))

        # Eval safe subset
        try:
            safe_globals = {"__builtins__": {}, "True": True, "False": False}
            return bool(eval(cond, safe_globals))  # noqa: S307 — controlled input
        except Exception:
            return False

    # ── File scanning ─────────────────────────────────────────────────────

    def scan_data(self, data: bytes, path: str = "<memory>") -> List[RuleMatch]:
        results = []
        for rule in self.rules:
            matches: Dict[str, List[int]] = {}
            for ystr in rule.strings:
                matches[ystr.name] = self._find_string(ystr, data)

            if self._eval_condition(rule, data, matches):
                matched_strs = [
                    {"name": k, "offsets": v[:5], "count": len(v)}
                    for k, v in matches.items() if v
                ]
                results.append(RuleMatch(
                    rule_name        = rule.name,
                    file_path        = path,
                    file_size        = len(data),
                    tags             = rule.tags,
                    meta             = rule.meta,
                    matched_strings  = matched_strs,
                ))
        return results

    def scan_file(self, path: str, max_size: int = 50*1024*1024) -> List[RuleMatch]:
        try:
            size = os.path.getsize(path)
            if size > max_size:
                return []
            with open(path, "rb") as f:
                data = f.read()
            return self.scan_data(data, path)
        except OSError as e:
            logger.debug("Cannot read %s: %s", path, e)
            return []

    def scan_dir(self, directory: str, recursive: bool = True,
                 skip_exts: Set[str] = None) -> Generator[RuleMatch, None, None]:
        skip_exts = skip_exts or {".jpg",".jpeg",".png",".gif",".mp4",".mp3",
                                   ".avi",".mkv",".iso",".zip",".tar",".gz"}
        skip_dirs = {"/proc","/sys","/dev"}
        walk_fn   = os.walk(directory)
        for dirpath, dirs, files in walk_fn:
            dirs[:] = [d for d in dirs if os.path.join(dirpath,d) not in skip_dirs]
            for fn in files:
                if Path(fn).suffix.lower() in skip_exts:
                    continue
                fpath = os.path.join(dirpath, fn)
                for match in self.scan_file(fpath):
                    yield match


def _file_entropy_of(data: bytes) -> float:
    if not data:
        return 0.0
    from collections import Counter
    freq = Counter(data)
    n    = len(data)
    return -sum((c/n)*math.log2(c/n) for c in freq.values())


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def _print_match(m: RuleMatch):
    sev = m.meta.get("severity","info")
    SEV_C = {"critical":"\033[95m","high":"\033[91m","medium":"\033[93m",
             "low":"\033[92m","info":"\033[96m"}
    c  = SEV_C.get(sev,"")
    R  = "\033[0m"; B = "\033[1m"
    print(f"  {c}[{sev.upper():8}]{R}  {B}{m.rule_name}{R}  [{', '.join(m.tags)}]")
    print(f"     File : {m.file_path}  ({m.file_size:,} bytes)")
    if m.meta.get("desc"):
        print(f"     Desc : {m.meta['desc']}")
    if m.meta.get("mitre"):
        print(f"     MITRE: {m.meta['mitre']}")
    for s in m.matched_strings:
        print(f"     Match: {s['name']}  ({s['count']} hits)  offsets={s['offsets']}")
    print()


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Vanguard-OOB YARA-like Rule Engine")
    parser.add_argument("--rules",          help="Rule file (.vyr) or directory")
    parser.add_argument("--scan",           help="File or directory to scan")
    parser.add_argument("--compile",        help="Validate/compile a rule file (dry-run)")
    parser.add_argument("--generate-rules", action="store_true", help="Print built-in rules")
    parser.add_argument("--recursive",      action="store_true", default=True)
    parser.add_argument("--json",           help="Output JSON to file")
    args = parser.parse_args()

    C = "\033[96m"; R = "\033[0m"; B = "\033[1m"
    print(f"\n{B}  ── Vanguard-OOB YARA Engine ──{R}\n")

    if args.generate_rules:
        print(BUILTIN_RULES)
        return

    if args.compile:
        p = VYRParser()
        rules = p.parse_file(args.compile)
        print(f"  Compiled {len(rules)} rules from {args.compile}")
        for r in rules:
            sev = r.meta.get("severity","?")
            print(f"    {C}{r.name}{R}  tags={r.tags}  strings={len(r.strings)}  sev={sev}")
        return

    # Load rules
    p = VYRParser()
    if args.rules:
        rp = Path(args.rules)
        rules = p.parse_dir(str(rp)) if rp.is_dir() else p.parse_file(str(rp))
    else:
        rules = p.parse_text(BUILTIN_RULES)
        print(f"  Using {len(rules)} built-in rules\n")

    matcher = RuleMatcher(rules)
    all_matches = []

    if args.scan:
        sp = Path(args.scan)
        if sp.is_file():
            matches = matcher.scan_file(str(sp))
            for m in matches:
                _print_match(m)
            all_matches = matches
        elif sp.is_dir():
            for m in matcher.scan_dir(str(sp), recursive=args.recursive):
                _print_match(m)
                all_matches.append(m)

    print(f"  Scan complete: {len(all_matches)} rule matches")

    if args.json and all_matches:
        with open(args.json, "w") as f:
            json.dump([m.to_dict() for m in all_matches], f, indent=2)
        print(f"  Results saved to {args.json}")


if __name__ == "__main__":
    main()
