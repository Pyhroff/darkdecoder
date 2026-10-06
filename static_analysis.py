"""Local static triage for suspicious source text.

This module deliberately uses only the Python standard library. It provides
deterministic evidence that complements, but never overrides, the LLM verdict.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
import re
from collections import Counter


PATTERNS = {
    "command_execution": [
        (r"\b(?:os\.system|os\.popen|subprocess\.(?:run|Popen|call|check_output)|shell_exec|child_process\.exec)\b", "process execution"),
        (r"\b(?:powershell|cmd\.exe|bash|sh)\b.*(?:-enc|-encodedcommand|/c|-c)\b", "shell command execution"),
    ],
    "download_execution": [
        (r"(?i)(?:curl|wget|Invoke-WebRequest|WebClient|requests\.(?:get|post)|urllib\.request)\b", "network retrieval"),
        (r"(?i)(?:downloadstring|downloadfile|urlopen)\s*\(", "download primitive"),
    ],
    "persistence": [
        (r"(?i)(?:Run(?:Once)?|CurrentVersion\\Run|schtasks|crontab|systemctl\s+enable)", "persistence mechanism"),
    ],
    "credential_access": [
        (r"(?i)(?:password|passwd|credential|token|cookie|browser.*(?:login|password)|SAM|LSASS)", "credential-related access"),
    ],
    "defense_evasion": [
        (r"(?i)(?:amsi|defender|disable.*(?:security|antivirus)|-windowstyle\s+hidden|bypass)", "defense-evasion indicator"),
    ],
    "obfuscation": [
        (r"(?i)(?:base64|fromhex|b64decode|charcode|chr\(|eval\(|exec\(|compile\(|rot13)", "encoding/dynamic execution"),
    ],
    "exfiltration": [
        (r"(?i)(?:socket|requests\.(?:post|put)|curl|wget|ftp|upload)", "possible outbound transfer"),
    ],
}


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _encoded_candidates(code: str) -> list[dict]:
    candidates = []
    # Long base64-looking tokens are useful evidence, but we never execute them.
    for match in re.finditer(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])", code):
        token = match.group(0)
        try:
            decoded = base64.b64decode(token, validate=True)
            if len(decoded) < 8:
                continue
            printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in decoded) / len(decoded)
            if printable >= 0.65:
                candidates.append({
                    "encoding": "base64",
                    "length": len(token),
                    "decoded_preview": decoded[:120].decode("utf-8", errors="replace"),
                })
        except (ValueError, binascii.Error):
            continue
    return candidates[:20]


def analyze_static(code: str) -> dict:
    findings = []
    capabilities = []
    seen = set()

    for capability, rules in PATTERNS.items():
        for pattern, evidence in rules:
            for match in re.finditer(pattern, code, re.MULTILINE):
                key = (capability, evidence, match.group(0)[:120])
                if key in seen:
                    continue
                seen.add(key)
                line = code.count("\n", 0, match.start()) + 1
                findings.append({
                    "capability": capability,
                    "evidence": evidence,
                    "line": line,
                    "match": match.group(0)[:120],
                })
        if any(f["capability"] == capability for f in findings):
            capabilities.append(capability)

    strings = re.findall(r"['\"]([^'\"]{16,})['\"]", code)
    high_entropy = sorted(
        [{"length": len(s), "entropy": round(_entropy(s), 2), "preview": s[:80]}
         for s in strings if len(s) >= 24 and _entropy(s) >= 4.3],
        key=lambda x: x["entropy"],
        reverse=True,
    )[:20]

    encoded = _encoded_candidates(code)
    obfuscation_score = min(10, len(encoded) * 2 + sum(1 for f in findings if f["capability"] == "obfuscation"))

    return {
        "engine": "DarkDecoder Local Static Triage v1",
        "input_sha256": hashlib.sha256(code.encode()).hexdigest(),
        "capabilities": sorted(set(capabilities)),
        "findings": findings[:100],
        "encoded_candidates": encoded,
        "high_entropy_strings": high_entropy,
        "obfuscation_score": obfuscation_score,
        "finding_count": len(findings),
    }
