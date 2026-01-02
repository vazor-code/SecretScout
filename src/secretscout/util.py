from __future__ import annotations

import hashlib
import math
import re
from typing import Iterable


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    ln = len(s)
    for c in freq.values():
        p = c / ln
        ent -= p * math.log2(p)
    return ent


_TOKEN_CANDIDATE = re.compile(
    r"(?i)(?:token|secret|api[_-]?key|password|passwd|client[_-]?secret)\b[^\S\r\n]*[:=][^\S\r\n]*([A-Za-z0-9_\-\+=/]{12,})"
)


def looks_like_high_entropy_token(s: str) -> bool:
    if len(s) < 20:
        return False
    if any(ch.isspace() for ch in s):
        return False
    if not re.fullmatch(r"[A-Za-z0-9_\-\+=/]+", s):
        return False
    return shannon_entropy(s) >= 3.6


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def fingerprint(rule_id: str, file: str, line: int, match: str) -> str:
    h = hashlib.sha256()
    h.update(rule_id.encode("utf-8"))
    h.update(b"\0")
    h.update(file.encode("utf-8"))
    h.update(b"\0")
    h.update(str(line).encode("utf-8"))
    h.update(b"\0")
    h.update(match.encode("utf-8"))
    return h.hexdigest()


def redact(s: str, head: int = 4, tail: int = 4) -> str:
    if len(s) <= head + tail + 3:
        return "***"
    return f"{s[:head]}…{s[-tail:]}"


def iter_entropy_candidates(line: str) -> Iterable[str]:
    m = _TOKEN_CANDIDATE.search(line)
    if m:
        yield m.group(1)
