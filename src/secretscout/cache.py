from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .util import sha256_bytes


@dataclass
class CacheEntry:
    sha256: str
    findings: list[dict[str, Any]]


class Cache:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.dir = root / ".secretscout-cache"
        self.path = self.dir / "cache.json"
        self._data: dict[str, CacheEntry] = {}

    def load(self) -> None:
        if not self.path.exists():
            self._data = {}
            return
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        data: dict[str, CacheEntry] = {}
        if isinstance(raw, dict):
            for k, v in raw.items():
                if not isinstance(v, dict):
                    continue
                data[k] = CacheEntry(sha256=str(v.get("sha256", "")), findings=list(v.get("findings", [])))
        self._data = data

    def save(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        payload = {k: {"sha256": v.sha256, "findings": v.findings} for k, v in self._data.items()}
        self.path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def get(self, rel_path: str, content: bytes) -> list[dict[str, Any]] | None:
        ent = self._data.get(rel_path)
        if not ent:
            return None
        if ent.sha256 != sha256_bytes(content):
            return None
        return ent.findings

    def put(self, rel_path: str, content: bytes, findings: list[dict[str, Any]]) -> None:
        self._data[rel_path] = CacheEntry(sha256=sha256_bytes(content), findings=findings)
