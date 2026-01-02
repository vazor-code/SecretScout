from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

    @classmethod
    def order(cls) -> dict["Severity", int]:
        return {cls.low: 0, cls.medium: 1, cls.high: 2, cls.critical: 3}

    def ge(self, other: "Severity") -> bool:
        return self.order()[self] >= self.order()[other]


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    description: str
    severity: Severity
    pattern: str
    multiline: bool = False
    tags: tuple[str, ...] = ()


@dataclass
class Finding:
    rule_id: str
    rule_title: str
    severity: Severity
    file: str
    line: int
    col: int
    match: str
    snippet: str
    fingerprint: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_title": self.rule_title,
            "severity": self.severity.value,
            "file": self.file,
            "line": self.line,
            "col": self.col,
            "match": self.match,
            "snippet": self.snippet,
            "fingerprint": self.fingerprint,
        }
