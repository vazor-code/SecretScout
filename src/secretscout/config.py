from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import tomllib  # py311+
except Exception:  # pragma: no cover
    tomllib = None  # type: ignore


@dataclass
class ScanConfig:
    max_file_size: int
    exclude: list[str]
    threads: int
    first_lines_ignore_file_marker: int


@dataclass
class ReportConfig:
    fail_on: str
    max_findings: int
    redact_head: int
    redact_tail: int


@dataclass
class RulesConfig:
    disable: list[str]
    allowlist: list[str]
    path_allowlist: list[str]


@dataclass
class Config:
    scan: ScanConfig
    report: ReportConfig
    rules: RulesConfig


DEFAULTS: dict[str, Any] = {
    "scan": {
        "max_file_size": 1048576,
        "exclude": [
            ".git/**",
            ".venv/**",
            "venv/**",
            "node_modules/**",
            "dist/**",
            "build/**",
            ".mypy_cache/**",
            ".ruff_cache/**",
            ".pytest_cache/**",
            ".secretscout-cache/**",
        ],
        "threads": 8,
        "first_lines_ignore_file_marker": 5,
    },
    "report": {"fail_on": "high", "max_findings": 200, "redact_head": 4, "redact_tail": 4},
    "rules": {"disable": [], "allowlist": [], "path_allowlist": []},
}


def load_toml_config(root: Path) -> dict[str, Any]:
    path = root / ".secretscout.toml"
    if not path.exists():
        return {}
    if tomllib is None:
        raise RuntimeError("tomllib not available; use Python 3.11+")
    return tomllib.loads(path.read_text(encoding="utf-8"))


def load_ignore_file(root: Path) -> list[str]:
    path = root / ".secretscoutignore"
    if not path.exists():
        return []
    pats: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        pats.append(line)
    return pats


def load_config(root: Path) -> Config:
    raw = load_toml_config(root)

    scan = {**DEFAULTS["scan"], **raw.get("scan", {})}
    report = {**DEFAULTS["report"], **raw.get("report", {})}
    rules = {**DEFAULTS["rules"], **raw.get("rules", {})}

    scan_cfg = ScanConfig(
        max_file_size=int(scan.get("max_file_size", DEFAULTS["scan"]["max_file_size"])),
        exclude=list(scan.get("exclude", DEFAULTS["scan"]["exclude"])),
        threads=max(1, int(scan.get("threads", DEFAULTS["scan"]["threads"]))),
        first_lines_ignore_file_marker=max(
            1, int(scan.get("first_lines_ignore_file_marker", DEFAULTS["scan"]["first_lines_ignore_file_marker"]))
        ),
    )
    report_cfg = ReportConfig(
        fail_on=str(report.get("fail_on", DEFAULTS["report"]["fail_on"])),
        max_findings=max(1, int(report.get("max_findings", DEFAULTS["report"]["max_findings"]))),
        redact_head=max(1, int(report.get("redact_head", DEFAULTS["report"]["redact_head"]))),
        redact_tail=max(1, int(report.get("redact_tail", DEFAULTS["report"]["redact_tail"]))),
    )
    rules_cfg = RulesConfig(
        disable=list(rules.get("disable", [])),
        allowlist=list(rules.get("allowlist", [])),
        path_allowlist=list(rules.get("path_allowlist", [])),
    )
    return Config(scan=scan_cfg, report=report_cfg, rules=rules_cfg)


def is_excluded(rel_path: str, patterns: list[str]) -> bool:
    p = rel_path.replace(os.sep, "/")
    return any(fnmatch.fnmatch(p, pat) for pat in patterns)
