from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from .config import load_config
from .fix import apply_fix
from .models import Severity
from .reporting import Format, emit
from .scanner import scan_path


def to_severity(value: str) -> Severity:
    try:
        return Severity(value.lower())
    except Exception:
        raise typer.BadParameter("Severity must be one of: low, medium, high, critical")


def cmd_scan(
    path: Path,
    fmt: Format,
    output: Optional[Path],
    fail_on: str,
    baseline: Optional[Path],
    staged: bool,
    tracked: bool,
    all_files: bool,
    exclude: list[str],
    no_cache: bool,
    max_findings: Optional[int],
) -> int:
    root = path.resolve()

    mode = "tracked"
    if staged:
        mode = "staged"
    elif all_files:
        mode = "all"
    elif tracked:
        mode = "tracked"

    cfg = load_config(root)
    mf = int(max_findings) if max_findings is not None else cfg.report.max_findings

    findings = scan_path(
        root,
        mode=mode,
        baseline_path=baseline,
        extra_exclude=exclude or [],
        use_cache=not no_cache,
    )

    payload = emit(findings, fmt=fmt, max_findings=mf)
    if payload is not None:
        if output:
            output.write_text(payload, encoding="utf-8")
        else:
            typer.echo(payload)

    threshold = to_severity(fail_on)
    return 1 if any(f.severity.ge(threshold) for f in findings) else 0


def cmd_baseline(path: Path, output: Path, tracked: bool) -> int:
    root = path.resolve()
    mode = "tracked" if tracked else "all"
    findings = scan_path(root, mode=mode, baseline_path=None, use_cache=False)
    fingerprints = sorted({f.fingerprint for f in findings})
    output.write_text(json.dumps({"fingerprints": fingerprints}, indent=2), encoding="utf-8")
    Console().print(f"✅ Wrote baseline with {len(fingerprints)} fingerprints to {output}")
    return 0


def cmd_init(path: Path) -> int:
    root = path.resolve()
    changes = apply_fix(root)
    con = Console()
    for c in changes:
        con.print(f"[green]✔[/green] {c}")
    con.print("Done. If you use pre-commit: `pip install pre-commit && pre-commit install`")
    return 0


def cmd_stats(path: Path, staged: bool, tracked: bool, all_files: bool, baseline: Optional[Path]) -> int:
    root = path.resolve()
    mode = "tracked"
    if staged:
        mode = "staged"
    elif all_files:
        mode = "all"
    elif tracked:
        mode = "tracked"

    findings = scan_path(root, mode=mode, baseline_path=baseline)
    con = Console()
    if not findings:
        con.print("[bold green]✅ No findings.[/bold green]")
        return 0

    by_sev: dict[str, int] = {}
    by_rule: dict[str, int] = {}
    by_file: dict[str, int] = {}

    for f in findings:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
        by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
        by_file[f.file] = by_file.get(f.file, 0) + 1

    con.print("[bold]By severity:[/bold]", by_sev)
    con.print("[bold]Top rules:[/bold]", dict(sorted(by_rule.items(), key=lambda kv: -kv[1])[:10]))
    con.print("[bold]Top files:[/bold]", dict(sorted(by_file.items(), key=lambda kv: -kv[1])[:10]))
    return 0
