from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from .commands import cmd_baseline, cmd_init, cmd_scan, cmd_stats
from .reporting import Format
from .rules_cmd import list_rules, show_rule

app = typer.Typer(add_completion=False, help="SecretScout: defensive secret scanner for repos and folders.")


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), exists=True, file_okay=False, dir_okay=True),
    format: Format = typer.Option("table", "--format", help="table|minimal|json|sarif|html"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write report to file (else stdout)."),
    fail_on: str = typer.Option("high", "--fail-on", help="Exit 1 if findings severity >= this."),
    baseline: Optional[Path] = typer.Option(None, "--baseline", help="Baseline JSON file to ignore known findings."),
    staged: bool = typer.Option(False, "--staged", help="Scan staged changes (git index)."),
    tracked: bool = typer.Option(False, "--tracked", help="Scan only git tracked files."),
    all_files: bool = typer.Option(False, "--all", help="Scan all files under PATH (ignores git)."),
    exclude: list[str] = typer.Option(None, "--exclude", help="Extra exclude glob patterns (repeatable)."),
    no_cache: bool = typer.Option(False, "--no-cache", help="Disable cache."),
    max_findings: Optional[int] = typer.Option(None, "--max-findings", help="Limit output findings."),
) -> None:
    code = cmd_scan(
        path=path,
        fmt=format,
        output=output,
        fail_on=fail_on,
        baseline=baseline,
        staged=staged,
        tracked=tracked,
        all_files=all_files,
        exclude=exclude or [],
        no_cache=no_cache,
        max_findings=max_findings,
    )
    raise typer.Exit(code=code)


@app.command()
def init(path: Path = typer.Argument(Path("."), exists=True, file_okay=False, dir_okay=True)) -> None:
    raise typer.Exit(code=cmd_init(path))


@app.command()
def fix(path: Path = typer.Argument(Path("."), exists=True, file_okay=False, dir_okay=True)) -> None:
    raise typer.Exit(code=cmd_init(path))


@app.command()
def baseline(
    path: Path = typer.Argument(Path("."), exists=True, file_okay=False, dir_okay=True),
    output: Path = typer.Option(Path(".secretscout.baseline.json"), "--output", "-o", help="Baseline output file."),
    tracked: bool = typer.Option(True, "--tracked/--all", help="By default, baseline git-tracked files."),
) -> None:
    raise typer.Exit(code=cmd_baseline(path, output, tracked))


@app.command()
def stats(
    path: Path = typer.Argument(Path("."), exists=True, file_okay=False, dir_okay=True),
    staged: bool = typer.Option(False, "--staged"),
    tracked: bool = typer.Option(False, "--tracked"),
    all_files: bool = typer.Option(False, "--all"),
    baseline: Optional[Path] = typer.Option(None, "--baseline"),
) -> None:
    raise typer.Exit(code=cmd_stats(path, staged=staged, tracked=tracked, all_files=all_files, baseline=baseline))


rules_app = typer.Typer(help="Manage and inspect rules.")
app.add_typer(rules_app, name="rules")


@rules_app.command("list")
def rules_list() -> None:
    list_rules()


@rules_app.command("show")
def rules_show(rule_id: str) -> None:
    show_rule(rule_id)
