from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime
from typing import Iterable, Literal

from rich.console import Console
from rich.table import Table

from .models import Finding, Severity

Format = Literal["table", "minimal", "json", "sarif", "html"]


def summarize(findings: Iterable[Finding]) -> dict[str, int]:
    c = Counter(f.severity.value for f in findings)
    return {k: int(v) for k, v in c.items()}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    order = Severity.order()
    return sorted(findings, key=lambda f: (-order[f.severity], f.file, f.line, f.col))


def print_table(findings: list[Finding], max_findings: int) -> None:
    console = Console()
    if not findings:
        console.print("[bold green]✅ No secrets found.[/bold green]")
        return

    f_sorted = sort_findings(findings)
    shown = f_sorted[:max_findings]

    table = Table(title="SecretScout findings")
    table.add_column("Severity", style="bold")
    table.add_column("Rule")
    table.add_column("File")
    table.add_column("Line")
    table.add_column("Match")
    table.add_column("Snippet")

    for f in shown:
        table.add_row(f.severity.value, f.rule_id, f.file, str(f.line), f.match, f.snippet)

    console.print(table)
    console.print(f"Summary: {summarize(f_sorted)}")
    if len(f_sorted) > max_findings:
        console.print(f"[yellow]Showing first {max_findings}/{len(f_sorted)} findings.[/yellow]")


def print_minimal(findings: list[Finding], max_findings: int) -> None:
    console = Console()
    f_sorted = sort_findings(findings)[:max_findings]
    for f in f_sorted:
        console.print(f"{f.severity.value}\t{f.rule_id}\t{f.file}:{f.line}:{f.col}\t{f.match}")
    if not f_sorted:
        console.print("OK")


def to_json(findings: list[Finding]) -> str:
    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "count": len(findings),
        "summary": summarize(findings),
        "findings": [f.to_dict() for f in sort_findings(findings)],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def to_sarif(findings: list[Finding]) -> str:
    rules_map: dict[str, dict] = {}
    results: list[dict] = []

    for f in sort_findings(findings):
        if f.rule_id not in rules_map:
            rules_map[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {"text": f.rule_title},
                "fullDescription": {"text": f.rule_title},
                "help": {"text": f.rule_title},
                "properties": {"severity": f.severity.value, "tags": ["secretscout"]},
            }

        level = {"low": "note", "medium": "warning", "high": "error", "critical": "error"}.get(
            f.severity.value, "warning"
        )

        results.append(
            {
                "ruleId": f.rule_id,
                "level": level,
                "message": {"text": f.rule_title},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file},
                            "region": {"startLine": f.line, "startColumn": f.col},
                        }
                    }
                ],
                "properties": {"fingerprint": f.fingerprint},
            }
        )

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "SecretScout", "rules": list(rules_map.values())}},
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, ensure_ascii=False, indent=2)


def to_html(findings: list[Finding]) -> str:
    f_sorted = sort_findings(findings)
    now = datetime.utcnow().isoformat() + "Z"
    rows = []
    for f in f_sorted:
        rows.append(
            "<tr>"
            f"<td class='sev sev-{html.escape(f.severity.value)}'>{html.escape(f.severity.value)}</td>"
            f"<td>{html.escape(f.rule_id)}</td>"
            f"<td>{html.escape(f.file)}</td>"
            f"<td>{f.line}:{f.col}</td>"
            f"<td><code>{html.escape(f.match)}</code></td>"
            f"<td><code>{html.escape(f.snippet)}</code></td>"
            "</tr>"
        )
    body = "\n".join(rows) if rows else "<tr><td colspan='6'>No findings</td></tr>"
    summary = summarize(f_sorted)

    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<title>SecretScout report</title>
<style>
body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; padding: 20px; }}
h1 {{ margin: 0 0 10px; }}
.meta {{ color: #555; margin-bottom: 16px; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ddd; padding: 8px; vertical-align: top; }}
th {{ background: #f7f7f7; }}
code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 0.95em; }}
.sev {{ font-weight: 700; }}
.sev-low {{ color: #2b6; }}
.sev-medium {{ color: #c90; }}
.sev-high {{ color: #d33; }}
.sev-critical {{ color: #a00; }}
</style>
</head>
<body>
<h1>SecretScout report</h1>
<div class="meta">
Generated: {html.escape(now)}<br/>
Count: {len(f_sorted)}<br/>
Summary: {html.escape(json.dumps(summary))}
</div>

<table>
<thead>
<tr>
  <th>Severity</th>
  <th>Rule</th>
  <th>File</th>
  <th>Line</th>
  <th>Match</th>
  <th>Snippet</th>
</tr>
</thead>
<tbody>
{body}
</tbody>
</table>
</body>
</html>
"""


def emit(findings: list[Finding], fmt: Format, max_findings: int) -> str | None:
    if fmt == "table":
        print_table(findings, max_findings=max_findings)
        return None
    if fmt == "minimal":
        print_minimal(findings, max_findings=max_findings)
        return None
    if fmt == "json":
        return to_json(findings)
    if fmt == "sarif":
        return to_sarif(findings)
    if fmt == "html":
        return to_html(findings)
    raise ValueError(f"Unknown format: {fmt}")
