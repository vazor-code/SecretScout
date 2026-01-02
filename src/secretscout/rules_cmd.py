from __future__ import annotations

from rich.console import Console
from rich.table import Table

from .rules import DEFAULT_RULES


def list_rules() -> None:
    con = Console()
    table = Table(title="SecretScout rules")
    table.add_column("ID", style="bold")
    table.add_column("Severity")
    table.add_column("Title")
    table.add_column("Tags")

    for r in DEFAULT_RULES:
        table.add_row(r.id, r.severity.value, r.title, ", ".join(r.tags))
    con.print(table)


def show_rule(rule_id: str) -> None:
    con = Console()
    rule = next((r for r in DEFAULT_RULES if r.id == rule_id), None)
    if not rule:
        con.print(f"[red]Rule not found:[/red] {rule_id}")
        return
    con.print(f"[bold]{rule.id}[/bold] ({rule.severity.value})")
    con.print(rule.title)
    con.print(rule.description)
    con.print(f"pattern: {rule.pattern}")
