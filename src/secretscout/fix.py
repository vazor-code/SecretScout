from __future__ import annotations

from pathlib import Path

PRE_COMMIT_SNIPPET = """\
- repo: local
  hooks:
    - id: secretscout
      name: SecretScout (defensive secret scan)
      entry: secretscout scan --staged --format minimal --fail-on high
      language: system
      pass_filenames: false
"""

DEFAULT_IGNORE = """\
# SecretScout ignore file (glob patterns)
.git/**
.venv/**
venv/**
node_modules/**
dist/**
build/**
.secretscout-cache/**
*.min.js
*.map
"""


def append_if_missing(path: Path, marker: str, block: str) -> None:
    if path.exists():
        text = path.read_text(encoding="utf-8")
        if marker in text:
            return
        new_text = text.rstrip() + "\n\n" + block.rstrip() + "\n"
    else:
        new_text = block.rstrip() + "\n"
    path.write_text(new_text, encoding="utf-8")


def ensure_file(path: Path, content: str) -> bool:
    if path.exists():
        return False
    path.write_text(content, encoding="utf-8")
    return True


def apply_fix(root: Path) -> list[str]:
    changes: list[str] = []

    pc = root / ".pre-commit-config.yaml"
    if pc.exists():
        append_if_missing(pc, marker="id: secretscout", block=PRE_COMMIT_SNIPPET)
        changes.append("Updated .pre-commit-config.yaml (added SecretScout hook if missing).")
    else:
        pc.write_text("repos:\n" + PRE_COMMIT_SNIPPET, encoding="utf-8")
        changes.append("Created .pre-commit-config.yaml (with SecretScout hook).")

    cfg = root / ".secretscout.toml"
    if not cfg.exists():
        cfg.write_text(
            """\
[scan]
max_file_size = 1048576
exclude = [".git/**", ".venv/**", "venv/**", "node_modules/**", "dist/**", "build/**", ".secretscout-cache/**"]
threads = 8
first_lines_ignore_file_marker = 5

[report]
fail_on = "high"
max_findings = 200
redact_head = 4
redact_tail = 4

[rules]
disable = []
allowlist = []
path_allowlist = []
""",
            encoding="utf-8",
        )
        changes.append("Created .secretscout.toml.")

    ig = root / ".secretscoutignore"
    if ensure_file(ig, DEFAULT_IGNORE):
        changes.append("Created .secretscoutignore.")

    gi = root / ".gitignore"
    ignore_block = """\
# SecretScout
.secretscout-cache/
secretscout_report.html
*.sarif
"""
    append_if_missing(gi, marker="# SecretScout", block=ignore_block)
    changes.append("Updated .gitignore (added SecretScout section).")

    return changes
