from __future__ import annotations

import subprocess
from pathlib import Path


def _run_git(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        check=False,
    )


def is_git_repo(root: Path) -> bool:
    p = _run_git(["rev-parse", "--is-inside-work-tree"], cwd=root)
    return p.returncode == 0 and p.stdout.strip() == b"true"


def tracked_files(root: Path) -> list[str]:
    p = _run_git(["ls-files", "-z"], cwd=root)
    if p.returncode != 0:
        return []
    return [s.decode("utf-8", errors="replace") for s in p.stdout.split(b"\0") if s]


def staged_files(root: Path) -> list[str]:
    p = _run_git(["diff", "--cached", "--name-only", "-z"], cwd=root)
    if p.returncode != 0:
        return []
    return [s.decode("utf-8", errors="replace") for s in p.stdout.split(b"\0") if s]


def read_staged_file(root: Path, rel_path: str) -> bytes | None:
    p = _run_git(["show", f":{rel_path}"], cwd=root)
    if p.returncode != 0:
        return None
    return p.stdout
