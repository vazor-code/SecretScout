from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable

from .cache import Cache
from .config import is_excluded, load_config, load_ignore_file
from .git import is_git_repo, read_staged_file, staged_files, tracked_files
from .models import Finding, Rule, Severity
from .rules import DEFAULT_RULES
from .util import fingerprint, iter_entropy_candidates, looks_like_high_entropy_token, redact


def load_baseline(path: Path | None) -> set[str]:
    if not path or not path.exists():
        return set()
    data = json.loads(path.read_text(encoding="utf-8"))
    fps = data.get("fingerprints", data) if isinstance(data, dict) else data
    return {str(x) for x in fps} if isinstance(fps, list) else set()


def build_rules(disable: list[str], allowlist: list[str]) -> tuple[list[Rule], list[re.Pattern[str]]]:
    rules = [r for r in DEFAULT_RULES if r.id not in set(disable)]
    allow = [re.compile(p) for p in allowlist]
    return rules, allow


def iter_files(root: Path, mode: str, extra_exclude: list[str] | None = None) -> Iterable[tuple[str, bytes | None]]:
    cfg = load_config(root)
    ignore_pats = load_ignore_file(root)
    patterns = cfg.scan.exclude + ignore_pats + (extra_exclude or [])

    if mode == "staged" and is_git_repo(root):
        for rel in staged_files(root):
            if not is_excluded(rel, patterns):
                yield rel, read_staged_file(root, rel)
        return

    if mode == "tracked" and is_git_repo(root):
        for rel in tracked_files(root):
            if not is_excluded(rel, patterns):
                yield rel, None
        return

    for p in root.rglob("*"):
        if p.is_dir():
            continue
        rel = str(p.relative_to(root)).replace("\\", "/")
        if not is_excluded(rel, patterns):
            yield rel, None


def _ignore_file_by_marker(text: str, first_lines: int) -> bool:
    head = "\n".join(text.splitlines()[:first_lines])
    return "secretscout:ignore-file" in head


def scan_bytes(
    rel_path: str,
    content: bytes,
    rules: list[Rule],
    allowlist: list[re.Pattern[str]],
    path_allowlist: list[re.Pattern[str]],
    baseline: set[str],
    redact_head: int,
    redact_tail: int,
) -> list[Finding]:
    for pat in path_allowlist:
        if pat.search(rel_path):
            return []

    text = content.decode("utf-8", errors="replace")
    findings: list[Finding] = []

    # Multiline rules
    for rule in rules:
        if not rule.multiline:
            continue
        for m in re.finditer(rule.pattern, text, flags=re.MULTILINE):
            upto = text[: m.start()]
            line = upto.count("\n") + 1
            col0 = m.start() - (upto.rfind("\n") + 1)
            match = m.group(0)
            if any(a.search(match) for a in allowlist):
                continue
            fp = fingerprint(rule.id, rel_path, line, match)
            if fp in baseline:
                continue
            sn = redact(match, head=redact_head, tail=redact_tail)
            findings.append(
                Finding(
                    rule_id=rule.id,
                    rule_title=rule.title,
                    severity=rule.severity,
                    file=rel_path,
                    line=line,
                    col=col0 + 1,
                    match=sn,
                    snippet=sn,
                    fingerprint=fp,
                )
            )

    # Line-by-line
    line_rules = [r for r in rules if not r.multiline and r.id != "generic-credential"]
    generic_rules = [r for r in rules if not r.multiline and r.id == "generic-credential"]

    lines = text.splitlines()
    for i, line in enumerate(lines, start=1):
        if "secretscout:ignore" in line:
            continue

        strong = False  # есть ли на строке high/critical (даже если baseline это потом скроет)

        # 1) специфичные правила
        for rule in line_rules:
            for m in re.finditer(rule.pattern, line):
                match_full = m.group(0)
                if any(a.search(match_full) for a in allowlist):
                    continue

                if rule.severity.ge(Severity.high):
                    strong = True

                fp = fingerprint(rule.id, rel_path, i, match_full)
                if fp in baseline:
                    continue

                findings.append(
                    Finding(
                        rule_id=rule.id,
                        rule_title=rule.title,
                        severity=rule.severity,
                        file=rel_path,
                        line=i,
                        col=m.start() + 1,
                        match=redact(match_full, head=redact_head, tail=redact_tail),
                        snippet=_line_snippet(line, m.start(), m.end(), redact_head, redact_tail),
                        fingerprint=fp,
                    )
                )

        # 2) generic-credential — только если нет strong
        if not strong:
            for rule in generic_rules:
                for m in re.finditer(rule.pattern, line):
                    match_full = m.group(0)
                    if any(a.search(match_full) for a in allowlist):
                        continue

                    fp = fingerprint(rule.id, rel_path, i, match_full)
                    if fp in baseline:
                        continue

                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            rule_title=rule.title,
                            severity=rule.severity,
                            file=rel_path,
                            line=i,
                            col=m.start() + 1,
                            match=redact(match_full, head=redact_head, tail=redact_tail),
                            snippet=_line_snippet(line, m.start(), m.end(), redact_head, redact_tail),
                            fingerprint=fp,
                        )
                    )

        # 3) entropy — тоже только если нет strong
        if not strong:
            for cand in iter_entropy_candidates(line):
                if any(a.search(cand) for a in allowlist):
                    continue
                if looks_like_high_entropy_token(cand):
                    fp = fingerprint("high-entropy", rel_path, i, cand)
                    if fp in baseline:
                        continue
                    start = line.find(cand)
                    findings.append(
                        Finding(
                            rule_id="high-entropy",
                            rule_title="High entropy token-like string",
                            severity=Severity.medium,
                            file=rel_path,
                            line=i,
                            col=max(1, start + 1),
                            match=redact(cand, head=redact_head, tail=redact_tail),
                            snippet=_line_snippet(line, start, start + len(cand), redact_head, redact_tail),
                            fingerprint=fp,
                        )
                    )

        for cand in iter_entropy_candidates(line):
            if any(a.search(cand) for a in allowlist):
                continue
            if looks_like_high_entropy_token(cand):
                fp = fingerprint("high-entropy", rel_path, i, cand)
                if fp in baseline:
                    continue
                start = line.find(cand)
                findings.append(
                    Finding(
                        rule_id="high-entropy",
                        rule_title="High entropy token-like string",
                        severity=Severity.medium,
                        file=rel_path,
                        line=i,
                        col=max(1, start + 1),
                        match=redact(cand, head=redact_head, tail=redact_tail),
                        snippet=_line_snippet(line, start, start + len(cand), redact_head, redact_tail),
                        fingerprint=fp,
                    )
                )

    return findings


def _line_snippet(line: str, start: int, end: int, rh: int, rt: int, max_len: int = 160) -> str:
    before = line[max(0, start - 40) : start]
    match = line[start:end]
    after = line[end : end + 40]
    snippet = f"{before}{redact(match, head=rh, tail=rt)}{after}".strip()
    return (snippet[: max_len - 1] + "…") if len(snippet) > max_len else snippet


def scan_path(
    root: Path,
    mode: str = "tracked",
    baseline_path: Path | None = None,
    extra_exclude: list[str] | None = None,
    use_cache: bool = True,
) -> list[Finding]:
    cfg = load_config(root)
    baseline = load_baseline(baseline_path)
    rules, allow = build_rules(cfg.rules.disable, cfg.rules.allowlist)
    path_allow = [re.compile(p) for p in cfg.rules.path_allowlist]

    cache = Cache(root)
    if use_cache:
        cache.load()

    tasks: list[tuple[str, bytes]] = []
    for rel, staged_content in iter_files(root, mode=mode, extra_exclude=extra_exclude):
        if staged_content is not None:
            content = staged_content
        else:
            p = root / rel
            try:
                if p.stat().st_size > cfg.scan.max_file_size:
                    continue
                content = p.read_bytes()
            except OSError:
                continue

        if b"\x00" in content[:4096]:
            continue

        head = content[:8192].decode("utf-8", errors="ignore")
        if _ignore_file_by_marker(head, cfg.scan.first_lines_ignore_file_marker):
            continue

        tasks.append((rel, content))

    def work(rel: str, content: bytes) -> list[Finding]:
        if use_cache:
            cached = cache.get(rel, content)
            if cached is not None:
                out: list[Finding] = []
                for d in cached:
                    f = Finding(
                        rule_id=str(d["rule_id"]),
                        rule_title=str(d.get("rule_title", d["rule_id"])),
                        severity=Severity(str(d["severity"])),
                        file=str(d["file"]),
                        line=int(d["line"]),
                        col=int(d["col"]),
                        match=str(d["match"]),
                        snippet=str(d["snippet"]),
                        fingerprint=str(d["fingerprint"]),
                    )
                    if f.fingerprint not in baseline:
                        out.append(f)
                return out

        out = scan_bytes(
            rel,
            content,
            rules,
            allow,
            path_allowlist=path_allow,
            baseline=baseline,
            redact_head=cfg.report.redact_head,
            redact_tail=cfg.report.redact_tail,
        )
        if use_cache:
            cache.put(rel, content, [f.to_dict() for f in out])
        return out

    findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=cfg.scan.threads) as ex:
        futures = [ex.submit(work, rel, content) for rel, content in tasks]
        for fut in as_completed(futures):
            findings.extend(fut.result())

    if use_cache:
        cache.save()
    return findings
