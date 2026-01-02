import re
from secretscout.rules import DEFAULT_RULES
from secretscout.scanner import scan_bytes


def test_detect_private_key_header():
    content = b"-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----\n"
    findings = scan_bytes(
        "a.txt",
        content,
        DEFAULT_RULES,
        allowlist=[],
        path_allowlist=[],
        baseline=set(),
        redact_head=4,
        redact_tail=4,
    )
    assert any(f.rule_id == "private-key" for f in findings)


def test_inline_ignore_skips_line():
    content = b"api_key='SUPERSECRET123456'  # secretscout:ignore\n"
    findings = scan_bytes(
        "a.py",
        content,
        DEFAULT_RULES,
        allowlist=[],
        path_allowlist=[],
        baseline=set(),
        redact_head=4,
        redact_tail=4,
    )
    assert findings == []


def test_path_allowlist_skips_file():
    content = b"token=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
    findings = scan_bytes(
        "tests/fixtures/a.py",
        content,
        DEFAULT_RULES,
        allowlist=[],
        path_allowlist=[re.compile(r"(^|/)tests?/fixtures(/|$)")],
        baseline=set(),
        redact_head=4,
        redact_tail=4,
    )
    assert findings == []


def test_baseline_skips_known_fingerprint():
    content = b"token=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
    findings = scan_bytes(
        "a.py",
        content,
        DEFAULT_RULES,
        allowlist=[],
        path_allowlist=[],
        baseline=set(),
        redact_head=4,
        redact_tail=4,
    )
    assert findings

    # baseline должен содержать ВСЕ старые fingerprints, а не только один
    fps = {f.fingerprint for f in findings}

    findings2 = scan_bytes(
        "a.py",
        content,
        DEFAULT_RULES,
        allowlist=[],
        path_allowlist=[],
        baseline=fps,
        redact_head=4,
        redact_tail=4,
    )
    assert findings2 == []

